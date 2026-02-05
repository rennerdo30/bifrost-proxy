// Package proxy provides proxy protocol implementations.
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/accesslog"
	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/ratelimit"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// HTTPHandler handles HTTP and HTTPS CONNECT proxy requests.
type HTTPHandler struct {
	getBackend       func(domain, clientIP string) backend.Backend
	authenticate     func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	authRequired     bool
	accessCheck      func(clientIP string) (bool, string)
	rateLimitUser    func(username, clientIP string) bool
	accessLogger     accesslog.Logger
	bandwidth        *ratelimit.BandwidthConfig
	dialTimeout      time.Duration
	onConnect        func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	onError          func(ctx context.Context, conn net.Conn, host string, err error)
	cacheInterceptor *cache.Interceptor
}

// HTTPHandlerConfig configures the HTTP handler.
type HTTPHandlerConfig struct {
	GetBackend       func(domain, clientIP string) backend.Backend
	Authenticate     func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	AuthRequired     bool
	AccessCheck      func(clientIP string) (bool, string)
	RateLimitUser    func(username, clientIP string) bool
	AccessLogger     accesslog.Logger
	Bandwidth        *ratelimit.BandwidthConfig
	DialTimeout      time.Duration
	OnConnect        func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	OnError          func(ctx context.Context, conn net.Conn, host string, err error)
	CacheInterceptor *cache.Interceptor
}

// NewHTTPHandler creates a new HTTP proxy handler.
func NewHTTPHandler(cfg HTTPHandlerConfig) *HTTPHandler {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	return &HTTPHandler{
		getBackend:       cfg.GetBackend,
		authenticate:     cfg.Authenticate,
		authRequired:     cfg.AuthRequired,
		accessCheck:      cfg.AccessCheck,
		rateLimitUser:    cfg.RateLimitUser,
		accessLogger:     cfg.AccessLogger,
		bandwidth:        cfg.Bandwidth,
		dialTimeout:      cfg.DialTimeout,
		onConnect:        cfg.OnConnect,
		onError:          cfg.OnError,
		cacheInterceptor: cfg.CacheInterceptor,
	}
}

// ServeConn handles a client connection.
func (h *HTTPHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	counting := newCountingConn(conn)

	// Add client info to context
	clientIP := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}
	ctx = util.WithClientIP(ctx, clientIP)
	startTime := time.Now()
	ctx = util.WithStartTime(ctx, startTime)

	// Read the first request
	reader := bufio.NewReader(counting)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			h.handleError(ctx, counting, "", fmt.Errorf("read request: %w", err))
		}
		return
	}

	// Extract host
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	ctx = util.WithDomain(ctx, util.GetHostFromRequest(host))

	// Access log entry (filled throughout request handling)
	entry := &accesslog.Entry{
		Timestamp: startTime,
		ClientIP:  clientIP,
		Method:    req.Method,
		Host:      host,
		Path:      req.URL.Path,
		Protocol:  req.Proto,
		UserAgent: req.UserAgent(),
	}
	defer func() {
		entry.Username = util.GetUsername(ctx)
		entry.Backend = util.GetBackend(ctx)
		entry.RequestID = util.GetRequestID(ctx)
		entry.Duration = time.Since(startTime)
		// If not set by handlers, use observed bytes
		if entry.BytesReceived == 0 {
			entry.BytesReceived = counting.BytesRead()
		}
		if entry.BytesSent == 0 {
			entry.BytesSent = counting.BytesWritten()
		}
		if entry.StatusCode == 0 {
			entry.StatusCode = http.StatusInternalServerError
		}
		if h.accessLogger != nil {
			_ = h.accessLogger.Log(*entry)
		}
	}()

	// Access control
	if h.accessCheck != nil {
		allowed, reason := h.accessCheck(clientIP)
		if !allowed {
			entry.StatusCode = http.StatusForbidden
			entry.Error = reason
			h.sendHTTPError(counting, http.StatusForbidden, "Forbidden")
			return
		}
	}

	// Authentication (Proxy-Authorization)
	if h.authRequired || req.Header.Get("Proxy-Authorization") != "" {
		userInfo, authErr := h.authenticateRequest(ctx, req)
		if authErr != nil {
			entry.StatusCode = http.StatusProxyAuthRequired
			entry.Error = authErr.Error()
			h.sendProxyAuthRequired(counting)
			return
		}
		if userInfo != nil {
			ctx = util.WithUsername(ctx, userInfo.Username)
		}
	}

	// Per-user rate limiting
	if h.rateLimitUser != nil {
		username := util.GetUsername(ctx)
		if !h.rateLimitUser(username, clientIP) {
			entry.StatusCode = http.StatusTooManyRequests
			entry.Error = "rate limit exceeded"
			h.sendHTTPError(counting, http.StatusTooManyRequests, "Too Many Requests")
			return
		}
	}

	// Handle based on method
	if req.Method == http.MethodConnect {
		if err := h.handleConnect(ctx, counting, req, clientIP, entry); err != nil {
			entry.Error = err.Error()
			h.handleError(ctx, counting, host, err)
		}
	} else {
		if err := h.handleHTTP(ctx, counting, req, reader, clientIP, entry); err != nil {
			entry.Error = err.Error()
			h.handleError(ctx, counting, host, err)
		}
	}
}

// handleConnect handles HTTPS CONNECT requests.
func (h *HTTPHandler) handleConnect(ctx context.Context, conn net.Conn, req *http.Request, clientIP string, entry *accesslog.Entry) error {
	host := req.Host

	// Ensure host has port
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Get backend for this domain
	domain := util.GetHostFromRequest(host)
	be := h.getBackend(domain, clientIP)
	if be == nil {
		h.sendResponse(conn, http.StatusBadGateway, "No backend available")
		entry.StatusCode = http.StatusBadGateway
		return fmt.Errorf("no backend for domain: %s", domain)
	}

	ctx = util.WithBackend(ctx, be.Name())

	// Dial the target through the backend
	targetConn, err := be.DialTimeout(ctx, "tcp", host, h.dialTimeout)
	if err != nil {
		h.sendResponse(conn, http.StatusBadGateway, "Connection failed")
		entry.StatusCode = http.StatusBadGateway
		return err
	}
	defer targetConn.Close()

	// Apply bandwidth throttling if configured
	if h.bandwidth != nil {
		targetConn = ratelimit.NewThrottledConn(targetConn, h.bandwidth.Download, h.bandwidth.Upload)
	}

	// Send 200 OK to client
	h.sendResponse(conn, http.StatusOK, "Connection Established")
	entry.StatusCode = http.StatusOK

	// Notify connect callback
	if h.onConnect != nil {
		h.onConnect(ctx, conn, host, be)
	}

	// Start bidirectional copy
	CopyBidirectional(ctx, conn, targetConn)
	return nil
}

// handleHTTP handles plain HTTP requests (forward proxy).
func (h *HTTPHandler) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request, reader *bufio.Reader, clientIP string, entry *accesslog.Entry) error {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Ensure host has port
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	// Try to serve from cache first (for GET requests)
	if h.cacheInterceptor != nil && req.Method == http.MethodGet {
		handled, err := h.cacheInterceptor.HandleRequest(ctx, conn, req)
		if err != nil {
			slog.Debug("cache error", "error", err, "host", host)
		}
		if handled {
			// Request was served from cache
			return
		}
	}

	// Get backend for this domain
	domain := util.GetHostFromRequest(host)
	be := h.getBackend(domain, clientIP)
	if be == nil {
		h.sendHTTPError(conn, http.StatusBadGateway, "No backend available")
		entry.StatusCode = http.StatusBadGateway
		return fmt.Errorf("no backend for domain: %s", domain)
	}

	ctx = util.WithBackend(ctx, be.Name())

	// Dial the target through the backend
	targetConn, err := be.DialTimeout(ctx, "tcp", host, h.dialTimeout)
	if err != nil {
		h.sendHTTPError(conn, http.StatusBadGateway, "Connection failed")
		entry.StatusCode = http.StatusBadGateway
		return err
	}
	defer targetConn.Close()

	// Apply bandwidth throttling if configured
	if h.bandwidth != nil {
		targetConn = ratelimit.NewThrottledConn(targetConn, h.bandwidth.Download, h.bandwidth.Upload)
	}

	// Notify connect callback
	if h.onConnect != nil {
		h.onConnect(ctx, conn, host, be)
	}

	// Remove proxy headers and forward the request
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	// Convert to relative URL for the upstream request
	req.URL.Scheme = ""
	req.URL.Host = ""

	// Write the request to target
	if err := req.Write(targetConn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Read response from target and forward to client
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	// Store response in cache if applicable
	if h.cacheInterceptor != nil {
		newBody, err := h.cacheInterceptor.StoreResponse(ctx, req, resp)
		if err != nil {
			slog.Debug("cache store error", "error", err, "host", host)
		} else {
			// Replace response body with the new one (the original was read for caching)
			resp.Body = newBody
		}
	}

	// Write response to client
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	entry.StatusCode = resp.StatusCode
	return nil
}

// sendResponse sends an HTTP response for CONNECT.
func (h *HTTPHandler) sendResponse(conn net.Conn, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", statusCode, message)
	if _, err := conn.Write([]byte(response)); err != nil {
		slog.Debug("failed to send HTTP response",
			"status_code", statusCode,
			"error", err,
			"remote_addr", conn.RemoteAddr(),
		)
	}
}

// sendHTTPError sends an HTTP error response.
func (h *HTTPHandler) sendHTTPError(conn net.Conn, statusCode int, message string) {
	body := fmt.Sprintf("<html><body><h1>%d %s</h1></body></html>", statusCode, message)
	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, message, len(body), body,
	)
	if _, err := conn.Write([]byte(response)); err != nil {
		slog.Debug("failed to send HTTP error response",
			"status_code", statusCode,
			"error", err,
			"remote_addr", conn.RemoteAddr(),
		)
	}
}

// handleError calls the error callback if set.
func (h *HTTPHandler) handleError(ctx context.Context, conn net.Conn, host string, err error) {
	if h.onError != nil {
		h.onError(ctx, conn, host, err)
	}
}

func (h *HTTPHandler) authenticateRequest(ctx context.Context, req *http.Request) (*auth.UserInfo, error) {
	if h.authenticate == nil {
		return nil, fmt.Errorf("authentication unavailable")
	}

	// Try Basic proxy auth first
	if username, password, ok := auth.ExtractProxyAuth(req); ok {
		return h.authenticate(ctx, username, password)
	}

	// Try Bearer token
	if token, ok := auth.ExtractProxyBearerToken(req); ok {
		return h.authenticate(ctx, "", token)
	}

	return nil, fmt.Errorf("missing proxy credentials")
}

func (h *HTTPHandler) sendProxyAuthRequired(conn net.Conn) {
	response := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"Bifrost\"\r\n" +
		"Proxy-Authenticate: Bearer\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		slog.Debug("failed to send proxy auth required", "error", err)
	}
}
