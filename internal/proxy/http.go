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

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// HTTPHandler handles HTTP and HTTPS CONNECT proxy requests.
type HTTPHandler struct {
	getBackend       func(domain, clientIP string) backend.Backend
	dialTimeout      time.Duration
	onConnect        func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	onError          func(ctx context.Context, conn net.Conn, host string, err error)
	cacheInterceptor *cache.Interceptor
}


// HTTPHandlerConfig configures the HTTP handler.
type HTTPHandlerConfig struct {
	GetBackend       func(domain, clientIP string) backend.Backend
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
		dialTimeout:      cfg.DialTimeout,
		onConnect:        cfg.OnConnect,
		onError:          cfg.OnError,
		cacheInterceptor: cfg.CacheInterceptor,
	}
}

// ServeConn handles a client connection.
func (h *HTTPHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Add client info to context
	clientIP := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}
	ctx = util.WithClientIP(ctx, clientIP)
	ctx = util.WithStartTime(ctx, time.Now())

	// Read the first request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			h.handleError(ctx, conn, "", fmt.Errorf("read request: %w", err))
		}
		return
	}

	// Extract host
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	ctx = util.WithDomain(ctx, util.GetHostFromRequest(host))

	// Handle based on method
	if req.Method == http.MethodConnect {
		h.handleConnect(ctx, conn, req, clientIP)
	} else {
		h.handleHTTP(ctx, conn, req, reader, clientIP)
	}
}

// handleConnect handles HTTPS CONNECT requests.
func (h *HTTPHandler) handleConnect(ctx context.Context, conn net.Conn, req *http.Request, clientIP string) {
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
		h.handleError(ctx, conn, host, fmt.Errorf("no backend for domain: %s", domain))
		return
	}

	ctx = util.WithBackend(ctx, be.Name())

	// Dial the target through the backend
	targetConn, err := be.DialTimeout(ctx, "tcp", host, h.dialTimeout)
	if err != nil {
		h.sendResponse(conn, http.StatusBadGateway, "Connection failed")
		h.handleError(ctx, conn, host, err)
		return
	}
	defer targetConn.Close()

	// Send 200 OK to client
	h.sendResponse(conn, http.StatusOK, "Connection Established")

	// Notify connect callback
	if h.onConnect != nil {
		h.onConnect(ctx, conn, host, be)
	}

	// Start bidirectional copy
	CopyBidirectional(ctx, conn, targetConn)
}

// handleHTTP handles plain HTTP requests (forward proxy).
func (h *HTTPHandler) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request, reader *bufio.Reader, clientIP string) {
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
		h.handleError(ctx, conn, host, fmt.Errorf("no backend for domain: %s", domain))
		return
	}

	ctx = util.WithBackend(ctx, be.Name())

	// Dial the target through the backend
	targetConn, err := be.DialTimeout(ctx, "tcp", host, h.dialTimeout)
	if err != nil {
		h.sendHTTPError(conn, http.StatusBadGateway, "Connection failed")
		h.handleError(ctx, conn, host, err)
		return
	}
	defer targetConn.Close()

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
		h.handleError(ctx, conn, host, fmt.Errorf("write request: %w", err))
		return
	}

	// Read response from target and forward to client
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		h.handleError(ctx, conn, host, fmt.Errorf("read response: %w", err))
		return
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
		h.handleError(ctx, conn, host, fmt.Errorf("write response: %w", err))
		return
	}
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
