// Package proxy provides proxy protocol implementations.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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

// NegotiateResult is returned by a NegotiateAuth hook. On success UserInfo is
// set. When the hook needs the client to continue the handshake it sets
// Challenge=true along with ChallengeStatus/ChallengeHeaders (the
// Proxy-Authenticate response). An error indicates a hard authentication
// failure.
type NegotiateResult struct {
	UserInfo         *auth.UserInfo
	ChallengeStatus  int
	ChallengeHeaders map[string]string
	Challenge        bool
}

// HTTPHandler handles HTTP and HTTPS CONNECT proxy requests.
type HTTPHandler struct {
	getBackend       func(domain, clientIP string) backend.Backend
	authenticate     func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	negotiateAuth    func(ctx context.Context, req *http.Request) (*NegotiateResult, error)
	authRequired     bool
	accessCheck      func(clientIP string) (bool, string)
	rateLimitUser    func(username, clientIP string) bool
	accessLogger     accesslog.Logger
	bandwidth        *ratelimit.BandwidthConfig
	dialTimeout      time.Duration
	dialNetwork      string
	onConnect        func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	onError          func(ctx context.Context, conn net.Conn, host string, err error)
	cacheInterceptor *cache.Interceptor
	// mitm enables live HTTPS interception when non-nil. It defaults to nil
	// (OFF): when nil, CONNECT requests use the opaque tunnel path unchanged.
	mitm *MITMInterceptor
}

// HTTPHandlerConfig configures the HTTP handler.
type HTTPHandlerConfig struct {
	GetBackend    func(domain, clientIP string) backend.Backend
	Authenticate  func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	NegotiateAuth func(ctx context.Context, req *http.Request) (*NegotiateResult, error)
	AuthRequired  bool
	AccessCheck   func(clientIP string) (bool, string)
	RateLimitUser func(username, clientIP string) bool
	AccessLogger  accesslog.Logger
	Bandwidth     *ratelimit.BandwidthConfig
	DialTimeout   time.Duration
	// DialNetwork is the network passed to backend dials ("tcp", "tcp4",
	// "tcp6"). Empty defaults to "tcp".
	DialNetwork      string
	OnConnect        func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	OnError          func(ctx context.Context, conn net.Conn, host string, err error)
	CacheInterceptor *cache.Interceptor
	// MITM enables live HTTPS interception. Leave nil (default) to keep CONNECT
	// tunnels opaque. Construct one only when config MITM is enabled and a CA
	// has been loaded.
	MITM *MITMInterceptor
}

// NewHTTPHandler creates a new HTTP proxy handler.
func NewHTTPHandler(cfg HTTPHandlerConfig) *HTTPHandler {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.DialNetwork == "" {
		cfg.DialNetwork = "tcp"
	}
	return &HTTPHandler{
		getBackend:       cfg.GetBackend,
		authenticate:     cfg.Authenticate,
		negotiateAuth:    cfg.NegotiateAuth,
		authRequired:     cfg.AuthRequired,
		accessCheck:      cfg.AccessCheck,
		rateLimitUser:    cfg.RateLimitUser,
		accessLogger:     cfg.AccessLogger,
		bandwidth:        cfg.Bandwidth,
		dialTimeout:      cfg.DialTimeout,
		dialNetwork:      cfg.DialNetwork,
		onConnect:        cfg.OnConnect,
		onError:          cfg.OnError,
		cacheInterceptor: cfg.CacheInterceptor,
		mitm:             cfg.MITM,
	}
}

// tlsConnectionStater is implemented by TLS connections that can report
// their handshake state (e.g. *tls.Conn).
type tlsConnectionStater interface {
	ConnectionState() tls.ConnectionState
}

// peerCertificate returns the leaf client certificate from a TLS-terminated
// connection, or nil if the connection is not TLS or presented no client
// certificate. It completes the TLS handshake if necessary so the peer
// certificates are populated.
func peerCertificate(conn net.Conn) *x509.Certificate {
	tc, ok := conn.(tlsConnectionStater)
	if !ok {
		return nil
	}
	// Ensure the handshake has completed so PeerCertificates is populated.
	if hc, ok := conn.(interface{ Handshake() error }); ok {
		if err := hc.Handshake(); err != nil {
			return nil
		}
	}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
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

	// If the client connection is TLS-terminated and presented a client
	// certificate, expose it on the context so the mTLS auth plugin can
	// authenticate the request. We populate the canonical auth context key.
	if cert := peerCertificate(conn); cert != nil {
		ctx = context.WithValue(ctx, auth.ClientCertContextKey, cert)
	}

	// Read the first request
	reader := bufio.NewReader(counting)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			h.handleError(ctx, counting, "", fmt.Errorf("read request: %w", err))
		}
		return
	}

	// http.ReadRequest on a raw net.Conn does not populate RemoteAddr; set it
	// so request-scoped consumers (e.g. the Negotiate handler's per-client
	// session key) can distinguish clients instead of all sharing "".
	req.RemoteAddr = conn.RemoteAddr().String()

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
			_ = h.accessLogger.Log(*entry) //nolint:errcheck // Best effort access logging
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

	// Negotiate (SPNEGO/Kerberos, optionally NTLM) authentication. This runs
	// before Basic/Bearer handling because it uses the Negotiate/NTLM
	// Proxy-Authorization schemes and may need to send a challenge.
	if h.negotiateAuth != nil && isNegotiateScheme(req.Header.Get("Proxy-Authorization")) {
		handled, ng := h.handleNegotiate(ctx, counting, req, entry)
		if handled {
			return
		}
		if ng != nil && ng.UserInfo != nil {
			ctx = util.WithUsername(ctx, ng.UserInfo.Username)
		}
	} else if h.authRequired || req.Header.Get("Proxy-Authorization") != "" {
		// Authentication (Proxy-Authorization)
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
	targetConn, err := be.DialTimeout(ctx, h.dialNetwork, host, h.dialTimeout)
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

	// Live HTTPS interception (MITM). Gated entirely behind a non-nil, in-scope
	// interceptor: when MITM is disabled (h.mitm == nil) or the host is bypassed,
	// shouldIntercept returns false and we fall through to the opaque tunnel,
	// keeping behavior byte-for-byte identical to a non-MITM build.
	if h.mitm.shouldIntercept(host) {
		if err := h.interceptConnect(ctx, conn, targetConn, host); err != nil {
			// Interception failures are logged via the error callback by the
			// caller; the tunnel is already half-consumed (TLS terminated) so we
			// cannot safely fall back to an opaque copy here.
			return err
		}
		return nil
	}

	// Start bidirectional copy (opaque tunnel; MITM disabled or bypassed).
	CopyBidirectional(ctx, conn, targetConn)
	return nil
}

// handleHTTP handles plain HTTP requests (forward proxy).
func (h *HTTPHandler) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request, _ *bufio.Reader, clientIP string, entry *accesslog.Entry) error {
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
			return nil
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
	targetConn, err := be.DialTimeout(ctx, h.dialNetwork, host, h.dialTimeout)
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
	if writeErr := req.Write(targetConn); writeErr != nil {
		return fmt.Errorf("write request: %w", writeErr)
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

	// Fall back to client-certificate (mTLS) authentication if a peer
	// certificate was presented on the TLS connection. The cert was placed
	// on the context by ServeConn; the authenticator (mtls plugin) reads it
	// from the context.
	if ctx.Value(auth.ClientCertContextKey) != nil {
		return h.authenticate(ctx, "", "")
	}

	return nil, fmt.Errorf("missing proxy credentials")
}

// isNegotiateScheme reports whether the Proxy-Authorization header uses the
// Negotiate or NTLM scheme.
func isNegotiateScheme(header string) bool {
	if header == "" {
		return false
	}
	scheme := header
	if i := strings.IndexByte(header, ' '); i >= 0 {
		scheme = header[:i]
	}
	switch strings.ToLower(scheme) {
	case "negotiate", "ntlm":
		return true
	default:
		return false
	}
}

// handleNegotiate drives the Negotiate authentication hook. It returns
// handled=true when the request is fully handled here (challenge sent or hard
// failure), in which case the caller must stop processing. When handled=false,
// the returned *NegotiateResult (if non-nil with UserInfo) carries the
// authenticated identity.
func (h *HTTPHandler) handleNegotiate(ctx context.Context, conn net.Conn, req *http.Request, entry *accesslog.Entry) (bool, *NegotiateResult) {
	result, err := h.negotiateAuth(ctx, req)
	if err != nil {
		entry.StatusCode = http.StatusProxyAuthRequired
		entry.Error = err.Error()
		h.sendNegotiateChallenge(conn, http.StatusProxyAuthRequired, map[string]string{
			"Proxy-Authenticate": "Negotiate",
		})
		return true, nil
	}

	if result != nil && result.Challenge {
		status := result.ChallengeStatus
		if status == 0 {
			status = http.StatusProxyAuthRequired
		}
		entry.StatusCode = status
		h.sendNegotiateChallenge(conn, status, result.ChallengeHeaders)
		return true, nil
	}

	return false, result
}

// sendNegotiateChallenge writes a proxy authentication challenge response with
// the supplied headers (e.g. Proxy-Authenticate).
func (h *HTTPHandler) sendNegotiateChallenge(conn net.Conn, status int, headers map[string]string) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, http.StatusText(status)))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	// Keep the connection open so the client can continue the handshake.
	sb.WriteString("Content-Length: 0\r\n")
	sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		slog.Debug("failed to send negotiate challenge", "error", err)
	}
}

func (h *HTTPHandler) sendProxyAuthRequired(conn net.Conn) {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 407 Proxy Authentication Required\r\n")
	// Advertise Negotiate first when it is configured, so SPNEGO/Negotiate
	// clients (which wait for a Negotiate challenge before sending a token)
	// can authenticate even on the initial no-credentials request.
	if h.negotiateAuth != nil {
		sb.WriteString("Proxy-Authenticate: Negotiate\r\n")
	}
	sb.WriteString("Proxy-Authenticate: Basic realm=\"Bifrost\"\r\n")
	sb.WriteString("Proxy-Authenticate: Bearer\r\n")
	sb.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		slog.Debug("failed to send proxy auth required", "error", err)
	}
}
