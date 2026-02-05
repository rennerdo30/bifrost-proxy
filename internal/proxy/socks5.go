package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/accesslog"
	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/ratelimit"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// domainRegex validates domain name format (RFC 1035 compliant).
// Allows alphanumeric characters, hyphens, and dots.
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// isValidDomain checks if a domain name has a valid format.
func isValidDomain(domain string) bool {
	// Empty domain is invalid
	if len(domain) == 0 {
		return false
	}
	// Domain cannot exceed 253 characters (RFC 1035)
	if len(domain) > 253 {
		return false
	}
	// Check format with regex
	return domainRegex.MatchString(domain)
}

// SOCKS5 constants
const (
	socks5Version         byte = 0x05
	socks5AuthNone        byte = 0x00
	socks5AuthPassword    byte = 0x02
	socks5AuthNoAccept    byte = 0xFF
	socks5CmdConnect      byte = 0x01
	socks5CmdBind         byte = 0x02
	socks5CmdUDPAssociate byte = 0x03
	socks5AddrIPv4        byte = 0x01
	socks5AddrDomain      byte = 0x03
	socks5AddrIPv6        byte = 0x04

	socks5ReplySuccess          byte = 0x00
	socks5ReplyGeneralFailure   byte = 0x01
	socks5ReplyConnNotAllowed   byte = 0x02
	socks5ReplyNetUnreachable   byte = 0x03
	socks5ReplyHostUnreachable  byte = 0x04
	socks5ReplyConnRefused      byte = 0x05
	socks5ReplyTTLExpired       byte = 0x06
	socks5ReplyCmdNotSupported  byte = 0x07
	socks5ReplyAddrNotSupported byte = 0x08
)

// SOCKS5Handler handles SOCKS5 proxy requests.
type SOCKS5Handler struct {
	getBackend           func(domain, clientIP string) backend.Backend
	authenticate         func(username, password string) bool
	authenticateWithInfo func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	authRequired         bool
	accessCheck          func(clientIP string) (bool, string)
	rateLimitUser        func(username, clientIP string) bool
	accessLogger         accesslog.Logger
	bandwidth            *ratelimit.BandwidthConfig
	dialTimeout          time.Duration
	onConnect            func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	onError              func(ctx context.Context, conn net.Conn, host string, err error)
}

// SOCKS5HandlerConfig configures the SOCKS5 handler.
type SOCKS5HandlerConfig struct {
	GetBackend           func(domain, clientIP string) backend.Backend
	Authenticate         func(username, password string) bool
	AuthenticateWithInfo func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	AuthRequired         bool
	AccessCheck          func(clientIP string) (bool, string)
	RateLimitUser        func(username, clientIP string) bool
	AccessLogger         accesslog.Logger
	Bandwidth            *ratelimit.BandwidthConfig
	DialTimeout          time.Duration
	OnConnect            func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	OnError              func(ctx context.Context, conn net.Conn, host string, err error)
}

// NewSOCKS5Handler creates a new SOCKS5 proxy handler.
func NewSOCKS5Handler(cfg SOCKS5HandlerConfig) *SOCKS5Handler {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	return &SOCKS5Handler{
		getBackend:           cfg.GetBackend,
		authenticate:         cfg.Authenticate,
		authenticateWithInfo: cfg.AuthenticateWithInfo,
		authRequired:         cfg.AuthRequired,
		accessCheck:          cfg.AccessCheck,
		rateLimitUser:        cfg.RateLimitUser,
		accessLogger:         cfg.AccessLogger,
		bandwidth:            cfg.Bandwidth,
		dialTimeout:          cfg.DialTimeout,
		onConnect:            cfg.OnConnect,
		onError:              cfg.OnError,
	}
}

// ServeConn handles a client connection.
func (h *SOCKS5Handler) ServeConn(ctx context.Context, conn net.Conn) {
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

	entry := &accesslog.Entry{
		Timestamp: startTime,
		ClientIP:  clientIP,
		Protocol:  "SOCKS5",
	}
	defer func() {
		entry.Username = util.GetUsername(ctx)
		entry.Backend = util.GetBackend(ctx)
		entry.RequestID = util.GetRequestID(ctx)
		entry.Duration = time.Since(startTime)
		if entry.BytesReceived == 0 {
			entry.BytesReceived = counting.BytesRead()
		}
		if entry.BytesSent == 0 {
			entry.BytesSent = counting.BytesWritten()
		}
		if entry.StatusCode == 0 {
			entry.StatusCode = int(socks5ReplyGeneralFailure)
		}
		if h.accessLogger != nil {
			_ = h.accessLogger.Log(*entry) //nolint:errcheck // Best effort access logging
		}
	}()

	// Handle authentication
	userInfo, err := h.handleAuth(ctx, counting)
	if err != nil {
		entry.StatusCode = int(socks5ReplyGeneralFailure)
		entry.Error = err.Error()
		h.handleError(ctx, counting, "", err)
		return
	}
	if userInfo != nil {
		ctx = util.WithUsername(ctx, userInfo.Username)
	}

	// Handle request
	target, err := h.handleRequest(ctx, counting, clientIP, entry)
	if err != nil {
		if entry.StatusCode == 0 {
			entry.StatusCode = int(socks5ReplyGeneralFailure)
		}
		entry.Error = err.Error()
		h.handleError(ctx, counting, target, err)
	}
}

// handleAuth performs SOCKS5 authentication handshake.
func (h *SOCKS5Handler) handleAuth(ctx context.Context, conn net.Conn) (*auth.UserInfo, error) {
	// Read version and auth methods count
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read auth header: %w", err)
	}

	if header[0] != socks5Version {
		return nil, errors.New("invalid SOCKS version")
	}

	// Read auth methods
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("read auth methods: %w", err)
	}

	// Select auth method
	var selectedMethod byte = socks5AuthNoAccept
	hasNone := false
	hasPassword := false

	for _, m := range methods {
		if m == socks5AuthNone {
			hasNone = true
		}
		if m == socks5AuthPassword {
			hasPassword = true
		}
	}

	if h.authRequired {
		if hasPassword {
			selectedMethod = socks5AuthPassword
		}
	} else {
		if hasNone {
			selectedMethod = socks5AuthNone
		} else if hasPassword && (h.authenticate != nil || h.authenticateWithInfo != nil) {
			selectedMethod = socks5AuthPassword
		}
	}

	// Send selected method
	if _, err := conn.Write([]byte{socks5Version, selectedMethod}); err != nil {
		return nil, fmt.Errorf("write auth response: %w", err)
	}

	if selectedMethod == socks5AuthNoAccept {
		return nil, errors.New("no acceptable auth method")
	}

	// Handle password authentication
	if selectedMethod == socks5AuthPassword {
		return h.handlePasswordAuth(ctx, conn)
	}

	return nil, nil
}

// handlePasswordAuth handles username/password authentication.
func (h *SOCKS5Handler) handlePasswordAuth(ctx context.Context, conn net.Conn) (*auth.UserInfo, error) {
	// Read version
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return nil, fmt.Errorf("read auth version: %w", err)
	}

	if version[0] != 0x01 {
		return nil, errors.New("invalid auth version")
	}

	// Read username
	usernameLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, usernameLen); err != nil {
		return nil, fmt.Errorf("read username length: %w", err)
	}

	username := make([]byte, usernameLen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, fmt.Errorf("read username: %w", err)
	}

	// Read password
	passwordLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLen); err != nil {
		return nil, fmt.Errorf("read password length: %w", err)
	}

	password := make([]byte, passwordLen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	// Authenticate
	var userInfo *auth.UserInfo
	var err error

	if h.authenticateWithInfo != nil {
		userInfo, err = h.authenticateWithInfo(ctx, string(username), string(password))
	} else if h.authenticate != nil {
		if h.authenticate(string(username), string(password)) {
			userInfo = &auth.UserInfo{Username: string(username)}
		} else {
			err = errors.New("authentication failed")
		}
	} else if h.authRequired {
		err = errors.New("authentication required")
	}

	if err != nil {
		if _, writeErr := conn.Write([]byte{0x01, 0x01}); writeErr != nil { // Auth failed
			slog.Debug("failed to send SOCKS5 auth failure response",
				"error", writeErr,
				"remote_addr", conn.RemoteAddr(),
			)
		}
		return nil, err
	}

	// Auth success
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		slog.Debug("failed to send SOCKS5 auth success response",
			"error", err,
			"remote_addr", conn.RemoteAddr(),
		)
		return nil, fmt.Errorf("write auth success: %w", err)
	}
	return userInfo, nil
}

// handleRequest handles the SOCKS5 connection request.
func (h *SOCKS5Handler) handleRequest(ctx context.Context, conn net.Conn, clientIP string, entry *accesslog.Entry) (string, error) {
	// Read request header
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if header[0] != socks5Version {
		return "", errors.New("invalid SOCKS version")
	}

	cmd := header[1]
	addrType := header[3]

	// Read target address
	var host string
	switch addrType {
	case socks5AddrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(addr).String()

	case socks5AddrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(addr).String()

	case socks5AddrDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		domainStr := string(domain)
		// Validate domain format to prevent malformed requests
		if !isValidDomain(domainStr) {
			h.sendReply(conn, socks5ReplyGeneralFailure, nil)
			if entry != nil {
				entry.StatusCode = int(socks5ReplyGeneralFailure)
			}
			return "", fmt.Errorf("invalid domain format: %s", domainStr)
		}
		host = domainStr

	default:
		h.sendReply(conn, socks5ReplyAddrNotSupported, nil)
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	// Format target address - wrap IPv6 in brackets
	var target string
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// IPv6 address - wrap in brackets
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}
	ctx = util.WithDomain(ctx, util.GetHostFromRequest(host))

	if entry != nil {
		entry.Host = host
	}

	// Handle command
	switch cmd {
	case socks5CmdConnect:
		if entry != nil {
			entry.Method = "CONNECT"
			entry.Path = target
		}
		return target, h.handleConnect(ctx, conn, target, clientIP, entry)
	case socks5CmdBind:
		h.sendReply(conn, socks5ReplyCmdNotSupported, nil)
		if entry != nil {
			entry.Method = "BIND"
			entry.StatusCode = int(socks5ReplyCmdNotSupported)
		}
		return target, errors.New("BIND not supported")
	case socks5CmdUDPAssociate:
		h.sendReply(conn, socks5ReplyCmdNotSupported, nil)
		if entry != nil {
			entry.Method = "UDP_ASSOCIATE"
			entry.StatusCode = int(socks5ReplyCmdNotSupported)
		}
		return target, errors.New("UDP ASSOCIATE not supported")
	default:
		h.sendReply(conn, socks5ReplyCmdNotSupported, nil)
		if entry != nil {
			entry.Method = fmt.Sprintf("CMD_%d", cmd)
			entry.StatusCode = int(socks5ReplyCmdNotSupported)
		}
		return target, fmt.Errorf("unsupported command: %d", cmd)
	}
}

// handleConnect handles the CONNECT command.
func (h *SOCKS5Handler) handleConnect(ctx context.Context, conn net.Conn, target string, clientIP string, entry *accesslog.Entry) error {
	// Get backend for this domain
	domain := util.GetHostFromRequest(target)

	// Access control
	if h.accessCheck != nil {
		allowed, reason := h.accessCheck(clientIP)
		if !allowed {
			h.sendReply(conn, socks5ReplyConnNotAllowed, nil)
			if entry != nil {
				entry.StatusCode = int(socks5ReplyConnNotAllowed)
				entry.Error = reason
			}
			return fmt.Errorf("access denied: %s", reason)
		}
	}

	// Per-user rate limiting
	if h.rateLimitUser != nil {
		username := util.GetUsername(ctx)
		if !h.rateLimitUser(username, clientIP) {
			h.sendReply(conn, socks5ReplyGeneralFailure, nil)
			if entry != nil {
				entry.StatusCode = int(socks5ReplyGeneralFailure)
				entry.Error = "rate limit exceeded"
			}
			return errors.New("rate limit exceeded")
		}
	}

	be := h.getBackend(domain, clientIP)
	if be == nil {
		h.sendReply(conn, socks5ReplyGeneralFailure, nil)
		if entry != nil {
			entry.StatusCode = int(socks5ReplyGeneralFailure)
		}
		return fmt.Errorf("no backend for domain: %s", domain)
	}

	ctx = util.WithBackend(ctx, be.Name())

	// Dial the target through the backend
	targetConn, err := be.DialTimeout(ctx, "tcp", target, h.dialTimeout)
	if err != nil {
		reply := h.errToReply(err)
		h.sendReply(conn, reply, nil)
		if entry != nil {
			entry.StatusCode = int(reply)
		}
		return err
	}
	defer targetConn.Close()

	// Apply bandwidth throttling if configured
	if h.bandwidth != nil {
		targetConn = ratelimit.NewThrottledConn(targetConn, h.bandwidth.Download, h.bandwidth.Upload)
	}

	// Get local address for reply
	localAddr := targetConn.LocalAddr()

	// Send success reply
	h.sendReply(conn, socks5ReplySuccess, localAddr)
	if entry != nil {
		entry.StatusCode = int(socks5ReplySuccess)
	}

	// Notify connect callback
	if h.onConnect != nil {
		h.onConnect(ctx, conn, target, be)
	}

	// Start bidirectional copy
	CopyBidirectional(ctx, conn, targetConn)
	return nil
}

// sendReply sends a SOCKS5 reply.
func (h *SOCKS5Handler) sendReply(conn net.Conn, reply byte, bindAddr net.Addr) {
	resp := []byte{socks5Version, reply, 0x00}

	if bindAddr == nil {
		// Use null address
		resp = append(resp, socks5AddrIPv4, 0, 0, 0, 0, 0, 0)
	} else {
		switch addr := bindAddr.(type) {
		case *net.TCPAddr:
			if ip4 := addr.IP.To4(); ip4 != nil {
				resp = append(resp, socks5AddrIPv4)
				resp = append(resp, ip4...)
			} else {
				resp = append(resp, socks5AddrIPv6)
				resp = append(resp, addr.IP...)
			}
			port := make([]byte, 2)
			binary.BigEndian.PutUint16(port, uint16(addr.Port)) //nolint:gosec // G115: TCP port is always 0-65535
			resp = append(resp, port...)
		default:
			resp = append(resp, socks5AddrIPv4, 0, 0, 0, 0, 0, 0)
		}
	}

	if _, err := conn.Write(resp); err != nil {
		slog.Debug("failed to send SOCKS5 reply",
			"reply", reply,
			"error", err,
			"remote_addr", conn.RemoteAddr(),
		)
	}
}

// errToReply converts an error to a SOCKS5 reply code.
func (h *SOCKS5Handler) errToReply(err error) byte {
	if err == nil {
		return socks5ReplySuccess
	}

	var netErr *net.OpError
	if errors.As(err, &netErr) {
		if netErr.Op == "dial" {
			return socks5ReplyConnRefused
		}
	}

	return socks5ReplyGeneralFailure
}

// handleError calls the error callback if set.
func (h *SOCKS5Handler) handleError(ctx context.Context, conn net.Conn, host string, err error) {
	if h.onError != nil {
		h.onError(ctx, conn, host, err)
	}
}
