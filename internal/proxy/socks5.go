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

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
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
	getBackend   func(domain, clientIP string) backend.Backend
	authenticate func(username, password string) bool
	authRequired bool
	dialTimeout  time.Duration
	onConnect    func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	onError      func(ctx context.Context, conn net.Conn, host string, err error)
}

// SOCKS5HandlerConfig configures the SOCKS5 handler.
type SOCKS5HandlerConfig struct {
	GetBackend   func(domain, clientIP string) backend.Backend
	Authenticate func(username, password string) bool
	AuthRequired bool
	DialTimeout  time.Duration
	OnConnect    func(ctx context.Context, conn net.Conn, host string, backend backend.Backend)
	OnError      func(ctx context.Context, conn net.Conn, host string, err error)
}

// NewSOCKS5Handler creates a new SOCKS5 proxy handler.
func NewSOCKS5Handler(cfg SOCKS5HandlerConfig) *SOCKS5Handler {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	return &SOCKS5Handler{
		getBackend:   cfg.GetBackend,
		authenticate: cfg.Authenticate,
		authRequired: cfg.AuthRequired,
		dialTimeout:  cfg.DialTimeout,
		onConnect:    cfg.OnConnect,
		onError:      cfg.OnError,
	}
}

// ServeConn handles a client connection.
func (h *SOCKS5Handler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Add client info to context
	clientIP := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}
	ctx = util.WithClientIP(ctx, clientIP)
	ctx = util.WithStartTime(ctx, time.Now())

	// Handle authentication
	if err := h.handleAuth(conn); err != nil {
		h.handleError(ctx, conn, "", err)
		return
	}

	// Handle request
	target, err := h.handleRequest(ctx, conn, clientIP)
	if err != nil {
		h.handleError(ctx, conn, target, err)
	}
}

// handleAuth performs SOCKS5 authentication handshake.
func (h *SOCKS5Handler) handleAuth(conn net.Conn) error {
	// Read version and auth methods count
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}

	if header[0] != socks5Version {
		return errors.New("invalid SOCKS version")
	}

	// Read auth methods
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read auth methods: %w", err)
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
		} else if hasPassword && h.authenticate != nil {
			selectedMethod = socks5AuthPassword
		}
	}

	// Send selected method
	if _, err := conn.Write([]byte{socks5Version, selectedMethod}); err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}

	if selectedMethod == socks5AuthNoAccept {
		return errors.New("no acceptable auth method")
	}

	// Handle password authentication
	if selectedMethod == socks5AuthPassword {
		if err := h.handlePasswordAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

// handlePasswordAuth handles username/password authentication.
func (h *SOCKS5Handler) handlePasswordAuth(conn net.Conn) error {
	// Read version
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return fmt.Errorf("read auth version: %w", err)
	}

	if version[0] != 0x01 {
		return errors.New("invalid auth version")
	}

	// Read username
	usernameLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, usernameLen); err != nil {
		return fmt.Errorf("read username length: %w", err)
	}

	username := make([]byte, usernameLen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	// Read password
	passwordLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLen); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}

	password := make([]byte, passwordLen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	// Authenticate
	if h.authenticate == nil || !h.authenticate(string(username), string(password)) {
		if _, err := conn.Write([]byte{0x01, 0x01}); err != nil { // Auth failed
			slog.Debug("failed to send SOCKS5 auth failure response",
				"error", err,
				"remote_addr", conn.RemoteAddr(),
			)
		}
		return errors.New("authentication failed")
	}

	// Auth success
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		slog.Debug("failed to send SOCKS5 auth success response",
			"error", err,
			"remote_addr", conn.RemoteAddr(),
		)
		return fmt.Errorf("write auth success: %w", err)
	}
	return nil
}

// handleRequest handles the SOCKS5 connection request.
func (h *SOCKS5Handler) handleRequest(ctx context.Context, conn net.Conn, clientIP string) (string, error) {
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

	// Handle command
	switch cmd {
	case socks5CmdConnect:
		return target, h.handleConnect(ctx, conn, target, clientIP)
	case socks5CmdBind:
		h.sendReply(conn, socks5ReplyCmdNotSupported, nil)
		return target, errors.New("BIND not supported")
	case socks5CmdUDPAssociate:
		h.sendReply(conn, socks5ReplyCmdNotSupported, nil)
		return target, errors.New("UDP ASSOCIATE not supported")
	default:
		h.sendReply(conn, socks5ReplyCmdNotSupported, nil)
		return target, fmt.Errorf("unsupported command: %d", cmd)
	}
}

// handleConnect handles the CONNECT command.
func (h *SOCKS5Handler) handleConnect(ctx context.Context, conn net.Conn, target string, clientIP string) error {
	// Get backend for this domain
	domain := util.GetHostFromRequest(target)
	be := h.getBackend(domain, clientIP)
	if be == nil {
		h.sendReply(conn, socks5ReplyGeneralFailure, nil)
		return fmt.Errorf("no backend for domain: %s", domain)
	}

	ctx = util.WithBackend(ctx, be.Name())

	// Dial the target through the backend
	targetConn, err := be.DialTimeout(ctx, "tcp", target, h.dialTimeout)
	if err != nil {
		h.sendReply(conn, h.errToReply(err), nil)
		return err
	}
	defer targetConn.Close()

	// Get local address for reply
	localAddr := targetConn.LocalAddr()

	// Send success reply
	h.sendReply(conn, socks5ReplySuccess, localAddr)

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
			binary.BigEndian.PutUint16(port, uint16(addr.Port))
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
