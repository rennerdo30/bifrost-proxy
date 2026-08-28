package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// SOCKS5 wire constants (RFC 1928) used when talking to the server as a
// SOCKS5 client.
const (
	// Address types carried in the ATYP field of a connect reply.
	socks5AddrIPv4   byte = 0x01
	socks5AddrDomain byte = 0x03
	socks5AddrIPv6   byte = 0x04

	// socks5PortLen is the width of the two-byte big-endian BND.PORT field.
	socks5PortLen = 2

	// Bound-address lengths, address bytes plus BND.PORT. These are the byte
	// counts that must be consumed in full before the tunneled stream starts.
	socks5BoundAddrLenIPv4 = net.IPv4len + socks5PortLen // 4 + 2
	socks5BoundAddrLenIPv6 = net.IPv6len + socks5PortLen // 16 + 2
)

// ServerConnection manages the connection to the Bifrost server.
type ServerConnection struct {
	mu     sync.RWMutex
	config ServerConnectionConfig
	dialer *net.Dialer
}

// ServerConnectionConfig holds server connection configuration.
type ServerConnectionConfig struct {
	Address    string
	Protocol   string // http, socks5
	Username   string
	Password   string
	Timeout    time.Duration
	RetryCount int
	RetryDelay time.Duration
}

// applyServerConnDefaults fills in default values for unset fields.
func applyServerConnDefaults(cfg ServerConnectionConfig) ServerConnectionConfig {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.RetryCount == 0 {
		cfg.RetryCount = 3
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = time.Second
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "http"
	}
	return cfg
}

// NewServerConnection creates a new server connection.
func NewServerConnection(cfg ServerConnectionConfig) *ServerConnection {
	cfg = applyServerConnDefaults(cfg)

	return &ServerConnection{
		config: cfg,
		dialer: &net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// Reconfigure atomically replaces the server connection settings. Existing,
// in-flight connections keep the settings they were created with; new dials use
// the updated values. This makes server address/protocol/credential/timeout
// changes hot-applicable without recreating the client or its listeners.
func (s *ServerConnection) Reconfigure(cfg ServerConnectionConfig) {
	cfg = applyServerConnDefaults(cfg)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	s.dialer = &net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: 30 * time.Second,
	}
}

// snapshot returns the current config and dialer under a read lock so callers
// operate on a consistent view even while Reconfigure runs concurrently.
func (s *ServerConnection) snapshot() (ServerConnectionConfig, *net.Dialer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.dialer
}

// Connect establishes a connection to the target through the server.
func (s *ServerConnection) Connect(ctx context.Context, target string) (net.Conn, error) {
	cfg, _ := s.snapshot()
	var lastErr error

	for attempt := 0; attempt <= cfg.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(cfg.RetryDelay):
			}
		}

		conn, err := s.connect(ctx, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", cfg.RetryCount+1, lastErr)
}

func (s *ServerConnection) connect(ctx context.Context, target string) (net.Conn, error) {
	cfg, _ := s.snapshot()
	switch cfg.Protocol {
	case "http":
		return s.connectHTTP(ctx, target)
	case "socks5":
		return s.connectSOCKS5(ctx, target)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}

// connectHTTP connects through HTTP CONNECT.
func (s *ServerConnection) connectHTTP(ctx context.Context, target string) (net.Conn, error) {
	cfg, dialer := s.snapshot()
	// Connect to server
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	// Send CONNECT request
	// For CONNECT, the URL must be set with the target as the host
	req := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: target,
		},
		Host:   target,
		Header: make(http.Header),
	}

	// Add authentication
	if cfg.Username != "" {
		auth := base64.StdEncoding.EncodeToString(
			[]byte(cfg.Username + ":" + cfg.Password),
		)
		req.Header.Set("Proxy-Authorization", "Basic "+auth)
	}

	if writeErr := req.Write(conn); writeErr != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", writeErr)
	}

	// Read response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return conn, nil
}

// connectSOCKS5 connects through SOCKS5.
func (s *ServerConnection) connectSOCKS5(ctx context.Context, target string) (net.Conn, error) {
	cfg, dialer := s.snapshot()
	// Connect to server
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	// SOCKS5 handshake
	var authMethods []byte
	if cfg.Username != "" {
		authMethods = []byte{0x00, 0x02} // No auth, Username/password
	} else {
		authMethods = []byte{0x00} // No auth only
	}

	// Send greeting
	greeting := append([]byte{0x05, byte(len(authMethods))}, authMethods...)
	if _, err := conn.Write(greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write greeting: %w", err)
	}

	// Read response. io.ReadFull, not Read: a short read would leave the
	// unconsumed byte to be mis-parsed as the auth method below.
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read greeting response: %w", err)
	}

	if response[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS version: %d", response[0])
	}

	// Handle auth
	if response[1] == 0x02 && cfg.Username != "" {
		if err := s.socks5Auth(conn); err != nil {
			conn.Close()
			return nil, err
		}
	} else if response[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("unsupported auth method: %d", response[1])
	}

	// Send connect request
	if err := s.socks5Connect(conn, target); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (s *ServerConnection) socks5Auth(conn net.Conn) error {
	cfg, _ := s.snapshot()
	// Username/password auth
	auth := make([]byte, 3+len(cfg.Username)+len(cfg.Password))
	auth[0] = 0x01 // Version
	auth[1] = byte(len(cfg.Username))
	copy(auth[2:], cfg.Username)
	auth[2+len(cfg.Username)] = byte(len(cfg.Password))
	copy(auth[3+len(cfg.Username):], cfg.Password)

	if _, err := conn.Write(auth); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	if response[1] != 0x00 {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func (s *ServerConnection) socks5Connect(conn net.Conn, target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Build request
	req := []byte{0x05, 0x01, 0x00} // Version, Connect, Reserved

	// Add address
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		req = append(req, 0x03) // Domain type
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01) // IPv4
		req = append(req, ip4...)
	} else {
		req = append(req, 0x04) // IPv6
		req = append(req, ip...)
	}

	// Add port (big endian)
	req = append(req, byte(portNum>>8), byte(portNum&0xff))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect: %w", err)
	}

	// Read response
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}

	if response[1] != 0x00 {
		return fmt.Errorf("connect failed: %d", response[1])
	}

	// Consume the bound address. Its bytes are discarded, but they MUST be
	// read in full: whatever is left unread here becomes the first bytes the
	// caller reads as tunneled payload. A plain Read may return short, which
	// is how this corrupted the head of a tunneled stream and surfaced as an
	// intermittent TLS handshake failure after an apparently successful
	// connect. A failure now means the stream is desynchronized, so it is
	// reported rather than discarded.
	switch response[3] {
	case socks5AddrIPv4:
		if _, err := io.ReadFull(conn, make([]byte, socks5BoundAddrLenIPv4)); err != nil {
			return fmt.Errorf("read bound address: %w", err)
		}
	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("read bound address length: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+socks5PortLen)); err != nil {
			return fmt.Errorf("read bound address: %w", err)
		}
	case socks5AddrIPv6:
		if _, err := io.ReadFull(conn, make([]byte, socks5BoundAddrLenIPv6)); err != nil {
			return fmt.Errorf("read bound address: %w", err)
		}
	default:
		return fmt.Errorf("unknown SOCKS5 address type %#x in connect reply", response[3])
	}

	return nil
}

// IsConnected checks if the server is reachable.
func (s *ServerConnection) IsConnected(ctx context.Context) bool {
	cfg, dialer := s.snapshot()
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
