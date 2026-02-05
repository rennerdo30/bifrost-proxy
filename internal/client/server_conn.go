package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ServerConnection manages the connection to the Bifrost server.
type ServerConnection struct {
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

// NewServerConnection creates a new server connection.
func NewServerConnection(cfg ServerConnectionConfig) *ServerConnection {
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

	return &ServerConnection{
		config: cfg,
		dialer: &net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// Connect establishes a connection to the target through the server.
func (s *ServerConnection) Connect(ctx context.Context, target string) (net.Conn, error) {
	var lastErr error

	for attempt := 0; attempt <= s.config.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(s.config.RetryDelay):
			}
		}

		conn, err := s.connect(ctx, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", s.config.RetryCount+1, lastErr)
}

func (s *ServerConnection) connect(ctx context.Context, target string) (net.Conn, error) {
	switch s.config.Protocol {
	case "http":
		return s.connectHTTP(ctx, target)
	case "socks5":
		return s.connectSOCKS5(ctx, target)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", s.config.Protocol)
	}
}

// connectHTTP connects through HTTP CONNECT.
func (s *ServerConnection) connectHTTP(ctx context.Context, target string) (net.Conn, error) {
	// Connect to server
	conn, err := s.dialer.DialContext(ctx, "tcp", s.config.Address)
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
	if s.config.Username != "" {
		auth := base64.StdEncoding.EncodeToString(
			[]byte(s.config.Username + ":" + s.config.Password),
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
	// Connect to server
	conn, err := s.dialer.DialContext(ctx, "tcp", s.config.Address)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	// SOCKS5 handshake
	var authMethods []byte
	if s.config.Username != "" {
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

	// Read response
	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read greeting response: %w", err)
	}

	if response[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS version: %d", response[0])
	}

	// Handle auth
	if response[1] == 0x02 && s.config.Username != "" {
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
	// Username/password auth
	auth := make([]byte, 3+len(s.config.Username)+len(s.config.Password))
	auth[0] = 0x01 // Version
	auth[1] = byte(len(s.config.Username))
	copy(auth[2:], s.config.Username)
	auth[2+len(s.config.Username)] = byte(len(s.config.Password))
	copy(auth[3+len(s.config.Username):], s.config.Password)

	if _, err := conn.Write(auth); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
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
	if _, err := conn.Read(response); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}

	if response[1] != 0x00 {
		return fmt.Errorf("connect failed: %d", response[1])
	}

	// Read and discard bound address
	switch response[3] {
	case 0x01: // IPv4
		buf := make([]byte, 6)
		_, _ = conn.Read(buf) //nolint:errcheck // Discarding bound address
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		_, _ = conn.Read(lenBuf) //nolint:errcheck // Discarding bound address
		buf := make([]byte, int(lenBuf[0])+2)
		_, _ = conn.Read(buf) //nolint:errcheck // Discarding bound address
	case 0x04: // IPv6
		buf := make([]byte, 18)
		_, _ = conn.Read(buf) //nolint:errcheck // Discarding bound address
	}

	return nil
}

// IsConnected checks if the server is reachable.
func (s *ServerConnection) IsConnected(ctx context.Context) bool {
	conn, err := s.dialer.DialContext(ctx, "tcp", s.config.Address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
