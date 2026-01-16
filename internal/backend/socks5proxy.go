package backend

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SOCKS5 constants
const (
	socks5Version    byte = 0x05
	socks5AuthNone   byte = 0x00
	socks5AuthPasswd byte = 0x02
	socks5CmdConnect byte = 0x01
	socks5AddrIPv4   byte = 0x01
	socks5AddrDomain byte = 0x03
	socks5AddrIPv6   byte = 0x04
	socks5ReplyOK    byte = 0x00
)

// SOCKS5ProxyBackend connects through an upstream SOCKS5 proxy.
type SOCKS5ProxyBackend struct {
	name      string
	address   string
	username  string
	password  string
	dialer    *net.Dialer
	startTime time.Time
	healthy   atomic.Bool
	stats     socks5ProxyStats
	mu        sync.RWMutex
	running   bool
}

type socks5ProxyStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// SOCKS5ProxyConfig holds configuration for a SOCKS5 proxy backend.
type SOCKS5ProxyConfig struct {
	Name           string        `yaml:"name"`
	Address        string        `yaml:"address"`
	Username       string        `yaml:"username"`
	Password       string        `yaml:"password"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// NewSOCKS5ProxyBackend creates a new SOCKS5 proxy backend.
func NewSOCKS5ProxyBackend(cfg SOCKS5ProxyConfig) *SOCKS5ProxyBackend {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}

	return &SOCKS5ProxyBackend{
		name:     cfg.Name,
		address:  cfg.Address,
		username: cfg.Username,
		password: cfg.Password,
		dialer: &net.Dialer{
			Timeout:   cfg.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// Name returns the backend name.
func (b *SOCKS5ProxyBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *SOCKS5ProxyBackend) Type() string {
	return "socks5_proxy"
}

// Dial creates a connection through the SOCKS5 proxy.
func (b *SOCKS5ProxyBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.RLock()
	if !b.running {
		b.mu.RUnlock()
		return nil, NewBackendError(b.name, "dial", ErrBackendNotStarted)
	}
	b.mu.RUnlock()

	// Connect to the proxy
	proxyConn, err := b.dialer.DialContext(ctx, "tcp", b.address)
	if err != nil {
		b.recordError(err)
		return nil, NewBackendError(b.name, "dial proxy", err)
	}

	// Perform SOCKS5 handshake
	if err := b.handshake(proxyConn); err != nil {
		proxyConn.Close()
		b.recordError(err)
		return nil, NewBackendError(b.name, "handshake", err)
	}

	// Send connect request
	if err := b.connect(proxyConn, address); err != nil {
		proxyConn.Close()
		b.recordError(err)
		return nil, NewBackendError(b.name, "connect", err)
	}

	b.stats.activeConns.Add(1)
	b.stats.totalConns.Add(1)

	// Wrap connection to track stats
	tracked := &TrackedConn{
		Conn: proxyConn,
		OnClose: func(bytesRead, bytesWritten int64) {
			b.stats.activeConns.Add(-1)
			b.stats.bytesRecv.Add(bytesRead)
			b.stats.bytesSent.Add(bytesWritten)
		},
	}

	return tracked, nil
}

func (b *SOCKS5ProxyBackend) handshake(conn net.Conn) error {
	// Determine authentication methods
	authMethods := []byte{socks5AuthNone}
	if b.username != "" {
		authMethods = []byte{socks5AuthNone, socks5AuthPasswd}
	}

	// Send greeting
	greeting := make([]byte, 2+len(authMethods))
	greeting[0] = socks5Version
	greeting[1] = byte(len(authMethods))
	copy(greeting[2:], authMethods)

	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	// Read server's choice
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read greeting response: %w", err)
	}

	if response[0] != socks5Version {
		return errors.New("invalid SOCKS version")
	}

	// Handle authentication
	switch response[1] {
	case socks5AuthNone:
		// No authentication required
	case socks5AuthPasswd:
		if err := b.authenticate(conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported auth method: %d", response[1])
	}

	return nil
}

func (b *SOCKS5ProxyBackend) authenticate(conn net.Conn) error {
	// Username/password authentication (RFC 1929)
	auth := make([]byte, 3+len(b.username)+len(b.password))
	auth[0] = 0x01 // Version
	auth[1] = byte(len(b.username))
	copy(auth[2:], b.username)
	auth[2+len(b.username)] = byte(len(b.password))
	copy(auth[3+len(b.username):], b.password)

	if _, err := conn.Write(auth); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	// Read response
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	if response[1] != 0x00 {
		return errors.New("authentication failed")
	}

	return nil
}

func (b *SOCKS5ProxyBackend) connect(conn net.Conn, address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Build connect request
	req := []byte{socks5Version, socks5CmdConnect, 0x00}

	// Add address
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		req = append(req, socks5AddrDomain)
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		req = append(req, socks5AddrIPv4)
		req = append(req, ip4...)
	} else {
		// IPv6
		req = append(req, socks5AddrIPv6)
		req = append(req, ip...)
	}

	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect: %w", err)
	}

	// Read response
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}

	if response[0] != socks5Version {
		return errors.New("invalid SOCKS version in response")
	}

	if response[1] != socks5ReplyOK {
		return fmt.Errorf("connect failed with code: %d", response[1])
	}

	// Read and discard bound address
	switch response[3] {
	case socks5AddrIPv4:
		discard := make([]byte, 4+2) // IPv4 + port
		if _, err := io.ReadFull(conn, discard); err != nil {
			return fmt.Errorf("read bound IPv4 address: %w", err)
		}
	case socks5AddrIPv6:
		discard := make([]byte, 16+2) // IPv6 + port
		if _, err := io.ReadFull(conn, discard); err != nil {
			return fmt.Errorf("read bound IPv6 address: %w", err)
		}
	case socks5AddrDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("read bound domain length: %w", err)
		}
		discard := make([]byte, int(lenByte[0])+2) // domain + port
		if _, err := io.ReadFull(conn, discard); err != nil {
			return fmt.Errorf("read bound domain: %w", err)
		}
	default:
		return fmt.Errorf("unknown address type in SOCKS5 response: %d", response[3])
	}

	return nil
}

// DialTimeout creates a connection with a specific timeout.
func (b *SOCKS5ProxyBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the backend.
func (b *SOCKS5ProxyBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	b.running = true
	b.startTime = time.Now()
	b.healthy.Store(true)
	return nil
}

// Stop shuts down the backend.
func (b *SOCKS5ProxyBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.running = false
	b.healthy.Store(false)
	return nil
}

// IsHealthy returns the health status.
func (b *SOCKS5ProxyBackend) IsHealthy() bool {
	return b.healthy.Load()
}

// Stats returns backend statistics.
func (b *SOCKS5ProxyBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "socks5_proxy",
		Healthy:           b.healthy.Load(),
		ActiveConnections: b.stats.activeConns.Load(),
		TotalConnections:  b.stats.totalConns.Load(),
		BytesSent:         b.stats.bytesSent.Load(),
		BytesReceived:     b.stats.bytesRecv.Load(),
		Errors:            b.stats.errors.Load(),
		LastError:         lastErr,
		LastErrorTime:     lastErrTime,
		Uptime:            time.Since(b.startTime),
	}
}

func (b *SOCKS5ProxyBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}
