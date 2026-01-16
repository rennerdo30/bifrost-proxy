package backend

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPProxyBackend connects through an upstream HTTP proxy using CONNECT.
type HTTPProxyBackend struct {
	name      string
	address   string
	username  string
	password  string
	dialer    *net.Dialer
	startTime time.Time
	healthy   atomic.Bool
	stats     httpProxyStats
	mu        sync.RWMutex
	running   bool
}

type httpProxyStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// HTTPProxyConfig holds configuration for an HTTP proxy backend.
type HTTPProxyConfig struct {
	Name           string        `yaml:"name"`
	Address        string        `yaml:"address"`
	Username       string        `yaml:"username"`
	Password       string        `yaml:"password"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// NewHTTPProxyBackend creates a new HTTP proxy backend.
func NewHTTPProxyBackend(cfg HTTPProxyConfig) *HTTPProxyBackend {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}

	return &HTTPProxyBackend{
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
func (b *HTTPProxyBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *HTTPProxyBackend) Type() string {
	return "http_proxy"
}

// Dial creates a connection through the HTTP proxy.
func (b *HTTPProxyBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
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

	// Send CONNECT request
	connectReq := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Opaque: address,
		},
		Host:   address,
		Header: make(http.Header),
	}

	// Add proxy authentication if configured
	if b.username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(b.username + ":" + b.password))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+auth)
	}

	if err := connectReq.Write(proxyConn); err != nil {
		proxyConn.Close()
		b.recordError(err)
		return nil, NewBackendError(b.name, "write CONNECT", err)
	}

	// Read response
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		proxyConn.Close()
		b.recordError(err)
		return nil, NewBackendError(b.name, "read CONNECT response", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		err := fmt.Errorf("proxy returned status %d", resp.StatusCode)
		b.recordError(err)
		return nil, NewBackendError(b.name, "CONNECT", err)
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

// DialTimeout creates a connection with a specific timeout.
func (b *HTTPProxyBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the backend.
func (b *HTTPProxyBackend) Start(ctx context.Context) error {
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
func (b *HTTPProxyBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.running = false
	b.healthy.Store(false)
	return nil
}

// IsHealthy returns the health status.
func (b *HTTPProxyBackend) IsHealthy() bool {
	return b.healthy.Load()
}

// Stats returns backend statistics.
func (b *HTTPProxyBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "http_proxy",
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

func (b *HTTPProxyBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}
