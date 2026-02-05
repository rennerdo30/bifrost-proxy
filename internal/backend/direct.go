package backend

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DirectBackend provides direct connections without any tunneling.
type DirectBackend struct {
	name      string
	dialer    *net.Dialer
	startTime time.Time
	healthy   atomic.Bool
	stats     directStats
	mu        sync.RWMutex
	running   bool
}

type directStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// DirectConfig holds configuration for a direct backend.
type DirectConfig struct {
	Name           string        `yaml:"name"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	KeepAlive      time.Duration `yaml:"keep_alive"`
	LocalAddr      string        `yaml:"local_addr"`
}

// NewDirectBackend creates a new direct connection backend.
func NewDirectBackend(cfg DirectConfig) *DirectBackend {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 30 * time.Second
	}

	var localAddr net.Addr
	if cfg.LocalAddr != "" {
		// Error is intentionally ignored - if the address is invalid,
		// we'll fall back to using the default local address
		localAddr, _ = net.ResolveTCPAddr("tcp", cfg.LocalAddr) //nolint:errcheck
	}

	return &DirectBackend{
		name: cfg.Name,
		dialer: &net.Dialer{
			Timeout:   cfg.ConnectTimeout,
			KeepAlive: cfg.KeepAlive,
			LocalAddr: localAddr,
		},
	}
}

// Name returns the backend name.
func (b *DirectBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *DirectBackend) Type() string {
	return "direct"
}

// Dial creates a direct connection to the target.
// The context deadline is respected and takes precedence over the configured timeout.
func (b *DirectBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.RLock()
	if !b.running {
		b.mu.RUnlock()
		return nil, NewBackendError(b.name, "dial", ErrBackendNotStarted)
	}
	b.mu.RUnlock()

	// Check if context is already canceled
	if err := ctx.Err(); err != nil {
		return nil, NewBackendError(b.name, "dial", err)
	}

	// Use the context deadline if it's sooner than the configured timeout
	dialer := b.dialer
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < dialer.Timeout {
			// Create a new dialer with the shorter timeout
			dialerCopy := *b.dialer
			dialerCopy.Timeout = remaining
			dialer = &dialerCopy
		}
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		b.recordError(err)
		return nil, NewBackendError(b.name, "dial", err)
	}

	b.stats.activeConns.Add(1)
	b.stats.totalConns.Add(1)

	// Wrap connection to track stats
	tracked := &TrackedConn{
		Conn: conn,
		OnClose: func(bytesRead, bytesWritten int64) {
			b.stats.activeConns.Add(-1)
			b.stats.bytesRecv.Add(bytesRead)
			b.stats.bytesSent.Add(bytesWritten)
		},
	}

	return tracked, nil
}

// DialTimeout creates a connection with a specific timeout.
func (b *DirectBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the backend.
func (b *DirectBackend) Start(ctx context.Context) error {
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
func (b *DirectBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.running = false
	b.healthy.Store(false)
	return nil
}

// IsHealthy returns the health status.
func (b *DirectBackend) IsHealthy() bool {
	return b.healthy.Load()
}

// Stats returns backend statistics.
func (b *DirectBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "direct",
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

func (b *DirectBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}
