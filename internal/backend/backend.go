// Package backend provides backend connection handling for Bifrost.
package backend

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// Backend represents a connection backend (direct, wireguard, openvpn, etc.)
// defaultConnectTimeout is the last-resort bound on an outbound backend dial,
// used only when neither the backend's own connect_timeout nor the global
// network.dial_timeout is configured.
const defaultConnectTimeout = 30 * time.Second

// withDialBound bounds ctx for an outbound dial by a backend that carries no
// dialer of its own. The documented precedence is backend connect_timeout >
// network.dial_timeout > default; these backends have no connect_timeout, so
// the supplied fallback (network.dial_timeout, possibly zero) applies, with
// the package default as the last resort — a zero bound never escapes.
func withDialBound(ctx context.Context, fallback time.Duration) (context.Context, context.CancelFunc) {
	if fallback <= 0 {
		fallback = defaultConnectTimeout
	}
	return context.WithTimeout(ctx, fallback)
}

type Backend interface {
	// Name returns the backend's unique name.
	Name() string

	// Type returns the backend type (direct, wireguard, openvpn, http_proxy, socks5_proxy).
	Type() string

	// Dial creates a connection to the target address through this backend.
	Dial(ctx context.Context, network, address string) (net.Conn, error)

	// DialTimeout creates a connection with a timeout.
	DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)

	// Start initializes the backend.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the backend.
	Stop(ctx context.Context) error

	// IsHealthy returns the current health status of the backend.
	IsHealthy() bool

	// Stats returns backend statistics.
	Stats() Stats
}

// Stats holds backend statistics.
type Stats struct {
	Name              string        `json:"name"`
	Type              string        `json:"type"`
	Healthy           bool          `json:"healthy"`
	ActiveConnections int64         `json:"active_connections"`
	TotalConnections  int64         `json:"total_connections"`
	BytesSent         int64         `json:"bytes_sent"`
	BytesReceived     int64         `json:"bytes_received"`
	Errors            int64         `json:"errors"`
	LastError         string        `json:"last_error,omitempty"`
	LastErrorTime     time.Time     `json:"last_error_time,omitempty"`
	Latency           time.Duration `json:"latency"`
	Uptime            time.Duration `json:"uptime"`
}

// Dialer is a function type for creating connections.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// TrackedConn wraps a net.Conn to track bytes transferred.
type TrackedConn struct {
	net.Conn
	BytesRead    int64
	BytesWritten int64
	OnClose      func(bytesRead, bytesWritten int64)
}

// Read reads data and tracks bytes.
func (c *TrackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.BytesRead += int64(n)
	return n, err
}

// Write writes data and tracks bytes.
func (c *TrackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.BytesWritten += int64(n)
	return n, err
}

// Close closes the connection and calls OnClose callback.
func (c *TrackedConn) Close() error {
	err := c.Conn.Close()
	if c.OnClose != nil {
		c.OnClose(c.BytesRead, c.BytesWritten)
	}
	return err
}

// isExpectedCloseError returns true if the error is an expected connection close.
func isExpectedCloseError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// Check for "use of closed network connection" which is common on connection close
	if err.Error() == "use of closed network connection" {
		return true
	}
	return false
}
