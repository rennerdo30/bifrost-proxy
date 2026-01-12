// Package backend provides backend connection handling for Bifrost.
package backend

import (
	"context"
	"io"
	"net"
	"time"
)

// Backend represents a connection backend (direct, wireguard, openvpn, etc.)
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

// CopyBidirectional copies data between two connections in both directions.
func CopyBidirectional(ctx context.Context, conn1, conn2 io.ReadWriteCloser) (sent, received int64, err error) {
	errCh := make(chan error, 2)
	var sentBytes, receivedBytes int64

	// Copy conn1 -> conn2
	go func() {
		n, copyErr := io.Copy(conn2, conn1)
		sentBytes = n
		errCh <- copyErr
	}()

	// Copy conn2 -> conn1
	go func() {
		n, copyErr := io.Copy(conn1, conn2)
		receivedBytes = n
		errCh <- copyErr
	}()

	// Wait for either copy to finish or context cancellation
	select {
	case err = <-errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}

	// Close both connections to unblock the other goroutine
	conn1.Close()
	conn2.Close()

	// Wait for the second copy to finish
	<-errCh

	return sentBytes, receivedBytes, err
}
