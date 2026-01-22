package backend

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectBackend(t *testing.T) {
	cfg := DirectConfig{
		Name:           "test-direct",
		ConnectTimeout: 5 * time.Second,
	}

	backend := NewDirectBackend(cfg)

	assert.Equal(t, "test-direct", backend.Name())
	assert.Equal(t, "direct", backend.Type())
	assert.False(t, backend.IsHealthy())

	// Start backend
	ctx := context.Background()
	err := backend.Start(ctx)
	require.NoError(t, err)
	assert.True(t, backend.IsHealthy())

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	// Test dial
	conn, err := backend.Dial(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Read data
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(buf))

	// Check stats
	stats := backend.Stats()
	assert.True(t, stats.Healthy)
	assert.Equal(t, int64(1), stats.TotalConnections)

	// Stop backend
	err = backend.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, backend.IsHealthy())
}

func TestDirectBackendDialTimeout(t *testing.T) {
	cfg := DirectConfig{
		Name:           "test-direct",
		ConnectTimeout: 1 * time.Second,
	}

	backend := NewDirectBackend(cfg)

	ctx := context.Background()
	err := backend.Start(ctx)
	require.NoError(t, err)

	// Try to connect to unreachable address
	_, err = backend.DialTimeout(ctx, "tcp", "192.0.2.1:12345", 100*time.Millisecond)
	assert.Error(t, err)

	// Check error count
	stats := backend.Stats()
	assert.Equal(t, int64(1), stats.Errors)

	backend.Stop(ctx)
}

func TestDirectBackendNotStarted(t *testing.T) {
	backend := NewDirectBackend(DirectConfig{Name: "test"})

	ctx := context.Background()
	_, err := backend.Dial(ctx, "tcp", "127.0.0.1:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestDirectBackend_StartIdempotent(t *testing.T) {
	cfg := DirectConfig{
		Name: "test-direct",
	}

	backend := NewDirectBackend(cfg)
	ctx := context.Background()

	// First start
	err := backend.Start(ctx)
	require.NoError(t, err)
	assert.True(t, backend.IsHealthy())

	// Second start should be idempotent (no error)
	err = backend.Start(ctx)
	require.NoError(t, err)
	assert.True(t, backend.IsHealthy())

	backend.Stop(ctx)
}

func TestDirectBackend_DefaultConfig(t *testing.T) {
	// Test that defaults are applied when zero values provided
	cfg := DirectConfig{
		Name: "test-defaults",
	}

	backend := NewDirectBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-defaults", backend.Name())
}

func TestDirectBackend_LocalAddr(t *testing.T) {
	cfg := DirectConfig{
		Name:      "test-local-addr",
		LocalAddr: "127.0.0.1:0",
	}

	backend := NewDirectBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-local-addr", backend.Name())
}

func TestDirectBackend_TrackedConnOnClose(t *testing.T) {
	cfg := DirectConfig{
		Name:           "test-direct",
		ConnectTimeout: 5 * time.Second,
	}

	backend := NewDirectBackend(cfg)
	ctx := context.Background()
	err := backend.Start(ctx)
	require.NoError(t, err)

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	// Test dial
	conn, err := backend.Dial(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)

	stats := backend.Stats()
	assert.Equal(t, int64(1), stats.ActiveConnections)

	// Read and close
	buf := make([]byte, 5)
	conn.Read(buf)
	conn.Close()

	// After close, active connections should be decremented
	time.Sleep(10 * time.Millisecond)
	stats = backend.Stats()
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Greater(t, stats.BytesReceived, int64(0))

	backend.Stop(ctx)
}
