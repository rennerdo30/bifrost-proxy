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
