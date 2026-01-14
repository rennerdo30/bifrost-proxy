package backend

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSOCKS5ProxyBackend(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-socks5", backend.Name())
	assert.Equal(t, "socks5_proxy", backend.Type())
}

func TestNewSOCKS5ProxyBackend_DefaultTimeout(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	assert.NotNil(t, backend)
}

func TestNewSOCKS5ProxyBackend_WithAuth(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:     "test-socks5",
		Address:  "proxy.example.com:1080",
		Username: "user",
		Password: "pass",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-socks5", backend.Name())
}

func TestSOCKS5ProxyBackend_Start(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)
	assert.True(t, backend.IsHealthy())

	// Start again should be idempotent
	err = backend.Start(ctx)
	require.NoError(t, err)
}

func TestSOCKS5ProxyBackend_Stop(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)
	err := backend.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, backend.IsHealthy())
}

func TestSOCKS5ProxyBackend_Stats(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)
	stats := backend.Stats()

	assert.Equal(t, "test-socks5", stats.Name)
	assert.Equal(t, "socks5_proxy", stats.Type)
	assert.True(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_Dial_NotStarted(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	_, err := backend.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestSOCKS5ProxyBackend_DialTimeout(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)

	// Should fail with timeout
	_, err := backend.DialTimeout(ctx, "tcp", "example.com:80", 100*time.Millisecond)
	assert.Error(t, err)

	stats := backend.Stats()
	assert.Greater(t, stats.Errors, int64(0))

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_IsHealthy(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	assert.False(t, backend.IsHealthy())

	ctx := context.Background()
	backend.Start(ctx)
	assert.True(t, backend.IsHealthy())

	backend.Stop(ctx)
	assert.False(t, backend.IsHealthy())
}

func TestSOCKS5ProxyBackend_handshake_NoAuth(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	// Create a mock SOCKS5 server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, _ := server.Accept()
		if conn != nil {
			defer conn.Close()
			// Read greeting
			buf := make([]byte, 3)
			conn.Read(buf)
			// Send response: no auth
			conn.Write([]byte{socks5Version, socks5AuthNone})
		}
	}()

	conn, dialErr := net.Dial("tcp", server.Addr().String())
	require.NoError(t, dialErr)
	defer conn.Close()

	handshakeErr := backend.handshake(conn)
	require.NoError(t, handshakeErr)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_handshake_WithAuth(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:     "test-socks5",
		Address:  "proxy.example.com:1080",
		Username: "user",
		Password: "pass",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	// Create a mock SOCKS5 server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, _ := server.Accept()
		if conn != nil {
			defer conn.Close()
			// Read greeting
			buf := make([]byte, 4)
			conn.Read(buf)
			// Send response: password auth
			conn.Write([]byte{socks5Version, socks5AuthPasswd})
			// Read auth
			authBuf := make([]byte, 20)
			conn.Read(authBuf)
			// Send auth success
			conn.Write([]byte{0x01, 0x00})
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.handshake(conn)
	require.NoError(t, err)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_authenticate(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:     "test-socks5",
		Address:  "proxy.example.com:1080",
		Username: "user",
		Password: "pass",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	// Create a mock SOCKS5 server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, _ := server.Accept()
		if conn != nil {
			defer conn.Close()
			// Read auth
			authBuf := make([]byte, 20)
			conn.Read(authBuf)
			// Send auth success
			conn.Write([]byte{0x01, 0x00})
		}
	}()

	conn, dialErr := net.Dial("tcp", server.Addr().String())
	require.NoError(t, dialErr)
	defer conn.Close()

	authErr := backend.authenticate(conn)
	require.NoError(t, authErr)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_authenticate_Failed(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:     "test-socks5",
		Address:  "proxy.example.com:1080",
		Username: "user",
		Password: "pass",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	// Create a mock SOCKS5 server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, _ := server.Accept()
		if conn != nil {
			defer conn.Close()
			// Read auth
			authBuf := make([]byte, 20)
			conn.Read(authBuf)
			// Send auth failure
			conn.Write([]byte{0x01, 0x01})
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.authenticate(conn)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_IPv4(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	// Create a mock SOCKS5 server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, _ := server.Accept()
		if conn != nil {
			defer conn.Close()
			// Read connect request
			buf := make([]byte, 10)
			conn.Read(buf)
			// Send success reply
			reply := []byte{socks5Version, socks5ReplyOK, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
			conn.Write(reply)
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.connect(conn, "127.0.0.1:80")
	require.NoError(t, err)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_Domain(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	// Create a mock SOCKS5 server
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, _ := server.Accept()
		if conn != nil {
			defer conn.Close()
			// Read connect request
			buf := make([]byte, 20)
			conn.Read(buf)
			// Send success reply
			reply := []byte{socks5Version, socks5ReplyOK, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
			conn.Write(reply)
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.connect(conn, "example.com:80")
	require.NoError(t, err)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_InvalidAddress(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	conn, _ := net.Pipe()
	defer conn.Close()

	connectErr := backend.connect(conn, "invalid-address")
	assert.Error(t, connectErr)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_InvalidPort(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()
	backend.Start(ctx)

	conn, _ := net.Pipe()
	defer conn.Close()

	connectErr := backend.connect(conn, "example.com:invalid")
	assert.Error(t, connectErr)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_recordError(t *testing.T) {
	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: "proxy.example.com:1080",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)

	// Trigger an error
	_, err := backend.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err)

	stats := backend.Stats()
	assert.Greater(t, stats.Errors, int64(0))
	assert.NotEmpty(t, stats.LastError)
	assert.False(t, stats.LastErrorTime.IsZero())

	backend.Stop(ctx)
}
