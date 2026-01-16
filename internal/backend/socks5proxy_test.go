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

// startMockSOCKS5Proxy starts a mock SOCKS5 server for testing full Dial flow.
func startMockSOCKS5Proxy(t *testing.T, requireAuth bool, authSuccess bool, connectSuccess bool) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(c net.Conn) {
				defer c.Close()

				// Read greeting
				buf := make([]byte, 10)
				n, err := c.Read(buf)
				if err != nil || n < 2 {
					return
				}

				// Send auth method response
				if requireAuth {
					c.Write([]byte{socks5Version, socks5AuthPasswd})

					// Read auth
					authBuf := make([]byte, 256)
					c.Read(authBuf)

					// Send auth response
					if authSuccess {
						c.Write([]byte{0x01, 0x00})
					} else {
						c.Write([]byte{0x01, 0x01})
						return
					}
				} else {
					c.Write([]byte{socks5Version, socks5AuthNone})
				}

				// Read connect request
				connectBuf := make([]byte, 256)
				c.Read(connectBuf)

				// Send connect response
				if connectSuccess {
					reply := []byte{socks5Version, socks5ReplyOK, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
					c.Write(reply)
					// Keep connection open briefly
					time.Sleep(100 * time.Millisecond)
				} else {
					reply := []byte{socks5Version, 0x05, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0} // Connection refused
					c.Write(reply)
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		listener.Close()
		<-done
	}
}

func TestSOCKS5ProxyBackend_Dial_Success(t *testing.T) {
	proxyAddr, cleanup := startMockSOCKS5Proxy(t, false, false, true)
	defer cleanup()

	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: proxyAddr,
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	conn, err := backend.Dial(ctx, "tcp", "example.com:80")
	require.NoError(t, err)
	assert.NotNil(t, conn)
	conn.Close()

	stats := backend.Stats()
	assert.Equal(t, int64(1), stats.TotalConnections)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_Dial_WithAuth_Success(t *testing.T) {
	proxyAddr, cleanup := startMockSOCKS5Proxy(t, true, true, true)
	defer cleanup()

	cfg := SOCKS5ProxyConfig{
		Name:     "test-socks5",
		Address:  proxyAddr,
		Username: "user",
		Password: "pass",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	conn, err := backend.Dial(ctx, "tcp", "example.com:80")
	require.NoError(t, err)
	assert.NotNil(t, conn)
	conn.Close()

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_Dial_AuthFailed(t *testing.T) {
	proxyAddr, cleanup := startMockSOCKS5Proxy(t, true, false, true)
	defer cleanup()

	cfg := SOCKS5ProxyConfig{
		Name:     "test-socks5",
		Address:  proxyAddr,
		Username: "user",
		Password: "wrongpass",
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	_, err = backend.Dial(ctx, "tcp", "example.com:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_Dial_ConnectFailed(t *testing.T) {
	proxyAddr, cleanup := startMockSOCKS5Proxy(t, false, false, false)
	defer cleanup()

	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: proxyAddr,
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	_, err = backend.Dial(ctx, "tcp", "example.com:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect failed")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_IPv6(t *testing.T) {
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
			buf := make([]byte, 30)
			conn.Read(buf)
			// Send success reply with IPv6 address
			reply := []byte{socks5Version, socks5ReplyOK, 0x00, socks5AddrIPv6}
			reply = append(reply, make([]byte, 16)...) // IPv6 address (zeros)
			reply = append(reply, 0, 80)               // Port
			conn.Write(reply)
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.connect(conn, "[::1]:80")
	require.NoError(t, err)

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_ResponseIPv6(t *testing.T) {
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
			// Send success reply with IPv6 address
			reply := []byte{socks5Version, socks5ReplyOK, 0x00, socks5AddrIPv6}
			reply = append(reply, make([]byte, 16)...) // IPv6 address
			reply = append(reply, 0, 80)               // Port
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

func TestSOCKS5ProxyBackend_connect_ResponseDomain(t *testing.T) {
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
			// Send success reply with domain address
			domain := "localhost"
			reply := []byte{socks5Version, socks5ReplyOK, 0x00, socks5AddrDomain}
			reply = append(reply, byte(len(domain)))
			reply = append(reply, []byte(domain)...)
			reply = append(reply, 0, 80) // Port
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

func TestSOCKS5ProxyBackend_connect_InvalidVersionResponse(t *testing.T) {
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
			// Send response with invalid version
			reply := []byte{0x04, socks5ReplyOK, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
			conn.Write(reply)
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.connect(conn, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SOCKS version")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_connect_UnknownAddressType(t *testing.T) {
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
			// Send response with unknown address type
			reply := []byte{socks5Version, socks5ReplyOK, 0x00, 0xFF, 127, 0, 0, 1, 0, 80}
			conn.Write(reply)
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.connect(conn, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown address type")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_handshake_InvalidVersion(t *testing.T) {
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
			// Send response with invalid version
			conn.Write([]byte{0x04, socks5AuthNone})
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.handshake(conn)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SOCKS version")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_handshake_UnsupportedAuthMethod(t *testing.T) {
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
			// Send response with unsupported auth method (0xFF)
			conn.Write([]byte{socks5Version, 0xFF})
		}
	}()

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	err = backend.handshake(conn)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth method")

	backend.Stop(ctx)
}

func TestSOCKS5ProxyBackend_TrackedConn_OnClose(t *testing.T) {
	proxyAddr, cleanup := startMockSOCKS5Proxy(t, false, false, true)
	defer cleanup()

	cfg := SOCKS5ProxyConfig{
		Name:    "test-socks5",
		Address: proxyAddr,
	}

	backend := NewSOCKS5ProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	conn, err := backend.Dial(ctx, "tcp", "example.com:80")
	require.NoError(t, err)
	assert.NotNil(t, conn)

	stats := backend.Stats()
	assert.Equal(t, int64(1), stats.ActiveConnections)

	conn.Close()
	time.Sleep(10 * time.Millisecond)

	stats = backend.Stats()
	assert.Equal(t, int64(0), stats.ActiveConnections)

	backend.Stop(ctx)
}
