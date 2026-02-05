package client

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServerConnection(t *testing.T) {
	cfg := ServerConnectionConfig{
		Address:  "localhost:7080",
		Protocol: "http",
	}

	conn := NewServerConnection(cfg)
	require.NotNil(t, conn)
	assert.Equal(t, "localhost:7080", conn.config.Address)
	assert.Equal(t, "http", conn.config.Protocol)
	assert.Equal(t, 30*time.Second, conn.config.Timeout)
	assert.Equal(t, 3, conn.config.RetryCount)
	assert.Equal(t, time.Second, conn.config.RetryDelay)
}

func TestNewServerConnection_Defaults(t *testing.T) {
	cfg := ServerConnectionConfig{
		Address: "localhost:7080",
	}

	conn := NewServerConnection(cfg)
	require.NotNil(t, conn)
	assert.Equal(t, "http", conn.config.Protocol)        // Default
	assert.Equal(t, 30*time.Second, conn.config.Timeout) // Default
	assert.Equal(t, 3, conn.config.RetryCount)           // Default
	assert.Equal(t, time.Second, conn.config.RetryDelay) // Default
}

func TestNewServerConnection_CustomValues(t *testing.T) {
	cfg := ServerConnectionConfig{
		Address:    "localhost:7080",
		Protocol:   "socks5",
		Username:   "user",
		Password:   "pass",
		Timeout:    60 * time.Second,
		RetryCount: 5,
		RetryDelay: 2 * time.Second,
	}

	conn := NewServerConnection(cfg)
	require.NotNil(t, conn)
	assert.Equal(t, "socks5", conn.config.Protocol)
	assert.Equal(t, "user", conn.config.Username)
	assert.Equal(t, "pass", conn.config.Password)
	assert.Equal(t, 60*time.Second, conn.config.Timeout)
	assert.Equal(t, 5, conn.config.RetryCount)
	assert.Equal(t, 2*time.Second, conn.config.RetryDelay)
}

func TestServerConnection_IsConnected_False(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address: "127.0.0.1:1", // Invalid port
		Timeout: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	assert.False(t, conn.IsConnected(ctx))
}

func TestServerConnection_IsConnected_True(t *testing.T) {
	// Start a simple TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	conn := NewServerConnection(ServerConnectionConfig{
		Address: listener.Addr().String(),
		Timeout: time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	assert.True(t, conn.IsConnected(ctx))
}

func TestServerConnection_Connect_UnsupportedProtocol(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address:    "localhost:7080",
		Protocol:   "invalid",
		Timeout:    100 * time.Millisecond,
		RetryCount: 1,                     // Set to 1 so it doesn't default to 3
		RetryDelay: 10 * time.Millisecond, // Fast retries
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := conn.Connect(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")
}

func TestServerConnection_Connect_ContextCanceled(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address:    "127.0.0.1:1", // Will fail
		Protocol:   "http",
		Timeout:    50 * time.Millisecond,
		RetryCount: 10, // Many retries
		RetryDelay: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short time
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := conn.Connect(ctx, "example.com:80")
	assert.Error(t, err)
}

func TestServerConnection_Connect_RetryLogic(t *testing.T) {
	attempts := 0

	// Start a server that fails first then succeeds
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			attempts++
			// Just close immediately to trigger retry
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:    listener.Addr().String(),
		Protocol:   "http",
		Timeout:    100 * time.Millisecond,
		RetryCount: 2,
		RetryDelay: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = conn.Connect(ctx, "example.com:80")
	// Will fail eventually, but should have retried
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed after")
}

func TestServerConnection_connectHTTP_Success(t *testing.T) {
	// Start a mock HTTP proxy server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockHTTPProxy(c)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "http",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.connectHTTP(ctx, "example.com:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_connectHTTP_WithAuth(t *testing.T) {
	// Start a mock HTTP proxy server with auth
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockHTTPProxyWithAuth(c)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "http",
		Username: "testuser",
		Password: "testpass",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.connectHTTP(ctx, "example.com:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_connectHTTP_ServerError(t *testing.T) {
	// Start a mock HTTP proxy that returns 403
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockHTTPProxyError(c)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "http",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectHTTP(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 403")
}

func TestServerConnection_connectSOCKS5_Success(t *testing.T) {
	// Start a mock SOCKS5 server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockSOCKS5(c, false)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.connectSOCKS5(ctx, "example.com:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_connectSOCKS5_WithAuth(t *testing.T) {
	// Start a mock SOCKS5 server with auth
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockSOCKS5(c, true)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Username: "testuser",
		Password: "testpass",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.connectSOCKS5(ctx, "example.com:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_connectSOCKS5_InvalidVersion(t *testing.T) {
	// Start a mock server that returns wrong version
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting
			buf := make([]byte, 3)
			c.Read(buf)
			// Send invalid version
			c.Write([]byte{0x04, 0x00}) // Wrong version
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SOCKS version")
}

func TestServerConnection_connectSOCKS5_UnsupportedAuth(t *testing.T) {
	// Start a mock server that returns unsupported auth method
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting
			buf := make([]byte, 3)
			c.Read(buf)
			// Send unsupported auth method
			c.Write([]byte{0x05, 0xFF}) // No acceptable methods
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth method")
}

func TestServerConnection_socks5Connect_IPv4(t *testing.T) {
	// Start a mock SOCKS5 server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockSOCKS5IPv4(c)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.connectSOCKS5(ctx, "192.168.1.1:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_socks5Connect_InvalidTarget(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address:  "localhost:7080",
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	// Create a fake connection
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Invalid target (no port)
	err := conn.socks5Connect(client, "example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid target")
}

func TestServerConnection_socks5Auth_Success(t *testing.T) {
	client, server := net.Pipe()

	conn := NewServerConnection(ServerConnectionConfig{
		Username: "testuser",
		Password: "testpass",
	})

	go func() {
		// Read auth request
		buf := make([]byte, 100)
		n, _ := server.Read(buf)
		// Verify auth request format
		assert.Equal(t, byte(0x01), buf[0]) // Version
		// Send success response
		server.Write([]byte{0x01, 0x00})
		_ = n
	}()

	err := conn.socks5Auth(client)
	assert.NoError(t, err)

	client.Close()
	server.Close()
}

func TestServerConnection_socks5Auth_Failure(t *testing.T) {
	client, server := net.Pipe()

	conn := NewServerConnection(ServerConnectionConfig{
		Username: "testuser",
		Password: "testpass",
	})

	go func() {
		// Read auth request
		buf := make([]byte, 100)
		server.Read(buf)
		// Send failure response
		server.Write([]byte{0x01, 0x01}) // Non-zero status
	}()

	err := conn.socks5Auth(client)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")

	client.Close()
	server.Close()
}

func TestServerConnectionConfig_Struct(t *testing.T) {
	cfg := ServerConnectionConfig{
		Address:    "localhost:7080",
		Protocol:   "socks5",
		Username:   "user",
		Password:   "pass",
		Timeout:    10 * time.Second,
		RetryCount: 5,
		RetryDelay: 2 * time.Second,
	}

	assert.Equal(t, "localhost:7080", cfg.Address)
	assert.Equal(t, "socks5", cfg.Protocol)
	assert.Equal(t, "user", cfg.Username)
	assert.Equal(t, "pass", cfg.Password)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, 5, cfg.RetryCount)
	assert.Equal(t, 2*time.Second, cfg.RetryDelay)
}

// Helper functions for mock servers

func handleMockHTTPProxy(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == "CONNECT" {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 Connection Established",
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(c)
	}
}

func handleMockHTTPProxyWithAuth(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == "CONNECT" {
		// Check auth header exists
		auth := req.Header.Get("Proxy-Authorization")
		if auth == "" {
			resp := &http.Response{
				StatusCode: http.StatusProxyAuthRequired,
				Status:     "407 Proxy Authentication Required",
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			resp.Write(c)
			return
		}

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 Connection Established",
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(c)
	}
}

func handleMockHTTPProxyError(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == "CONNECT" {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Forbidden",
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(c)
	}
}

func handleMockSOCKS5(c net.Conn, requireAuth bool) {
	defer c.Close()

	// Read greeting
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil || n < 2 {
		return
	}

	// Respond with auth method
	if requireAuth {
		c.Write([]byte{0x05, 0x02}) // Username/password auth

		// Read auth
		n, err = c.Read(buf)
		if err != nil || n < 3 {
			return
		}

		// Accept auth
		c.Write([]byte{0x01, 0x00})
	} else {
		c.Write([]byte{0x05, 0x00}) // No auth
	}

	// Read connect request
	n, err = c.Read(buf)
	if err != nil || n < 4 {
		return
	}

	// Send success response with domain address type
	// Response format: VER REP RSV ATYP BND.ADDR BND.PORT
	response := []byte{
		0x05, 0x00, 0x00, // Version, Success, Reserved
		0x03,                                        // Address type: Domain
		0x09,                                        // Domain length
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', // Domain
		0x00, 0x50, // Port 80
	}
	c.Write(response)
}

func handleMockSOCKS5IPv4(c net.Conn) {
	defer c.Close()

	// Read greeting
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil || n < 2 {
		return
	}

	// Respond with no auth
	c.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = c.Read(buf)
	if err != nil || n < 4 {
		return
	}

	// Send success response with IPv4 address type
	response := []byte{
		0x05, 0x00, 0x00, // Version, Success, Reserved
		0x01,         // Address type: IPv4
		127, 0, 0, 1, // IP address
		0x00, 0x50, // Port 80
	}
	c.Write(response)
}

func TestServerConnection_socks5Connect_ConnectFailed(t *testing.T) {
	// Start a mock SOCKS5 server that returns connect failed
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting
			buf := make([]byte, 3)
			c.Read(buf)
			// Send no auth
			c.Write([]byte{0x05, 0x00})
			// Read connect request
			buf = make([]byte, 256)
			c.Read(buf)
			// Send failure (connection refused)
			c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connect failed")
}

func TestServerConnection_socks5Connect_IPv6(t *testing.T) {
	// Start a mock SOCKS5 server that returns IPv6 response
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting
			buf := make([]byte, 3)
			c.Read(buf)
			// Send no auth
			c.Write([]byte{0x05, 0x00})
			// Read connect request
			buf = make([]byte, 256)
			c.Read(buf)
			// Send success response with IPv6 address type
			response := []byte{
				0x05, 0x00, 0x00, // Version, Success, Reserved
				0x04, // Address type: IPv6
			}
			// Add 16 bytes for IPv6 + 2 bytes for port
			response = append(response, make([]byte, 18)...)
			c.Write(response)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Connect to IPv6 address
	netConn, err := conn.connectSOCKS5(ctx, "[::1]:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_Connect_HTTP(t *testing.T) {
	// Start a mock HTTP proxy server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockHTTPProxy(c)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:    listener.Addr().String(),
		Protocol:   "http",
		Timeout:    time.Second,
		RetryCount: 0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.Connect(ctx, "example.com:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_Connect_SOCKS5(t *testing.T) {
	// Start a mock SOCKS5 server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockSOCKS5(c, false)
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:    listener.Addr().String(),
		Protocol:   "socks5",
		Timeout:    time.Second,
		RetryCount: 0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	netConn, err := conn.Connect(ctx, "example.com:80")
	require.NoError(t, err)
	require.NotNil(t, netConn)
	netConn.Close()
}

func TestServerConnection_Connect_FailAllRetries(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address:    "127.0.0.1:1", // Invalid port
		Protocol:   "http",
		Timeout:    100 * time.Millisecond,
		RetryCount: 2,
		RetryDelay: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := conn.Connect(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("failed after %d attempts", 3)) // 0, 1, 2 = 3 attempts
}

func TestServerConnection_connectHTTP_DialError(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address:  "127.0.0.1:1", // Invalid port
		Protocol: "http",
		Timeout:  100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := conn.connectHTTP(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dial server")
}

func TestServerConnection_connectSOCKS5_DialError(t *testing.T) {
	conn := NewServerConnection(ServerConnectionConfig{
		Address:  "127.0.0.1:1", // Invalid port
		Protocol: "socks5",
		Timeout:  100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dial server")
}

func TestServerConnection_connectSOCKS5_GreetingWriteError(t *testing.T) {
	// Start a mock server that closes immediately
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Close immediately without reading
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
}

func TestServerConnection_connectSOCKS5_GreetingReadError(t *testing.T) {
	// Start a mock server that accepts but doesn't respond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting but don't respond
			buf := make([]byte, 10)
			c.Read(buf)
			// Close without sending response
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read greeting response")
}

func TestServerConnection_socks5Auth_WriteError(t *testing.T) {
	client, server := net.Pipe()

	conn := NewServerConnection(ServerConnectionConfig{
		Username: "testuser",
		Password: "testpass",
	})

	// Close the server side immediately to cause write error
	server.Close()

	err := conn.socks5Auth(client)
	assert.Error(t, err)

	client.Close()
}

func TestServerConnection_socks5Auth_ReadError(t *testing.T) {
	client, server := net.Pipe()

	conn := NewServerConnection(ServerConnectionConfig{
		Username: "testuser",
		Password: "testpass",
	})

	go func() {
		// Read auth request
		buf := make([]byte, 100)
		server.Read(buf)
		// Close without sending response
		server.Close()
	}()

	err := conn.socks5Auth(client)
	assert.Error(t, err)

	client.Close()
}

func TestServerConnection_socks5Connect_WriteError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	conn := NewServerConnection(ServerConnectionConfig{})

	// Close server to cause write error
	server.Close()

	err := conn.socks5Connect(client, "example.com:80")
	assert.Error(t, err)
}

func TestServerConnection_socks5Connect_ReadError(t *testing.T) {
	client, server := net.Pipe()

	conn := NewServerConnection(ServerConnectionConfig{})

	go func() {
		// Read connect request
		buf := make([]byte, 256)
		server.Read(buf)
		// Close without sending full response
		server.Close()
	}()

	err := conn.socks5Connect(client, "example.com:80")
	assert.Error(t, err)

	client.Close()
}

func TestServerConnection_socks5Connect_InvalidPort(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewServerConnection(ServerConnectionConfig{})

	// Invalid port
	err := conn.socks5Connect(client, "example.com:invalidport")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
}

func TestServerConnection_connectHTTP_WriteError(t *testing.T) {
	// Start a mock server that closes after accepting
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Close immediately to cause write error
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "http",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectHTTP(ctx, "example.com:80")
	assert.Error(t, err)
}

func TestServerConnection_connectHTTP_ReadError(t *testing.T) {
	// Start a mock server that accepts, receives request, but closes before response
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read request but don't respond
			buf := make([]byte, 1024)
			c.Read(buf)
			// Close without sending response
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "http",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectHTTP(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read response")
}

func TestServerConnection_connectSOCKS5_AuthRequired_AuthFailed(t *testing.T) {
	// Start a mock SOCKS5 server that requires auth but rejects it
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting
			buf := make([]byte, 256)
			c.Read(buf)
			// Require auth
			c.Write([]byte{0x05, 0x02}) // Username/password auth required

			// Read auth
			c.Read(buf)
			// Reject auth
			c.Write([]byte{0x01, 0x01}) // Auth failed
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Username: "testuser",
		Password: "testpass",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestServerConnection_connectSOCKS5_ConnectRequestError(t *testing.T) {
	// Start a mock SOCKS5 server that accepts auth but fails on connect
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			c, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Read greeting
			buf := make([]byte, 256)
			c.Read(buf)
			// No auth required
			c.Write([]byte{0x05, 0x00})
			// Read connect request
			c.Read(buf)
			// Close without sending response - should cause read error
			c.Close()
		}
	}()

	conn := NewServerConnection(ServerConnectionConfig{
		Address:  listener.Addr().String(),
		Protocol: "socks5",
		Timeout:  time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = conn.connectSOCKS5(ctx, "example.com:80")
	assert.Error(t, err)
}
