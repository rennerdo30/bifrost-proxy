package backend

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPProxyBackend(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-http", backend.Name())
	assert.Equal(t, "http_proxy", backend.Type())
}

func TestHTTPProxyBackend_WithAuth(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:     "test-http",
		Address:  "proxy.example.com:8080",
		Username: "user",
		Password: "pass",
	}

	backend := NewHTTPProxyBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-http", backend.Name())
}

func TestHTTPProxyBackend_Start(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)
	assert.True(t, backend.IsHealthy())

	// Start again should be idempotent
	err = backend.Start(ctx)
	require.NoError(t, err)
}

func TestHTTPProxyBackend_Stop(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)
	err := backend.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, backend.IsHealthy())
}

func TestHTTPProxyBackend_Stats(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)
	stats := backend.Stats()

	assert.Equal(t, "test-http", stats.Name)
	assert.Equal(t, "http_proxy", stats.Type)
	assert.True(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)

	backend.Stop(ctx)
}

func TestHTTPProxyBackend_Dial_NotStarted(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	_, err := backend.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestHTTPProxyBackend_DialTimeout(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)

	// Should fail with timeout
	_, err := backend.DialTimeout(ctx, "tcp", "example.com:80", 100*time.Millisecond)
	assert.Error(t, err)

	stats := backend.Stats()
	assert.Greater(t, stats.Errors, int64(0))

	backend.Stop(ctx)
}

// TestHTTPProxyBackend_Dial_WithMockProxy is skipped due to complexity of mocking HTTP CONNECT
// The Dial method is tested through error cases and basic functionality tests above

func TestHTTPProxyBackend_Dial_WithAuth(t *testing.T) {
	// Test that auth credentials are set in config
	cfg := HTTPProxyConfig{
		Name:     "test-http",
		Address:  "proxy.example.com:8080",
		Username: "user",
		Password: "pass",
	}

	backend := NewHTTPProxyBackend(cfg)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-http", backend.Name())

	ctx := context.Background()
	err := backend.Start(ctx)
	require.NoError(t, err)

	// Dial will fail but should attempt auth
	_, err = backend.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err) // Will fail connecting to proxy, but auth would be included

	backend.Stop(ctx)
}

func TestHTTPProxyBackend_Dial_ProxyError(t *testing.T) {
	// Test error handling when proxy is unreachable
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "127.0.0.1:1", // Unreachable port
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	// Dial should fail
	_, err = backend.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err)

	stats := backend.Stats()
	assert.Greater(t, stats.Errors, int64(0))
	assert.NotEmpty(t, stats.LastError)

	backend.Stop(ctx)
}

func TestHTTPProxyBackend_IsHealthy(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	assert.False(t, backend.IsHealthy())

	ctx := context.Background()
	backend.Start(ctx)
	assert.True(t, backend.IsHealthy())

	backend.Stop(ctx)
	assert.False(t, backend.IsHealthy())
}

func TestHTTPProxyBackend_recordError(t *testing.T) {
	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: "proxy.example.com:8080",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	backend.Start(ctx)

	// Trigger an error by trying to dial without a proxy
	_, err := backend.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err)

	stats := backend.Stats()
	assert.Greater(t, stats.Errors, int64(0))
	assert.NotEmpty(t, stats.LastError)
	assert.False(t, stats.LastErrorTime.IsZero())

	backend.Stop(ctx)
}

// startMockHTTPProxy starts a mock HTTP proxy server for testing.
// It accepts CONNECT requests and responds with the given status code.
// If requireAuth is true, it requires Basic auth with user:pass credentials.
func startMockHTTPProxy(t *testing.T, statusCode int, requireAuth bool) (string, func()) {
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

				// Read the CONNECT request
				reader := bufio.NewReader(c)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}

				// Check auth if required
				if requireAuth {
					auth := req.Header.Get("Proxy-Authorization")
					// Expect "Basic dXNlcjpwYXNz" (base64 of "user:pass")
					if auth != "Basic dXNlcjpwYXNz" {
						resp := &http.Response{
							StatusCode: http.StatusProxyAuthRequired,
							Status:     "407 Proxy Authentication Required",
							Proto:      "HTTP/1.1",
							ProtoMajor: 1,
							ProtoMinor: 1,
							Header:     make(http.Header),
						}
						resp.Write(c)
						return
					}
				}

				// Send response
				resp := &http.Response{
					StatusCode: statusCode,
					Status:     http.StatusText(statusCode),
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
				}
				resp.Write(c)

				// If successful, keep connection open briefly
				if statusCode == http.StatusOK {
					time.Sleep(100 * time.Millisecond)
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		listener.Close()
		<-done
	}
}

func TestHTTPProxyBackend_Dial_Success(t *testing.T) {
	proxyAddr, cleanup := startMockHTTPProxy(t, http.StatusOK, false)
	defer cleanup()

	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: proxyAddr,
	}

	backend := NewHTTPProxyBackend(cfg)
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

func TestHTTPProxyBackend_Dial_WithAuth_Success(t *testing.T) {
	proxyAddr, cleanup := startMockHTTPProxy(t, http.StatusOK, true)
	defer cleanup()

	cfg := HTTPProxyConfig{
		Name:     "test-http",
		Address:  proxyAddr,
		Username: "user",
		Password: "pass",
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	conn, err := backend.Dial(ctx, "tcp", "example.com:80")
	require.NoError(t, err)
	assert.NotNil(t, conn)
	conn.Close()

	backend.Stop(ctx)
}

func TestHTTPProxyBackend_Dial_ProxyReturnsError(t *testing.T) {
	proxyAddr, cleanup := startMockHTTPProxy(t, http.StatusForbidden, false)
	defer cleanup()

	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: proxyAddr,
	}

	backend := NewHTTPProxyBackend(cfg)
	ctx := context.Background()

	err := backend.Start(ctx)
	require.NoError(t, err)

	_, err = backend.Dial(ctx, "tcp", "example.com:80")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "403"))

	stats := backend.Stats()
	assert.Greater(t, stats.Errors, int64(0))

	backend.Stop(ctx)
}

func TestHTTPProxyBackend_TrackedConn_OnClose(t *testing.T) {
	proxyAddr, cleanup := startMockHTTPProxy(t, http.StatusOK, false)
	defer cleanup()

	cfg := HTTPProxyConfig{
		Name:    "test-http",
		Address: proxyAddr,
	}

	backend := NewHTTPProxyBackend(cfg)
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
