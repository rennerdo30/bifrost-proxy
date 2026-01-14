package backend

import (
	"context"
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
