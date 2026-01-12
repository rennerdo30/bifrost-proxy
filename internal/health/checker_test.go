package health

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTCPChecker(t *testing.T) {
	// Start a TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Create checker
	checker := NewTCPChecker(Config{
		Target:  listener.Addr().String(),
		Timeout: 5 * time.Second,
	})

	// Check should succeed
	ctx := context.Background()
	result := checker.Check(ctx)

	assert.True(t, result.Healthy)
	assert.NotEmpty(t, result.Message)
	assert.Greater(t, result.Latency, time.Duration(0))
}

func TestTCPChecker_Unhealthy(t *testing.T) {
	checker := NewTCPChecker(Config{
		Target:  "127.0.0.1:1", // Port 1 is typically not listening
		Timeout: 100 * time.Millisecond,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.False(t, result.Healthy)
	assert.NotEmpty(t, result.Error)
}

func TestHTTPChecker(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract host:port
	addr := server.Listener.Addr().String()

	checker := NewHTTPChecker(Config{
		Target:  addr,
		Path:    "/health",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.True(t, result.Healthy)
	assert.Contains(t, result.Message, "200")
}

func TestHTTPChecker_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	addr := server.Listener.Addr().String()

	checker := NewHTTPChecker(Config{
		Target:  addr,
		Path:    "/health",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.False(t, result.Healthy)
	assert.Contains(t, result.Message, "500")
}

func TestHealthManager(t *testing.T) {
	mgr := NewManager()

	// Start a TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Register health check
	checker := NewTCPChecker(Config{
		Target:  listener.Addr().String(),
		Timeout: time.Second,
	})

	var lastResult Result
	var mu sync.Mutex
	mgr.Register("test", checker, 100*time.Millisecond, func(name string, result Result) {
		mu.Lock()
		lastResult = result
		mu.Unlock()
	})

	// Start manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, mgr.Start(ctx))

	// Wait for check
	time.Sleep(200 * time.Millisecond)

	// Should have result
	result, ok := mgr.GetResult("test")
	assert.True(t, ok)
	assert.True(t, result.Healthy)

	// Callback should have been called
	mu.Lock()
	lastResultHealthy := lastResult.Healthy
	mu.Unlock()
	assert.True(t, lastResultHealthy)

	// Manager should report healthy
	assert.True(t, mgr.IsHealthy())

	mgr.Stop()
}
