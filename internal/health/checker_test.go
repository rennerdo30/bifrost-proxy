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

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "tcp", cfg.Type)
	assert.Equal(t, 30*time.Second, cfg.Interval)
	assert.Equal(t, 5*time.Second, cfg.Timeout)
}

func TestNew_TCP(t *testing.T) {
	cfg := Config{Type: "tcp", Target: "localhost:80", Timeout: time.Second}
	checker := New(cfg)

	assert.NotNil(t, checker)
	assert.Equal(t, "tcp", checker.Type())
}

func TestNew_HTTP(t *testing.T) {
	cfg := Config{Type: "http", Target: "localhost:80", Timeout: time.Second}
	checker := New(cfg)

	assert.NotNil(t, checker)
	assert.Equal(t, "http", checker.Type())
}

func TestNew_Ping(t *testing.T) {
	cfg := Config{Type: "ping", Target: "localhost", Timeout: time.Second}
	checker := New(cfg)

	assert.NotNil(t, checker)
	assert.Equal(t, "ping", checker.Type())
}

func TestNew_EmptyType(t *testing.T) {
	cfg := Config{Type: "", Target: "localhost:80", Timeout: time.Second}
	checker := New(cfg)

	assert.NotNil(t, checker)
	assert.Equal(t, "tcp", checker.Type()) // Defaults to TCP
}

func TestNew_UnknownType(t *testing.T) {
	cfg := Config{Type: "unknown", Target: "localhost:80", Timeout: time.Second}
	checker := New(cfg)

	assert.NotNil(t, checker)
	assert.Equal(t, "tcp", checker.Type()) // Defaults to TCP
}

func TestTCPChecker_Type(t *testing.T) {
	checker := NewTCPChecker(Config{Target: "localhost:80"})
	assert.Equal(t, "tcp", checker.Type())
}

func TestHTTPChecker_Type(t *testing.T) {
	checker := NewHTTPChecker(Config{Target: "localhost:80"})
	assert.Equal(t, "http", checker.Type())
}

func TestPingChecker_Type(t *testing.T) {
	checker := NewPingChecker(Config{Target: "localhost"})
	assert.Equal(t, "ping", checker.Type())
}

func TestPingChecker_WithPort(t *testing.T) {
	// Should extract host from target with port
	checker := NewPingChecker(Config{Target: "localhost:8080"})
	assert.NotNil(t, checker)
	assert.Equal(t, "localhost", checker.target)
}

func TestPingChecker_DefaultTimeout(t *testing.T) {
	checker := NewPingChecker(Config{Target: "localhost"})
	assert.Equal(t, 5*time.Second, checker.timeout)
}

func TestPingChecker_Check_Localhost(t *testing.T) {
	checker := NewPingChecker(Config{
		Target:  "127.0.0.1",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	// Localhost ping should succeed
	assert.True(t, result.Healthy)
	assert.NotEmpty(t, result.Message)
}

func TestPingChecker_Check_InvalidTarget(t *testing.T) {
	checker := NewPingChecker(Config{
		Target:  "240.0.0.1", // Invalid/unreachable IP
		Timeout: 1 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result := checker.Check(ctx)

	// Should fail for unreachable IP
	assert.False(t, result.Healthy)
}

func TestManager_Unregister(t *testing.T) {
	mgr := NewManager()

	checker := NewTCPChecker(Config{Target: "localhost:80"})
	mgr.Register("test", checker, time.Second, nil)

	// Verify it's registered
	_, _ = mgr.GetResult("test")
	// Result might be empty but check is registered
	mgr.mu.RLock()
	_, checkExists := mgr.checks["test"]
	mgr.mu.RUnlock()
	assert.True(t, checkExists)

	// Unregister
	mgr.Unregister("test")

	// Verify it's gone
	mgr.mu.RLock()
	_, checkExists = mgr.checks["test"]
	mgr.mu.RUnlock()
	assert.False(t, checkExists)
}

func TestManager_CheckNow(t *testing.T) {
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

	mgr := NewManager()
	checker := NewTCPChecker(Config{
		Target:  listener.Addr().String(),
		Timeout: time.Second,
	})
	mgr.Register("immediate-test", checker, time.Hour, nil)

	ctx := context.Background()
	result, err := mgr.CheckNow(ctx, "immediate-test")

	require.NoError(t, err)
	assert.True(t, result.Healthy)
}

func TestManager_CheckNow_NotFound(t *testing.T) {
	mgr := NewManager()

	ctx := context.Background()
	_, err := mgr.CheckNow(ctx, "nonexistent")

	assert.Error(t, err)
	assert.Equal(t, ErrCheckNotFound, err)
}

func TestManager_GetResult_NotFound(t *testing.T) {
	mgr := NewManager()

	_, exists := mgr.GetResult("nonexistent")
	assert.False(t, exists)
}

func TestManager_IsHealthy_WithUnhealthyCheck(t *testing.T) {
	mgr := NewManager()

	// Register a check that will fail
	checker := NewTCPChecker(Config{
		Target:  "127.0.0.1:1", // Port 1 won't be listening
		Timeout: 100 * time.Millisecond,
	})
	mgr.Register("failing", checker, time.Second, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)

	// Wait for check
	time.Sleep(200 * time.Millisecond)

	// Should be unhealthy
	assert.False(t, mgr.IsHealthy())

	mgr.Stop()
}

func TestManager_StartTwice(t *testing.T) {
	mgr := NewManager()

	ctx := context.Background()

	// Start once
	err := mgr.Start(ctx)
	require.NoError(t, err)

	// Start again - should be no-op
	err = mgr.Start(ctx)
	require.NoError(t, err)

	mgr.Stop()
}

func TestManager_StopTwice(t *testing.T) {
	mgr := NewManager()

	ctx := context.Background()
	mgr.Start(ctx)

	// Stop once
	mgr.Stop()

	// Stop again - should be no-op
	mgr.Stop()
}

func TestManager_Register_ZeroInterval(t *testing.T) {
	mgr := NewManager()

	checker := NewTCPChecker(Config{Target: "localhost:80"})
	mgr.Register("test", checker, 0, nil)

	// Should use default interval of 30 seconds
	mgr.mu.RLock()
	check := mgr.checks["test"]
	mgr.mu.RUnlock()

	assert.Equal(t, 30*time.Second, check.interval)
}

func TestHealthError(t *testing.T) {
	err := &HealthError{Message: "test error"}
	assert.Equal(t, "test error", err.Error())
}

func TestResult_Struct(t *testing.T) {
	now := time.Now()
	r := Result{
		Healthy:   true,
		Message:   "OK",
		Latency:   10 * time.Millisecond,
		Timestamp: now,
		Error:     "",
	}

	assert.True(t, r.Healthy)
	assert.Equal(t, "OK", r.Message)
	assert.Equal(t, 10*time.Millisecond, r.Latency)
	assert.Equal(t, now, r.Timestamp)
	assert.Empty(t, r.Error)
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Type:     "http",
		Target:   "example.com:443",
		Interval: time.Minute,
		Timeout:  10 * time.Second,
		Path:     "/health",
	}

	assert.Equal(t, "http", cfg.Type)
	assert.Equal(t, "example.com:443", cfg.Target)
	assert.Equal(t, "/health", cfg.Path)
}

func TestHTTPChecker_WithTLS(t *testing.T) {
	checker := NewHTTPChecker(Config{
		Target:  "localhost:443",
		Path:    "/health",
		Timeout: time.Second,
	})

	assert.NotNil(t, checker)
	// Can't easily test TLS without a real server
}

func TestHTTPChecker_DefaultTimeout(t *testing.T) {
	checker := NewHTTPChecker(Config{
		Target: "localhost:80",
	})

	assert.Equal(t, 5*time.Second, checker.client.Timeout)
}

func TestTCPChecker_DefaultTimeout(t *testing.T) {
	checker := NewTCPChecker(Config{
		Target: "localhost:80",
	})

	assert.Equal(t, 5*time.Second, checker.timeout)
}
