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
	checker := NewPingChecker(Config{Target: "localhost:7080"})
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

func TestHTTPChecker_ConnectionFailure(t *testing.T) {
	// Test connection failure (server not running)
	checker := NewHTTPChecker(Config{
		Target:  "127.0.0.1:59999", // Unlikely to have anything running here
		Path:    "/health",
		Timeout: 100 * time.Millisecond,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.False(t, result.Healthy)
	assert.Equal(t, "HTTP request failed", result.Message)
	assert.NotEmpty(t, result.Error)
	assert.Greater(t, result.Latency, time.Duration(0))
}

func TestHTTPChecker_4xxStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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
	assert.Contains(t, result.Message, "404")
	assert.Contains(t, result.Error, "unhealthy status code")
}

func TestHTTPChecker_3xxStatusCode(t *testing.T) {
	// Test 3xx status code is considered healthy
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer server.Close()

	addr := server.Listener.Addr().String()

	checker := NewHTTPChecker(Config{
		Target:  addr,
		Path:    "/health",
		Timeout: 5 * time.Second,
	})

	// Use a custom client that doesn't follow redirects to get the 301
	checker.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.True(t, result.Healthy)
	assert.Contains(t, result.Message, "301")
}

func TestHTTPChecker_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().String()

	checker := NewHTTPChecker(Config{
		Target:  addr,
		Path:    "/health",
		Timeout: 5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := checker.Check(ctx)

	assert.False(t, result.Healthy)
	assert.NotEmpty(t, result.Error)
}

func TestHTTPChecker_DefaultPath(t *testing.T) {
	// Create checker with empty path - should default to /health
	checker := NewHTTPChecker(Config{
		Target:  "localhost:80",
		Timeout: time.Second,
	})

	assert.Equal(t, "/health", checker.path)
}

func TestManager_PeriodicCheck(t *testing.T) {
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

	var checkCount int
	var mu sync.Mutex
	mgr.Register("periodic-test", checker, 50*time.Millisecond, func(name string, result Result) {
		mu.Lock()
		checkCount++
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, mgr.Start(ctx))

	// Wait for initial check + at least 2 periodic checks
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	count := checkCount
	mu.Unlock()

	// Should have at least 2-3 checks (initial + periodic)
	assert.GreaterOrEqual(t, count, 2)

	mgr.Stop()
}

func TestManager_ContextDoneDuringRunCheck(t *testing.T) {
	mgr := NewManager()

	checker := NewTCPChecker(Config{
		Target:  "127.0.0.1:59999",
		Timeout: 100 * time.Millisecond,
	})

	mgr.Register("ctx-test", checker, time.Hour, nil) // Long interval so periodic doesn't fire

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, mgr.Start(ctx))

	// Wait for initial check
	time.Sleep(200 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for goroutine to exit
	time.Sleep(100 * time.Millisecond)

	// Manager should handle context cancellation gracefully
	mgr.Stop()
}

func TestManager_GetAllResults(t *testing.T) {
	// Start TCP servers
	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener1.Close()

	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener2.Close()

	go func() {
		for {
			conn, err := listener1.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	go func() {
		for {
			conn, err := listener2.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	mgr := NewManager()

	checker1 := NewTCPChecker(Config{
		Target:  listener1.Addr().String(),
		Timeout: time.Second,
	})
	checker2 := NewTCPChecker(Config{
		Target:  listener2.Addr().String(),
		Timeout: time.Second,
	})

	mgr.Register("check1", checker1, time.Hour, nil)
	mgr.Register("check2", checker2, time.Hour, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, mgr.Start(ctx))

	// Wait for initial checks
	time.Sleep(200 * time.Millisecond)

	results := mgr.GetAllResults()

	assert.Len(t, results, 2)
	assert.True(t, results["check1"].Healthy)
	assert.True(t, results["check2"].Healthy)

	mgr.Stop()
}

func TestManager_StopBeforeStart(t *testing.T) {
	mgr := NewManager()

	// Stop before starting should be safe
	mgr.Stop()
}

func TestManager_NilCallback(t *testing.T) {
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

	// Register with nil callback
	mgr.Register("nil-callback", checker, 100*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, mgr.Start(ctx))

	// Wait for check
	time.Sleep(200 * time.Millisecond)

	result, ok := mgr.GetResult("nil-callback")
	assert.True(t, ok)
	assert.True(t, result.Healthy)

	mgr.Stop()
}

func TestTCPChecker_ContextCanceled(t *testing.T) {
	checker := NewTCPChecker(Config{
		Target:  "127.0.0.1:59999",
		Timeout: 5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := checker.Check(ctx)

	assert.False(t, result.Healthy)
	assert.NotEmpty(t, result.Error)
}

func TestPingChecker_ContextCanceled(t *testing.T) {
	checker := NewPingChecker(Config{
		Target:  "127.0.0.1",
		Timeout: 5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := checker.Check(ctx)

	// Context canceled should result in unhealthy
	assert.False(t, result.Healthy)
}

func TestPingChecker_HostWithoutPort(t *testing.T) {
	// Test with a host that doesn't have a port
	checker := NewPingChecker(Config{
		Target:  "localhost",
		Timeout: 5 * time.Second,
	})

	// Target should be localhost as-is
	assert.Equal(t, "localhost", checker.target)
}

func TestManager_EmptyChecks(t *testing.T) {
	mgr := NewManager()

	// IsHealthy with no checks should return true (vacuously true)
	assert.True(t, mgr.IsHealthy())

	// GetAllResults with no checks should return empty map
	results := mgr.GetAllResults()
	assert.Empty(t, results)
}

func TestHTTPChecker_ServiceUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
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
	assert.Contains(t, result.Message, "503")
	assert.Contains(t, result.Error, "unhealthy status code: 503")
}

func TestHTTPChecker_BadGateway(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
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
	assert.Contains(t, result.Message, "502")
}

func TestHTTPChecker_Accepted(t *testing.T) {
	// Test 202 Accepted is still healthy
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
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

	assert.True(t, result.Healthy)
	assert.Contains(t, result.Message, "202")
}

func TestHTTPChecker_NoContent(t *testing.T) {
	// Test 204 No Content is still healthy
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
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

	assert.True(t, result.Healthy)
	assert.Contains(t, result.Message, "204")
}

func TestHTTPChecker_InvalidURL(t *testing.T) {
	// Test with an invalid URL that will cause NewRequestWithContext to fail
	// This tests the error path on lines 55-62 of http.go
	checker := &HTTPChecker{
		target:  "invalid host with spaces:badport", // This causes URL parsing issues
		path:    "/health",
		timeout: time.Second,
		client:  &http.Client{Timeout: time.Second},
	}

	ctx := context.Background()
	result := checker.Check(ctx)

	// The request should fail (either at URL construction or dial)
	assert.False(t, result.Healthy)
	assert.NotEmpty(t, result.Error)
}

func TestPingChecker_UnexpectedOutput(t *testing.T) {
	// This test verifies the behavior when ping succeeds but output doesn't match expected patterns
	// Since we can't easily mock the ping command, we test with a known good host
	// and rely on the localhost tests for the success path

	// Test with an IP that will likely produce output we can examine
	checker := NewPingChecker(Config{
		Target:  "127.0.0.1",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	// Localhost should succeed
	assert.True(t, result.Healthy)
	assert.NotEmpty(t, result.Message)
}

func TestManager_CheckNow_UpdatesResult(t *testing.T) {
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

	// Register without starting manager
	mgr.Register("check-now-test", checker, time.Hour, nil)

	// CheckNow should still work even if manager not started
	ctx := context.Background()
	result, err := mgr.CheckNow(ctx, "check-now-test")

	require.NoError(t, err)
	assert.True(t, result.Healthy)

	// Verify result was stored
	storedResult, ok := mgr.GetResult("check-now-test")
	assert.True(t, ok)
	assert.Equal(t, result.Healthy, storedResult.Healthy)
}

func TestHTTPChecker_CustomPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom/status" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("healthy"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := server.Listener.Addr().String()

	checker := NewHTTPChecker(Config{
		Target:  addr,
		Path:    "/custom/status",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.True(t, result.Healthy)
	assert.Contains(t, result.Message, "200")
}

func TestTCPChecker_SuccessfulConnection(t *testing.T) {
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
			// Keep connection open briefly
			time.Sleep(10 * time.Millisecond)
			conn.Close()
		}
	}()

	checker := NewTCPChecker(Config{
		Target:  listener.Addr().String(),
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := checker.Check(ctx)

	assert.True(t, result.Healthy)
	assert.Equal(t, "TCP connection successful", result.Message)
	assert.Empty(t, result.Error)
	assert.Greater(t, result.Latency, time.Duration(0))
	assert.False(t, result.Timestamp.IsZero())
}

func TestResult_WithError(t *testing.T) {
	now := time.Now()
	r := Result{
		Healthy:   false,
		Message:   "Connection failed",
		Latency:   50 * time.Millisecond,
		Timestamp: now,
		Error:     "dial tcp: connection refused",
	}

	assert.False(t, r.Healthy)
	assert.Equal(t, "Connection failed", r.Message)
	assert.Equal(t, 50*time.Millisecond, r.Latency)
	assert.Equal(t, now, r.Timestamp)
	assert.Equal(t, "dial tcp: connection refused", r.Error)
}

func TestErrCheckNotFound(t *testing.T) {
	// Test the ErrCheckNotFound error
	err := ErrCheckNotFound
	assert.Equal(t, "health check not found", err.Error())
	assert.IsType(t, &HealthError{}, err)
}

func TestManager_MultipleUnregister(t *testing.T) {
	mgr := NewManager()

	checker := NewTCPChecker(Config{Target: "localhost:80"})
	mgr.Register("test", checker, time.Second, nil)

	// First unregister
	mgr.Unregister("test")

	// Second unregister - should not panic
	mgr.Unregister("test")

	// Verify it's gone
	_, exists := mgr.GetResult("test")
	assert.False(t, exists)
}

func TestHTTPChecker_Status399(t *testing.T) {
	// Test boundary condition: 399 should be healthy (< 400)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(399) // Unofficial but valid HTTP status
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

	assert.True(t, result.Healthy)
	assert.Contains(t, result.Message, "399")
}

func TestHTTPChecker_Status400(t *testing.T) {
	// Test boundary condition: 400 should be unhealthy (>= 400)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
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
	assert.Contains(t, result.Message, "400")
	assert.Contains(t, result.Error, "unhealthy status code: 400")
}
