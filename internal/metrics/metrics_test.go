package metrics

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

func TestNew(t *testing.T) {
	m := New()

	if m == nil {
		t.Fatal("New() returned nil")
	}

	// Check that all metrics are initialized
	if m.ConnectionsTotal == nil {
		t.Error("ConnectionsTotal is nil")
	}
	if m.ConnectionsActive == nil {
		t.Error("ConnectionsActive is nil")
	}
	if m.ConnectionDuration == nil {
		t.Error("ConnectionDuration is nil")
	}
	if m.RequestsTotal == nil {
		t.Error("RequestsTotal is nil")
	}
	if m.RequestDuration == nil {
		t.Error("RequestDuration is nil")
	}
	if m.RequestSize == nil {
		t.Error("RequestSize is nil")
	}
	if m.ResponseSize == nil {
		t.Error("ResponseSize is nil")
	}
	if m.BackendHealth == nil {
		t.Error("BackendHealth is nil")
	}
	if m.BackendConnections == nil {
		t.Error("BackendConnections is nil")
	}
	if m.BackendLatency == nil {
		t.Error("BackendLatency is nil")
	}
	if m.BackendErrors == nil {
		t.Error("BackendErrors is nil")
	}
	if m.BytesSent == nil {
		t.Error("BytesSent is nil")
	}
	if m.BytesReceived == nil {
		t.Error("BytesReceived is nil")
	}
	if m.RateLimitHits == nil {
		t.Error("RateLimitHits is nil")
	}
	if m.AuthAttempts == nil {
		t.Error("AuthAttempts is nil")
	}
	if m.AuthFailures == nil {
		t.Error("AuthFailures is nil")
	}
	if m.Uptime == nil {
		t.Error("Uptime is nil")
	}
	if m.GoRoutines == nil {
		t.Error("GoRoutines is nil")
	}
	if m.registry == nil {
		t.Error("registry is nil")
	}
}

func TestMetricsHandler(t *testing.T) {
	m := New()

	handler := m.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	// Test that the handler serves metrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Handler returned status %d, want 200", w.Code)
	}

	body := w.Body.String()
	// Should contain some prometheus metrics
	if !strings.Contains(body, "bifrost") || !strings.Contains(body, "go_") {
		t.Error("Handler response should contain bifrost and go metrics")
	}
}

func TestMetricsRegistry(t *testing.T) {
	m := New()

	reg := m.Registry()
	if reg == nil {
		t.Error("Registry() returned nil")
	}

	// Gather metrics to verify registry works
	families, err := reg.Gather()
	if err != nil {
		t.Errorf("Registry.Gather() error = %v", err)
	}

	if len(families) == 0 {
		t.Error("Registry should have registered metrics")
	}
}

func TestConnectionMetrics(t *testing.T) {
	m := New()

	// Record a connection
	m.ConnectionsTotal.WithLabelValues("http", "backend1").Inc()
	m.ConnectionsActive.WithLabelValues("http", "backend1").Inc()
	m.ConnectionDuration.WithLabelValues("http", "backend1").Observe(1.5)

	// Gather and verify
	families, _ := m.registry.Gather()

	found := false
	for _, f := range families {
		if f.GetName() == "bifrost_connections_total" {
			found = true
			break
		}
	}

	if !found {
		t.Error("bifrost_connections_total metric not found")
	}
}

func TestRequestMetrics(t *testing.T) {
	m := New()

	// Record a request
	m.RequestsTotal.WithLabelValues("http", "GET", "200").Inc()
	m.RequestDuration.WithLabelValues("http", "GET").Observe(0.1)
	m.RequestSize.WithLabelValues("http").Observe(1024)
	m.ResponseSize.WithLabelValues("http").Observe(2048)

	// Should not panic
}

func TestBackendMetrics(t *testing.T) {
	m := New()

	// Record backend metrics
	m.BackendHealth.WithLabelValues("backend1", "wireguard").Set(1)
	m.BackendConnections.WithLabelValues("backend1").Set(10)
	m.BackendLatency.WithLabelValues("backend1").Observe(0.05)
	m.BackendErrors.WithLabelValues("backend1", "connection").Inc()

	// Should not panic
}

func TestTrafficMetrics(t *testing.T) {
	m := New()

	// Record traffic
	m.BytesSent.WithLabelValues("backend1").Add(1024)
	m.BytesReceived.WithLabelValues("backend1").Add(2048)

	// Should not panic
}

func TestRateLimitMetrics(t *testing.T) {
	m := New()

	// Record rate limit hit
	m.RateLimitHits.WithLabelValues("ip").Inc()

	// Should not panic
}

func TestAuthMetrics(t *testing.T) {
	m := New()

	// Record auth attempts
	m.AuthAttempts.WithLabelValues("native").Inc()
	m.AuthFailures.WithLabelValues("native", "invalid_password").Inc()

	// Should not panic
}

func TestSystemMetrics(t *testing.T) {
	m := New()

	// Set system metrics
	m.Uptime.Set(3600)
	m.GoRoutines.Set(50)

	// Should not panic
}

// Collector tests

func TestNewCollector(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	if c == nil {
		t.Fatal("NewCollector() returned nil")
	}

	if c.metrics != m {
		t.Error("Collector should have metrics reference")
	}
}

func TestCollectorStartStop(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Start
	c.Start()
	if !c.running {
		t.Error("Collector should be running after Start()")
	}

	// Start again (should be no-op)
	c.Start()

	// Stop
	c.Stop()
	if c.running {
		t.Error("Collector should not be running after Stop()")
	}

	// Stop again (should be no-op)
	c.Stop()
}

func TestCollectorCollect(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Collect should update uptime and goroutines
	c.collect()

	// Gather metrics
	families, _ := m.registry.Gather()

	uptimeFound := false
	goroutinesFound := false

	for _, f := range families {
		switch f.GetName() {
		case "bifrost_uptime_seconds":
			uptimeFound = true
		case "bifrost_goroutines":
			goroutinesFound = true
		}
	}

	if !uptimeFound {
		t.Error("uptime metric not found after collect")
	}
	if !goroutinesFound {
		t.Error("goroutines metric not found after collect")
	}
}

func TestCollectorRecordConnection(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Record connection start
	done := c.RecordConnection("http", "backend1")

	// Simulate some work
	time.Sleep(10 * time.Millisecond)

	// Record connection end
	done(10 * time.Millisecond)

	// Should not panic
}

func TestCollectorRecordRequest(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordRequest("http", "GET", "200", 100*time.Millisecond)

	// Should not panic
}

func TestCollectorRecordBytes(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordBytes("backend1", 1024, 2048)

	// Should not panic
}

func TestCollectorRecordBackendError(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordBackendError("backend1", "connection")

	// Should not panic
}

func TestCollectorRecordRateLimit(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordRateLimit("ip")

	// Should not panic
}

func TestCollectorRecordAuthAttempt(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Successful auth
	c.RecordAuthAttempt("native", true, "")

	// Failed auth
	c.RecordAuthAttempt("ldap", false, "invalid_credentials")

	// Should not panic
}

func TestCollectorLoop(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Start the collector loop
	c.Start()
	defer c.Stop()

	// Verify metrics were collected by the async loop
	require.Eventually(t, func() bool {
		families, _ := m.registry.Gather()
		return len(families) > 0
	}, time.Second, 10*time.Millisecond, "metrics should be collected during loop")
}

// mockBackend implements the backend.Backend interface for testing.
type mockBackend struct {
	name              string
	backendType       string
	healthy           bool
	activeConnections int64
	latency           time.Duration
}

func (m *mockBackend) Name() string {
	return m.name
}

func (m *mockBackend) Type() string {
	return m.backendType
}

func (m *mockBackend) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, nil
}

func (m *mockBackend) DialTimeout(_ context.Context, _, _ string, _ time.Duration) (net.Conn, error) {
	return nil, nil
}

func (m *mockBackend) Start(_ context.Context) error {
	return nil
}

func (m *mockBackend) Stop(_ context.Context) error {
	return nil
}

func (m *mockBackend) IsHealthy() bool {
	return m.healthy
}

func (m *mockBackend) Stats() backend.Stats {
	return backend.Stats{
		Name:              m.name,
		Type:              m.backendType,
		Healthy:           m.healthy,
		ActiveConnections: m.activeConnections,
		Latency:           m.latency,
	}
}

// TestNewCollectorWithInterval_ZeroInterval tests that zero interval defaults to DefaultCollectionInterval.
func TestNewCollectorWithInterval_ZeroInterval(t *testing.T) {
	m := New()
	c := NewCollectorWithInterval(m, nil, 0)

	require.NotNil(t, c)
	assert.Equal(t, DefaultCollectionInterval, c.interval, "zero interval should default to DefaultCollectionInterval")
}

// TestNewCollectorWithInterval_NegativeInterval tests that negative interval defaults to DefaultCollectionInterval.
func TestNewCollectorWithInterval_NegativeInterval(t *testing.T) {
	m := New()
	c := NewCollectorWithInterval(m, nil, -5*time.Second)

	require.NotNil(t, c)
	assert.Equal(t, DefaultCollectionInterval, c.interval, "negative interval should default to DefaultCollectionInterval")
}

// TestNewCollectorWithInterval_CustomInterval tests that custom interval is respected.
func TestNewCollectorWithInterval_CustomInterval(t *testing.T) {
	m := New()
	customInterval := 30 * time.Second
	c := NewCollectorWithInterval(m, nil, customInterval)

	require.NotNil(t, c)
	assert.Equal(t, customInterval, c.interval, "custom interval should be respected")
}

// TestCollectorCollectWithBackends tests collect with actual backends.
func TestCollectorCollectWithBackends(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	// Add a healthy backend with latency
	healthyBackend := &mockBackend{
		name:              "healthy-backend",
		backendType:       "direct",
		healthy:           true,
		activeConnections: 5,
		latency:           100 * time.Millisecond,
	}
	err := mgr.Add(healthyBackend)
	require.NoError(t, err)

	// Add an unhealthy backend without latency
	unhealthyBackend := &mockBackend{
		name:              "unhealthy-backend",
		backendType:       "wireguard",
		healthy:           false,
		activeConnections: 0,
		latency:           0, // Zero latency should not be observed
	}
	err = mgr.Add(unhealthyBackend)
	require.NoError(t, err)

	c := NewCollector(m, mgr)
	c.collect()

	// Gather metrics and verify backend metrics are collected
	families, err := m.registry.Gather()
	require.NoError(t, err)

	// Check for backend health metric
	backendHealthFound := false
	backendConnectionsFound := false
	backendLatencyFound := false

	for _, f := range families {
		switch f.GetName() {
		case "bifrost_backend_health":
			backendHealthFound = true
			// Verify we have metrics for both backends
			assert.GreaterOrEqual(t, len(f.GetMetric()), 2, "should have health metrics for both backends")
		case "bifrost_backend_connections":
			backendConnectionsFound = true
		case "bifrost_backend_latency_seconds":
			backendLatencyFound = true
		}
	}

	assert.True(t, backendHealthFound, "backend health metric should be found")
	assert.True(t, backendConnectionsFound, "backend connections metric should be found")
	assert.True(t, backendLatencyFound, "backend latency metric should be found")
}

// TestCollectorCollectWithHealthyBackend tests collect with only healthy backend.
func TestCollectorCollectWithHealthyBackend(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	healthyBackend := &mockBackend{
		name:              "test-backend",
		backendType:       "http_proxy",
		healthy:           true,
		activeConnections: 10,
		latency:           50 * time.Millisecond,
	}
	err := mgr.Add(healthyBackend)
	require.NoError(t, err)

	c := NewCollector(m, mgr)
	c.collect()

	// Verify backend health is set to 1.0
	families, err := m.registry.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if f.GetName() == "bifrost_backend_health" {
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "backend" && label.GetValue() == "test-backend" {
						assert.Equal(t, float64(1), metric.GetGauge().GetValue(), "healthy backend should have health = 1.0")
					}
				}
			}
		}
	}
}

// TestCollectorCollectWithUnhealthyBackend tests collect with only unhealthy backend.
func TestCollectorCollectWithUnhealthyBackend(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	unhealthyBackend := &mockBackend{
		name:              "test-unhealthy",
		backendType:       "openvpn",
		healthy:           false,
		activeConnections: 0,
		latency:           0, // Zero latency
	}
	err := mgr.Add(unhealthyBackend)
	require.NoError(t, err)

	c := NewCollector(m, mgr)
	c.collect()

	// Verify backend health is set to 0.0
	families, err := m.registry.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if f.GetName() == "bifrost_backend_health" {
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "backend" && label.GetValue() == "test-unhealthy" {
						assert.Equal(t, float64(0), metric.GetGauge().GetValue(), "unhealthy backend should have health = 0.0")
					}
				}
			}
		}
	}
}

// TestCollectorCollectWithZeroLatency tests that zero latency is not observed.
func TestCollectorCollectWithZeroLatency(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	backendWithZeroLatency := &mockBackend{
		name:              "zero-latency",
		backendType:       "direct",
		healthy:           true,
		activeConnections: 3,
		latency:           0, // Zero latency should be skipped
	}
	err := mgr.Add(backendWithZeroLatency)
	require.NoError(t, err)

	c := NewCollector(m, mgr)

	// Collect multiple times
	c.collect()
	c.collect()
	c.collect()

	// Gather metrics
	families, err := m.registry.Gather()
	require.NoError(t, err)

	// Check latency metric - with zero latency, histogram should have 0 samples
	for _, f := range families {
		if f.GetName() == "bifrost_backend_latency_seconds" {
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "backend" && label.GetValue() == "zero-latency" {
						// With zero latency, no observations should be made
						assert.Equal(t, uint64(0), metric.GetHistogram().GetSampleCount(),
							"zero latency should not be observed")
					}
				}
			}
		}
	}
}

// TestCollectorCollectWithPositiveLatency tests that positive latency is observed.
func TestCollectorCollectWithPositiveLatency(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	backendWithLatency := &mockBackend{
		name:              "positive-latency",
		backendType:       "direct",
		healthy:           true,
		activeConnections: 2,
		latency:           25 * time.Millisecond,
	}
	err := mgr.Add(backendWithLatency)
	require.NoError(t, err)

	c := NewCollector(m, mgr)

	// Collect multiple times
	c.collect()
	c.collect()

	// Gather metrics
	families, err := m.registry.Gather()
	require.NoError(t, err)

	// Check latency metric - should have observations
	latencyObserved := false
	for _, f := range families {
		if f.GetName() == "bifrost_backend_latency_seconds" {
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "backend" && label.GetValue() == "positive-latency" {
						// With positive latency, observations should be made
						assert.Equal(t, uint64(2), metric.GetHistogram().GetSampleCount(),
							"positive latency should be observed twice")
						latencyObserved = true
					}
				}
			}
		}
	}
	assert.True(t, latencyObserved, "latency metric should be observed")
}

// TestCollectorCollectLoopWithBackends tests the full collect loop with backends.
func TestCollectorCollectLoopWithBackends(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	testBackend := &mockBackend{
		name:              "loop-test-backend",
		backendType:       "socks5_proxy",
		healthy:           true,
		activeConnections: 7,
		latency:           15 * time.Millisecond,
	}
	err := mgr.Add(testBackend)
	require.NoError(t, err)

	// Use a short interval for testing
	c := NewCollectorWithInterval(m, mgr, 10*time.Millisecond)

	c.Start()
	defer c.Stop()

	// Verify backend metrics were collected by the async loop
	require.Eventually(t, func() bool {
		families, err := m.registry.Gather()
		if err != nil {
			return false
		}
		for _, f := range families {
			if f.GetName() == "bifrost_backend_health" {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond, "backend health metric should be collected during loop")
}

// TestCollectorRecordConnectionVerifyMetrics verifies actual metric values for connection recording.
func TestCollectorRecordConnectionVerifyMetrics(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Record connection start
	done := c.RecordConnection("socks5", "test-backend")

	// Gather metrics and verify active connections increased
	families, err := m.registry.Gather()
	require.NoError(t, err)

	activeConnFound := false
	totalConnFound := false

	for _, f := range families {
		switch f.GetName() {
		case "bifrost_connections_active":
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["protocol"] == "socks5" && labels["backend"] == "test-backend" {
					assert.Equal(t, float64(1), metric.GetGauge().GetValue(), "active connections should be 1")
					activeConnFound = true
				}
			}
		case "bifrost_connections_total":
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["protocol"] == "socks5" && labels["backend"] == "test-backend" {
					assert.Equal(t, float64(1), metric.GetCounter().GetValue(), "total connections should be 1")
					totalConnFound = true
				}
			}
		}
	}

	assert.True(t, activeConnFound, "active connections metric should be found")
	assert.True(t, totalConnFound, "total connections metric should be found")

	// Record connection end
	done(50 * time.Millisecond)

	// Verify active connections decreased
	families, err = m.registry.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if f.GetName() == "bifrost_connections_active" {
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["protocol"] == "socks5" && labels["backend"] == "test-backend" {
					assert.Equal(t, float64(0), metric.GetGauge().GetValue(), "active connections should be 0 after done")
				}
			}
		}
	}
}

// TestCollectorRecordRequestVerifyMetrics verifies actual metric values for request recording.
func TestCollectorRecordRequestVerifyMetrics(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordRequest("http", "POST", "201", 250*time.Millisecond)

	families, err := m.registry.Gather()
	require.NoError(t, err)

	requestsFound := false
	for _, f := range families {
		if f.GetName() == "bifrost_requests_total" {
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["protocol"] == "http" && labels["method"] == "POST" && labels["status"] == "201" {
					assert.Equal(t, float64(1), metric.GetCounter().GetValue(), "request counter should be 1")
					requestsFound = true
				}
			}
		}
	}
	assert.True(t, requestsFound, "requests metric should be found")
}

// TestCollectorRecordBytesVerifyMetrics verifies actual metric values for bytes recording.
func TestCollectorRecordBytesVerifyMetrics(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordBytes("byte-test", 5000, 10000)

	families, err := m.registry.Gather()
	require.NoError(t, err)

	sentFound := false
	receivedFound := false

	for _, f := range families {
		switch f.GetName() {
		case "bifrost_bytes_sent_total":
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "backend" && label.GetValue() == "byte-test" {
						assert.Equal(t, float64(5000), metric.GetCounter().GetValue(), "bytes sent should be 5000")
						sentFound = true
					}
				}
			}
		case "bifrost_bytes_received_total":
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "backend" && label.GetValue() == "byte-test" {
						assert.Equal(t, float64(10000), metric.GetCounter().GetValue(), "bytes received should be 10000")
						receivedFound = true
					}
				}
			}
		}
	}

	assert.True(t, sentFound, "bytes sent metric should be found")
	assert.True(t, receivedFound, "bytes received metric should be found")
}

// TestCollectorRecordBackendErrorVerifyMetrics verifies actual metric values for backend error recording.
func TestCollectorRecordBackendErrorVerifyMetrics(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordBackendError("error-test", "timeout")

	families, err := m.registry.Gather()
	require.NoError(t, err)

	errorFound := false
	for _, f := range families {
		if f.GetName() == "bifrost_backend_errors_total" {
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["backend"] == "error-test" && labels["error_type"] == "timeout" {
					assert.Equal(t, float64(1), metric.GetCounter().GetValue(), "backend error counter should be 1")
					errorFound = true
				}
			}
		}
	}
	assert.True(t, errorFound, "backend error metric should be found")
}

// TestCollectorRecordRateLimitVerifyMetrics verifies actual metric values for rate limit recording.
func TestCollectorRecordRateLimitVerifyMetrics(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.RecordRateLimit("connection")
	c.RecordRateLimit("connection")
	c.RecordRateLimit("bandwidth")

	families, err := m.registry.Gather()
	require.NoError(t, err)

	connectionLimitFound := false
	bandwidthLimitFound := false

	for _, f := range families {
		if f.GetName() == "bifrost_rate_limit_hits_total" {
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "type" {
						switch label.GetValue() {
						case "connection":
							assert.Equal(t, float64(2), metric.GetCounter().GetValue(), "connection rate limit should be 2")
							connectionLimitFound = true
						case "bandwidth":
							assert.Equal(t, float64(1), metric.GetCounter().GetValue(), "bandwidth rate limit should be 1")
							bandwidthLimitFound = true
						}
					}
				}
			}
		}
	}

	assert.True(t, connectionLimitFound, "connection rate limit metric should be found")
	assert.True(t, bandwidthLimitFound, "bandwidth rate limit metric should be found")
}

// TestCollectorRecordAuthAttemptVerifyMetrics verifies actual metric values for auth attempt recording.
func TestCollectorRecordAuthAttemptVerifyMetrics(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// Successful attempt
	c.RecordAuthAttempt("oauth", true, "")
	// Failed attempt
	c.RecordAuthAttempt("oauth", false, "token_expired")
	// Another failed attempt
	c.RecordAuthAttempt("oauth", false, "invalid_token")

	families, err := m.registry.Gather()
	require.NoError(t, err)

	attemptsFound := false
	failuresFound := 0

	for _, f := range families {
		switch f.GetName() {
		case "bifrost_auth_attempts_total":
			for _, metric := range f.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "method" && label.GetValue() == "oauth" {
						assert.Equal(t, float64(3), metric.GetCounter().GetValue(), "auth attempts should be 3")
						attemptsFound = true
					}
				}
			}
		case "bifrost_auth_failures_total":
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["method"] == "oauth" {
					assert.Equal(t, float64(1), metric.GetCounter().GetValue(), "each failure reason should be 1")
					failuresFound++
				}
			}
		}
	}

	assert.True(t, attemptsFound, "auth attempts metric should be found")
	assert.Equal(t, 2, failuresFound, "should have 2 different failure reasons")
}

// TestCollectorMultipleBackends tests collection with multiple backends of different types.
func TestCollectorMultipleBackends(t *testing.T) {
	m := New()
	mgr := backend.NewManager()

	backends := []*mockBackend{
		{name: "direct-1", backendType: "direct", healthy: true, activeConnections: 5, latency: 10 * time.Millisecond},
		{name: "wg-1", backendType: "wireguard", healthy: true, activeConnections: 3, latency: 25 * time.Millisecond},
		{name: "ovpn-1", backendType: "openvpn", healthy: false, activeConnections: 0, latency: 0},
		{name: "http-1", backendType: "http_proxy", healthy: true, activeConnections: 8, latency: 5 * time.Millisecond},
	}

	for _, b := range backends {
		err := mgr.Add(b)
		require.NoError(t, err)
	}

	c := NewCollector(m, mgr)
	c.collect()

	families, err := m.registry.Gather()
	require.NoError(t, err)

	// Count backend metrics
	healthMetricsCount := 0
	for _, f := range families {
		if f.GetName() == "bifrost_backend_health" {
			healthMetricsCount = len(f.GetMetric())
		}
	}

	assert.Equal(t, 4, healthMetricsCount, "should have health metrics for all 4 backends")
}

// TestCollectorStartStopMultipleTimes tests starting and stopping the collector multiple times.
func TestCollectorStartStopMultipleTimes(t *testing.T) {
	m := New()
	c := NewCollectorWithInterval(m, nil, 10*time.Millisecond)

	// Start-stop cycle 1
	c.Start()
	assert.True(t, c.running)
	time.Sleep(15 * time.Millisecond)
	c.Stop()
	assert.False(t, c.running)

	// Start-stop cycle 2
	c.Start()
	assert.True(t, c.running)
	time.Sleep(15 * time.Millisecond)
	c.Stop()
	assert.False(t, c.running)

	// Start-stop cycle 3
	c.Start()
	assert.True(t, c.running)
	c.Stop()
	assert.False(t, c.running)
}

// TestCollectorUptimeIncreases tests that uptime metric increases over time.
func TestCollectorUptimeIncreases(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	// First collection
	c.collect()

	families1, err := m.registry.Gather()
	require.NoError(t, err)

	var uptime1 float64
	for _, f := range families1 {
		if f.GetName() == "bifrost_uptime_seconds" {
			uptime1 = f.GetMetric()[0].GetGauge().GetValue()
			break
		}
	}

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Second collection
	c.collect()

	families2, err := m.registry.Gather()
	require.NoError(t, err)

	var uptime2 float64
	for _, f := range families2 {
		if f.GetName() == "bifrost_uptime_seconds" {
			uptime2 = f.GetMetric()[0].GetGauge().GetValue()
			break
		}
	}

	assert.Greater(t, uptime2, uptime1, "uptime should increase over time")
}

// TestCollectorGoRoutinesRealistic tests that goroutines metric returns a realistic value.
func TestCollectorGoRoutinesRealistic(t *testing.T) {
	m := New()
	c := NewCollector(m, nil)

	c.collect()

	families, err := m.registry.Gather()
	require.NoError(t, err)

	var goroutines float64
	for _, f := range families {
		if f.GetName() == "bifrost_goroutines" {
			goroutines = f.GetMetric()[0].GetGauge().GetValue()
			break
		}
	}

	// Should be at least 1 (the main goroutine)
	assert.GreaterOrEqual(t, goroutines, float64(1), "goroutines should be at least 1")
	// Should be reasonable (less than 10000 in a test scenario)
	assert.Less(t, goroutines, float64(10000), "goroutines should be reasonable")
}
