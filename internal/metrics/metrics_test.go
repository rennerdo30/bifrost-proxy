package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	// Start and immediately stop
	c.Start()
	time.Sleep(50 * time.Millisecond)
	c.Stop()

	// Verify metrics were collected
	families, _ := m.registry.Gather()
	if len(families) == 0 {
		t.Error("No metrics collected during loop")
	}
}
