package metrics

import (
	"runtime"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// Collector collects and updates metrics periodically.
type Collector struct {
	metrics    *Metrics
	backends   *backend.Manager
	startTime  time.Time
	ticker     *time.Ticker
	done       chan struct{}
	mu         sync.Mutex
	running    bool
}

// NewCollector creates a new metrics collector.
func NewCollector(metrics *Metrics, backends *backend.Manager) *Collector {
	return &Collector{
		metrics:   metrics,
		backends:  backends,
		startTime: time.Now(),
	}
}

// Start starts the metrics collector.
func (c *Collector) Start() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return
	}

	c.running = true
	c.done = make(chan struct{})
	c.ticker = time.NewTicker(15 * time.Second)

	go c.collectLoop()
}

// Stop stops the metrics collector.
func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	close(c.done)
	c.ticker.Stop()
	c.running = false
}

// collectLoop periodically collects metrics.
func (c *Collector) collectLoop() {
	// Initial collection
	c.collect()

	for {
		select {
		case <-c.done:
			return
		case <-c.ticker.C:
			c.collect()
		}
	}
}

// collect performs a single metrics collection.
func (c *Collector) collect() {
	// Update uptime
	c.metrics.Uptime.Set(time.Since(c.startTime).Seconds())

	// Update goroutine count
	c.metrics.GoRoutines.Set(float64(runtime.NumGoroutine()))

	// Update backend metrics
	if c.backends != nil {
		for _, b := range c.backends.All() {
			stats := b.Stats()

			// Health status
			healthy := 0.0
			if stats.Healthy {
				healthy = 1.0
			}
			c.metrics.BackendHealth.WithLabelValues(b.Name(), b.Type()).Set(healthy)

			// Active connections
			c.metrics.BackendConnections.WithLabelValues(b.Name()).Set(float64(stats.ActiveConnections))

			// Latency
			if stats.Latency > 0 {
				c.metrics.BackendLatency.WithLabelValues(b.Name()).Observe(stats.Latency.Seconds())
			}
		}
	}
}

// RecordConnection records a new connection.
func (c *Collector) RecordConnection(protocol, backend string) func(duration time.Duration) {
	c.metrics.ConnectionsTotal.WithLabelValues(protocol, backend).Inc()
	c.metrics.ConnectionsActive.WithLabelValues(protocol, backend).Inc()

	return func(duration time.Duration) {
		c.metrics.ConnectionsActive.WithLabelValues(protocol, backend).Dec()
		c.metrics.ConnectionDuration.WithLabelValues(protocol, backend).Observe(duration.Seconds())
	}
}

// RecordRequest records a request.
func (c *Collector) RecordRequest(protocol, method, status string, duration time.Duration) {
	c.metrics.RequestsTotal.WithLabelValues(protocol, method, status).Inc()
	c.metrics.RequestDuration.WithLabelValues(protocol, method).Observe(duration.Seconds())
}

// RecordBytes records bytes transferred.
func (c *Collector) RecordBytes(backend string, sent, received int64) {
	c.metrics.BytesSent.WithLabelValues(backend).Add(float64(sent))
	c.metrics.BytesReceived.WithLabelValues(backend).Add(float64(received))
}

// RecordBackendError records a backend error.
func (c *Collector) RecordBackendError(backend, errorType string) {
	c.metrics.BackendErrors.WithLabelValues(backend, errorType).Inc()
}

// RecordRateLimit records a rate limit hit.
func (c *Collector) RecordRateLimit(limitType string) {
	c.metrics.RateLimitHits.WithLabelValues(limitType).Inc()
}

// RecordAuthAttempt records an authentication attempt.
func (c *Collector) RecordAuthAttempt(method string, success bool, reason string) {
	c.metrics.AuthAttempts.WithLabelValues(method).Inc()
	if !success {
		c.metrics.AuthFailures.WithLabelValues(method, reason).Inc()
	}
}
