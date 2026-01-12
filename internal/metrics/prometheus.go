// Package metrics provides Prometheus metrics for Bifrost.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for Bifrost.
type Metrics struct {
	// Connection metrics
	ConnectionsTotal   *prometheus.CounterVec
	ConnectionsActive  *prometheus.GaugeVec
	ConnectionDuration *prometheus.HistogramVec

	// Request metrics
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	RequestSize     *prometheus.HistogramVec
	ResponseSize    *prometheus.HistogramVec

	// Backend metrics
	BackendHealth       *prometheus.GaugeVec
	BackendConnections  *prometheus.GaugeVec
	BackendLatency      *prometheus.HistogramVec
	BackendErrors       *prometheus.CounterVec

	// Traffic metrics
	BytesSent     *prometheus.CounterVec
	BytesReceived *prometheus.CounterVec

	// Rate limiting metrics
	RateLimitHits *prometheus.CounterVec

	// Auth metrics
	AuthAttempts *prometheus.CounterVec
	AuthFailures *prometheus.CounterVec

	// System metrics
	Uptime     prometheus.Gauge
	GoRoutines prometheus.Gauge

	registry *prometheus.Registry
}

// New creates a new Metrics instance with all metrics registered.
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	// Connection metrics
	m.ConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_connections_total",
			Help: "Total number of connections",
		},
		[]string{"protocol", "backend"},
	)

	m.ConnectionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bifrost_connections_active",
			Help: "Number of active connections",
		},
		[]string{"protocol", "backend"},
	)

	m.ConnectionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bifrost_connection_duration_seconds",
			Help:    "Duration of connections",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 20),
		},
		[]string{"protocol", "backend"},
	)

	// Request metrics
	m.RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_requests_total",
			Help: "Total number of requests",
		},
		[]string{"protocol", "method", "status"},
	)

	m.RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bifrost_request_duration_seconds",
			Help:    "Duration of requests",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"protocol", "method"},
	)

	m.RequestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bifrost_request_size_bytes",
			Help:    "Size of requests in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 2, 15),
		},
		[]string{"protocol"},
	)

	m.ResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bifrost_response_size_bytes",
			Help:    "Size of responses in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 2, 15),
		},
		[]string{"protocol"},
	)

	// Backend metrics
	m.BackendHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bifrost_backend_health",
			Help: "Health status of backends (1 = healthy, 0 = unhealthy)",
		},
		[]string{"backend", "type"},
	)

	m.BackendConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bifrost_backend_connections",
			Help: "Number of active connections per backend",
		},
		[]string{"backend"},
	)

	m.BackendLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bifrost_backend_latency_seconds",
			Help:    "Latency of backend health checks",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
		},
		[]string{"backend"},
	)

	m.BackendErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_backend_errors_total",
			Help: "Total number of backend errors",
		},
		[]string{"backend", "error_type"},
	)

	// Traffic metrics
	m.BytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_bytes_sent_total",
			Help: "Total bytes sent",
		},
		[]string{"backend"},
	)

	m.BytesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_bytes_received_total",
			Help: "Total bytes received",
		},
		[]string{"backend"},
	)

	// Rate limiting metrics
	m.RateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"type"},
	)

	// Auth metrics
	m.AuthAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"method"},
	)

	m.AuthFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bifrost_auth_failures_total",
			Help: "Total number of authentication failures",
		},
		[]string{"method", "reason"},
	)

	// System metrics
	m.Uptime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "bifrost_uptime_seconds",
			Help: "Server uptime in seconds",
		},
	)

	m.GoRoutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "bifrost_goroutines",
			Help: "Number of goroutines",
		},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.ConnectionsTotal,
		m.ConnectionsActive,
		m.ConnectionDuration,
		m.RequestsTotal,
		m.RequestDuration,
		m.RequestSize,
		m.ResponseSize,
		m.BackendHealth,
		m.BackendConnections,
		m.BackendLatency,
		m.BackendErrors,
		m.BytesSent,
		m.BytesReceived,
		m.RateLimitHits,
		m.AuthAttempts,
		m.AuthFailures,
		m.Uptime,
		m.GoRoutines,
	)

	// Register default Go metrics
	m.registry.MustRegister(prometheus.NewGoCollector())
	m.registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return m
}

// Handler returns an HTTP handler for the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}
