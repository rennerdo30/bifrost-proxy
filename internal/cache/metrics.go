package cache

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for the cache.
type Metrics struct {
	// Hits tracks cache hits by domain.
	Hits *prometheus.CounterVec

	// Misses tracks cache misses by domain and reason.
	Misses *prometheus.CounterVec

	// BytesServed tracks bytes served from cache vs origin.
	BytesServed *prometheus.CounterVec

	// BytesCached tracks total bytes stored in cache.
	BytesCached prometheus.Counter

	// StorageSize tracks current storage size by tier.
	StorageSize *prometheus.GaugeVec

	// StorageEntries tracks current entry count by tier.
	StorageEntries *prometheus.GaugeVec

	// StorageUsage tracks storage usage percentage by tier.
	StorageUsage *prometheus.GaugeVec

	// Evictions tracks evictions by tier and reason.
	Evictions *prometheus.CounterVec

	// OperationLatency tracks latency of cache operations.
	OperationLatency *prometheus.HistogramVec

	// ActiveRules tracks number of active cache rules.
	ActiveRules prometheus.Gauge

	// ActivePresets tracks number of enabled presets.
	ActivePresets prometheus.Gauge
}

// NewMetrics creates a new Metrics instance and registers with the registry.
func NewMetrics(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		Hits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"domain"},
		),

		Misses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"domain", "reason"},
		),

		BytesServed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "bytes_served_total",
				Help:      "Total bytes served",
			},
			[]string{"source"}, // "cache" or "origin"
		),

		BytesCached: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "bytes_cached_total",
				Help:      "Total bytes stored in cache",
			},
		),

		StorageSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "storage_size_bytes",
				Help:      "Current storage size in bytes",
			},
			[]string{"tier"}, // "memory" or "disk"
		),

		StorageEntries: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "storage_entries",
				Help:      "Current number of cached entries",
			},
			[]string{"tier"},
		),

		StorageUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "storage_usage_percent",
				Help:      "Storage usage percentage",
			},
			[]string{"tier"},
		),

		Evictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "evictions_total",
				Help:      "Total number of evictions",
			},
			[]string{"tier", "reason"}, // reason: "size", "ttl", "lru"
		),

		OperationLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "operation_duration_seconds",
				Help:      "Cache operation latency",
				Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 15), // 100us to ~3s
			},
			[]string{"operation"}, // "get", "put", "delete"
		),

		ActiveRules: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "active_rules",
				Help:      "Number of active cache rules",
			},
		),

		ActivePresets: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "bifrost",
				Subsystem: "cache",
				Name:      "active_presets",
				Help:      "Number of enabled cache presets",
			},
		),
	}

	// Register all metrics
	if registry != nil {
		registry.MustRegister(
			m.Hits,
			m.Misses,
			m.BytesServed,
			m.BytesCached,
			m.StorageSize,
			m.StorageEntries,
			m.StorageUsage,
			m.Evictions,
			m.OperationLatency,
			m.ActiveRules,
			m.ActivePresets,
		)
	}

	return m
}

// RecordHit records a cache hit.
func (m *Metrics) RecordHit(domain string, bytes int64) {
	if m == nil {
		return
	}
	m.Hits.WithLabelValues(domain).Inc()
	m.BytesServed.WithLabelValues("cache").Add(float64(bytes))
}

// RecordMiss records a cache miss.
func (m *Metrics) RecordMiss(domain, reason string) {
	if m == nil {
		return
	}
	m.Misses.WithLabelValues(domain, reason).Inc()
}

// RecordOriginBytes records bytes served from origin.
func (m *Metrics) RecordOriginBytes(bytes int64) {
	if m == nil {
		return
	}
	m.BytesServed.WithLabelValues("origin").Add(float64(bytes))
}

// RecordCachedBytes records bytes stored in cache.
func (m *Metrics) RecordCachedBytes(bytes int64) {
	if m == nil {
		return
	}
	m.BytesCached.Add(float64(bytes))
}

// RecordEviction records a cache eviction.
func (m *Metrics) RecordEviction(tier, reason string) {
	if m == nil {
		return
	}
	m.Evictions.WithLabelValues(tier, reason).Inc()
}

// UpdateStorageMetrics updates storage gauges.
func (m *Metrics) UpdateStorageMetrics(tier string, entries, size, maxSize int64) {
	if m == nil {
		return
	}
	m.StorageEntries.WithLabelValues(tier).Set(float64(entries))
	m.StorageSize.WithLabelValues(tier).Set(float64(size))
	if maxSize > 0 {
		m.StorageUsage.WithLabelValues(tier).Set(float64(size) / float64(maxSize) * 100)
	}
}

// UpdateRuleMetrics updates rule-related gauges.
func (m *Metrics) UpdateRuleMetrics(rules, presets int) {
	if m == nil {
		return
	}
	m.ActiveRules.Set(float64(rules))
	m.ActivePresets.Set(float64(presets))
}

// ObserveOperation records the latency of a cache operation.
func (m *Metrics) ObserveOperation(operation string, seconds float64) {
	if m == nil {
		return
	}
	m.OperationLatency.WithLabelValues(operation).Observe(seconds)
}

// MissReasonNotFound is used when the entry is not in cache.
const MissReasonNotFound = "not_found"

// MissReasonExpired is used when the entry has expired.
const MissReasonExpired = "expired"

// MissReasonNoRule is used when no caching rule matches.
const MissReasonNoRule = "no_rule"

// MissReasonDisabled is used when caching is disabled.
const MissReasonDisabled = "disabled"

// EvictionReasonSize is used when evicting due to size limit.
const EvictionReasonSize = "size"

// EvictionReasonTTL is used when evicting due to TTL expiry.
const EvictionReasonTTL = "ttl"

// EvictionReasonLRU is used when evicting due to LRU policy.
const EvictionReasonLRU = "lru"
