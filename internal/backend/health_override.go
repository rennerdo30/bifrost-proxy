package backend

import (
	"sync/atomic"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/health"
)

// HealthOverride is implemented by backends that support external health updates.
type HealthOverride interface {
	SetHealth(result health.Result)
	ClearHealthOverride()
}

// HealthWrappedBackend wraps a Backend and allows health checks to override IsHealthy/Stats.
type HealthWrappedBackend struct {
	Backend
	overrideEnabled atomic.Bool
	healthy         atomic.Bool
	lastError       atomic.Value // string
	lastErrorTime   atomic.Value // time.Time
	latency         atomic.Int64 // nanoseconds
}

// WrapWithHealth creates a health-aware wrapper around a backend.
func WrapWithHealth(b Backend) *HealthWrappedBackend {
	return &HealthWrappedBackend{Backend: b}
}

// SetHealth updates the health override based on the latest check result.
func (b *HealthWrappedBackend) SetHealth(result health.Result) {
	b.overrideEnabled.Store(true)
	b.healthy.Store(result.Healthy)
	if result.Latency > 0 {
		b.latency.Store(result.Latency.Nanoseconds())
	}
	if !result.Healthy {
		if result.Error != "" {
			b.lastError.Store(result.Error)
			b.lastErrorTime.Store(time.Now())
		}
	}
}

// ClearHealthOverride clears any external health override.
func (b *HealthWrappedBackend) ClearHealthOverride() {
	b.overrideEnabled.Store(false)
}

// IsHealthy returns the overridden health when available.
func (b *HealthWrappedBackend) IsHealthy() bool {
	if b.overrideEnabled.Load() {
		return b.healthy.Load()
	}
	return b.Backend.IsHealthy()
}

// Stats returns backend statistics with health override applied when set.
func (b *HealthWrappedBackend) Stats() Stats {
	stats := b.Backend.Stats()
	if !b.overrideEnabled.Load() {
		return stats
	}

	stats.Healthy = b.healthy.Load()

	if v := b.lastError.Load(); v != nil {
		stats.LastError = v.(string) //nolint:errcheck // Type is always string
	}
	if v := b.lastErrorTime.Load(); v != nil {
		stats.LastErrorTime = v.(time.Time) //nolint:errcheck // Type is always time.Time
	}
	if n := b.latency.Load(); n > 0 {
		stats.Latency = time.Duration(n)
	}

	return stats
}
