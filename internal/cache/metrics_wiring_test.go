package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// counterValue reads the current value of a Prometheus counter or gauge
// without requiring the testutil helper package (and its extra test deps).
func counterValue(t *testing.T, c prometheus.Metric) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	default:
		t.Fatalf("metric is neither a counter nor a gauge")
		return 0
	}
}

// newWiredManager builds a memory-backed manager with a custom rule and a
// registered Prometheus metrics recorder attached.
func newWiredManager(t *testing.T, maxEntries int) (*Manager, *Metrics) {
	t.Helper()

	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(time.Hour),
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize:    10 * MB,
				MaxEntries: maxEntries,
			},
		},
		Rules: []RuleConfig{
			{
				Name:    "test",
				Domains: []string{"example.com"},
				Enabled: true,
				TTL:     Duration(time.Hour),
			},
		},
	}

	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	m := NewMetrics(prometheus.NewRegistry())
	mgr.SetMetrics(m)

	return mgr, m
}

func putBody(t *testing.T, mgr *Manager, url, body string) {
	t.Helper()
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: int64(len(body)),
	}
	require.NoError(t, mgr.Put(ctx, req, resp, io.NopCloser(bytes.NewReader([]byte(body)))))
}

func TestManager_MetricsWiring(t *testing.T) {
	mgr, m := newWiredManager(t, 100)
	ctx := context.Background()
	require.NoError(t, mgr.Start(ctx))
	defer func() { _ = mgr.Stop(ctx) }()

	const host = "example.com"
	url := "http://example.com/file"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	// Miss: nothing cached yet.
	_, err = mgr.Get(ctx, req)
	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, 1.0, counterValue(t, m.Misses.WithLabelValues(host, MissReasonNotFound)))

	// Miss: request with no matching rule.
	otherReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://nomatch.test/x", nil)
	require.NoError(t, err)
	_, err = mgr.Get(ctx, otherReq)
	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, 1.0, counterValue(t, m.Misses.WithLabelValues("nomatch.test", MissReasonNoRule)))

	// Store a response and verify cached bytes are recorded.
	body := "hello cache world"
	putBody(t, mgr, url, body)
	assert.Equal(t, float64(len(body)), counterValue(t, m.BytesCached))

	// Hit: entry is now served from cache.
	entry, err := mgr.Get(ctx, req)
	require.NoError(t, err)
	entry.Close()
	assert.Equal(t, 1.0, counterValue(t, m.Hits.WithLabelValues(host)))
	assert.Equal(t, float64(len(body)), counterValue(t, m.BytesServed.WithLabelValues("cache")))

	// Storage gauges reflect one stored entry.
	assert.Equal(t, 1.0, counterValue(t, m.StorageEntries.WithLabelValues("memory")))
	assert.GreaterOrEqual(t, counterValue(t, m.ActiveRules), 1.0)
}

func TestManager_MetricsWiring_Eviction(t *testing.T) {
	// maxEntries=1 forces an eviction on the second distinct entry.
	mgr, m := newWiredManager(t, 1)
	ctx := context.Background()
	require.NoError(t, mgr.Start(ctx))
	defer func() { _ = mgr.Stop(ctx) }()

	putBody(t, mgr, "http://example.com/a", "first entry")
	putBody(t, mgr, "http://example.com/b", "second entry")

	assert.Equal(t, 1.0, counterValue(t, m.Evictions.WithLabelValues("memory", EvictionReasonSize)))
}

func TestManager_MetricsWiring_NilSafe(t *testing.T) {
	// A manager without metrics attached must not panic on any hot path.
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(time.Hour),
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB, MaxEntries: 100},
		},
		Rules: []RuleConfig{{Name: "test", Domains: []string{"example.com"}, Enabled: true, TTL: Duration(time.Hour)}},
	}
	mgr, err := NewManager(cfg)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, mgr.Start(ctx))
	defer func() { _ = mgr.Stop(ctx) }()

	mgr.SyncMetrics() // no-op without metrics
	putBody(t, mgr, "http://example.com/file", "payload")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/file", nil)
	require.NoError(t, err)
	entry, err := mgr.Get(ctx, req)
	require.NoError(t, err)
	entry.Close()
}
