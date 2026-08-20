package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/accesslog"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/cache"
)

// captureLogger is an accesslog.Logger that records every entry in memory.
type captureLogger struct {
	mu      sync.Mutex
	entries []accesslog.Entry
}

func (c *captureLogger) Log(entry accesslog.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entry)
	return nil
}

func (c *captureLogger) Close() error { return nil }

func (c *captureLogger) snapshot() []accesslog.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]accesslog.Entry(nil), c.entries...)
}

// recordedMetric captures one RecordMetrics invocation.
type recordedMetric struct {
	protocol string
	method   string
	status   string
	backend  string
}

// metricsRecorder collects RecordMetrics callbacks in a race-safe way.
type metricsRecorder struct {
	mu     sync.Mutex
	got    recordedMetric
	called atomic.Bool
}

func (r *metricsRecorder) hook() func(protocol, method, status, backendName string, duration time.Duration, sent, recv int64) {
	return func(protocol, method, status, backendName string, _ time.Duration, _, _ int64) {
		r.mu.Lock()
		r.got = recordedMetric{protocol: protocol, method: method, status: status, backend: backendName}
		r.mu.Unlock()
		r.called.Store(true)
	}
}

func (r *metricsRecorder) wait(t *testing.T) recordedMetric {
	t.Helper()
	require.Eventually(t, r.called.Load, 2*time.Second, 10*time.Millisecond,
		"RecordMetrics was never invoked")
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got
}

// newCachePopulatedInterceptor returns an interceptor whose memory cache
// already holds a fresh 200 response for url with the given body.
func newCachePopulatedInterceptor(t *testing.T, url, body string) *cache.Interceptor {
	t.Helper()

	mgr, err := cache.NewManager(&cache.Config{
		Enabled:    true,
		DefaultTTL: cache.Duration(time.Hour),
		Storage: cache.StorageConfig{
			Type:   "memory",
			Memory: &cache.MemoryConfig{MaxSize: 10 * cache.MB, MaxEntries: 16},
		},
		Rules: []cache.RuleConfig{{
			Name:    "test",
			Domains: []string{"cache.example.com"},
			Enabled: true,
			TTL:     cache.Duration(time.Hour),
		}},
	})
	require.NoError(t, err)

	ctx := context.Background()
	mgr.Start(ctx)
	t.Cleanup(func() { mgr.Stop(context.Background()) }) //nolint:errcheck // test cleanup

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: int64(len(body)),
	}
	require.NoError(t, mgr.Put(ctx, req, resp, io.NopCloser(bytes.NewReader([]byte(body)))))

	return cache.NewInterceptor(mgr)
}

// TestHTTPHandler_CacheHitRecordsServedStatus is the regression test for cache
// hits being reported as HTTP 500: the cache-served branch used to return
// without touching entry.StatusCode, so the deferred closure defaulted it to
// 500 and emitted bifrost_requests_total{status="500"} for every hit.
func TestHTTPHandler_CacheHitRecordsServedStatus(t *testing.T) {
	const (
		cacheURL  = "http://cache.example.com/asset.txt"
		cacheBody = "cached-payload"
	)

	interceptor := newCachePopulatedInterceptor(t, cacheURL, cacheBody)

	logger := &captureLogger{}
	recorder := &metricsRecorder{}

	handler := NewHTTPHandler(HTTPHandlerConfig{
		// A cache hit must never reach backend selection.
		GetBackend: func(domain, clientIP string) backend.Backend {
			t.Errorf("getBackend must not be called for a cache hit (domain %q)", domain)
			return nil
		},
		CacheInterceptor: interceptor,
		AccessLogger:     logger,
		RecordMetrics:    recorder.hook(),
	})

	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := clientConn.Write([]byte("GET " + cacheURL + " HTTP/1.1\r\nHost: cache.example.com\r\n\r\n"))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	require.NoError(t, err)
	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "client must receive the cached status")
	assert.Equal(t, cacheBody, string(payload))
	assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))

	clientConn.Close()

	got := recorder.wait(t)
	assert.Equal(t, "http", got.protocol)
	assert.Equal(t, http.MethodGet, got.method)
	assert.Equal(t, "200", got.status, "a cache hit must be recorded as 200, not 500")
	assert.Equal(t, backendNameCache, got.backend, "a cache hit must carry the synthetic cache backend label")

	logged := logger.snapshot()
	require.Len(t, logged, 1)
	assert.Equal(t, http.StatusOK, logged[0].StatusCode, "access log must record the cached status")
	assert.Equal(t, backendNameCache, logged[0].Backend)
}

// TestHTTPHandler_RecordMetricsCarriesBackendName guards the per-backend
// Prometheus breakdown: the HTTP path must forward the selected backend name to
// RecordMetrics instead of an empty label.
func TestHTTPHandler_RecordMetricsCarriesBackendName(t *testing.T) {
	upstream := &http.Server{ReadHeaderTimeout: time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	upstream.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hi")) //nolint:errcheck // test upstream
	})
	go upstream.Serve(ln) //nolint:errcheck // test upstream
	t.Cleanup(func() { upstream.Close() })

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "http-be"})
	require.NoError(t, directBackend.Start(context.Background()))
	t.Cleanup(func() { directBackend.Stop(context.Background()) }) //nolint:errcheck // test cleanup

	recorder := &metricsRecorder{}
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:    func(string, string) backend.Backend { return directBackend },
		RecordMetrics: recorder.hook(),
	})

	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = clientConn.Write([]byte("GET http://" + ln.Addr().String() + "/ HTTP/1.1\r\nHost: " + ln.Addr().String() + "\r\n\r\n"))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body) //nolint:errcheck // draining
	resp.Body.Close()
	clientConn.Close()

	got := recorder.wait(t)
	assert.Equal(t, "http", got.protocol)
	assert.Equal(t, "418", got.status)
	assert.Equal(t, "http-be", got.backend, "HTTP metrics must carry the selected backend name")
}
