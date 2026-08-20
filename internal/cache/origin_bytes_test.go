package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInterceptor_StoreResponse_RecordsOriginBytes closes the last gap in the
// cache Prometheus subsystem: BytesServed{source="origin"} had no production
// writer at all, so the bandwidth-saved ratio against {source="cache"} could
// never be computed.
func TestInterceptor_StoreResponse_RecordsOriginBytes(t *testing.T) {
	mgr, m := newWiredManager(t, 8)
	ctx := context.Background()
	mgr.Start(ctx)
	defer mgr.Stop(ctx) //nolint:errcheck // test cleanup

	interceptor := NewInterceptor(mgr)

	tests := []struct {
		name string
		url  string
		body string
	}{
		// Matches the "example.com" rule, so it is stored.
		{name: "cacheable domain", url: "http://example.com/a", body: "cacheable"},
		// No rule matches, so nothing is stored — but the bytes still came from
		// the origin and must be counted.
		{name: "non-cacheable domain", url: "http://other.invalid/b", body: "passthrough"},
	}

	var want float64
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, tc.url, nil)
			require.NoError(t, err)
			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				ContentLength: int64(len(tc.body)),
				Body:          io.NopCloser(bytes.NewReader([]byte(tc.body))),
			}

			forwarded, err := interceptor.StoreResponse(ctx, req, resp)
			require.NoError(t, err)
			got, err := io.ReadAll(forwarded)
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(got), "the body must still reach the client")

			want += float64(len(tc.body))
			assert.Equal(t, want,
				counterValue(t, m.BytesServed.WithLabelValues("origin")),
				"origin bytes must be counted for every response fetched from the origin")
		})
	}
}

// TestInterceptor_StoreResponse_IgnoresUnknownContentLength guards against a
// Prometheus counter decrease: net/http reports -1 for an unknown length.
func TestInterceptor_StoreResponse_IgnoresUnknownContentLength(t *testing.T) {
	mgr, m := newWiredManager(t, 8)
	ctx := context.Background()
	mgr.Start(ctx)
	defer mgr.Stop(ctx) //nolint:errcheck // test cleanup

	interceptor := NewInterceptor(mgr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/c", nil)
	require.NoError(t, err)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: -1,
		Body:          io.NopCloser(bytes.NewReader([]byte("chunked"))),
	}

	_, err = interceptor.StoreResponse(ctx, req, resp)
	require.NoError(t, err)

	assert.Zero(t, counterValue(t, m.BytesServed.WithLabelValues("origin")))
}

// TestManager_RecordOriginBytes_NoMetricsAttached verifies the passthrough is
// safe when no recorder is attached (metrics disabled).
func TestManager_RecordOriginBytes_NoMetricsAttached(t *testing.T) {
	mgr, err := NewManager(&Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 1 * MB},
		},
	})
	require.NoError(t, err)
	mgr.RecordOriginBytes(1234)
}
