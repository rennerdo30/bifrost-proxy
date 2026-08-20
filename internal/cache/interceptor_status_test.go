package cache

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInterceptor_HandleRequestWithResult_ReportsServedStatus pins the status
// code reported back to the proxy layer for cache hits. The proxy uses it for
// the access log and the Prometheus status label, so a wrong (or missing) value
// shows up as a fabricated 500 on every hit.
func TestInterceptor_HandleRequestWithResult_ReportsServedStatus(t *testing.T) {
	mgr, _ := newWiredManager(t, 8)
	ctx := context.Background()
	mgr.Start(ctx)
	defer mgr.Stop(ctx) //nolint:errcheck // test cleanup

	const url = "http://example.com/blob"
	putBody(t, mgr, url, "hello world")

	interceptor := NewInterceptor(mgr)

	tests := []struct {
		name       string
		rangeValue string
		wantStatus int
	}{
		{name: "full response", wantStatus: http.StatusOK},
		{name: "range response", rangeValue: "bytes=0-4", wantStatus: http.StatusPartialContent},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			require.NoError(t, err)
			if tc.rangeValue != "" {
				req.Header.Set("Range", tc.rangeValue)
			}

			clientConn, serverConn := net.Pipe()
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				_, _ = io.Copy(io.Discard, clientConn) //nolint:errcheck // draining
			}()

			hit, err := interceptor.HandleRequestWithResult(ctx, serverConn, req)
			serverConn.Close()
			clientConn.Close()
			<-drained

			require.NoError(t, err)
			require.True(t, hit.Handled)
			assert.Equal(t, tc.wantStatus, hit.StatusCode)
		})
	}
}

// TestInterceptor_HandleRequestWithResult_MissHasNoStatus verifies that a miss
// carries no status code, so callers cannot mistake it for a served response.
func TestInterceptor_HandleRequestWithResult_MissHasNoStatus(t *testing.T) {
	mgr, _ := newWiredManager(t, 8)
	ctx := context.Background()
	mgr.Start(ctx)
	defer mgr.Stop(ctx) //nolint:errcheck // test cleanup

	interceptor := NewInterceptor(mgr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/absent", nil)
	require.NoError(t, err)

	hit, err := interceptor.HandleRequestWithResult(ctx, nil, req)
	require.NoError(t, err)
	assert.False(t, hit.Handled)
	assert.Zero(t, hit.StatusCode)
}
