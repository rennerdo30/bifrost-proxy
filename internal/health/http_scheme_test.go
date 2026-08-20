package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPChecker_HTTPSScheme covers the config-reachable HTTPS health check
// path: with scheme "https" the checker must speak TLS, and
// insecure_skip_verify must be what allows a self-signed backend certificate
// (so that omitting it genuinely fails closed rather than silently passing).
func TestHTTPChecker_HTTPSScheme(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/healthz", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := strings.TrimPrefix(srv.URL, "https://")

	t.Run("https with insecure_skip_verify succeeds", func(t *testing.T) {
		checker := NewHTTPChecker(Config{
			Type:               "http",
			Target:             target,
			Path:               "/healthz",
			Scheme:             "https",
			InsecureSkipVerify: true,
			Timeout:            5 * time.Second,
		})
		require.Equal(t, "http", checker.Type())

		result := checker.Check(context.Background())
		assert.True(t, result.Healthy, "expected healthy, got error: %s", result.Error)
		assert.Equal(t, "HTTP 200", result.Message)
	})

	t.Run("https without insecure_skip_verify fails closed on self-signed cert", func(t *testing.T) {
		checker := NewHTTPChecker(Config{
			Type:    "http",
			Target:  target,
			Path:    "/healthz",
			Scheme:  "https",
			Timeout: 5 * time.Second,
		})

		result := checker.Check(context.Background())
		assert.False(t, result.Healthy, "self-signed cert must not verify by default")
		assert.NotEmpty(t, result.Error)
	})

	t.Run("default scheme is plain http", func(t *testing.T) {
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer plain.Close()

		checker := NewHTTPChecker(Config{
			Type:    "http",
			Target:  strings.TrimPrefix(plain.URL, "http://"),
			Path:    "/",
			Timeout: 5 * time.Second,
		})

		result := checker.Check(context.Background())
		assert.True(t, result.Healthy, "expected healthy, got error: %s", result.Error)
	})
}
