package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The production handler (HandlerWithUI) had drifted from the test-only
// Handler(): static UI responses carried no CSP/X-Frame-Options/nosniff, and
// the 11 documented pprof routes were swallowed by the static catch-all.
func TestHandlerWithUI_SecurityHeadersOnStaticUI(t *testing.T) {
	api := New(Config{})
	h := api.HandlerWithUI()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", rec.Header().Get("X-Frame-Options"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"),
		"the static UI must carry a CSP, matching the server dashboard")
}

func TestHandlerWithUI_PprofIsReachable(t *testing.T) {
	api := New(Config{})
	h := api.HandlerWithUI()

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code,
		"the documented pprof index must exist on the production handler")
	assert.Contains(t, rec.Body.String(), "goroutine")
}

func TestHandlerWithUI_PprofRequiresTokenWhenConfigured(t *testing.T) {
	api := New(Config{Token: "secret"})
	h := api.HandlerWithUI()

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"pprof must sit behind the API token when one is set")

	req = httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
