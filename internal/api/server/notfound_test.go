package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNotFound_APIPathsReturnJSON is a regression test for the Web UI crashing
// with a generic "Something went wrong" on the Request Log page.
//
// The SPA catch-all (r.NotFound -> staticHandler) served index.html for EVERY
// unmatched path, including /api/**. Callers therefore got 200 + text/html
// where they expected JSON, so res.json() threw and the UI surfaced an
// unexplained error instead of a real one. It also made every missing route
// look healthy to any status-code-only probe, which is how the gap hid.
//
// Concretely: /api/v1/debug/entries is registered only in client mode, so
// under the server binary it fell through to the SPA handler.
func TestNotFound_APIPathsReturnJSON(t *testing.T) {
	a := New(Config{})
	srv := httptest.NewServer(a.RouterWithWebSocket(nil))
	defer srv.Close()

	for _, path := range []string{
		"/api/v1/debug/entries",
		"/api/v1/debug/entries/last/50",
		"/api/v1/debug/errors",
		"/api/v1/definitely-not-a-route",
	} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path) //nolint:noctx // test
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusNotFound, resp.StatusCode,
				"unmatched API path must 404, not fall through to the SPA")
			require.Contains(t, resp.Header.Get("Content-Type"), "application/json",
				"unmatched API path must return JSON, never index.html")
		})
	}
}

// TestNotFound_NonAPIPathsStillServeSPA guards the other half: client-side
// routes must keep working on a hard refresh.
func TestNotFound_NonAPIPathsStillServeSPA(t *testing.T) {
	a := New(Config{})
	srv := httptest.NewServer(a.RouterWithWebSocket(nil))
	defer srv.Close()

	for _, path := range []string{"/traffic", "/routes", "/settings"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path) //nolint:noctx // test
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode,
				"SPA deep links must still resolve on hard refresh")
			require.True(t, strings.Contains(resp.Header.Get("Content-Type"), "text/html"),
				"SPA deep links must be served index.html")
		})
	}
}
