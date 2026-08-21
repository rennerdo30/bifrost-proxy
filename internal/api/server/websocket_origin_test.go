package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// originTestTimeout bounds each handshake attempt in this file.
const originTestTimeout = 5 * time.Second

// tryDialWithOrigin attempts a WebSocket upgrade with the given Origin header
// (empty string means "send no Origin header at all") and reports the handshake
// error plus the HTTP status the server replied with.
func tryDialWithOrigin(t *testing.T, srv *httptest.Server, origin string) (error, int) { //nolint:revive // (error, status) reads better than the reverse here
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), originTestTimeout)
	defer cancel()

	opts := &websocket.DialOptions{HTTPHeader: http.Header{}}
	if origin != "" {
		opts.HTTPHeader.Set("Origin", origin)
	}

	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+wsTestPath, opts)
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	if conn != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}
	return err, status
}

// newOriginTestServer starts a hub-backed test server with the given
// api.allowed_origins allowlist.
func newOriginTestServer(t *testing.T, allowedOrigins []string) *httptest.Server {
	t.Helper()

	hub := NewWebSocketHub()
	hub.SetAllowedOrigins(allowedOrigins)
	go hub.Run()
	t.Cleanup(hub.Stop)

	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	return srv
}

// TestWebSocket_RejectsCrossOriginUpgrade is the regression test for the
// long-standing gap where /api/v1/ws performed no meaningful Origin check at
// all: the handler passed InsecureSkipVerify:true to websocket.Accept, and the
// implementation it replaced (golang.org/x/net/websocket) only checked that the
// Origin header parsed as a URL — it never compared it to the request Host.
//
// WebSockets are exempt from both the same-origin policy and CORS, and when no
// api.token is configured the route has no auth either, so any web page the
// operator's browser visited could open a socket to a local Bifrost and read the
// live traffic stream.
func TestWebSocket_RejectsCrossOriginUpgrade(t *testing.T) {
	srv := newOriginTestServer(t, nil)

	err, status := tryDialWithOrigin(t, srv, "https://evil.example.com")

	require.Error(t, err, "a cross-origin upgrade must be refused")
	assert.Equal(t, http.StatusForbidden, status, "origin rejection should be a 403")
}

// TestWebSocket_AcceptsSameOriginUpgrade proves the check does not break the
// dashboard this server itself serves, which is the common case and needs no
// configuration.
func TestWebSocket_AcceptsSameOriginUpgrade(t *testing.T) {
	srv := newOriginTestServer(t, nil)

	err, _ := tryDialWithOrigin(t, srv, srv.URL)

	require.NoError(t, err, "a same-origin upgrade must succeed without any allowlist")
}

// TestWebSocket_AcceptsAllowlistedProxyOrigin covers the reverse-proxy case that
// caused the check to be disabled wholesale in the first place: Home Assistant
// Ingress (and Traefik, nginx, Cloudflare Tunnel) rewrite Host, so the browser's
// Origin no longer matches it. That now requires an explicit, per-deployment
// grant in api.allowed_origins instead of a blanket bypass.
func TestWebSocket_AcceptsAllowlistedProxyOrigin(t *testing.T) {
	const proxyOrigin = "http://homeassistant.local:8123"
	srv := newOriginTestServer(t, []string{proxyOrigin})

	err, _ := tryDialWithOrigin(t, srv, proxyOrigin)

	require.NoError(t, err, "an allowlisted proxy origin must be accepted")

	// The allowlist must be an allowlist, not an off switch: a different origin
	// is still refused while the entry above is honoured.
	err, status := tryDialWithOrigin(t, srv, "https://evil.example.com")
	require.Error(t, err, "allowlisting one origin must not allow all origins")
	assert.Equal(t, http.StatusForbidden, status)
}

// TestWebSocket_AllowlistSupportsWildcardHostPatterns documents that entries may
// use shell-style wildcards, so an operator with per-branch preview hostnames
// does not have to list them individually.
func TestWebSocket_AllowlistSupportsWildcardHostPatterns(t *testing.T) {
	srv := newOriginTestServer(t, []string{"*.bifrost.example.com"})

	err, _ := tryDialWithOrigin(t, srv, "https://dash.bifrost.example.com")
	require.NoError(t, err, "wildcard host pattern should match a subdomain")

	err, status := tryDialWithOrigin(t, srv, "https://bifrost.example.net")
	require.Error(t, err, "wildcard must not match an unrelated domain")
	assert.Equal(t, http.StatusForbidden, status)
}

// TestWebSocket_AllowlistMatchingRules pins the two matching behaviours an
// operator is most likely to trip over — a missing port and the reach of `*` —
// and the suffix-extension attack a sloppy matcher would allow. These are
// documented in docs/src/content/docs/api/websocket.mdx; the test exists so the
// docs cannot quietly become wrong.
func TestWebSocket_AllowlistMatchingRules(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		origin  string
		allowed bool
	}{
		{
			name:    "exact host matches",
			pattern: "bifrost.example.com",
			origin:  "https://bifrost.example.com",
			allowed: true,
		},
		{
			// Ports are part of the host and are matched literally, so a pattern
			// without one does not cover an origin with one.
			name:    "host pattern does not cover a non-default port",
			pattern: "bifrost.example.com",
			origin:  "http://bifrost.example.com:8080",
			allowed: false,
		},
		{
			name:    "host pattern with the port matches",
			pattern: "bifrost.example.com:8080",
			origin:  "http://bifrost.example.com:8080",
			allowed: true,
		},
		{
			// `*` spans dots...
			name:    "wildcard spans multiple labels",
			pattern: "*.example.com",
			origin:  "https://a.b.example.com",
			allowed: true,
		},
		{
			// ...but not the port separator.
			name:    "wildcard does not span the port separator",
			pattern: "*.example.com",
			origin:  "https://a.example.com:1234",
			allowed: false,
		},
		{
			// The attack a suffix-match implementation would permit.
			name:    "pattern cannot be extended into an attacker domain",
			pattern: "bifrost.example.com",
			origin:  "https://bifrost.example.com.evil.example.net",
			allowed: false,
		},
		{
			name:    "matching is case-insensitive",
			pattern: "bifrost.example.com",
			origin:  "https://BIFROST.Example.COM",
			allowed: true,
		},
		{
			// A scheme-qualified pattern pins the scheme too.
			name:    "scheme-qualified pattern rejects the other scheme",
			pattern: "https://bifrost.example.com",
			origin:  "http://bifrost.example.com",
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newOriginTestServer(t, []string{tc.pattern})

			err, status := tryDialWithOrigin(t, srv, tc.origin)
			if tc.allowed {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, http.StatusForbidden, status)
		})
	}
}

// TestWebSocket_RejectsOpaqueOrigin covers the sandboxed-iframe / data-URL case.
// Such contexts send the literal string "null" as their Origin, which has no
// host and so must not be treated like the "no Origin header" carve-out.
func TestWebSocket_RejectsOpaqueOrigin(t *testing.T) {
	srv := newOriginTestServer(t, nil)

	err, status := tryDialWithOrigin(t, srv, "null")

	require.Error(t, err, "an opaque origin must not be accepted")
	assert.Equal(t, http.StatusForbidden, status)
}

// TestWebSocket_AcceptsMissingOriginHeader documents the deliberate carve-out:
// non-browser clients (the CLI, curl, integration tests) send no Origin header
// and are not subject to the browser-driven attack this check defends against.
// Browsers always send one on a WebSocket handshake, so this is not a bypass for
// the threat model — a page cannot suppress its own Origin.
func TestWebSocket_AcceptsMissingOriginHeader(t *testing.T) {
	srv := newOriginTestServer(t, nil)

	err, _ := tryDialWithOrigin(t, srv, "")

	require.NoError(t, err, "a client that sends no Origin header must still connect")
}

// TestWebSocket_WildcardDisablesOriginCheck covers the documented escape hatch.
// It exists so operators behind an unusual proxy are not stuck, but it is an
// explicit opt-out that the server warns about at startup rather than the old
// silent default.
func TestWebSocket_WildcardDisablesOriginCheck(t *testing.T) {
	hub := NewWebSocketHub()
	hub.SetAllowedOrigins([]string{config.AllowedOriginsWildcard})
	go hub.Run()
	t.Cleanup(hub.Stop)

	assert.True(t, hub.SkipsOriginCheck(), "the wildcard must be reported so startup can warn about it")

	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)

	err, _ := tryDialWithOrigin(t, srv, "https://evil.example.com")
	require.NoError(t, err, "the explicit wildcard opt-out must accept any origin")
}

// TestWebSocketHub_SetAllowedOrigins_SeparatesWildcard checks the wildcard is
// consumed as a flag rather than being passed through as a host pattern, and
// that a repeated call replaces rather than accumulates state.
func TestWebSocketHub_SetAllowedOrigins_SeparatesWildcard(t *testing.T) {
	hub := NewWebSocketHub()

	hub.SetAllowedOrigins([]string{"a.example.com", config.AllowedOriginsWildcard, "b.example.com"})
	assert.True(t, hub.SkipsOriginCheck())
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, hub.allowedOrigins)

	// Re-configuring must clear the previous wildcard, not keep it latched on.
	hub.SetAllowedOrigins([]string{"c.example.com"})
	assert.False(t, hub.SkipsOriginCheck())
	assert.Equal(t, []string{"c.example.com"}, hub.allowedOrigins)

	hub.SetAllowedOrigins(nil)
	assert.False(t, hub.SkipsOriginCheck())
	assert.Empty(t, hub.allowedOrigins)
}
