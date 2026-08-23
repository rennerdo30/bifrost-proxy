package server

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upgradeWithHost performs a raw WebSocket handshake against srv with a forged
// Host header, which is what a DNS-rebinding attacker presents. websocket.Dial
// derives Host from the dial URL, so it cannot express this case.
func upgradeWithHost(t *testing.T, srv *httptest.Server, host, origin string) int {
	t.Helper()

	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, srv.URL+wsTestPath, nil)
	require.NoError(t, err)
	// Host is set on the struct field, not the header map: net/http writes the
	// request line and Host header from req.Host.
	req.Host = host
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestWebSocket_RejectsDNSRebindingHost is the regression test for the residual
// left by the Origin allowlist: github.com/coder/websocket accepts any request
// whose Origin host equals the request Host (accept.go, strings.EqualFold), so
// an attacker who controls a DNS name can serve a page from that name, rebind it
// to this server's address, and arrive with Host and Origin both reading
// "evil.example:8080". They match, so the Origin check passes — and with
// api.token unset the route has no auth, exposing the live traffic stream to any
// browser that loads the attacker's page.
//
// The Host must therefore be independently trustworthy: an IP literal or a
// loopback name (neither of which an attacker can re-point), or explicitly named
// in api.allowed_origins.
func TestWebSocket_RejectsDNSRebindingHost(t *testing.T) {
	srv := newOriginTestServer(t, nil)

	// Self-consistent Host and Origin under a name the attacker controls.
	status := upgradeWithHost(t, srv, "evil.example:8080", "http://evil.example:8080")
	assert.Equal(t, http.StatusForbidden, status,
		"a rebound attacker-controlled Host must be refused even though Origin matches it")
}

func TestWebSocket_AcceptsRebindSafeHosts(t *testing.T) {
	srv := newOriginTestServer(t, nil)

	// The port the test server is really on, so the handshake can complete.
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	for _, host := range []string{
		"127.0.0.1:" + port, // IPv4 literal: no name to re-point
		"[::1]:" + port,     // IPv6 literal, bracketed
		"localhost:" + port, // reserved name, resolves to loopback
		"app.localhost:" + port,
	} {
		t.Run(host, func(t *testing.T) {
			status := upgradeWithHost(t, srv, host, "http://"+host)
			assert.Equal(t, http.StatusSwitchingProtocols, status,
				"%s is not forgeable by DNS rebinding and must be accepted", host)
		})
	}
}

// TestWebSocket_AllowlistedHostAccepted covers the reverse-proxy deployment: a
// Host-rewriting proxy (Home Assistant Ingress) is named in api.allowed_origins,
// which must grant the Host check as well as the Origin check so one entry
// covers the whole upgrade.
func TestWebSocket_AllowlistedHostAccepted(t *testing.T) {
	srv := newOriginTestServer(t, []string{"homeassistant.local:8123"})

	status := upgradeWithHost(t, srv, "homeassistant.local:8123", "http://homeassistant.local:8123")
	assert.Equal(t, http.StatusSwitchingProtocols, status,
		"an allowlisted proxy Host must be accepted")

	// A neighboring name must not be swept in by the same entry.
	status = upgradeWithHost(t, srv, "evil-homeassistant.local:8123", "http://evil-homeassistant.local:8123")
	assert.Equal(t, http.StatusForbidden, status)
}

// TestWebSocket_WildcardOptOutSkipsHostCheck confirms the documented escape
// hatch still disables the whole check, so an operator who needs the old
// behavior has exactly one way to ask for it.
func TestWebSocket_WildcardOptOutSkipsHostCheck(t *testing.T) {
	srv := newOriginTestServer(t, []string{"*"})

	status := upgradeWithHost(t, srv, "evil.example:8080", "http://evil.example:8080")
	assert.Equal(t, http.StatusSwitchingProtocols, status,
		`api.allowed_origins: ["*"] must remain a complete opt-out`)
}
