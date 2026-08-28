package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// These pin the contract the server dashboard depends on now that it exchanges
// the API token for an HttpOnly session cookie instead of keeping the token in
// localStorage.
//
// The server half of this flow was built and config-gated but no client ever
// used it; the dashboard kept a long-lived bearer token where any injected
// script could read it. If any of these break, the dashboard silently falls
// back to storing the token — or stops authenticating at all.

// The dashboard sends the token as a JSON body, not an Authorization header,
// because at sign-in time it has no stored credential to put in a header.
func TestDashboardSession_LoginAcceptsJSONBodyAndSetsCookie(t *testing.T) {
	srv := newAuthFlowServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cookie := loginForSessionCookie(ctx, t, srv)
	require.NotEmpty(t, cookie)

	// The cookie must authenticate a plain REST call, with no Authorization
	// header anywhere — that is the whole point of not storing the token.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/status", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", cookie)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"the session cookie alone must authenticate a REST request")
	assert.Empty(t, req.Header.Get("Authorization"),
		"guard: this case must not be passing via a bearer token")
}

// A wrong token must not mint a session, or the exchange would be a bypass
// rather than a credential swap.
func TestDashboardSession_LoginRejectsWrongToken(t *testing.T) {
	srv := newAuthFlowServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/login",
		strings.NewReader(`{"token":"not-the-token"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Cookies(), "a rejected login must not set a session cookie")
}

// Without a session store the endpoint answers 503, which is the dashboard's
// signal to fall back to storing the bearer token. If this ever became a 404 or
// a 500 the fallback would not trigger and sign-in would appear broken.
func TestDashboardSession_LoginUnavailableWithoutSessionStore(t *testing.T) {
	api := New(Config{
		Backends: backend.NewManager(),
		Token:    authFlowToken,
		// No SessionManager: mirrors a server with no `session:` block.
	})
	// NewWebSocketHub was a thin wrapper removed as dead code in #312; this is
	// the surviving constructor, and MaxWebSocketClients is the default it passed.
	hub := NewWebSocketHubWithMaxClients(MaxWebSocketClients)
	go hub.Run()
	t.Cleanup(hub.Stop)
	srv := httptest.NewServer(api.RouterWithWebSocket(hub))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/login",
		strings.NewReader(`{"token":"`+authFlowToken+`"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"the dashboard keys its bearer-token fallback on exactly 503")
}

// Signing out must actually invalidate the session server-side, not merely
// clear browser state — otherwise the cookie stays usable if it leaked.
func TestDashboardSession_LogoutInvalidatesTheCookie(t *testing.T) {
	srv := newAuthFlowServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cookie := loginForSessionCookie(ctx, t, srv)

	logoutReq, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/logout", nil)
	require.NoError(t, err)
	logoutReq.Header.Set("Cookie", cookie)
	logoutReq.Header.Set("X-Requested-With", "XMLHttpRequest")

	logoutResp, err := srv.Client().Do(logoutReq)
	require.NoError(t, err)
	_ = logoutResp.Body.Close()
	require.Less(t, logoutResp.StatusCode, http.StatusInternalServerError,
		"logout must not error")

	// The same cookie must no longer authenticate.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/status", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", cookie)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"the session must be destroyed server-side, so the old cookie is dead")
}
