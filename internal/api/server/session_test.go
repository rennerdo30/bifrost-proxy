package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth/session"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// newTestSessionManager returns an in-memory session manager suitable for tests.
func newTestSessionManager(t *testing.T) *session.Manager {
	t.Helper()
	mcfg := session.DefaultManagerConfig()
	mcfg.SecureCookies = false
	mgr := session.NewManager(session.NewMemoryStore(0), mcfg)
	t.Cleanup(func() { _ = mgr.Close() }) //nolint:errcheck // test cleanup
	return mgr
}

func TestAPI_SessionManager_DisabledWithoutToken(t *testing.T) {
	api := New(Config{
		Backends:       backend.NewManager(),
		SessionManager: newTestSessionManager(t),
	})
	// Sessions gate nothing when the API is unauthenticated, so the manager must
	// be ignored to avoid advertising a login endpoint that grants free access.
	assert.Nil(t, api.sessionManager)
}

func TestAPI_SessionManager_EnabledWithToken(t *testing.T) {
	api := New(Config{
		Backends:       backend.NewManager(),
		Token:          "secret",
		SessionManager: newTestSessionManager(t),
	})
	assert.NotNil(t, api.sessionManager)
}

func TestAPI_SessionLoginFlow(t *testing.T) {
	api := New(Config{
		Backends:       backend.NewManager(),
		Token:          "secret-token",
		SessionManager: newTestSessionManager(t),
	})
	handler := api.RouterWithWebSocket(nil)

	// Wrong token is rejected (fail closed).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"nope"}`))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Correct token via Bearer header issues a session cookie.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	cookies := w.Result().Cookies() //nolint:bodyclose // httptest recorder has no body to close
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "bifrost_session" && c.Value != "" {
			sessionCookie = c
		}
	}
	require.NotNil(t, sessionCookie, "expected a session cookie to be set")

	// The cookie authenticates subsequent requests without the token.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// No credentials at all is still rejected.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Logout destroys the session so the cookie no longer authenticates.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.AddCookie(sessionCookie)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "destroyed session must no longer authenticate")
}

func TestAPI_SessionLogin_TokenStillWorks(t *testing.T) {
	// Enabling sessions must not weaken the direct-token path.
	api := New(Config{
		Backends:       backend.NewManager(),
		Token:          "secret-token",
		SessionManager: newTestSessionManager(t),
	})
	handler := api.RouterWithWebSocket(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_SessionLogin_ExpiresAtReturned(t *testing.T) {
	api := New(Config{
		Backends:       backend.NewManager(),
		Token:          "secret-token",
		SessionManager: newTestSessionManager(t),
	})
	handler := api.RouterWithWebSocket(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"secret-token"}`))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "authenticated", body["status"])
	assert.NotEmpty(t, body["expires_at"])
}
