package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/api/apitoken"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// authFlowToken is the api.token used by the round-trip tests below.
const authFlowToken = "round-trip-token"

// newAuthFlowServer starts the full server-dashboard handler (REST + WebSocket)
// with api.token configured, mirroring what the binary serves.
func newAuthFlowServer(t *testing.T) (*httptest.Server, *WebSocketHub) {
	t.Helper()

	api := New(Config{
		Backends:       backend.NewManager(),
		Token:          authFlowToken,
		SessionManager: newTestSessionManager(t),
	})

	hub := NewWebSocketHub()
	go hub.Run()
	t.Cleanup(hub.Stop)

	srv := httptest.NewServer(api.RouterWithWebSocket(hub))
	t.Cleanup(srv.Close)
	return srv, hub
}

// TestAuthFlow_RESTAndWebSocketWithAPIToken is the end-to-end check that setting
// the documented api.token no longer bricks the server dashboard.
//
// The audit found that with api.token set the SPA shell loaded (static assets
// are unauthenticated) but every /api/v1/* call and the WebSocket returned 401,
// with no way to supply a token from the UI. This asserts all three credential
// paths the dashboard can actually use from a browser:
//
//   - REST, via the Authorization: Bearer header (fetch can set headers)
//   - WebSocket, via ?token= (a browser cannot set headers on a WS handshake)
//   - WebSocket, via the session cookie obtained from POST /api/v1/login
//
// and that an unauthenticated caller still gets 401 on all of them.
func TestAuthFlow_RESTAndWebSocketWithAPIToken(t *testing.T) {
	srv, _ := newAuthFlowServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + wsTestPath

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Run("REST is refused without a credential", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/api/v1/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("REST succeeds with a Bearer header", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/health", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+authFlowToken)

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("WebSocket is refused without a credential", func(t *testing.T) {
		conn, resp, err := websocket.Dial(ctx, wsURL, nil) //nolint:bodyclose // closed below
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if conn != nil {
			_ = conn.Close(websocket.StatusNormalClosure, "")
		}
		require.Error(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("WebSocket succeeds with the query token", func(t *testing.T) {
		// A browser cannot attach an Authorization header to `new WebSocket(...)`,
		// so this is the path the dashboard uses today.
		conn, resp, err := websocket.Dial(ctx, wsURL+"?token="+authFlowToken, nil) //nolint:bodyclose // closed below
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		require.NoError(t, err, "?token= must authenticate the WS handshake")
		defer func() { _ = conn.Close(websocket.StatusNormalClosure, "") }()

		// Prove the socket actually carries traffic rather than merely upgrading.
		require.NoError(t, conn.Write(ctx, websocket.MessageText, []byte("ping")))
		_, data, err := conn.Read(ctx)
		require.NoError(t, err)
		assert.Equal(t, "pong", string(data))
	})

	t.Run("WebSocket succeeds with a login session cookie", func(t *testing.T) {
		cookie := loginForSessionCookie(ctx, t, srv)

		header := http.Header{}
		header.Set("Cookie", cookie)
		conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: header}) //nolint:bodyclose // closed below
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		require.NoError(t, err, "the session cookie must authenticate the WS handshake")
		defer func() { _ = conn.Close(websocket.StatusNormalClosure, "") }()

		require.NoError(t, conn.Write(ctx, websocket.MessageText, []byte("ping")))
		_, data, err := conn.Read(ctx)
		require.NoError(t, err)
		assert.Equal(t, "pong", string(data))
	})
}

// loginForSessionCookie exchanges the api.token for a session cookie via
// POST /api/v1/login and returns it as a Cookie header value.
func loginForSessionCookie(ctx context.Context, t *testing.T, srv *httptest.Server) string {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/login",
		strings.NewReader(`{"token":"`+authFlowToken+`"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "login with the correct token must succeed")

	cookies := resp.Cookies()
	require.NotEmpty(t, cookies, "login must set a session cookie")
	return cookies[0].Name + "=" + cookies[0].Value
}

// TestAuthFlow_QueryTokenIsNotWrittenToTheRequestLog asserts against the real
// request logger that authenticating with ?token= does not disclose the
// credential.
//
// chi's DefaultLogFormatter prints r.RequestURI verbatim, so before
// apitoken.StripQueryMiddleware was installed, every WebSocket handshake and SSE
// subscription wrote the operator's api.token to the server's own stdout log at
// info level — and to any reverse-proxy access log in front of it.
func TestAuthFlow_QueryTokenIsNotWrittenToTheRequestLog(t *testing.T) {
	var logged bytes.Buffer
	restore := middleware.DefaultLogger
	middleware.DefaultLogger = middleware.RequestLogger(&middleware.DefaultLogFormatter{
		Logger:  log.New(&logged, "", 0),
		NoColor: true,
	})
	t.Cleanup(func() { middleware.DefaultLogger = restore })

	api := New(Config{
		Backends: backend.NewManager(),
		Token:    authFlowToken,
	})
	handler := api.RouterWithWebSocket(nil)

	// /api/v1/health sits inside the auth group, so a 200 proves the stripped
	// token still authenticated the request.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health?token="+authFlowToken, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "?token= must still authenticate REST calls")

	logLine := logged.String()
	require.NotEmpty(t, logLine, "the request logger should have produced output")
	assert.NotContains(t, logLine, authFlowToken, "the api.token must never be written to the request log")
	assert.Contains(t, logLine, apitoken.RedactedValue, "the log should show a credential was presented")
}

// TestAuthFlow_CrossOriginWebSocketRejectedEvenWhenAuthenticated makes explicit
// that the origin check and the token check are independent gates. A page on
// another origin that has somehow obtained the token (or an operator's browser
// replaying a cookie) must still be refused the upgrade.
func TestAuthFlow_CrossOriginWebSocketRejectedEvenWhenAuthenticated(t *testing.T) {
	srv, _ := newAuthFlowServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + wsTestPath

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	header := http.Header{}
	header.Set("Origin", "https://evil.example.com")
	conn, resp, err := websocket.Dial(ctx, wsURL+"?token="+authFlowToken, //nolint:bodyclose // closed below
		&websocket.DialOptions{HTTPHeader: header})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if conn != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}

	require.Error(t, err, "a valid token must not buy a cross-origin upgrade")
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
