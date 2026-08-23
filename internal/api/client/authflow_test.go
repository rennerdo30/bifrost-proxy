package client

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/api/apitoken"
)

// authFlowToken is the api.token used by the client-dashboard round-trip tests.
const authFlowToken = "client-round-trip-token"

// sseReadTimeout bounds how long the SSE assertions wait for the stream's
// opening frame.
const sseReadTimeout = 10 * time.Second

// TestAuthFlow_ClientRESTAndSSEWithAPIToken is the end-to-end check that setting
// api.token no longer bricks the client dashboard.
//
// The audit rated this "high": the client UI advertises an API Token field, the
// daemon enforces it with a constant-time compare, but the dashboard sent no
// credential at all — so every REST call and the EventSource subscription to
// /api/v1/logs/stream returned 401 with no way to recover from the UI.
//
// This exercises both transports the dashboard actually uses from a browser:
// REST via the Authorization header, and SSE via ?token= (EventSource cannot set
// request headers).
func TestAuthFlow_ClientRESTAndSSEWithAPIToken(t *testing.T) {
	api := New(Config{Token: authFlowToken})
	srv := httptest.NewServer(api.HandlerWithUI())
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), sseReadTimeout)
	defer cancel()

	t.Run("REST is refused without a credential", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/api/v1/version")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("REST succeeds with a Bearer header", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/version", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+authFlowToken)

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("SSE log stream is refused without a credential", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/api/v1/logs/stream")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("SSE log stream succeeds with the query token", func(t *testing.T) {
		streamCtx, streamCancel := context.WithTimeout(ctx, sseReadTimeout)
		defer streamCancel()

		req, err := http.NewRequestWithContext(streamCtx, http.MethodGet,
			srv.URL+"/api/v1/logs/stream?token="+authFlowToken, nil)
		require.NoError(t, err)

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode, "?token= must authenticate the SSE stream")
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

		// The handler emits a {"type":"connected"} frame immediately, which proves
		// the stream is live rather than merely returning 200 headers.
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, line, "connected")
	})
}

// TestAuthFlow_ClientQueryTokenIsNotWrittenToTheRequestLog is the client-side
// half of the credential-leak fix. The dashboard's log stream is a long-lived
// EventSource authenticated with ?token=, and chi's formatter prints
// r.RequestURI verbatim, so the token was logged on every reconnect.
func TestAuthFlow_ClientQueryTokenIsNotWrittenToTheRequestLog(t *testing.T) {
	var logged bytes.Buffer
	restore := middleware.DefaultLogger
	middleware.DefaultLogger = middleware.RequestLogger(&middleware.DefaultLogFormatter{
		Logger:  log.New(&logged, "", 0),
		NoColor: true,
	})
	t.Cleanup(func() { middleware.DefaultLogger = restore })

	api := New(Config{Token: authFlowToken})
	handler := api.HandlerWithUI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version?token="+authFlowToken, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "?token= must still authenticate REST calls")

	logLine := logged.String()
	require.NotEmpty(t, logLine)
	assert.NotContains(t, logLine, authFlowToken, "the api.token must never be written to the request log")
	assert.Contains(t, logLine, apitoken.RedactedValue)
}
