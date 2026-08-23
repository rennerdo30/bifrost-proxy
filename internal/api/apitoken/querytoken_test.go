package apitoken

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStripQueryMiddleware_MovesTokenOutOfURL is the regression test for the
// credential leak: both dashboards authenticate their WebSocket / EventSource
// connections with `?token=<api.token>`, and chi's request logger prints
// r.RequestURI verbatim, so the operator's API token was written to the
// process's own log on every such connection.
func TestStripQueryMiddleware_MovesTokenOutOfURL(t *testing.T) {
	const secret = "super-secret-token"

	var (
		seenRawQuery   string
		seenRequestURI string
		seenToken      string
	)
	handler := StripQueryMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenRawQuery = r.URL.RawQuery
		seenRequestURI = r.RequestURI
		seenToken = FromContext(r)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws?token="+secret+"&other=keepme", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// The credential must still reach the auth middleware...
	assert.Equal(t, secret, seenToken, "the token must be recoverable from the context")

	// ...but must be gone from every URL representation a logger might print.
	assert.NotContains(t, seenRawQuery, secret, "RawQuery must not carry the token")
	assert.NotContains(t, seenRequestURI, secret, "RequestURI is what chi's logger prints")
	assert.Contains(t, seenRawQuery, RedactedValue, "a placeholder should record that a token was presented")

	// Unrelated parameters must survive untouched.
	assert.Contains(t, seenRawQuery, "other=keepme")
}

func TestStripQueryMiddleware_NoTokenIsAPassthrough(t *testing.T) {
	var (
		seenURI   string
		seenToken string
		called    bool
	)
	handler := StripQueryMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		seenURI = r.RequestURI
		seenToken = FromContext(r)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?limit=10", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, called)
	assert.Equal(t, "/api/v1/stats?limit=10", seenURI, "a request without a token must be untouched")
	assert.Empty(t, seenToken)
}

func TestFromContext_EmptyWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?token=leak", nil)
	// Without the middleware there is nothing in the context; callers must not
	// silently fall back to reading the URL.
	assert.Empty(t, FromContext(req))
}

func TestStripQueryMiddleware_EmptyTokenParamIsPassthrough(t *testing.T) {
	var seenURI string
	handler := StripQueryMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenURI = r.RequestURI
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws?token=", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "/api/v1/ws?token=", seenURI)
}
