package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// newClaimsServer serves a fixed JSON document on both an introspection-style
// POST and a userinfo-style GET.
func newClaimsServer(t *testing.T, doc map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(doc))
	}))
}

func newOAuthAuthenticator(t *testing.T, cfg map[string]any) auth.Authenticator {
	t.Helper()
	a, err := auth.NewFactory().Create(auth.ProviderConfig{
		Name: "oauth", Type: "oauth", Enabled: true, Config: cfg,
	})
	require.NoError(t, err)
	return a
}

// required_claims was parsed and shown in the dashboard but never read: a
// deployment gating on hd=example.com let every active token through. Both
// validation paths must enforce it now.
func TestOAuth_RequiredClaims_EnforcedOnIntrospection(t *testing.T) {
	srv := newClaimsServer(t, map[string]any{
		"active": true, "username": "u", "hd": "evil.example",
	})
	defer srv.Close()

	a := newOAuthAuthenticator(t, map[string]any{
		"client_id":       "id",
		"client_secret":   "s",
		"introspect_url":  srv.URL,
		"required_claims": map[string]any{"hd": "example.com"},
	})

	_, err := a.Authenticate(context.Background(), "bearer", "tok")
	require.Error(t, err, "a mismatched required claim must reject the token")
	assert.NotContains(t, err.Error(), "evil.example", "claim values must never leak into errors")
}

func TestOAuth_RequiredClaims_EnforcedOnUserinfo(t *testing.T) {
	srv := newClaimsServer(t, map[string]any{
		"sub": "u", "email": "u@example.com",
		// hd missing entirely
	})
	defer srv.Close()

	a := newOAuthAuthenticator(t, map[string]any{
		"client_id":       "id",
		"userinfo_url":    srv.URL,
		"required_claims": map[string]any{"hd": "example.com"},
	})

	_, err := a.Authenticate(context.Background(), "bearer", "tok")
	require.Error(t, err, "a missing required claim must reject the token")
	assert.Contains(t, err.Error(), "hd", "the claim NAME may be named")
}

func TestOAuth_RequiredClaims_MatchingTokenPasses(t *testing.T) {
	srv := newClaimsServer(t, map[string]any{
		"active": true, "username": "u", "hd": "example.com",
	})
	defer srv.Close()

	a := newOAuthAuthenticator(t, map[string]any{
		"client_id":       "id",
		"client_secret":   "s",
		"introspect_url":  srv.URL,
		"required_claims": map[string]any{"hd": "example.com"},
	})

	user, err := a.Authenticate(context.Background(), "bearer", "tok")
	require.NoError(t, err)
	assert.Equal(t, "u", user.Username)
}

// A deployment with NO required_claims — including one that set the empty map
// the old default template shipped — is unaffected: enforcement cannot lock
// out configs that never asked for it.
func TestOAuth_RequiredClaims_EmptyIsNoOp(t *testing.T) {
	srv := newClaimsServer(t, map[string]any{"active": true, "username": "u"})
	defer srv.Close()

	for _, cfg := range []map[string]any{
		{"client_id": "id", "client_secret": "s", "introspect_url": srv.URL},
		{"client_id": "id", "client_secret": "s", "introspect_url": srv.URL,
			"required_claims": map[string]any{}},
	} {
		a := newOAuthAuthenticator(t, cfg)
		_, err := a.Authenticate(context.Background(), "bearer", "tok")
		assert.NoError(t, err)
	}
}

// The exact comparison rules: strings exact, bools/numbers by canonical text,
// arrays by string membership, objects never.
func TestCheckRequiredClaims_Semantics(t *testing.T) {
	claims := map[string]any{
		"str":   "value",
		"flag":  true,
		"num":   json.Number("42"),
		"aud":   []any{"api", "dashboard"},
		"objct": map[string]any{"nested": "x"},
	}

	assert.NoError(t, checkRequiredClaims(map[string]string{"str": "value"}, claims))
	assert.Error(t, checkRequiredClaims(map[string]string{"str": "other"}, claims))
	assert.NoError(t, checkRequiredClaims(map[string]string{"flag": "true"}, claims))
	assert.Error(t, checkRequiredClaims(map[string]string{"flag": "false"}, claims))
	assert.NoError(t, checkRequiredClaims(map[string]string{"num": "42"}, claims))
	assert.Error(t, checkRequiredClaims(map[string]string{"num": "43"}, claims))
	assert.NoError(t, checkRequiredClaims(map[string]string{"aud": "api"}, claims))
	assert.Error(t, checkRequiredClaims(map[string]string{"aud": "other"}, claims))
	assert.Error(t, checkRequiredClaims(map[string]string{"objct": "x"}, claims),
		"an object-valued claim can never satisfy a string requirement")
	assert.Error(t, checkRequiredClaims(map[string]string{"missing": "x"}, claims))
}
