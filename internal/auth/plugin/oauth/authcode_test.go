// Package oauth provides OAuth/OIDC authentication for Bifrost.
package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateAuthURL tests authorization URL generation.
func TestGenerateAuthURL(t *testing.T) {
	cfg := oauthConfig{
		clientID:     "test-client",
		clientSecret: "test-secret",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
		RedirectURI:  "http://localhost:7090/callback",
		Scopes:       []string{"openid", "profile", "email"},
		UsePKCE:      false,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	authURL, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)
	assert.NotEmpty(t, state)
	assert.True(t, strings.HasPrefix(authURL, "https://example.com/oauth/authorize?"))

	// Parse and verify URL parameters
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	params := parsed.Query()
	assert.Equal(t, "code", params.Get("response_type"))
	assert.Equal(t, "test-client", params.Get("client_id"))
	assert.Equal(t, "http://localhost:7090/callback", params.Get("redirect_uri"))
	assert.Equal(t, state, params.Get("state"))
	assert.Equal(t, "openid profile email", params.Get("scope"))

	// No PKCE parameters without UsePKCE
	assert.Empty(t, params.Get("code_challenge"))
	assert.Empty(t, params.Get("code_challenge_method"))
}

// TestGenerateAuthURLWithPKCE tests authorization URL generation with PKCE.
func TestGenerateAuthURLWithPKCE(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
		UsePKCE:      true,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	authURL, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)
	assert.NotEmpty(t, state)

	// Parse and verify PKCE parameters
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	params := parsed.Query()
	assert.NotEmpty(t, params.Get("code_challenge"))
	assert.Equal(t, "S256", params.Get("code_challenge_method"))
}

// TestExchangeCode tests code exchange.
func TestExchangeCode(t *testing.T) {
	// Create mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "test-code", r.Form.Get("code"))
		assert.Equal(t, "http://localhost:7090/callback", r.Form.Get("redirect_uri"))
		assert.Equal(t, "test-client", r.Form.Get("client_id"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-123",
			"token_type":    "Bearer",
			"refresh_token": "refresh-token-456",
			"expires_in":    3600,
			"scope":         "openid profile",
		})
	}))
	defer tokenServer.Close()

	cfg := oauthConfig{
		clientID:     "test-client",
		clientSecret: "test-secret",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     tokenServer.URL,
		RedirectURI:  "http://localhost:7090/callback",
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Generate auth URL to create pending auth
	_, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	// Exchange code
	tokens, err := flow.ExchangeCode(context.Background(), "test-code", state)
	require.NoError(t, err)
	assert.Equal(t, "access-token-123", tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
	assert.Equal(t, "refresh-token-456", tokens.RefreshToken)
	assert.Equal(t, 3600, tokens.ExpiresIn)
}

// TestExchangeCodeInvalidState tests code exchange with invalid state.
func TestExchangeCodeInvalidState(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Try to exchange with invalid state
	_, err := flow.ExchangeCode(context.Background(), "test-code", "invalid-state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired state")
}

// TestExchangeCodeExpiredState tests code exchange with expired state.
func TestExchangeCodeExpiredState(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Generate auth URL
	_, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	// Manually expire the state
	flow.mu.Lock()
	flow.pendingAuths[state].expiresAt = time.Now().Add(-1 * time.Minute)
	flow.mu.Unlock()

	// Try to exchange
	_, err = flow.ExchangeCode(context.Background(), "test-code", state)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// TestExchangeCodeWithPKCE tests code exchange with PKCE.
func TestExchangeCodeWithPKCE(t *testing.T) {
	var receivedCodeVerifier string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		receivedCodeVerifier = r.Form.Get("code_verifier")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token-pkce",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     tokenServer.URL,
		UsePKCE:      true,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Generate auth URL (creates pending auth with code verifier)
	_, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	// Exchange code
	tokens, err := flow.ExchangeCode(context.Background(), "test-code", state)
	require.NoError(t, err)
	assert.Equal(t, "access-token-pkce", tokens.AccessToken)

	// Verify code verifier was sent
	assert.NotEmpty(t, receivedCodeVerifier)
}

// TestExchangeCodeTokenError tests code exchange with error response.
func TestExchangeCodeTokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "The authorization code has expired",
		})
	}))
	defer tokenServer.Close()

	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     tokenServer.URL,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Generate auth URL
	_, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	// Exchange code
	_, err = flow.ExchangeCode(context.Background(), "test-code", state)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Contains(t, err.Error(), "expired")
}

// TestRefreshTokens tests token refresh.
func TestRefreshTokens(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		assert.Equal(t, "refresh-token-456", r.Form.Get("refresh_token"))
		assert.Equal(t, "test-client", r.Form.Get("client_id"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token",
			"token_type":    "Bearer",
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		})
	}))
	defer tokenServer.Close()

	cfg := oauthConfig{
		clientID:     "test-client",
		clientSecret: "test-secret",
	}

	authCodeCfg := AuthCodeConfig{
		TokenURL: tokenServer.URL,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	tokens, err := flow.RefreshTokens(context.Background(), "refresh-token-456")
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", tokens.AccessToken)
	assert.Equal(t, "new-refresh-token", tokens.RefreshToken)
}

// TestRefreshTokensError tests token refresh error handling.
func TestRefreshTokensError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "Refresh token expired",
		})
	}))
	defer tokenServer.Close()

	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		TokenURL: tokenServer.URL,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	_, err := flow.RefreshTokens(context.Background(), "expired-refresh-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

// TestCallbackHandler tests the OAuth callback handler.
func TestCallbackHandler(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "callback-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     tokenServer.URL,
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Generate auth URL to get state
	_, state, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	// Create callback request
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+state, nil)
	rec := httptest.NewRecorder()

	flow.CallbackHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Authentication Successful")
}

// TestCallbackHandlerError tests callback handler with error from provider.
func TestCallbackHandlerError(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Create callback request with error
	req := httptest.NewRequest("GET", "/callback?error=access_denied&error_description=User+denied+access", nil)
	rec := httptest.NewRecorder()

	flow.CallbackHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "access_denied")
}

// TestCallbackHandlerMissingParams tests callback handler with missing parameters.
func TestCallbackHandlerMissingParams(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Missing code
	req := httptest.NewRequest("GET", "/callback?state=some-state", nil)
	rec := httptest.NewRecorder()
	flow.CallbackHandler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Missing state
	req = httptest.NewRequest("GET", "/callback?code=test-code", nil)
	rec = httptest.NewRecorder()
	flow.CallbackHandler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestGenerateRandomString tests random string generation.
func TestGenerateRandomString(t *testing.T) {
	s1, err := generateRandomString(32)
	require.NoError(t, err)
	assert.Len(t, s1, 32)

	s2, err := generateRandomString(32)
	require.NoError(t, err)
	assert.Len(t, s2, 32)

	// Should be unique
	assert.NotEqual(t, s1, s2)
}

// TestGenerateCodeChallenge tests PKCE code challenge generation.
func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := generateCodeChallenge(verifier)

	// Verify it's base64 URL encoded (no padding, + or /)
	assert.NotContains(t, challenge, "=")
	assert.NotContains(t, challenge, "+")
	assert.NotContains(t, challenge, "/")
	assert.NotEmpty(t, challenge)

	// Same verifier should produce same challenge
	challenge2 := generateCodeChallenge(verifier)
	assert.Equal(t, challenge, challenge2)

	// Different verifier should produce different challenge
	challenge3 := generateCodeChallenge("different-verifier")
	assert.NotEqual(t, challenge, challenge3)
}

// TestMemoryTokenStore tests the in-memory token store.
func TestMemoryTokenStore(t *testing.T) {
	store := NewMemoryTokenStore()
	ctx := context.Background()

	tokens := &TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
	}

	// Store tokens
	err := store.Store(ctx, "user1", tokens)
	require.NoError(t, err)

	// Get tokens
	retrieved, err := store.Get(ctx, "user1")
	require.NoError(t, err)
	assert.Equal(t, "access-token", retrieved.AccessToken)

	// Get non-existent user
	_, err = store.Get(ctx, "user2")
	assert.Error(t, err)

	// Delete tokens
	err = store.Delete(ctx, "user1")
	require.NoError(t, err)

	// Should be gone
	_, err = store.Get(ctx, "user1")
	assert.Error(t, err)
}

// TestMemoryTokenStoreCleanup tests token store cleanup.
func TestMemoryTokenStoreCleanup(t *testing.T) {
	store := NewMemoryTokenStore()
	ctx := context.Background()

	// Store with short expiry
	tokens := &TokenResponse{
		AccessToken: "access-token",
		ExpiresIn:   1, // 1 second
	}

	err := store.Store(ctx, "user1", tokens)
	require.NoError(t, err)

	// Should exist initially
	_, err = store.Get(ctx, "user1")
	require.NoError(t, err)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Cleanup
	store.Cleanup()

	// Should be cleaned up
	store.mu.RLock()
	_, exists := store.tokens["user1"]
	store.mu.RUnlock()
	assert.False(t, exists)
}

// TestDefaultRedirectURI tests default redirect URI.
func TestDefaultRedirectURI(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
		// No RedirectURI specified
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Should use default
	assert.Equal(t, "http://localhost:7090/callback", flow.authCodeCfg.RedirectURI)
}

// TestMultipleAuthURLs tests generating multiple auth URLs.
func TestMultipleAuthURLs(t *testing.T) {
	cfg := oauthConfig{
		clientID: "test-client",
	}

	authCodeCfg := AuthCodeConfig{
		AuthorizeURL: "https://example.com/oauth/authorize",
		TokenURL:     "https://example.com/oauth/token",
	}

	flow := NewAuthCodeFlow(cfg, authCodeCfg)

	// Generate multiple auth URLs
	_, state1, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	_, state2, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	_, state3, err := flow.GenerateAuthURL()
	require.NoError(t, err)

	// All states should be unique
	assert.NotEqual(t, state1, state2)
	assert.NotEqual(t, state2, state3)
	assert.NotEqual(t, state1, state3)

	// All should be pending
	flow.mu.Lock()
	assert.Len(t, flow.pendingAuths, 3)
	flow.mu.Unlock()
}
