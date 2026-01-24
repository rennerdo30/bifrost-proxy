// Package oauth provides OAuth/OIDC authentication for Bifrost.
// This file implements the OAuth 2.0 Authorization Code flow with PKCE.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// AuthCodeConfig contains configuration for the authorization code flow.
type AuthCodeConfig struct {
	AuthorizeURL string   // OAuth authorization endpoint
	TokenURL     string   // OAuth token endpoint
	RedirectURI  string   // Redirect URI for callback (default: http://localhost:7090/callback)
	Scopes       []string // Scopes to request
	UsePKCE      bool     // Use PKCE (recommended for public clients)
}

// AuthCodeFlow handles OAuth 2.0 Authorization Code flow with optional PKCE.
type AuthCodeFlow struct {
	config       oauthConfig
	authCodeCfg  AuthCodeConfig
	httpClient   *http.Client
	pendingAuths map[string]*pendingAuth // state -> pending auth info
	mu           sync.Mutex
}

type pendingAuth struct {
	codeVerifier string
	expiresAt    time.Time
	resultCh     chan authResult
}

type authResult struct {
	tokens *TokenResponse
	err    error
}

// TokenResponse represents the OAuth token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

// NewAuthCodeFlow creates a new authorization code flow handler.
func NewAuthCodeFlow(config oauthConfig, authCodeCfg AuthCodeConfig) *AuthCodeFlow {
	if authCodeCfg.RedirectURI == "" {
		authCodeCfg.RedirectURI = "http://localhost:7090/callback"
	}

	return &AuthCodeFlow{
		config:       config,
		authCodeCfg:  authCodeCfg,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		pendingAuths: make(map[string]*pendingAuth),
	}
}

// GenerateAuthURL generates an authorization URL for the user to visit.
// Returns the URL and the state parameter used for CSRF protection.
func (f *AuthCodeFlow) GenerateAuthURL() (string, string, error) {
	// Generate state parameter for CSRF protection
	state, err := generateRandomString(32)
	if err != nil {
		return "", "", fmt.Errorf("generate state: %w", err)
	}

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {f.config.clientID},
		"redirect_uri":  {f.authCodeCfg.RedirectURI},
		"state":         {state},
	}

	if len(f.authCodeCfg.Scopes) > 0 {
		params.Set("scope", strings.Join(f.authCodeCfg.Scopes, " "))
	}

	var codeVerifier string
	if f.authCodeCfg.UsePKCE {
		// Generate PKCE code verifier
		codeVerifier, err = generateRandomString(64)
		if err != nil {
			return "", "", fmt.Errorf("generate code verifier: %w", err)
		}

		// Generate code challenge
		codeChallenge := generateCodeChallenge(codeVerifier)
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	// Store pending auth
	f.mu.Lock()
	f.pendingAuths[state] = &pendingAuth{
		codeVerifier: codeVerifier,
		expiresAt:    time.Now().Add(10 * time.Minute),
		resultCh:     make(chan authResult, 1),
	}
	// Cleanup old entries
	now := time.Now()
	for k, v := range f.pendingAuths {
		if now.After(v.expiresAt) {
			close(v.resultCh)
			delete(f.pendingAuths, k)
		}
	}
	f.mu.Unlock()

	authURL := f.authCodeCfg.AuthorizeURL + "?" + params.Encode()
	return authURL, state, nil
}

// ExchangeCode exchanges an authorization code for tokens.
func (f *AuthCodeFlow) ExchangeCode(ctx context.Context, code, state string) (*TokenResponse, error) {
	f.mu.Lock()
	pending, ok := f.pendingAuths[state]
	if !ok {
		f.mu.Unlock()
		return nil, fmt.Errorf("invalid or expired state parameter")
	}
	if time.Now().After(pending.expiresAt) {
		delete(f.pendingAuths, state)
		f.mu.Unlock()
		return nil, fmt.Errorf("state parameter expired")
	}
	codeVerifier := pending.codeVerifier
	delete(f.pendingAuths, state)
	f.mu.Unlock()

	// Prepare token request
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {f.authCodeCfg.RedirectURI},
		"client_id":    {f.config.clientID},
	}

	if f.config.clientSecret != "" {
		data.Set("client_secret", f.config.clientSecret)
	}

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", f.authCodeCfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Some providers want client credentials in Authorization header
	if f.config.clientSecret != "" {
		req.SetBasicAuth(f.config.clientID, f.config.clientSecret)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	// Limit response size to 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("token error: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	return &tokens, nil
}

// RefreshTokens refreshes an access token using a refresh token.
func (f *AuthCodeFlow) RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {f.config.clientID},
	}

	if f.config.clientSecret != "" {
		data.Set("client_secret", f.config.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", f.authCodeCfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if f.config.clientSecret != "" {
		req.SetBasicAuth(f.config.clientID, f.config.clientSecret)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("refresh error: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("refresh request returned status %d", resp.StatusCode)
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	return &tokens, nil
}

// CallbackHandler returns an HTTP handler for the OAuth callback.
func (f *AuthCodeFlow) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for error response from provider
		if errCode := r.URL.Query().Get("error"); errCode != "" {
			errDesc := r.URL.Query().Get("error_description")
			slog.Warn("OAuth callback error", "error", errCode, "description", errDesc)
			http.Error(w, fmt.Sprintf("OAuth error: %s - %s", errCode, errDesc), http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
			return
		}

		// Exchange code for tokens
		tokens, err := f.ExchangeCode(r.Context(), code, state)
		if err != nil {
			slog.Error("OAuth code exchange failed", "error", err)
			http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
			return
		}

		// Send result to waiting channel if any
		f.mu.Lock()
		if pending, ok := f.pendingAuths[state]; ok {
			select {
			case pending.resultCh <- authResult{tokens: tokens}:
			default:
			}
		}
		f.mu.Unlock()

		// Respond with success page
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card { background: white; padding: 2rem 3rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                text-align: center; }
        h1 { color: #10B981; margin-bottom: 0.5rem; }
        p { color: #6B7280; }
    </style>
</head>
<body>
    <div class="card">
        <h1>&#10004; Authentication Successful</h1>
        <p>You can close this window and return to the application.</p>
    </div>
    <script>window.close();</script>
</body>
</html>
`))
	})
}

// StartCallbackServer starts a temporary HTTP server to receive the OAuth callback.
// Returns when the callback is received or the context is cancelled.
func (f *AuthCodeFlow) StartCallbackServer(ctx context.Context, state string) (*TokenResponse, error) {
	// Parse redirect URI to get port
	redirectURL, err := url.Parse(f.authCodeCfg.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URI: %w", err)
	}

	port := redirectURL.Port()
	if port == "" {
		if redirectURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Get the result channel
	f.mu.Lock()
	pending, ok := f.pendingAuths[state]
	if !ok {
		f.mu.Unlock()
		return nil, fmt.Errorf("no pending auth for state")
	}
	resultCh := pending.resultCh
	f.mu.Unlock()

	// Create server
	mux := http.NewServeMux()
	mux.Handle(redirectURL.Path, f.CallbackHandler())

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", port, err)
	}

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	slog.Info("OAuth callback server started", "port", port, "path", redirectURL.Path)

	// Wait for result, error, or context cancellation
	select {
	case result := <-resultCh:
		server.Shutdown(context.Background())
		if result.err != nil {
			return nil, result.err
		}
		return result.tokens, nil
	case err := <-errCh:
		return nil, fmt.Errorf("callback server error: %w", err)
	case <-ctx.Done():
		server.Shutdown(context.Background())
		return nil, ctx.Err()
	}
}

// InteractiveLogin performs an interactive OAuth login.
// It generates an auth URL, starts a callback server, and waits for the user to complete login.
func (f *AuthCodeFlow) InteractiveLogin(ctx context.Context) (*TokenResponse, error) {
	authURL, state, err := f.GenerateAuthURL()
	if err != nil {
		return nil, fmt.Errorf("generate auth URL: %w", err)
	}

	slog.Info("Starting interactive OAuth login",
		"auth_url", authURL,
		"redirect_uri", f.authCodeCfg.RedirectURI)

	// Print URL for user (caller should handle opening browser)
	fmt.Printf("\nPlease open the following URL in your browser to login:\n\n%s\n\n", authURL)

	// Start callback server and wait
	tokens, err := f.StartCallbackServer(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("callback: %w", err)
	}

	return tokens, nil
}

// generateRandomString generates a cryptographically random string.
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}

// generateCodeChallenge generates a PKCE code challenge from a code verifier.
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// AuthCodeAuthenticator wraps an OAuth authenticator with authorization code flow support.
type AuthCodeAuthenticator struct {
	*Authenticator
	authCodeFlow *AuthCodeFlow
	tokenStore   TokenStore
}

// TokenStore interface for storing and retrieving tokens.
type TokenStore interface {
	// Store saves tokens for a user
	Store(ctx context.Context, userID string, tokens *TokenResponse) error
	// Get retrieves tokens for a user
	Get(ctx context.Context, userID string) (*TokenResponse, error)
	// Delete removes tokens for a user
	Delete(ctx context.Context, userID string) error
}

// MemoryTokenStore is an in-memory token store implementation.
type MemoryTokenStore struct {
	tokens map[string]*storedToken
	mu     sync.RWMutex
}

type storedToken struct {
	tokens    *TokenResponse
	expiresAt time.Time
}

// NewMemoryTokenStore creates a new in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]*storedToken),
	}
}

// Store saves tokens for a user.
func (s *MemoryTokenStore) Store(_ context.Context, userID string, tokens *TokenResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	s.tokens[userID] = &storedToken{
		tokens:    tokens,
		expiresAt: expiresAt,
	}
	return nil
}

// Get retrieves tokens for a user.
func (s *MemoryTokenStore) Get(_ context.Context, userID string) (*TokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, ok := s.tokens[userID]
	if !ok {
		return nil, auth.ErrInvalidCredentials
	}

	// Check if expired
	if time.Now().After(stored.expiresAt) {
		return stored.tokens, nil // Return anyway, caller can check refresh token
	}

	return stored.tokens, nil
}

// Delete removes tokens for a user.
func (s *MemoryTokenStore) Delete(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, userID)
	return nil
}

// Cleanup removes expired tokens.
func (s *MemoryTokenStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, v := range s.tokens {
		if now.After(v.expiresAt) {
			delete(s.tokens, k)
		}
	}
}
