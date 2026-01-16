// Package auth provides OAuth/OIDC authentication for Bifrost.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthConfig holds OAuth authenticator configuration.
type OAuthConfig struct {
	Provider       string   // Provider name (generic, google, github, etc.)
	ClientID       string   // OAuth client ID
	ClientSecret   string   // OAuth client secret
	IssuerURL      string   // OIDC issuer URL
	IntrospectURL  string   // Token introspection endpoint (if not using OIDC discovery)
	UserInfoURL    string   // User info endpoint (if not using OIDC discovery)
	Scopes         []string // Required scopes
	RequiredClaims map[string]string // Required claims in token
}

// OAuthAuthenticator implements OAuth/OIDC authentication.
type OAuthAuthenticator struct {
	config       OAuthConfig
	httpClient   *http.Client
	tokenCache   map[string]*cachedToken
	cacheMu      sync.RWMutex
	cacheMaxAge  time.Duration
}

type cachedToken struct {
	user      *UserInfo
	expiresAt time.Time
}

// hashToken creates a SHA-256 hash of the token for secure cache key storage.
// This prevents tokens from being exposed if memory is dumped.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// NewOAuthAuthenticator creates a new OAuth authenticator.
func NewOAuthAuthenticator(cfg OAuthConfig) (*OAuthAuthenticator, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("OAuth client_id is required")
	}

	// If issuer URL provided, try to discover endpoints
	if cfg.IssuerURL != "" && cfg.IntrospectURL == "" {
		introspect, userinfo, err := discoverOIDCEndpoints(cfg.IssuerURL)
		if err == nil {
			if cfg.IntrospectURL == "" {
				cfg.IntrospectURL = introspect
			}
			if cfg.UserInfoURL == "" {
				cfg.UserInfoURL = userinfo
			}
		}
	}

	// Fallback to userinfo endpoint if no introspection
	if cfg.IntrospectURL == "" && cfg.UserInfoURL == "" {
		return nil, fmt.Errorf("either introspect_url or userinfo_url is required")
	}

	return &OAuthAuthenticator{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		tokenCache:  make(map[string]*cachedToken),
		cacheMaxAge: 5 * time.Minute,
	}, nil
}

// Authenticate validates an OAuth token.
// For proxy auth, the "password" field contains the Bearer token.
func (a *OAuthAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	// The token can be passed as password (for Basic auth compatibility)
	// or the username can be "bearer" and password is the token
	token := password
	if strings.ToLower(username) == "bearer" || username == "" {
		token = password
	} else if password == "" {
		token = username
	}

	if token == "" {
		return nil, ErrInvalidCredentials
	}

	// Hash token for secure cache storage - prevents token exposure in memory dumps
	tokenHash := hashToken(token)

	// Check cache using hashed token
	a.cacheMu.RLock()
	if cached, ok := a.tokenCache[tokenHash]; ok && time.Now().Before(cached.expiresAt) {
		a.cacheMu.RUnlock()
		return cached.user, nil
	}
	a.cacheMu.RUnlock()

	// Validate token
	var user *UserInfo
	var err error

	if a.config.IntrospectURL != "" {
		user, err = a.introspectToken(ctx, token)
	} else if a.config.UserInfoURL != "" {
		user, err = a.getUserInfo(ctx, token)
	} else {
		return nil, fmt.Errorf("no validation endpoint configured")
	}

	if err != nil {
		return nil, err
	}

	// Cache the result using hashed token
	a.cacheMu.Lock()
	a.tokenCache[tokenHash] = &cachedToken{
		user:      user,
		expiresAt: time.Now().Add(a.cacheMaxAge),
	}
	// Cleanup old entries periodically
	if len(a.tokenCache) > 1000 {
		now := time.Now()
		for k, v := range a.tokenCache {
			if now.After(v.expiresAt) {
				delete(a.tokenCache, k)
			}
		}
	}
	a.cacheMu.Unlock()

	return user, nil
}

// introspectToken validates a token using the introspection endpoint.
func (a *OAuthAuthenticator) introspectToken(ctx context.Context, token string) (*UserInfo, error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.IntrospectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create introspect request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.config.ClientID, a.config.ClientSecret)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspect request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspect returned status %d", resp.StatusCode)
	}

	var result struct {
		Active   bool   `json:"active"`
		Username string `json:"username"`
		Sub      string `json:"sub"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Scope    string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode introspect response: %w", err)
	}

	if !result.Active {
		return nil, ErrInvalidCredentials
	}

	// Check required scopes
	if len(a.config.Scopes) > 0 {
		tokenScopes := strings.Split(result.Scope, " ")
		scopeSet := make(map[string]bool)
		for _, s := range tokenScopes {
			scopeSet[s] = true
		}
		for _, required := range a.config.Scopes {
			if !scopeSet[required] {
				return nil, fmt.Errorf("missing required scope: %s", required)
			}
		}
	}

	username := result.Username
	if username == "" {
		username = result.Sub
	}
	if username == "" {
		username = result.Email
	}

	return &UserInfo{
		Username: username,
		Email:    result.Email,
		FullName: result.Name,
	}, nil
}

// getUserInfo validates a token by calling the userinfo endpoint.
func (a *OAuthAuthenticator) getUserInfo(ctx context.Context, token string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrInvalidCredentials
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	var result struct {
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}

	username := result.PreferredUsername
	if username == "" {
		username = result.Sub
	}
	if username == "" {
		username = result.Email
	}

	return &UserInfo{
		Username: username,
		Email:    result.Email,
		FullName: result.Name,
		Groups:   result.Groups,
	}, nil
}

// Name returns the authenticator name.
func (a *OAuthAuthenticator) Name() string {
	if a.config.Provider != "" {
		return "oauth-" + a.config.Provider
	}
	return "oauth"
}

// Type returns the authenticator type.
func (a *OAuthAuthenticator) Type() string {
	return "oauth"
}

// discoverOIDCEndpoints attempts to discover OIDC endpoints from the issuer.
func discoverOIDCEndpoints(issuerURL string) (introspect, userinfo string, err error) {
	wellKnownURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	// Limit body read to 1MB to prevent memory exhaustion from malicious servers
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("read OIDC discovery: %w", err)
	}

	var config struct {
		IntrospectionEndpoint string `json:"introspection_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
	}

	if err := json.Unmarshal(body, &config); err != nil {
		return "", "", fmt.Errorf("parse OIDC discovery: %w", err)
	}

	return config.IntrospectionEndpoint, config.UserinfoEndpoint, nil
}
