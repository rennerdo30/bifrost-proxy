// Package oauth provides OAuth/OIDC authentication for Bifrost.
package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("oauth", &plugin{})
}

// plugin implements the auth.Plugin interface for OAuth authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "oauth"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "OAuth/OIDC authentication with token introspection"
}

// Create creates a new OAuthAuthenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	// If issuer URL provided, try to discover endpoints
	if cfg.issuerURL != "" && cfg.introspectURL == "" {
		introspect, userinfo, err := discoverOIDCEndpoints(cfg.issuerURL)
		if err == nil {
			if cfg.introspectURL == "" {
				cfg.introspectURL = introspect
			}
			if cfg.userInfoURL == "" {
				cfg.userInfoURL = userinfo
			}
		}
	}

	// Fallback to userinfo endpoint if no introspection
	if cfg.introspectURL == "" && cfg.userInfoURL == "" {
		return nil, fmt.Errorf("either introspect_url or userinfo_url is required")
	}

	return &Authenticator{
		config: *cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		tokenCache:  make(map[string]*cachedToken),
		cacheMaxAge: 5 * time.Minute,
	}, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	cfg, err := parseConfig(config)
	if err != nil {
		return err
	}

	// Check if we can get endpoints
	if cfg.introspectURL == "" && cfg.userInfoURL == "" && cfg.issuerURL == "" {
		return fmt.Errorf("either introspect_url, userinfo_url, or issuer_url is required")
	}

	return nil
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"provider":        "generic",
		"client_id":       "",
		"client_secret":   "",
		"issuer_url":      "",
		"introspect_url":  "",
		"userinfo_url":    "",
		"scopes":          []string{},
		"required_claims": map[string]string{},
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "provider": {
      "type": "string",
      "description": "Provider name (generic, google, github, etc.)"
    },
    "client_id": {
      "type": "string",
      "description": "OAuth client ID"
    },
    "client_secret": {
      "type": "string",
      "description": "OAuth client secret"
    },
    "issuer_url": {
      "type": "string",
      "description": "OIDC issuer URL (for automatic endpoint discovery)"
    },
    "introspect_url": {
      "type": "string",
      "description": "Token introspection endpoint URL"
    },
    "userinfo_url": {
      "type": "string",
      "description": "User info endpoint URL"
    },
    "scopes": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Required scopes"
    },
    "required_claims": {
      "type": "object",
      "additionalProperties": {"type": "string"},
      "description": "Required claims in token"
    }
  },
  "required": ["client_id"]
}`
}

type oauthConfig struct {
	provider       string
	clientID       string
	clientSecret   string
	issuerURL      string
	introspectURL  string
	userInfoURL    string
	scopes         []string
	requiredClaims map[string]string
}

func parseConfig(config map[string]any) (*oauthConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("oauth config is required")
	}

	cfg := &oauthConfig{
		provider: "generic",
	}

	clientID, _ := config["client_id"].(string) //nolint:errcheck // Type assertion - empty string is valid if missing
	if clientID == "" {
		return nil, fmt.Errorf("OAuth client_id is required")
	}
	cfg.clientID = clientID

	if clientSecret, ok := config["client_secret"].(string); ok {
		cfg.clientSecret = clientSecret
	}
	if provider, ok := config["provider"].(string); ok && provider != "" {
		cfg.provider = provider
	}
	if issuerURL, ok := config["issuer_url"].(string); ok {
		cfg.issuerURL = issuerURL
	}
	if introspectURL, ok := config["introspect_url"].(string); ok {
		cfg.introspectURL = introspectURL
	}
	if userInfoURL, ok := config["userinfo_url"].(string); ok {
		cfg.userInfoURL = userInfoURL
	}

	// Parse scopes
	if scopesAny, ok := config["scopes"]; ok {
		cfg.scopes = parseStringSlice(scopesAny)
	}

	// Parse required claims
	if claimsAny, ok := config["required_claims"]; ok {
		if claims, ok := claimsAny.(map[string]any); ok {
			cfg.requiredClaims = make(map[string]string)
			for k, v := range claims {
				if vs, ok := v.(string); ok {
					cfg.requiredClaims[k] = vs
				}
			}
		} else if claims, ok := claimsAny.(map[string]string); ok {
			cfg.requiredClaims = claims
		}
	}

	return cfg, nil
}

func parseStringSlice(v any) []string {
	var result []string
	switch s := v.(type) {
	case []any:
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	case []string:
		result = s
	}
	return result
}

// checkRequiredClaims enforces the configured required_claims against the raw
// claims of a validated token. The setting was parsed, surfaced in the
// dashboard, and never read — a deployment gating access on, say,
// hd=example.com was letting every token through. Semantics, exact and
// deterministic:
//
//   - a missing claim fails
//   - a string claim must equal the expected value exactly
//   - a boolean or numeric claim must equal the expected value's canonical
//     text form ("true", "42")
//   - an array claim (aud-style) matches iff the expected value is one of its
//     string elements
//   - an object-valued claim never matches — there is no sensible string
//     comparison for it
//
// Claim VALUES are never logged or included in errors: tokens can carry
// personal data, and an error message travels further than a token does.
func checkRequiredClaims(required map[string]string, claims map[string]any) error {
	for name, expected := range required {
		value, present := claims[name]
		if !present {
			return fmt.Errorf("token is missing required claim %q", name)
		}
		if !claimMatches(value, expected) {
			return fmt.Errorf("token claim %q does not have the required value", name)
		}
	}
	return nil
}

// claimMatches implements the comparison rules documented on
// checkRequiredClaims.
func claimMatches(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return v == expected
	case bool:
		return strconv.FormatBool(v) == expected
	case json.Number:
		return v.String() == expected
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64) == expected
	case []any:
		for _, elem := range v {
			if s, ok := elem.(string); ok && s == expected {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// enforceRequiredClaims applies required_claims to a raw validation-endpoint
// response body. Numbers decode via json.Number so their text form is stable.
func (a *Authenticator) enforceRequiredClaims(body []byte) error {
	if len(a.config.requiredClaims) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}
	return checkRequiredClaims(a.config.requiredClaims, claims)
}

type cachedToken struct {
	user      *auth.UserInfo
	expiresAt time.Time
}

// hashToken creates a SHA-256 hash of the token for secure cache key storage.
// This prevents tokens from being exposed if memory is dumped.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Authenticator implements OAuth/OIDC authentication.
type Authenticator struct {
	config      oauthConfig
	httpClient  *http.Client
	tokenCache  map[string]*cachedToken
	cacheMu     sync.RWMutex
	cacheMaxAge time.Duration
}

// Authenticate validates an OAuth token.
// For proxy auth, the "password" field contains the Bearer token.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	// The token can be passed as password (for Basic auth compatibility)
	// or the username can be "bearer" and password is the token
	token := password
	if strings.ToLower(username) == "bearer" || username == "" {
		token = password
	} else if password == "" {
		token = username
	}

	if token == "" {
		return nil, auth.ErrInvalidCredentials
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
	var user *auth.UserInfo
	var err error

	if a.config.introspectURL != "" {
		user, err = a.introspectToken(ctx, token)
	} else if a.config.userInfoURL != "" {
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
	cacheLen := len(a.tokenCache)
	a.cacheMu.Unlock()

	// Cleanup old entries in a separate operation to minimize lock hold time
	if cacheLen > 1000 {
		a.cleanupExpiredTokens()
	}

	return user, nil
}

// cleanupExpiredTokens removes expired entries from the token cache.
func (a *Authenticator) cleanupExpiredTokens() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	now := time.Now()
	for k, v := range a.tokenCache {
		if now.After(v.expiresAt) {
			delete(a.tokenCache, k)
		}
	}
}

// introspectToken validates a token using the introspection endpoint.
func (a *Authenticator) introspectToken(ctx context.Context, token string) (*auth.UserInfo, error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create introspect request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.config.clientID, a.config.clientSecret)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspect request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspect returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read introspect response: %w", err)
	}

	var result struct {
		Active   bool   `json:"active"`
		Username string `json:"username"`
		Sub      string `json:"sub"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode introspect response: %w", err)
	}

	if !result.Active {
		return nil, auth.ErrInvalidCredentials
	}

	if err := a.enforceRequiredClaims(body); err != nil {
		return nil, err
	}

	// Check required scopes
	if len(a.config.scopes) > 0 {
		tokenScopes := strings.Split(result.Scope, " ")
		scopeSet := make(map[string]bool)
		for _, s := range tokenScopes {
			scopeSet[s] = true
		}
		for _, required := range a.config.scopes {
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

	return &auth.UserInfo{
		Username: username,
		Email:    result.Email,
		FullName: result.Name,
	}, nil
}

// getUserInfo validates a token by calling the userinfo endpoint.
func (a *Authenticator) getUserInfo(ctx context.Context, token string) (*auth.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.config.userInfoURL, nil)
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
		return nil, auth.ErrInvalidCredentials
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read userinfo response: %w", err)
	}

	var result struct {
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}

	if err := a.enforceRequiredClaims(body); err != nil {
		return nil, err
	}

	username := result.PreferredUsername
	if username == "" {
		username = result.Sub
	}
	if username == "" {
		username = result.Email
	}

	return &auth.UserInfo{
		Username: username,
		Email:    result.Email,
		FullName: result.Name,
		Groups:   result.Groups,
	}, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	if a.config.provider != "" && a.config.provider != "generic" {
		return "oauth-" + a.config.provider
	}
	return "oauth"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "oauth"
}

// discoverOIDCEndpoints attempts to discover OIDC endpoints from the issuer.
func discoverOIDCEndpoints(issuerURL string) (introspect, userinfo string, err error) {
	wellKnownURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("create OIDC discovery request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
