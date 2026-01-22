// Package apikey provides API key authentication for Bifrost.
// It supports both header-based (X-API-Key) and bearer token authentication.
package apikey

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("apikey", &plugin{})
}

// plugin implements the auth.Plugin interface for API key authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "apikey"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "API key/token authentication with support for hashed keys and expiration"
}

// Create creates a new API key authenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		headerName: cfg.HeaderName,
		keys:       make(map[string]*APIKey),
	}

	for _, k := range cfg.Keys {
		authenticator.keys[k.Name] = k
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"header_name": "X-API-Key",
		"keys": []map[string]any{
			{
				"name":     "example-key",
				"key_hash": "$2a$12$...",
				"groups":   []string{"api-users"},
			},
		},
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "header_name": {
      "type": "string",
      "description": "HTTP header name for API key (default: X-API-Key)",
      "default": "X-API-Key"
    },
    "keys": {
      "type": "array",
      "description": "List of API key configurations",
      "items": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string",
            "description": "Unique identifier for this key"
          },
          "key_hash": {
            "type": "string",
            "description": "bcrypt hash of the API key"
          },
          "key_plain": {
            "type": "string",
            "description": "Plain text API key (use key_hash in production)"
          },
          "groups": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Groups associated with this key"
          },
          "expires_at": {
            "type": "string",
            "format": "date-time",
            "description": "Expiration date (RFC3339 format)"
          },
          "disabled": {
            "type": "boolean",
            "description": "Whether this key is disabled"
          }
        },
        "required": ["name"],
        "oneOf": [
          {"required": ["key_hash"]},
          {"required": ["key_plain"]}
        ]
      }
    }
  },
  "required": ["keys"]
}`
}

// apiKeyConfig represents the parsed configuration.
type apiKeyConfig struct {
	HeaderName string
	Keys       []*APIKey
}

// APIKey represents a single API key.
type APIKey struct {
	Name      string
	KeyHash   string
	KeyPlain  string // For comparison when plain key is used
	Groups    []string
	ExpiresAt *time.Time
	Disabled  bool
}

// parseConfig parses the configuration map.
func parseConfig(config map[string]any) (*apiKeyConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("apikey auth config is required")
	}

	cfg := &apiKeyConfig{
		HeaderName: "X-API-Key",
	}

	if headerName, ok := config["header_name"].(string); ok && headerName != "" {
		cfg.HeaderName = headerName
	}

	keysAny, ok := config["keys"]
	if !ok {
		return nil, fmt.Errorf("apikey auth config: 'keys' field is required")
	}

	keysSlice, err := toSliceOfMaps(keysAny)
	if err != nil {
		return nil, fmt.Errorf("apikey auth config: 'keys' must be an array: %w", err)
	}

	for i, k := range keysSlice {
		apiKey, err := parseAPIKey(k)
		if err != nil {
			return nil, fmt.Errorf("apikey auth config: key at index %d: %w", i, err)
		}
		cfg.Keys = append(cfg.Keys, apiKey)
	}

	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("apikey auth config: at least one key is required")
	}

	return cfg, nil
}

// parseAPIKey parses a single API key configuration.
func parseAPIKey(m map[string]any) (*APIKey, error) {
	name, _ := m["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("'name' is required")
	}

	keyHash, _ := m["key_hash"].(string)
	keyPlain, _ := m["key_plain"].(string)

	if keyHash == "" && keyPlain == "" {
		return nil, fmt.Errorf("key %q: either 'key_hash' or 'key_plain' is required", name)
	}

	key := &APIKey{
		Name:     name,
		KeyHash:  keyHash,
		KeyPlain: keyPlain,
	}

	// Parse groups
	if groupsAny, ok := m["groups"]; ok {
		key.Groups = toStringSlice(groupsAny)
	}

	// Parse expiration
	if expiresAtStr, ok := m["expires_at"].(string); ok && expiresAtStr != "" {
		t, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return nil, fmt.Errorf("key %q: invalid expires_at format: %w", name, err)
		}
		key.ExpiresAt = &t
	}

	// Parse disabled
	if disabled, ok := m["disabled"].(bool); ok {
		key.Disabled = disabled
	}

	return key, nil
}

// toSliceOfMaps converts an any to []map[string]any.
func toSliceOfMaps(v any) ([]map[string]any, error) {
	if v == nil {
		return nil, nil
	}

	// Try direct conversion
	if ms, ok := v.([]map[string]any); ok {
		return ms, nil
	}

	// Try []any conversion
	slice, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array")
	}

	result := make([]map[string]any, 0, len(slice))
	for _, item := range slice {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected object in array")
		}
		result = append(result, m)
	}

	return result, nil
}

// toStringSlice converts an any to []string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}

	if ss, ok := v.([]string); ok {
		return ss
	}

	if slice, ok := v.([]any); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// Authenticator provides API key authentication.
type Authenticator struct {
	headerName string
	keys       map[string]*APIKey
	mu         sync.RWMutex
}

// Authenticate validates an API key.
// The username parameter is expected to contain the API key name or the key itself,
// and the password parameter contains the actual key value.
// For header-based auth, username will be empty and password contains the key.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// If username is provided, look up key by name
	if username != "" {
		key, exists := a.keys[username]
		if !exists {
			return nil, auth.NewAuthError("apikey", "authenticate", auth.ErrInvalidCredentials)
		}
		return a.validateKey(key, password)
	}

	// Otherwise, try to match against all keys
	for _, key := range a.keys {
		userInfo, err := a.validateKey(key, password)
		if err == nil {
			return userInfo, nil
		}
	}

	return nil, auth.NewAuthError("apikey", "authenticate", auth.ErrInvalidCredentials)
}

// validateKey validates a password against a specific key.
func (a *Authenticator) validateKey(key *APIKey, password string) (*auth.UserInfo, error) {
	if key.Disabled {
		return nil, auth.NewAuthError("apikey", "authenticate", auth.ErrUserDisabled)
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, auth.NewAuthError("apikey", "authenticate", auth.ErrInvalidCredentials)
	}

	// Validate the key
	var valid bool
	if key.KeyHash != "" {
		// Compare using bcrypt
		err := bcrypt.CompareHashAndPassword([]byte(key.KeyHash), []byte(password))
		valid = err == nil
	} else if key.KeyPlain != "" {
		// Constant-time comparison for plain keys
		valid = subtle.ConstantTimeCompare([]byte(key.KeyPlain), []byte(password)) == 1
	}

	if !valid {
		return nil, auth.NewAuthError("apikey", "authenticate", auth.ErrInvalidCredentials)
	}

	return &auth.UserInfo{
		Username: key.Name,
		Groups:   key.Groups,
		Metadata: map[string]string{
			"auth_type": "apikey",
		},
	}, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "apikey"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "apikey"
}

// HeaderName returns the header name used for API key extraction.
func (a *Authenticator) HeaderName() string {
	return a.headerName
}

// AddKey adds a new API key dynamically.
func (a *Authenticator) AddKey(key *APIKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keys[key.Name] = key
}

// RemoveKey removes an API key.
func (a *Authenticator) RemoveKey(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.keys, name)
}

// DisableKey disables an API key.
func (a *Authenticator) DisableKey(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if key, exists := a.keys[name]; exists {
		key.Disabled = true
		return true
	}
	return false
}

// EnableKey enables an API key.
func (a *Authenticator) EnableKey(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if key, exists := a.keys[name]; exists {
		key.Disabled = false
		return true
	}
	return false
}
