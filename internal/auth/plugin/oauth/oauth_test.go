// Package oauth provides OAuth/OIDC authentication for Bifrost.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginType tests the plugin Type method.
func TestPluginType(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "oauth", p.Type())
}

// TestPluginDescription tests the plugin Description method.
func TestPluginDescription(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "OAuth/OIDC authentication with token introspection", p.Description())
}

// TestPluginDefaultConfig tests the plugin DefaultConfig method.
func TestPluginDefaultConfig(t *testing.T) {
	p := &plugin{}
	cfg := p.DefaultConfig()

	assert.Equal(t, "generic", cfg["provider"])
	assert.Equal(t, "", cfg["client_id"])
	assert.Equal(t, "", cfg["client_secret"])
	assert.Equal(t, "", cfg["issuer_url"])
	assert.Equal(t, "", cfg["introspect_url"])
	assert.Equal(t, "", cfg["userinfo_url"])
	assert.IsType(t, []string{}, cfg["scopes"])
	assert.IsType(t, map[string]string{}, cfg["required_claims"])
}

// TestPluginConfigSchema tests the plugin ConfigSchema method.
func TestPluginConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	assert.Contains(t, schema, "$schema")
	assert.Contains(t, schema, "client_id")
	assert.Contains(t, schema, "client_secret")
	assert.Contains(t, schema, "issuer_url")
	assert.Contains(t, schema, "introspect_url")
	assert.Contains(t, schema, "userinfo_url")
	assert.Contains(t, schema, "scopes")
	assert.Contains(t, schema, "required_claims")

	// Verify it's valid JSON
	var js map[string]any
	err := json.Unmarshal([]byte(schema), &js)
	assert.NoError(t, err)
}

// TestPluginValidateConfig tests the plugin ValidateConfig method.
func TestPluginValidateConfig(t *testing.T) {
	p := &plugin{}

	tests := []struct {
		name      string
		config    map[string]any
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
			errMsg:    "oauth config is required",
		},
		{
			name:      "empty config",
			config:    map[string]any{},
			wantError: true,
			errMsg:    "client_id is required",
		},
		{
			name: "missing client_id",
			config: map[string]any{
				"userinfo_url": "https://example.com/userinfo",
			},
			wantError: true,
			errMsg:    "client_id is required",
		},
		{
			name: "missing endpoints",
			config: map[string]any{
				"client_id": "test-client",
			},
			wantError: true,
			errMsg:    "either introspect_url, userinfo_url, or issuer_url is required",
		},
		{
			name: "valid with userinfo_url",
			config: map[string]any{
				"client_id":    "test-client",
				"userinfo_url": "https://example.com/userinfo",
			},
			wantError: false,
		},
		{
			name: "valid with introspect_url",
			config: map[string]any{
				"client_id":      "test-client",
				"introspect_url": "https://example.com/introspect",
			},
			wantError: false,
		},
		{
			name: "valid with issuer_url",
			config: map[string]any{
				"client_id":  "test-client",
				"issuer_url": "https://example.com",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.config)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPluginCreate tests the plugin Create method.
func TestPluginCreate(t *testing.T) {
	p := &plugin{}

	tests := []struct {
		name      string
		config    map[string]any
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
			errMsg:    "oauth config is required",
		},
		{
			name: "missing client_id",
			config: map[string]any{
				"userinfo_url": "https://example.com/userinfo",
			},
			wantError: true,
			errMsg:    "client_id is required",
		},
		{
			name: "missing endpoints",
			config: map[string]any{
				"client_id": "test-client",
			},
			wantError: true,
			errMsg:    "either introspect_url or userinfo_url is required",
		},
		{
			name: "valid with userinfo_url",
			config: map[string]any{
				"client_id":    "test-client",
				"userinfo_url": "https://example.com/userinfo",
			},
			wantError: false,
		},
		{
			name: "valid with introspect_url",
			config: map[string]any{
				"client_id":      "test-client",
				"introspect_url": "https://example.com/introspect",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator, err := p.Create(tt.config)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, authenticator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authenticator)
			}
		})
	}
}

// TestPluginCreateWithOIDCDiscovery tests Create with OIDC discovery.
func TestPluginCreateWithOIDCDiscovery(t *testing.T) {
	discoveryResponse := map[string]string{
		"introspection_endpoint": "https://discovered.example.com/introspect",
		"userinfo_endpoint":      "https://discovered.example.com/userinfo",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			json.NewEncoder(w).Encode(discoveryResponse)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"client_id":  "test-client",
		"issuer_url": server.URL,
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

// TestPluginCreateWithFailedOIDCDiscovery tests Create when OIDC discovery fails.
func TestPluginCreateWithFailedOIDCDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := &plugin{}
	_, err := p.Create(map[string]any{
		"client_id":  "test-client",
		"issuer_url": server.URL,
	})
	// Should fail because discovery fails and no fallback endpoints
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either introspect_url or userinfo_url is required")
}

// TestParseConfig tests the parseConfig function.
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]any
		wantError bool
		errMsg    string
		validate  func(t *testing.T, cfg *oauthConfig)
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
			errMsg:    "oauth config is required",
		},
		{
			name: "empty client_id string",
			config: map[string]any{
				"client_id": "",
			},
			wantError: true,
			errMsg:    "client_id is required",
		},
		{
			name: "client_id not a string",
			config: map[string]any{
				"client_id": 123,
			},
			wantError: true,
			errMsg:    "client_id is required",
		},
		{
			name: "minimal valid config",
			config: map[string]any{
				"client_id": "test-client",
			},
			wantError: false,
			validate: func(t *testing.T, cfg *oauthConfig) {
				assert.Equal(t, "test-client", cfg.clientID)
				assert.Equal(t, "generic", cfg.provider) // default
			},
		},
		{
			name: "full config",
			config: map[string]any{
				"client_id":      "test-client",
				"client_secret":  "secret",
				"provider":       "google",
				"issuer_url":     "https://accounts.google.com",
				"introspect_url": "https://example.com/introspect",
				"userinfo_url":   "https://example.com/userinfo",
				"scopes":         []string{"openid", "email"},
				"required_claims": map[string]string{
					"aud": "my-client",
				},
			},
			wantError: false,
			validate: func(t *testing.T, cfg *oauthConfig) {
				assert.Equal(t, "test-client", cfg.clientID)
				assert.Equal(t, "secret", cfg.clientSecret)
				assert.Equal(t, "google", cfg.provider)
				assert.Equal(t, "https://accounts.google.com", cfg.issuerURL)
				assert.Equal(t, "https://example.com/introspect", cfg.introspectURL)
				assert.Equal(t, "https://example.com/userinfo", cfg.userInfoURL)
				assert.Equal(t, []string{"openid", "email"}, cfg.scopes)
				assert.Equal(t, map[string]string{"aud": "my-client"}, cfg.requiredClaims)
			},
		},
		{
			name: "scopes as []any",
			config: map[string]any{
				"client_id": "test-client",
				"scopes":    []any{"openid", "email", "profile"},
			},
			wantError: false,
			validate: func(t *testing.T, cfg *oauthConfig) {
				assert.Equal(t, []string{"openid", "email", "profile"}, cfg.scopes)
			},
		},
		{
			name: "required_claims as map[string]any",
			config: map[string]any{
				"client_id": "test-client",
				"required_claims": map[string]any{
					"aud": "my-client",
					"iss": "https://issuer.example.com",
				},
			},
			wantError: false,
			validate: func(t *testing.T, cfg *oauthConfig) {
				assert.Equal(t, "my-client", cfg.requiredClaims["aud"])
				assert.Equal(t, "https://issuer.example.com", cfg.requiredClaims["iss"])
			},
		},
		{
			name: "empty provider uses default",
			config: map[string]any{
				"client_id": "test-client",
				"provider":  "",
			},
			wantError: false,
			validate: func(t *testing.T, cfg *oauthConfig) {
				assert.Equal(t, "generic", cfg.provider)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

// TestParseStringSlice tests the parseStringSlice function.
func TestParseStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []string
	}{
		{
			name:     "[]string input",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "[]any with strings",
			input:    []any{"x", "y", "z"},
			expected: []string{"x", "y", "z"},
		},
		{
			name:     "[]any with mixed types (non-strings ignored)",
			input:    []any{"a", 123, "b", true, "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "unsupported type returns nil",
			input:    "not a slice",
			expected: nil,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty []string",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "empty []any",
			input:    []any{},
			expected: nil, // returns nil because append doesn't add anything
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHashToken tests the hashToken function.
func TestHashToken(t *testing.T) {
	// Same input should produce same hash
	hash1 := hashToken("my-secret-token")
	hash2 := hashToken("my-secret-token")
	assert.Equal(t, hash1, hash2)

	// Different inputs should produce different hashes
	hash3 := hashToken("different-token")
	assert.NotEqual(t, hash1, hash3)

	// Hash should be hex encoded (64 chars for SHA-256)
	assert.Len(t, hash1, 64)

	// Empty string should still produce valid hash
	hashEmpty := hashToken("")
	assert.Len(t, hashEmpty, 64)
}

// TestAuthenticatorName tests the Authenticator Name method.
func TestAuthenticatorName(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		expected string
	}{
		{
			name:     "generic provider",
			provider: "generic",
			expected: "oauth",
		},
		{
			name:     "empty provider",
			provider: "",
			expected: "oauth",
		},
		{
			name:     "google provider",
			provider: "google",
			expected: "oauth-google",
		},
		{
			name:     "github provider",
			provider: "github",
			expected: "oauth-github",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				config: oauthConfig{
					provider: tt.provider,
				},
			}
			assert.Equal(t, tt.expected, a.Name())
		})
	}
}

// TestAuthenticatorType tests the Authenticator Type method.
func TestAuthenticatorType(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, "oauth", a.Type())
}

// TestAuthenticatorAuthenticate tests the Authenticate method.
func TestAuthenticatorAuthenticate(t *testing.T) {
	t.Run("empty token returns error", func(t *testing.T) {
		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: "https://example.com/userinfo",
			},
			tokenCache: make(map[string]*cachedToken),
		}

		_, err := a.Authenticate(context.Background(), "", "")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))
	})

	t.Run("bearer username uses password as token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer my-token" {
				json.NewEncoder(w).Encode(map[string]any{
					"preferred_username": "testuser",
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 5 * time.Minute,
		}

		user, err := a.Authenticate(context.Background(), "bearer", "my-token")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("BEARER (uppercase) username uses password as token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"preferred_username": "testuser",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 5 * time.Minute,
		}

		user, err := a.Authenticate(context.Background(), "BEARER", "my-token")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("empty username uses password as token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"sub": "user123",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 5 * time.Minute,
		}

		user, err := a.Authenticate(context.Background(), "", "my-token")
		require.NoError(t, err)
		assert.Equal(t, "user123", user.Username)
	})

	t.Run("token as username with empty password", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer my-token-as-username" {
				json.NewEncoder(w).Encode(map[string]any{
					"preferred_username": "testuser",
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 5 * time.Minute,
		}

		user, err := a.Authenticate(context.Background(), "my-token-as-username", "")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("no validation endpoint configured", func(t *testing.T) {
		a := &Authenticator{
			config:     oauthConfig{},
			httpClient: &http.Client{Timeout: 10 * time.Second},
			tokenCache: make(map[string]*cachedToken),
		}

		_, err := a.Authenticate(context.Background(), "", "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no validation endpoint configured")
	})
}

// TestAuthenticatorAuthenticateCaching tests the caching behavior.
func TestAuthenticatorAuthenticateCaching(t *testing.T) {
	t.Run("cache hit returns cached result", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			json.NewEncoder(w).Encode(map[string]any{
				"preferred_username": "testuser",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 5 * time.Minute,
		}

		// First call
		user1, err := a.Authenticate(context.Background(), "", "cached-token")
		require.NoError(t, err)
		assert.Equal(t, 1, callCount)

		// Second call (should use cache)
		user2, err := a.Authenticate(context.Background(), "", "cached-token")
		require.NoError(t, err)
		assert.Equal(t, 1, callCount) // Still 1
		assert.Equal(t, user1.Username, user2.Username)
	})

	t.Run("expired cache triggers new request", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			json.NewEncoder(w).Encode(map[string]any{
				"preferred_username": "testuser",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 1 * time.Millisecond, // Very short cache
		}

		// First call
		_, err := a.Authenticate(context.Background(), "", "cached-token")
		require.NoError(t, err)
		assert.Equal(t, 1, callCount)

		// Wait for cache to expire
		time.Sleep(10 * time.Millisecond)

		// Second call (cache expired)
		_, err = a.Authenticate(context.Background(), "", "cached-token")
		require.NoError(t, err)
		assert.Equal(t, 2, callCount)
	})

	t.Run("cache cleanup when size exceeds 1000", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"preferred_username": "testuser",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient:  &http.Client{Timeout: 10 * time.Second},
			tokenCache:  make(map[string]*cachedToken),
			cacheMaxAge: 5 * time.Minute,
		}

		// Pre-populate cache with 1001 expired entries
		expiredTime := time.Now().Add(-1 * time.Hour)
		for i := 0; i < 1001; i++ {
			tokenHash := hashToken(string(rune(i)))
			a.tokenCache[tokenHash] = &cachedToken{
				user:      &auth.UserInfo{Username: "expired"},
				expiresAt: expiredTime,
			}
		}

		// Authenticate (should trigger cleanup)
		_, err := a.Authenticate(context.Background(), "", "new-token")
		require.NoError(t, err)

		// Cache should have been cleaned up (expired entries removed)
		assert.Less(t, len(a.tokenCache), 1002)
	})
}

// TestIntrospectToken tests the introspectToken method.
func TestIntrospectToken(t *testing.T) {
	t.Run("successful introspection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

			username, password, ok := r.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "client-id", username)
			assert.Equal(t, "client-secret", password)

			err := r.ParseForm()
			require.NoError(t, err)
			assert.Equal(t, "my-token", r.Form.Get("token"))
			assert.Equal(t, "access_token", r.Form.Get("token_type_hint"))

			json.NewEncoder(w).Encode(map[string]any{
				"active":   true,
				"username": "testuser",
				"email":    "test@example.com",
				"name":     "Test User",
				"scope":    "read write",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				clientID:      "client-id",
				clientSecret:  "client-secret",
				introspectURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.introspectToken(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test User", user.FullName)
	})

	t.Run("inactive token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"active": false,
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.introspectToken(context.Background(), "invalid-token")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))
	})

	t.Run("HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.introspectToken(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "introspect returned status 500")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.introspectToken(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode introspect response")
	})

	t.Run("network error", func(t *testing.T) {
		a := &Authenticator{
			config: oauthConfig{
				introspectURL: "http://localhost:99999/introspect", // Invalid port
			},
			httpClient: &http.Client{Timeout: 1 * time.Second},
		}

		_, err := a.introspectToken(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "introspect request")
	})

	t.Run("missing required scope", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"active":   true,
				"username": "testuser",
				"scope":    "read",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
				scopes:        []string{"read", "write"},
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.introspectToken(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required scope: write")
	})

	t.Run("all required scopes present", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"active":   true,
				"username": "testuser",
				"scope":    "read write admin",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
				scopes:        []string{"read", "write"},
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.introspectToken(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("username fallback to sub", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "user123",
				"email":  "test@example.com",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.introspectToken(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "user123", user.Username)
	})

	t.Run("username fallback to email", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"email":  "test@example.com",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				introspectURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.introspectToken(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", user.Username)
	})
}

// TestGetUserInfo tests the getUserInfo method.
func TestGetUserInfo(t *testing.T) {
	t.Run("successful userinfo request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "Bearer my-token", r.Header.Get("Authorization"))

			json.NewEncoder(w).Encode(map[string]any{
				"sub":                "user123",
				"name":               "Test User",
				"preferred_username": "testuser",
				"email":              "test@example.com",
				"groups":             []string{"admin", "users"},
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.getUserInfo(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test User", user.FullName)
		assert.Equal(t, []string{"admin", "users"}, user.Groups)
	})

	t.Run("unauthorized returns ErrInvalidCredentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.getUserInfo(context.Background(), "invalid-token")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrInvalidCredentials))
	})

	t.Run("non-200/401 status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.getUserInfo(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "userinfo returned status 403")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		_, err := a.getUserInfo(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode userinfo response")
	})

	t.Run("network error", func(t *testing.T) {
		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: "http://localhost:99999/userinfo",
			},
			httpClient: &http.Client{Timeout: 1 * time.Second},
		}

		_, err := a.getUserInfo(context.Background(), "my-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "userinfo request")
	})

	t.Run("username fallback to sub", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"sub":   "user123",
				"email": "test@example.com",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.getUserInfo(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "user123", user.Username)
	})

	t.Run("username fallback to email", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"email": "test@example.com",
			})
		}))
		defer server.Close()

		a := &Authenticator{
			config: oauthConfig{
				userInfoURL: server.URL,
			},
			httpClient: &http.Client{Timeout: 10 * time.Second},
		}

		user, err := a.getUserInfo(context.Background(), "my-token")
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", user.Username)
	})
}

// TestDiscoverOIDCEndpoints tests the discoverOIDCEndpoints function.
func TestDiscoverOIDCEndpoints(t *testing.T) {
	t.Run("successful discovery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
			json.NewEncoder(w).Encode(map[string]string{
				"introspection_endpoint": "https://example.com/introspect",
				"userinfo_endpoint":      "https://example.com/userinfo",
			})
		}))
		defer server.Close()

		introspect, userinfo, err := discoverOIDCEndpoints(server.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/introspect", introspect)
		assert.Equal(t, "https://example.com/userinfo", userinfo)
	})

	t.Run("issuer URL with trailing slash", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
			json.NewEncoder(w).Encode(map[string]string{
				"introspection_endpoint": "https://example.com/introspect",
				"userinfo_endpoint":      "https://example.com/userinfo",
			})
		}))
		defer server.Close()

		introspect, userinfo, err := discoverOIDCEndpoints(server.URL + "/")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/introspect", introspect)
		assert.Equal(t, "https://example.com/userinfo", userinfo)
	})

	t.Run("HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, _, err := discoverOIDCEndpoints(server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OIDC discovery returned status 404")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		_, _, err := discoverOIDCEndpoints(server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse OIDC discovery")
	})

	t.Run("network error", func(t *testing.T) {
		_, _, err := discoverOIDCEndpoints("http://localhost:99999")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fetch OIDC discovery")
	})

	t.Run("partial endpoints", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"userinfo_endpoint": "https://example.com/userinfo",
			})
		}))
		defer server.Close()

		introspect, userinfo, err := discoverOIDCEndpoints(server.URL)
		require.NoError(t, err)
		assert.Equal(t, "", introspect)
		assert.Equal(t, "https://example.com/userinfo", userinfo)
	})
}

// TestPluginRegistration tests that the plugin is properly registered via init().
func TestPluginRegistration(t *testing.T) {
	plugin, ok := auth.GetPlugin("oauth")
	require.True(t, ok, "oauth plugin should be registered")
	assert.Equal(t, "oauth", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

// TestAuthenticatorWithIntrospectURL tests the full flow with introspect URL.
func TestAuthenticatorWithIntrospectURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"active":   true,
			"username": "testuser",
			"email":    "test@example.com",
			"name":     "Test User",
			"scope":    "openid profile email",
		})
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"client_id":      "client-id",
		"client_secret":  "client-secret",
		"introspect_url": server.URL,
	})
	require.NoError(t, err)

	user, err := authenticator.Authenticate(context.Background(), "", "my-token")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.FullName)
}

// TestAuthenticatorWithUserInfoURL tests the full flow with userinfo URL.
func TestAuthenticatorWithUserInfoURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sub":                "user123",
			"preferred_username": "testuser",
			"email":              "test@example.com",
			"name":               "Test User",
			"groups":             []string{"admin"},
		})
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"client_id":    "client-id",
		"userinfo_url": server.URL,
	})
	require.NoError(t, err)

	user, err := authenticator.Authenticate(context.Background(), "", "my-token")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.FullName)
	assert.Equal(t, []string{"admin"}, user.Groups)
}

// TestContextCancellation tests that context cancellation is properly handled.
func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]any{
			"preferred_username": "testuser",
		})
	}))
	defer server.Close()

	a := &Authenticator{
		config: oauthConfig{
			userInfoURL: server.URL,
		},
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		tokenCache:  make(map[string]*cachedToken),
		cacheMaxAge: 5 * time.Minute,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := a.Authenticate(ctx, "", "my-token")
	require.Error(t, err)
	// Error should be related to context deadline or cancellation
	assert.True(t, errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "context deadline exceeded") ||
		strings.Contains(err.Error(), "userinfo request"))
}

// TestIntrospectTokenContextCancellation tests context cancellation for introspect.
func TestIntrospectTokenContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]any{
			"active":   true,
			"username": "testuser",
		})
	}))
	defer server.Close()

	a := &Authenticator{
		config: oauthConfig{
			introspectURL: server.URL,
		},
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		tokenCache:  make(map[string]*cachedToken),
		cacheMaxAge: 5 * time.Minute,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := a.introspectToken(ctx, "my-token")
	require.Error(t, err)
}

// TestIntrospectTokenInvalidURL tests introspectToken with an invalid URL.
func TestIntrospectTokenInvalidURL(t *testing.T) {
	a := &Authenticator{
		config: oauthConfig{
			introspectURL: "://invalid-url", // Invalid URL scheme
		},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	_, err := a.introspectToken(context.Background(), "my-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create introspect request")
}

// TestGetUserInfoInvalidURL tests getUserInfo with an invalid URL.
func TestGetUserInfoInvalidURL(t *testing.T) {
	a := &Authenticator{
		config: oauthConfig{
			userInfoURL: "://invalid-url", // Invalid URL scheme
		},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	_, err := a.getUserInfo(context.Background(), "my-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create userinfo request")
}

// TestConcurrentAccess tests thread safety of the authenticator.
func TestConcurrentAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"preferred_username": "testuser",
		})
	}))
	defer server.Close()

	a := &Authenticator{
		config: oauthConfig{
			userInfoURL: server.URL,
		},
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		tokenCache:  make(map[string]*cachedToken),
		cacheMaxAge: 5 * time.Minute,
	}

	const goroutines = 50
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			// Use different tokens to test both cache misses and hits
			token := "token"
			if id%2 == 0 {
				token = "token-" + string(rune('A'+id%26))
			}
			_, err := a.Authenticate(context.Background(), "", token)
			if err != nil {
				t.Errorf("concurrent authenticate failed: %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
