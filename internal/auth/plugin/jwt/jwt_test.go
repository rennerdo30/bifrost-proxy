package jwt

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestRSAKey generates a test RSA key pair
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// base64URLEncode encodes data as base64 URL-safe without padding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// rsaPublicKeyToPEM converts an RSA public key to PEM format
func rsaPublicKeyToPEM(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// createJWT creates a JWT token with the given claims
func createJWT(t *testing.T, header map[string]any, claims map[string]any, privateKey *rsa.PrivateKey) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	headerB64 := base64URLEncode(headerJSON)
	claimsB64 := base64URLEncode(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	// Sign with RS256
	h := sha256.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	require.NoError(t, err)

	signatureB64 := base64URLEncode(signature)
	return signingInput + "." + signatureB64
}

// createHMACJWT creates a JWT token with HMAC signature
func createHMACJWT(t *testing.T, header map[string]any, claims map[string]any, secret []byte) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	headerB64 := base64URLEncode(headerJSON)
	claimsB64 := base64URLEncode(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	// Sign with HS256
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)

	signatureB64 := base64URLEncode(signature)
	return signingInput + "." + signatureB64
}

// createJWKS creates a JWKS JSON for a public key
func createJWKS(t *testing.T, key *rsa.PublicKey, kid string) string {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"n":   base64URLEncode(key.N.Bytes()),
				"e":   base64URLEncode(big.NewInt(int64(key.E)).Bytes()),
				"alg": "RS256",
			},
		},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)
	return string(data)
}

// ============================================================
// Plugin Interface Tests
// ============================================================

func TestPlugin_Type(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "jwt", p.Type())
}

func TestPlugin_Description(t *testing.T) {
	p := &plugin{}
	assert.Contains(t, p.Description(), "JWT")
}

func TestPlugin_DefaultConfig(t *testing.T) {
	p := &plugin{}
	defaults := p.DefaultConfig()

	assert.NotNil(t, defaults)
	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", defaults["jwks_url"])
	assert.Equal(t, "https://auth.example.com", defaults["issuer"])
	assert.Equal(t, "bifrost-proxy", defaults["audience"])
	assert.Equal(t, "sub", defaults["username_claim"])
	assert.Equal(t, "groups", defaults["groups_claim"])

	algs, ok := defaults["algorithms"].([]string)
	assert.True(t, ok)
	assert.Contains(t, algs, "RS256")
	assert.Contains(t, algs, "ES256")
}

func TestPlugin_ConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	assert.Contains(t, schema, "json-schema.org")
	assert.Contains(t, schema, "jwks_url")
	assert.Contains(t, schema, "public_key_pem")
	assert.Contains(t, schema, "issuer")
	assert.Contains(t, schema, "audience")
	assert.Contains(t, schema, "algorithms")
	assert.Contains(t, schema, "username_claim")
	assert.Contains(t, schema, "groups_claim")
	assert.Contains(t, schema, "email_claim")
	assert.Contains(t, schema, "leeway_seconds")
	assert.Contains(t, schema, "jwks_refresh_interval")
}

func TestPlugin_ValidateConfig(t *testing.T) {
	p := &plugin{}

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "jwt auth config is required",
		},
		{
			name:    "empty config",
			config:  map[string]any{},
			wantErr: true,
			errMsg:  "either 'jwks_url' or 'public_key_pem' is required",
		},
		{
			name: "valid jwks_url",
			config: map[string]any{
				"jwks_url": "https://example.com/.well-known/jwks.json",
			},
			wantErr: false,
		},
		{
			name: "valid public_key_pem",
			config: map[string]any{
				"public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
			},
			wantErr: false,
		},
		{
			name: "invalid jwks_refresh_interval",
			config: map[string]any{
				"jwks_url":              "https://example.com/jwks",
				"jwks_refresh_interval": "invalid",
			},
			wantErr: true,
			errMsg:  "invalid jwks_refresh_interval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================
// parseConfig Tests
// ============================================================

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]any
		verify  func(t *testing.T, cfg *jwtConfig)
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "default values",
			config: map[string]any{
				"jwks_url": "https://example.com/jwks",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, "https://example.com/jwks", cfg.JWKSURL)
				assert.Equal(t, []string{"RS256"}, cfg.Algorithms)
				assert.Equal(t, "sub", cfg.UsernameClaim)
				assert.Equal(t, "groups", cfg.GroupsClaim)
				assert.Equal(t, "email", cfg.EmailClaim)
				assert.Equal(t, int64(60), cfg.LeewaySeconds)
				assert.Equal(t, time.Hour, cfg.JWKSRefreshInterval)
			},
		},
		{
			name: "custom algorithms as []any",
			config: map[string]any{
				"jwks_url":   "https://example.com/jwks",
				"algorithms": []any{"RS256", "RS384", "HS256"},
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, []string{"RS256", "RS384", "HS256"}, cfg.Algorithms)
			},
		},
		{
			name: "custom algorithms as []string",
			config: map[string]any{
				"jwks_url":   "https://example.com/jwks",
				"algorithms": []string{"ES256"},
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, []string{"ES256"}, cfg.Algorithms)
			},
		},
		{
			name: "issuer and audience",
			config: map[string]any{
				"jwks_url": "https://example.com/jwks",
				"issuer":   "https://auth.example.com",
				"audience": "my-app",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, "https://auth.example.com", cfg.Issuer)
				assert.Equal(t, "my-app", cfg.Audience)
			},
		},
		{
			name: "custom claims",
			config: map[string]any{
				"jwks_url":       "https://example.com/jwks",
				"username_claim": "preferred_username",
				"groups_claim":   "roles",
				"email_claim":    "mail",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, "preferred_username", cfg.UsernameClaim)
				assert.Equal(t, "roles", cfg.GroupsClaim)
				assert.Equal(t, "mail", cfg.EmailClaim)
			},
		},
		{
			name: "leeway_seconds as int",
			config: map[string]any{
				"jwks_url":       "https://example.com/jwks",
				"leeway_seconds": 30,
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, int64(30), cfg.LeewaySeconds)
			},
		},
		{
			name: "leeway_seconds as float64",
			config: map[string]any{
				"jwks_url":       "https://example.com/jwks",
				"leeway_seconds": 45.0,
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, int64(45), cfg.LeewaySeconds)
			},
		},
		{
			name: "valid jwks_refresh_interval",
			config: map[string]any{
				"jwks_url":              "https://example.com/jwks",
				"jwks_refresh_interval": "30m",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, 30*time.Minute, cfg.JWKSRefreshInterval)
			},
		},
		{
			name: "public_key_pem only",
			config: map[string]any{
				"public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.NotEmpty(t, cfg.PublicKeyPEM)
				assert.Empty(t, cfg.JWKSURL)
			},
		},
		{
			name: "empty username_claim keeps default",
			config: map[string]any{
				"jwks_url":       "https://example.com/jwks",
				"username_claim": "",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, "sub", cfg.UsernameClaim)
			},
		},
		{
			name: "empty groups_claim keeps default",
			config: map[string]any{
				"jwks_url":     "https://example.com/jwks",
				"groups_claim": "",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, "groups", cfg.GroupsClaim)
			},
		},
		{
			name: "empty email_claim keeps default",
			config: map[string]any{
				"jwks_url":    "https://example.com/jwks",
				"email_claim": "",
			},
			verify: func(t *testing.T, cfg *jwtConfig) {
				assert.Equal(t, "email", cfg.EmailClaim)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.verify != nil {
					tt.verify(t, cfg)
				}
			}
		})
	}
}

// ============================================================
// parsePublicKey Tests
// ============================================================

func TestParsePublicKey(t *testing.T) {
	// Generate a valid RSA key for testing
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	tests := []struct {
		name    string
		pemData string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid RSA public key",
			pemData: validPEM,
			wantErr: false,
		},
		{
			name:    "invalid PEM - no block",
			pemData: "not a pem",
			wantErr: true,
			errMsg:  "failed to decode PEM block",
		},
		{
			name:    "invalid PEM - corrupt data",
			pemData: "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
			wantErr: true,
		},
		{
			name:    "empty PEM",
			pemData: "",
			wantErr: true,
			errMsg:  "failed to decode PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parsePublicKey(tt.pemData)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

// ============================================================
// Plugin Create Tests
// ============================================================

func TestPlugin_Create_WithStaticKey(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	jwtAuth := authenticator.(*Authenticator)
	assert.NotNil(t, jwtAuth.keys["static"])
}

func TestPlugin_Create_WithInvalidKey(t *testing.T) {
	p := &plugin{}
	_, err := p.Create(map[string]any{
		"public_key_pem": "invalid-pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse public key")
}

func TestPlugin_Create_WithJWKS(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	jwks := createJWKS(t, &privateKey.PublicKey, "test-key-1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"jwks_url":              server.URL,
		"jwks_refresh_interval": "24h",
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)
	defer authenticator.(*Authenticator).Close()
}

func TestPlugin_Create_WithFailedJWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := &plugin{}
	// Should still create authenticator even if initial JWKS fetch fails
	authenticator, err := p.Create(map[string]any{
		"jwks_url":              server.URL,
		"jwks_refresh_interval": "24h",
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)
	defer authenticator.(*Authenticator).Close()
}

// ============================================================
// Authenticator Tests
// ============================================================

func TestAuthenticator_Name(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, "jwt", a.Name())
}

func TestAuthenticator_Type(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, "jwt", a.Type())
}

func TestAuthenticator_Close(t *testing.T) {
	// Test Close with nil stopCh
	a := &Authenticator{}
	err := a.Close()
	assert.NoError(t, err)

	// Test Close with non-nil stopCh
	a2 := &Authenticator{stopCh: make(chan struct{})}
	err = a2.Close()
	assert.NoError(t, err)
}

// ============================================================
// Authenticate Tests
// ============================================================

func TestAuthenticator_Authenticate_EmptyToken(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
	})
	require.NoError(t, err)

	_, err = authenticator.Authenticate(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestAuthenticator_Authenticate_BearerPrefix(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	// Create a valid token
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	// Test with "Bearer " prefix (uppercase)
	user, err := authenticator.Authenticate(context.Background(), "", "Bearer "+token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	// Test with "bearer " prefix (lowercase)
	user2, err := authenticator.Authenticate(context.Background(), "", "bearer "+token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user2.Username)
}

func TestAuthenticator_Authenticate_ValidToken(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":    "testuser",
		"email":  "test@example.com",
		"name":   "Test User",
		"groups": []string{"admin", "users"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.FullName)
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
	assert.Equal(t, "jwt", user.Metadata["auth_type"])
}

func TestAuthenticator_Authenticate_MissingUsernameClaim(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"username_claim": "custom_user",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser", // Using sub but expecting custom_user
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing username claim")
}

func TestAuthenticator_Authenticate_GroupsAsAnySlice(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":    "testuser",
		"groups": []any{"group1", "group2"}, // []any instead of []string
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "group1")
	assert.Contains(t, user.Groups, "group2")
}

// ============================================================
// validateToken Tests
// ============================================================

func TestAuthenticator_ValidateToken_InvalidFormat(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	tests := []struct {
		name  string
		token string
	}{
		{"no parts", "invalid"},
		{"one part", "one"},
		{"two parts", "one.two"},
		{"four parts", "one.two.three.four"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.validateToken(tt.token)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid token format")
		})
	}
}

func TestAuthenticator_ValidateToken_InvalidHeaderEncoding(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	_, err := a.validateToken("!!!invalid-base64!!!.payload.sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header encoding")
}

func TestAuthenticator_ValidateToken_InvalidHeaderJSON(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	invalidHeader := base64URLEncode([]byte("not json"))
	_, err := a.validateToken(invalidHeader + ".payload.sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header JSON")
}

func TestAuthenticator_ValidateToken_AlgorithmNotAllowed(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"test"}`))
	_, err := a.validateToken(header + "." + payload + ".sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm not allowed")
}

func TestAuthenticator_ValidateToken_InvalidPayloadEncoding(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	_, err := a.validateToken(header + ".!!!invalid-base64!!!.sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid payload encoding")
}

func TestAuthenticator_ValidateToken_InvalidPayloadJSON(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte("not json"))
	_, err := a.validateToken(header + "." + payload + ".sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid payload JSON")
}

func TestAuthenticator_ValidateToken_NoSigningKey(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"RS256"}},
		keys:   make(map[string]any),
	}

	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"test"}`))
	_, err := a.validateToken(header + "." + payload + ".sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signing key available")
}

func TestAuthenticator_ValidateToken_ExpiredToken(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"leeway_seconds": 0, // No leeway
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"exp": float64(time.Now().Add(-time.Hour).Unix()), // Expired
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}

func TestAuthenticator_ValidateToken_NotYetValid(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"leeway_seconds": 0, // No leeway
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"nbf": float64(time.Now().Add(time.Hour).Unix()), // Not yet valid
		"exp": float64(time.Now().Add(2 * time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not yet valid")
}

func TestAuthenticator_ValidateToken_InvalidIssuer(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"issuer":         "https://auth.example.com",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"iss": "https://wrong-issuer.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestAuthenticator_ValidateToken_MissingIssuer(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"issuer":         "https://auth.example.com",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		// No iss claim
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestAuthenticator_ValidateToken_InvalidAudienceString(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"audience":       "my-app",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"aud": "wrong-app",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience")
}

func TestAuthenticator_ValidateToken_ValidAudienceArray(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"audience":       "my-app",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"aud": []any{"other-app", "my-app", "another-app"},
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticator_ValidateToken_InvalidAudienceArray(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"audience":       "my-app",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"aud": []any{"other-app", "another-app"},
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience")
}

func TestAuthenticator_ValidateToken_MissingAudience(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		"audience":       "my-app",
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		// No aud claim
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience")
}

// ============================================================
// getSigningKey Tests
// ============================================================

func TestAuthenticator_GetSigningKey_ByKid(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{
		config: &jwtConfig{},
		keys: map[string]any{
			"key-1": &privateKey.PublicKey,
			"key-2": &privateKey.PublicKey,
		},
	}

	key, err := a.getSigningKey("key-1")
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestAuthenticator_GetSigningKey_StaticFallback(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{
		config: &jwtConfig{},
		keys: map[string]any{
			"static": &privateKey.PublicKey,
		},
	}

	// No kid, should fall back to static
	key, err := a.getSigningKey("")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Kid not found, should fall back to static
	key, err = a.getSigningKey("nonexistent")
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestAuthenticator_GetSigningKey_FirstAvailable(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{
		config: &jwtConfig{},
		keys: map[string]any{
			"key-1": &privateKey.PublicKey,
		},
	}

	// No kid and no static, should return first available
	key, err := a.getSigningKey("")
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestAuthenticator_GetSigningKey_NoKeysAvailable(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{},
		keys:   make(map[string]any),
	}

	_, err := a.getSigningKey("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signing key available")
}

// ============================================================
// verifySignature Tests
// ============================================================

func TestAuthenticator_VerifySignature_UnsupportedAlgorithm(t *testing.T) {
	a := &Authenticator{}

	err := a.verifySignature("input", base64URLEncode([]byte("sig")), "UNSUPPORTED", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestAuthenticator_VerifySignature_InvalidSignatureEncoding(t *testing.T) {
	a := &Authenticator{}

	err := a.verifySignature("input", "!!!invalid-base64!!!", "RS256", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature encoding")
}

// ============================================================
// verifyRSA Tests
// ============================================================

func TestAuthenticator_VerifyRSA_ValidSignature(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{}

	signingInput := "test-input"
	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	require.NoError(t, err)

	err = a.verifyRSA(signingInput, signature, "RS256", &privateKey.PublicKey)
	assert.NoError(t, err)
}

func TestAuthenticator_VerifyRSA_InvalidKeyType(t *testing.T) {
	a := &Authenticator{}

	err := a.verifyRSA("input", []byte("sig"), "RS256", "not-an-rsa-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type for RSA")
}

func TestAuthenticator_VerifyRSA_InvalidSignature(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{}

	err := a.verifyRSA("input", []byte("invalid-signature"), "RS256", &privateKey.PublicKey)
	require.Error(t, err)
}

func TestAuthenticator_VerifyRSA_Algorithms(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{}

	tests := []struct {
		alg  string
		hash crypto.Hash
	}{
		{"RS256", crypto.SHA256},
		{"RS384", crypto.SHA384},
		{"RS512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			signingInput := "test-input-" + tt.alg
			h := tt.hash.New()
			h.Write([]byte(signingInput))
			hashed := h.Sum(nil)

			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, tt.hash, hashed)
			require.NoError(t, err)

			err = a.verifyRSA(signingInput, signature, tt.alg, &privateKey.PublicKey)
			assert.NoError(t, err)
		})
	}
}

// ============================================================
// verifyHMAC Tests
// ============================================================

func TestAuthenticator_VerifyHMAC_ValidSignature(t *testing.T) {
	a := &Authenticator{}
	secret := []byte("my-secret-key")

	signingInput := "test-input"
	mac := hmac.New(crypto.SHA256.New, secret)
	mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)

	err := a.verifyHMAC(signingInput, signature, "HS256", secret)
	assert.NoError(t, err)
}

func TestAuthenticator_VerifyHMAC_InvalidKeyType(t *testing.T) {
	a := &Authenticator{}

	err := a.verifyHMAC("input", []byte("sig"), "HS256", "not-bytes")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type for HMAC")
}

func TestAuthenticator_VerifyHMAC_SignatureMismatch(t *testing.T) {
	a := &Authenticator{}
	secret := []byte("my-secret-key")

	err := a.verifyHMAC("input", []byte("wrong-signature"), "HS256", secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestAuthenticator_VerifyHMAC_Algorithms(t *testing.T) {
	a := &Authenticator{}
	secret := []byte("my-secret-key")

	tests := []struct {
		alg  string
		hash crypto.Hash
	}{
		{"HS256", crypto.SHA256},
		{"HS384", crypto.SHA384},
		{"HS512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			signingInput := "test-input-" + tt.alg
			mac := hmac.New(tt.hash.New, secret)
			mac.Write([]byte(signingInput))
			signature := mac.Sum(nil)

			err := a.verifyHMAC(signingInput, signature, tt.alg, secret)
			assert.NoError(t, err)
		})
	}
}

func TestAuthenticator_VerifyHMAC_UnsupportedAlgorithm(t *testing.T) {
	a := &Authenticator{}
	secret := []byte("my-secret-key")

	err := a.verifyHMAC("input", []byte("sig"), "HS999", secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

// ============================================================
// verifyECDSA Tests
// ============================================================

func TestAuthenticator_VerifyECDSA_NotImplemented(t *testing.T) {
	a := &Authenticator{}

	err := a.verifyECDSA("input", []byte("sig"), "ES256", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// ============================================================
// refreshJWKS Tests
// ============================================================

func TestAuthenticator_RefreshJWKS_NoURL(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{JWKSURL: ""},
		keys:   make(map[string]any),
	}

	err := a.refreshJWKS()
	assert.NoError(t, err) // Should be no-op
}

func TestAuthenticator_RefreshJWKS_Success(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	jwks := createJWKS(t, &privateKey.PublicKey, "test-key-1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.NoError(t, err)

	a.keysMu.RLock()
	defer a.keysMu.RUnlock()
	assert.Contains(t, a.keys, "test-key-1")
}

func TestAuthenticator_RefreshJWKS_PreservesStaticKey(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	jwks := createJWKS(t, &privateKey.PublicKey, "dynamic-key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	staticKey := &privateKey.PublicKey
	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys: map[string]any{
			"static": staticKey,
		},
	}

	err := a.refreshJWKS()
	require.NoError(t, err)

	a.keysMu.RLock()
	defer a.keysMu.RUnlock()
	assert.Contains(t, a.keys, "static")
	assert.Contains(t, a.keys, "dynamic-key")
}

func TestAuthenticator_RefreshJWKS_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestAuthenticator_RefreshJWKS_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWKS")
}

func TestAuthenticator_RefreshJWKS_SkipsNonSigningKeys(t *testing.T) {
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "enc", // Encryption key, not signing
				"kid": "enc-key",
				"n":   "test",
				"e":   "AQAB",
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwks)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.NoError(t, err)

	a.keysMu.RLock()
	defer a.keysMu.RUnlock()
	assert.NotContains(t, a.keys, "enc-key")
}

func TestAuthenticator_RefreshJWKS_UnsupportedKeyType(t *testing.T) {
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "oct",
				"use": "sig",
				"kid": "oct-key",
				"k":   "test",
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwks)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.NoError(t, err) // No error, just logs warning

	a.keysMu.RLock()
	defer a.keysMu.RUnlock()
	assert.NotContains(t, a.keys, "oct-key")
}

func TestAuthenticator_RefreshJWKS_InvalidKeyData(t *testing.T) {
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "bad-key",
				"n":   "!!!invalid-base64!!!",
				"e":   "AQAB",
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwks)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.NoError(t, err) // No error, just logs warning

	a.keysMu.RLock()
	defer a.keysMu.RUnlock()
	assert.NotContains(t, a.keys, "bad-key")
}

func TestAuthenticator_RefreshJWKS_ConnectionError(t *testing.T) {
	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: "http://localhost:99999"},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

// ============================================================
// parseRSAKey Tests
// ============================================================

func TestParseRSAKey_Valid(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	n := base64URLEncode(privateKey.PublicKey.N.Bytes())
	e := base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes())

	key, err := parseRSAKey(n, e)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, privateKey.PublicKey.E, key.E)
}

func TestParseRSAKey_InvalidN(t *testing.T) {
	_, err := parseRSAKey("!!!invalid!!!", "AQAB")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid n")
}

func TestParseRSAKey_InvalidE(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	n := base64URLEncode(privateKey.PublicKey.N.Bytes())

	_, err := parseRSAKey(n, "!!!invalid!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid e")
}

// ============================================================
// toStringSlice Tests
// ============================================================

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		expect []string
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "string slice",
			input:  []string{"a", "b", "c"},
			expect: []string{"a", "b", "c"},
		},
		{
			name:   "any slice with strings",
			input:  []any{"a", "b", "c"},
			expect: []string{"a", "b", "c"},
		},
		{
			name:   "any slice with mixed types",
			input:  []any{"a", 123, "c"},
			expect: []string{"a", "c"},
		},
		{
			name:   "unsupported type",
			input:  "not a slice",
			expect: nil,
		},
		{
			name:   "empty any slice",
			input:  []any{},
			expect: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toStringSlice(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// ============================================================
// getHashFunc Tests
// ============================================================

func TestGetHashFunc(t *testing.T) {
	tests := []struct {
		alg        string
		expectHash crypto.Hash
		expectNil  bool
	}{
		{"RS256", crypto.SHA256, false},
		{"ES256", crypto.SHA256, false},
		{"HS256", crypto.SHA256, false},
		{"RS384", crypto.SHA384, false},
		{"ES384", crypto.SHA384, false},
		{"HS384", crypto.SHA384, false},
		{"RS512", crypto.SHA512, false},
		{"ES512", crypto.SHA512, false},
		{"HS512", crypto.SHA512, false},
		{"UNKNOWN", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			hashFunc, cryptoHash := getHashFunc(tt.alg)
			if tt.expectNil {
				assert.Nil(t, hashFunc)
				assert.Equal(t, crypto.Hash(0), cryptoHash)
			} else {
				assert.NotNil(t, hashFunc)
				assert.Equal(t, tt.expectHash, cryptoHash)
			}
		})
	}
}

// ============================================================
// hmacNew and hmacEqual Tests
// ============================================================

func TestHmacNew(t *testing.T) {
	key := []byte("test-key")
	mac := hmacNew(crypto.SHA256.New, key)
	assert.NotNil(t, mac)

	mac.Write([]byte("test data"))
	result := mac.Sum(nil)
	assert.Len(t, result, 32) // SHA256 produces 32 bytes
}

func TestHmacEqual(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	c := []byte("world")

	assert.True(t, hmacEqual(a, b))
	assert.False(t, hmacEqual(a, c))
	assert.True(t, hmacEqual([]byte{}, []byte{}))
}

// ============================================================
// JWKS Background Refresh Tests
// ============================================================

func TestAuthenticator_JWKSBackgroundRefresh(t *testing.T) {
	callCount := 0
	privateKey := generateTestRSAKey(t)
	jwks := createJWKS(t, &privateKey.PublicKey, "refresh-key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"jwks_url":              server.URL,
		"jwks_refresh_interval": "50ms",
	})
	require.NoError(t, err)

	jwtAuth := authenticator.(*Authenticator)
	defer jwtAuth.Close()

	// Wait for at least 2 refresh cycles
	time.Sleep(150 * time.Millisecond)

	assert.GreaterOrEqual(t, callCount, 2, "JWKS should be refreshed multiple times")
}

func TestAuthenticator_JWKSBackgroundRefresh_StopsOnClose(t *testing.T) {
	callCount := 0
	privateKey := generateTestRSAKey(t)
	jwks := createJWKS(t, &privateKey.PublicKey, "refresh-key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"jwks_url":              server.URL,
		"jwks_refresh_interval": "50ms",
	})
	require.NoError(t, err)

	jwtAuth := authenticator.(*Authenticator)

	// Close immediately
	jwtAuth.Close()

	countAfterClose := callCount
	time.Sleep(150 * time.Millisecond)

	// Should not have many more calls after close (allow for 1-2 in-flight)
	assert.LessOrEqual(t, callCount, countAfterClose+2)
}

// ============================================================
// Integration Tests
// ============================================================

func TestAuthenticator_FullFlow_WithJWKS(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	kid := "test-key-1"
	jwks := createJWKS(t, &privateKey.PublicKey, kid)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"jwks_url":              server.URL,
		"algorithms":            []string{"RS256"},
		"issuer":                "https://auth.example.com",
		"audience":              "my-app",
		"jwks_refresh_interval": "24h",
	})
	require.NoError(t, err)
	defer authenticator.(*Authenticator).Close()

	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	claims := map[string]any{
		"sub":    "john.doe",
		"email":  "john.doe@example.com",
		"name":   "John Doe",
		"groups": []any{"developers", "admins"},
		"iss":    "https://auth.example.com",
		"aud":    "my-app",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"iat":    float64(time.Now().Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)

	assert.Equal(t, "john.doe", user.Username)
	assert.Equal(t, "john.doe@example.com", user.Email)
	assert.Equal(t, "John Doe", user.FullName)
	assert.Contains(t, user.Groups, "developers")
	assert.Contains(t, user.Groups, "admins")
}

func TestAuthenticator_FullFlow_WithStaticKey(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "static-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "static-user", user.Username)
}

func TestAuthenticator_FullFlow_WithHMAC(t *testing.T) {
	secret := []byte("my-super-secret-key-at-least-32-bytes-long")

	a := &Authenticator{
		config: &jwtConfig{
			Algorithms:    []string{"HS256"},
			UsernameClaim: "sub",
			GroupsClaim:   "groups",
			EmailClaim:    "email",
			LeewaySeconds: 60,
		},
		keys: map[string]any{
			"static": secret,
		},
	}

	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "hmac-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createHMACJWT(t, header, claims, secret)

	user, err := a.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "hmac-user", user.Username)
}

// ============================================================
// Plugin Registration Test
// ============================================================

func TestPluginRegistration(t *testing.T) {
	plugin, ok := auth.GetPlugin("jwt")
	require.True(t, ok, "jwt plugin should be registered")
	assert.Equal(t, "jwt", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

// ============================================================
// Additional Edge Case Tests for 100% Coverage
// ============================================================

func TestPlugin_Create_ParseConfigError(t *testing.T) {
	p := &plugin{}
	// Pass nil config which will fail parseConfig
	_, err := p.Create(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwt auth config is required")
}

func TestAuthenticator_ValidateToken_SignatureVerificationFailed(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	differentKey := generateTestRSAKey(t) // Different key for signing
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	// Create a token signed with a different key
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	// Sign with differentKey but try to verify with privateKey's public key
	token := createJWT(t, header, claims, differentKey)

	_, err = authenticator.Authenticate(context.Background(), "", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestAuthenticator_VerifySignature_ECDSAPath(t *testing.T) {
	a := &Authenticator{
		config: &jwtConfig{Algorithms: []string{"ES256"}},
		keys:   map[string]any{"static": "dummy-key"},
	}

	header := base64URLEncode([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"test"}`))
	sig := base64URLEncode([]byte("dummy-signature"))

	// validateToken will call verifySignature with ES256
	_, err := a.validateToken(header + "." + payload + "." + sig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestAuthenticator_VerifyRSA_UnsupportedHashAlgorithm(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	a := &Authenticator{}

	// Test with an algorithm that maps to nil hash function
	// We can't easily trigger this through verifyRSA since getHashFunc
	// is called internally, but we can call verifyRSA directly with
	// an algorithm that would have nil hash
	// Actually the function receives alg and calls getHashFunc
	// The only way to get nil is with an unknown algorithm

	// Since RS256/RS384/RS512 all have valid hash funcs,
	// we need to test with an invalid algorithm
	// But verifySignature filters to only call verifyRSA for RS* algorithms
	// So this path is unreachable in normal flow

	// We can still test the function directly
	err := a.verifyRSA("input", []byte("sig"), "RS999", &privateKey.PublicKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestAuthenticator_RefreshJWKS_InvalidJWKJSON(t *testing.T) {
	// Test case where individual JWK JSON parsing fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Invalid JSON in the keys array
		w.Write([]byte(`{"keys":[invalid-json]}`))
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWKS")
}

func TestAuthenticator_RefreshJWKS_EmptyUseField(t *testing.T) {
	// Test case where use field is empty (should still process the key)
	privateKey := generateTestRSAKey(t)
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "", // Empty use field
				"kid": "empty-use-key",
				"n":   base64URLEncode(privateKey.PublicKey.N.Bytes()),
				"e":   base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			},
		},
	}
	jwksJSON, _ := json.Marshal(jwks)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer server.Close()

	a := &Authenticator{
		config:     &jwtConfig{JWKSURL: server.URL},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	err := a.refreshJWKS()
	require.NoError(t, err)

	a.keysMu.RLock()
	defer a.keysMu.RUnlock()
	assert.Contains(t, a.keys, "empty-use-key")
}

func TestAuthenticator_Authenticate_WithKid(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	jwks := createJWKS(t, &privateKey.PublicKey, "specific-kid")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	defer server.Close()

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"jwks_url":              server.URL,
		"algorithms":            []string{"RS256"},
		"jwks_refresh_interval": "24h",
	})
	require.NoError(t, err)
	defer authenticator.(*Authenticator).Close()

	// Create token with kid in header
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "specific-kid"}
	claims := map[string]any{
		"sub": "testuser",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestParsePublicKey_ValidRSAKey(t *testing.T) {
	// Test with a properly formatted RSA key
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	key, err := parsePublicKey(validPEM)
	require.NoError(t, err)
	require.NotNil(t, key)

	rsaKey, ok := key.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, privateKey.PublicKey.E, rsaKey.E)
}

func TestAuthenticator_ValidateToken_NoExpClaim(t *testing.T) {
	// Test token without exp claim (should be valid, exp check is optional)
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		// No exp claim
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticator_ValidateToken_NoNbfClaim(t *testing.T) {
	// Test token without nbf claim (should be valid, nbf check is optional)
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		// No nbf claim
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticator_ValidateToken_NoIssuerConfig(t *testing.T) {
	// Test when issuer is not configured (should skip issuer validation)
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		// No issuer configured
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"iss": "any-issuer", // Any issuer should be accepted
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestAuthenticator_ValidateToken_NoAudienceConfig(t *testing.T) {
	// Test when audience is not configured (should skip audience validation)
	privateKey := generateTestRSAKey(t)
	validPEM := rsaPublicKeyToPEM(t, &privateKey.PublicKey)

	p := &plugin{}
	authenticator, err := p.Create(map[string]any{
		"public_key_pem": validPEM,
		"algorithms":     []string{"RS256"},
		// No audience configured
	})
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "testuser",
		"aud": "any-audience", // Any audience should be accepted
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := createJWT(t, header, claims, privateKey)

	user, err := authenticator.Authenticate(context.Background(), "", token)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}
