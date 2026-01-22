package totp

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTOTP generates a TOTP code for testing purposes
func generateTOTPWithAlgorithm(secret string, timestamp time.Time, digits int, period int, algorithm string) string {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}

	counter := uint64(timestamp.Unix()) / uint64(period)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	var h func() hash.Hash
	switch algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}

	mac := hmac.New(h, secretBytes)
	mac.Write(counterBytes)
	hs := mac.Sum(nil)

	offset := hs[len(hs)-1] & 0x0F
	code := binary.BigEndian.Uint32(hs[offset:offset+4]) & 0x7FFFFFFF
	code = code % uint32(pow10(digits))

	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, code)
}

func generateTOTP(secret string, timestamp time.Time, digits int, period int) string {
	return generateTOTPWithAlgorithm(secret, timestamp, digits, period, "SHA1")
}

func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

func createTOTPAuthenticator(t *testing.T, cfg map[string]any) *Authenticator {
	t.Helper()
	p := &plugin{}
	authenticator, err := p.Create(cfg)
	require.NoError(t, err)
	return authenticator.(*Authenticator)
}

// =============================================================================
// Plugin Tests
// =============================================================================

func TestPlugin_Type(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "totp", p.Type())
}

func TestPlugin_Description(t *testing.T) {
	p := &plugin{}
	assert.Contains(t, p.Description(), "Time-based One-Time Password")
	assert.Contains(t, p.Description(), "RFC 6238")
}

func TestPlugin_DefaultConfig(t *testing.T) {
	p := &plugin{}
	defaults := p.DefaultConfig()

	assert.Equal(t, "Bifrost Proxy", defaults["issuer"])
	assert.Equal(t, 6, defaults["digits"])
	assert.Equal(t, 30, defaults["period"])
	assert.Equal(t, "SHA1", defaults["algorithm"])
	assert.Equal(t, 1, defaults["skew"])
	assert.Equal(t, "/etc/bifrost/totp-secrets.yaml", defaults["secrets_file"])
}

func TestPlugin_ConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "issuer")
	assert.Contains(t, schema, "digits")
	assert.Contains(t, schema, "period")
	assert.Contains(t, schema, "algorithm")
	assert.Contains(t, schema, "skew")
	assert.Contains(t, schema, "secrets_file")
	assert.Contains(t, schema, "secrets")
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
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "empty config is valid",
			config:  map[string]any{},
			wantErr: false,
		},
		{
			name: "valid config with all options",
			config: map[string]any{
				"issuer":    "Test Issuer",
				"digits":    6,
				"period":    30,
				"algorithm": "SHA1",
				"skew":      1,
			},
			wantErr: false,
		},
		{
			name: "invalid digits (not 6 or 8)",
			config: map[string]any{
				"digits": 5,
			},
			wantErr: true,
			errMsg:  "digits must be 6 or 8",
		},
		{
			name: "invalid digits (7)",
			config: map[string]any{
				"digits": 7,
			},
			wantErr: true,
			errMsg:  "digits must be 6 or 8",
		},
		{
			name: "invalid algorithm",
			config: map[string]any{
				"algorithm": "MD5",
			},
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
		{
			name: "invalid period (zero)",
			config: map[string]any{
				"period": 0,
			},
			wantErr: true,
			errMsg:  "period must be positive",
		},
		{
			name: "invalid period (negative)",
			config: map[string]any{
				"period": -1,
			},
			wantErr: true,
			errMsg:  "period must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPlugin_Create(t *testing.T) {
	p := &plugin{}

	t.Run("creates authenticator with defaults", func(t *testing.T) {
		auth, err := p.Create(nil)
		require.NoError(t, err)
		require.NotNil(t, auth)
		assert.Equal(t, "totp", auth.Name())
	})

	t.Run("creates authenticator with inline secrets", func(t *testing.T) {
		auth, err := p.Create(map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, auth)
	})

	t.Run("fails with invalid config", func(t *testing.T) {
		_, err := p.Create(map[string]any{
			"digits": 5,
		})
		assert.Error(t, err)
	})

	t.Run("fails with non-existent secrets file", func(t *testing.T) {
		_, err := p.Create(map[string]any{
			"secrets_file": "/nonexistent/path/secrets.yaml",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load secrets file")
	})
}

// =============================================================================
// parseConfig Tests
// =============================================================================

func TestParseConfig(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		cfg, err := parseConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, "Bifrost Proxy", cfg.Issuer)
		assert.Equal(t, 6, cfg.Digits)
		assert.Equal(t, int64(30), cfg.Period)
		assert.Equal(t, "SHA1", cfg.Algorithm)
		assert.Equal(t, 1, cfg.Skew)
	})

	t.Run("custom issuer", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"issuer": "My App",
		})
		require.NoError(t, err)
		assert.Equal(t, "My App", cfg.Issuer)
	})

	t.Run("empty issuer uses default", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"issuer": "",
		})
		require.NoError(t, err)
		assert.Equal(t, "Bifrost Proxy", cfg.Issuer)
	})

	t.Run("digits as int", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"digits": 8,
		})
		require.NoError(t, err)
		assert.Equal(t, 8, cfg.Digits)
	})

	t.Run("digits as float64", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"digits": float64(8),
		})
		require.NoError(t, err)
		assert.Equal(t, 8, cfg.Digits)
	})

	t.Run("period as int", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"period": 60,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(60), cfg.Period)
	})

	t.Run("period as float64", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"period": float64(60),
		})
		require.NoError(t, err)
		assert.Equal(t, int64(60), cfg.Period)
	})

	t.Run("algorithm normalization (lowercase to uppercase)", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"algorithm": "sha256",
		})
		require.NoError(t, err)
		assert.Equal(t, "SHA256", cfg.Algorithm)
	})

	t.Run("algorithm SHA512", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"algorithm": "SHA512",
		})
		require.NoError(t, err)
		assert.Equal(t, "SHA512", cfg.Algorithm)
	})

	t.Run("empty algorithm uses default", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"algorithm": "",
		})
		require.NoError(t, err)
		assert.Equal(t, "SHA1", cfg.Algorithm)
	})

	t.Run("skew as int", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"skew": 2,
		})
		require.NoError(t, err)
		assert.Equal(t, 2, cfg.Skew)
	})

	t.Run("skew as float64", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"skew": float64(3),
		})
		require.NoError(t, err)
		assert.Equal(t, 3, cfg.Skew)
	})

	t.Run("secrets_file is stored", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{
			"secrets_file": "/path/to/secrets.yaml",
		})
		require.NoError(t, err)
		assert.Equal(t, "/path/to/secrets.yaml", cfg.SecretsFile)
	})

	t.Run("invalid secrets returns error", func(t *testing.T) {
		_, err := parseConfig(map[string]any{
			"secrets": "invalid",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secrets must be an array")
	})
}

// =============================================================================
// parseSecrets Tests
// =============================================================================

func TestParseSecrets(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		secrets, err := parseSecrets(nil)
		require.NoError(t, err)
		assert.Nil(t, secrets)
	})

	t.Run("[]any type", func(t *testing.T) {
		secrets, err := parseSecrets([]any{
			map[string]any{"username": "user1", "secret": "JBSWY3DPEHPK3PXP"},
		})
		require.NoError(t, err)
		require.Len(t, secrets, 1)
		assert.Equal(t, "user1", secrets[0].Username)
	})

	t.Run("[]map[string]any type", func(t *testing.T) {
		secrets, err := parseSecrets([]map[string]any{
			{"username": "user1", "secret": "JBSWY3DPEHPK3PXP"},
			{"username": "user2", "secret": "GEZDGNBVGY3TQOJQ"},
		})
		require.NoError(t, err)
		require.Len(t, secrets, 2)
		assert.Equal(t, "user1", secrets[0].Username)
		assert.Equal(t, "user2", secrets[1].Username)
	})

	t.Run("invalid type returns error", func(t *testing.T) {
		_, err := parseSecrets("not an array")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secrets must be an array")
	})

	t.Run("invalid item type in []any returns error", func(t *testing.T) {
		_, err := parseSecrets([]any{
			"not a map",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret at index 0 must be an object")
	})

	t.Run("invalid secret in []any returns error", func(t *testing.T) {
		_, err := parseSecrets([]any{
			map[string]any{"username": "", "secret": "JBSWY3DPEHPK3PXP"},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret at index 0")
		assert.Contains(t, err.Error(), "username is required")
	})

	t.Run("invalid secret in []map[string]any returns error", func(t *testing.T) {
		_, err := parseSecrets([]map[string]any{
			{"username": "user1", "secret": ""},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret at index 0")
		assert.Contains(t, err.Error(), "secret is required")
	})
}

// =============================================================================
// parseSecret Tests
// =============================================================================

func TestParseSecret(t *testing.T) {
	t.Run("valid secret", func(t *testing.T) {
		secret, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "JBSWY3DPEHPK3PXP",
		})
		require.NoError(t, err)
		assert.Equal(t, "testuser", secret.Username)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", secret.Secret)
		assert.False(t, secret.Disabled)
	})

	t.Run("missing username", func(t *testing.T) {
		_, err := parseSecret(map[string]any{
			"secret": "JBSWY3DPEHPK3PXP",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username is required")
	})

	t.Run("empty username", func(t *testing.T) {
		_, err := parseSecret(map[string]any{
			"username": "",
			"secret":   "JBSWY3DPEHPK3PXP",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username is required")
	})

	t.Run("missing secret", func(t *testing.T) {
		_, err := parseSecret(map[string]any{
			"username": "testuser",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret is required")
	})

	t.Run("empty secret", func(t *testing.T) {
		_, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret is required")
	})

	t.Run("invalid base32 secret", func(t *testing.T) {
		_, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "invalid!!!",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base32 secret")
	})

	t.Run("secret with spaces is normalized", func(t *testing.T) {
		secret, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "JBSW Y3DP EHPK 3PXP",
		})
		require.NoError(t, err)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", secret.Secret)
	})

	t.Run("lowercase secret is normalized", func(t *testing.T) {
		secret, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "jbswy3dpehpk3pxp",
		})
		require.NoError(t, err)
		assert.Equal(t, "JBSWY3DPEHPK3PXP", secret.Secret)
	})

	t.Run("with groups as []string", func(t *testing.T) {
		secret, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "JBSWY3DPEHPK3PXP",
			"groups":   []string{"admin", "users"},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"admin", "users"}, secret.Groups)
	})

	t.Run("with groups as []any", func(t *testing.T) {
		secret, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "JBSWY3DPEHPK3PXP",
			"groups":   []any{"admin", "users"},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"admin", "users"}, secret.Groups)
	})

	t.Run("disabled user", func(t *testing.T) {
		secret, err := parseSecret(map[string]any{
			"username": "testuser",
			"secret":   "JBSWY3DPEHPK3PXP",
			"disabled": true,
		})
		require.NoError(t, err)
		assert.True(t, secret.Disabled)
	})
}

// =============================================================================
// toStringSlice Tests
// =============================================================================

func TestToStringSlice(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		result := toStringSlice(nil)
		assert.Nil(t, result)
	})

	t.Run("[]string returns as-is", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		result := toStringSlice(input)
		assert.Equal(t, input, result)
	})

	t.Run("[]any with strings", func(t *testing.T) {
		input := []any{"a", "b", "c"}
		result := toStringSlice(input)
		assert.Equal(t, []string{"a", "b", "c"}, result)
	})

	t.Run("[]any with mixed types", func(t *testing.T) {
		input := []any{"a", 123, "b", nil, "c"}
		result := toStringSlice(input)
		assert.Equal(t, []string{"a", "b", "c"}, result)
	})

	t.Run("unsupported type returns nil", func(t *testing.T) {
		result := toStringSlice("not a slice")
		assert.Nil(t, result)
	})

	t.Run("empty []any returns empty slice", func(t *testing.T) {
		result := toStringSlice([]any{})
		assert.Equal(t, []string{}, result)
	})
}

// =============================================================================
// Authenticator Tests
// =============================================================================

func TestAuthenticator_Name(t *testing.T) {
	a := createTOTPAuthenticator(t, nil)
	assert.Equal(t, "totp", a.Name())
}

func TestAuthenticator_Type(t *testing.T) {
	a := createTOTPAuthenticator(t, nil)
	assert.Equal(t, "totp", a.Type())
}

func TestAuthenticator_Authenticate(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	t.Run("successful authentication", func(t *testing.T) {
		now := time.Now()
		code := generateTOTP(secret, now, 6, 30)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "totp", user.Metadata["auth_type"])
	})

	t.Run("successful with code containing spaces", func(t *testing.T) {
		now := time.Now()
		code := generateTOTP(secret, now, 6, 30)
		codeWithSpaces := code[:3] + " " + code[3:]

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		user, err := a.Authenticate(context.Background(), "testuser", codeWithSpaces)
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("successful with skew (past)", func(t *testing.T) {
		pastTime := time.Now().Add(-30 * time.Second)
		code := generateTOTP(secret, pastTime, 6, 30)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
			"skew": 1,
		})

		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("successful with skew (future)", func(t *testing.T) {
		futureTime := time.Now().Add(30 * time.Second)
		code := generateTOTP(secret, futureTime, 6, 30)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
			"skew": 1,
		})

		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("user not found", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		_, err := a.Authenticate(context.Background(), "unknownuser", "123456")
		assert.Error(t, err)
		var authErr *auth.AuthError
		require.True(t, errors.As(err, &authErr))
		assert.True(t, errors.Is(authErr.Unwrap(), auth.ErrUserNotFound))
	})

	t.Run("disabled user", func(t *testing.T) {
		now := time.Now()
		code := generateTOTP(secret, now, 6, 30)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret, "disabled": true},
			},
		})

		_, err := a.Authenticate(context.Background(), "testuser", code)
		assert.Error(t, err)
		var authErr *auth.AuthError
		require.True(t, errors.As(err, &authErr))
		assert.True(t, errors.Is(authErr.Unwrap(), auth.ErrUserDisabled))
	})

	t.Run("invalid code", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		_, err := a.Authenticate(context.Background(), "testuser", "000000")
		assert.Error(t, err)
		var authErr *auth.AuthError
		require.True(t, errors.As(err, &authErr))
		assert.True(t, errors.Is(authErr.Unwrap(), auth.ErrInvalidCredentials))
	})

	t.Run("wrong code length", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		_, err := a.Authenticate(context.Background(), "testuser", "12345")
		assert.Error(t, err)
	})

	t.Run("empty code", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		_, err := a.Authenticate(context.Background(), "testuser", "")
		assert.Error(t, err)
	})

	t.Run("with groups", func(t *testing.T) {
		now := time.Now()
		code := generateTOTP(secret, now, 6, 30)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{
					"username": "testuser",
					"secret":   secret,
					"groups":   []string{"admin", "users"},
				},
			},
		})

		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Contains(t, user.Groups, "admin")
		assert.Contains(t, user.Groups, "users")
	})

	t.Run("8 digit code", func(t *testing.T) {
		now := time.Now()
		code := generateTOTP(secret, now, 8, 30)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
			"digits": 8,
		})

		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})
}

func TestAuthenticator_Authenticate_Algorithms(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

	algorithms := []string{"SHA1", "SHA256", "SHA512"}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			now := time.Now()
			code := generateTOTPWithAlgorithm(secret, now, 6, 30, algo)

			a := createTOTPAuthenticator(t, map[string]any{
				"secrets": []map[string]any{
					{"username": "testuser", "secret": secret},
				},
				"algorithm": algo,
			})

			user, err := a.Authenticate(context.Background(), "testuser", code)
			require.NoError(t, err)
			assert.Equal(t, "testuser", user.Username)
		})
	}
}

func TestAuthenticator_AddUser(t *testing.T) {
	t.Run("add valid user", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)
		err := a.AddUser("newuser", "JBSWY3DPEHPK3PXP", []string{"users"})
		require.NoError(t, err)

		// Verify user can authenticate
		now := time.Now()
		code := generateTOTP("JBSWY3DPEHPK3PXP", now, 6, 30)
		user, err := a.Authenticate(context.Background(), "newuser", code)
		require.NoError(t, err)
		assert.Equal(t, "newuser", user.Username)
		assert.Contains(t, user.Groups, "users")
	})

	t.Run("add user with lowercase secret", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)
		err := a.AddUser("newuser", "jbswy3dpehpk3pxp", nil)
		require.NoError(t, err)

		now := time.Now()
		code := generateTOTP("JBSWY3DPEHPK3PXP", now, 6, 30)
		_, err = a.Authenticate(context.Background(), "newuser", code)
		require.NoError(t, err)
	})

	t.Run("add user with spaces in secret", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)
		err := a.AddUser("newuser", "JBSW Y3DP EHPK 3PXP", nil)
		require.NoError(t, err)

		now := time.Now()
		code := generateTOTP("JBSWY3DPEHPK3PXP", now, 6, 30)
		_, err = a.Authenticate(context.Background(), "newuser", code)
		require.NoError(t, err)
	})

	t.Run("invalid base32 secret", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)
		err := a.AddUser("newuser", "invalid!!!", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base32 secret")
	})

	t.Run("overwrite existing user", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP"},
			},
		})

		newSecret := "GEZDGNBVGY3TQOJQ"
		err := a.AddUser("testuser", newSecret, []string{"newgroup"})
		require.NoError(t, err)

		now := time.Now()
		code := generateTOTP(newSecret, now, 6, 30)
		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Contains(t, user.Groups, "newgroup")
	})
}

func TestAuthenticator_RemoveUser(t *testing.T) {
	t.Run("remove existing user", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP"},
			},
		})

		a.RemoveUser("testuser")

		_, err := a.Authenticate(context.Background(), "testuser", "123456")
		assert.Error(t, err)
	})

	t.Run("remove non-existent user (no error)", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)
		a.RemoveUser("nonexistent") // Should not panic
	})
}

func TestAuthenticator_GenerateSecret(t *testing.T) {
	t.Run("SHA1 generates 20-byte secret", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"algorithm": "SHA1",
		})

		secret, err := a.GenerateSecret()
		require.NoError(t, err)
		assert.NotEmpty(t, secret)

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		assert.Equal(t, 20, len(decoded))
	})

	t.Run("SHA256 generates 32-byte secret", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"algorithm": "SHA256",
		})

		secret, err := a.GenerateSecret()
		require.NoError(t, err)

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		assert.Equal(t, 32, len(decoded))
	})

	t.Run("SHA512 generates 64-byte secret", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"algorithm": "SHA512",
		})

		secret, err := a.GenerateSecret()
		require.NoError(t, err)

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		assert.Equal(t, 64, len(decoded))
	})

	t.Run("generated secret is valid for authentication", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)

		secret, err := a.GenerateSecret()
		require.NoError(t, err)

		err = a.AddUser("newuser", secret, nil)
		require.NoError(t, err)

		now := time.Now()
		code := generateTOTP(secret, now, 6, 30)
		user, err := a.Authenticate(context.Background(), "newuser", code)
		require.NoError(t, err)
		assert.Equal(t, "newuser", user.Username)
	})

	t.Run("error from rand.Read", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)

		// Save original and restore after test
		original := cryptoRandRead
		defer func() { cryptoRandRead = original }()

		cryptoRandRead = func(b []byte) (int, error) {
			return 0, errors.New("random generator failed")
		}

		_, err := a.GenerateSecret()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "random generator failed")
	})
}

func TestAuthenticator_GenerateProvisioningURI(t *testing.T) {
	t.Run("generates valid URI with defaults", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)
		uri := a.GenerateProvisioningURI("testuser", "JBSWY3DPEHPK3PXP")

		assert.Contains(t, uri, "otpauth://totp/")
		assert.Contains(t, uri, "Bifrost Proxy:testuser")
		assert.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
		assert.Contains(t, uri, "issuer=Bifrost Proxy")
		assert.Contains(t, uri, "algorithm=SHA1")
		assert.Contains(t, uri, "digits=6")
		assert.Contains(t, uri, "period=30")
	})

	t.Run("generates valid URI with custom config", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"issuer":    "My App",
			"digits":    8,
			"period":    60,
			"algorithm": "SHA256",
		})
		uri := a.GenerateProvisioningURI("alice", "GEZDGNBVGY3TQOJQ")

		assert.Contains(t, uri, "otpauth://totp/My App:alice")
		assert.Contains(t, uri, "secret=GEZDGNBVGY3TQOJQ")
		assert.Contains(t, uri, "issuer=My App")
		assert.Contains(t, uri, "algorithm=SHA256")
		assert.Contains(t, uri, "digits=8")
		assert.Contains(t, uri, "period=60")
	})
}

func TestAuthenticator_GetCurrentCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	t.Run("returns current code for valid user", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
		})

		code, err := a.GetCurrentCode("testuser")
		require.NoError(t, err)
		assert.Len(t, code, 6)

		// Verify the returned code is valid for authentication
		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("returns error for unknown user", func(t *testing.T) {
		a := createTOTPAuthenticator(t, nil)

		_, err := a.GetCurrentCode("unknownuser")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})

	t.Run("8 digit code", func(t *testing.T) {
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": secret},
			},
			"digits": 8,
		})

		code, err := a.GetCurrentCode("testuser")
		require.NoError(t, err)
		assert.Len(t, code, 8)
	})
}

// =============================================================================
// loadSecretsFile Tests
// =============================================================================

func TestAuthenticator_LoadSecretsFile(t *testing.T) {
	t.Run("loads valid secrets file", func(t *testing.T) {
		tempDir := t.TempDir()
		secretsFile := filepath.Join(tempDir, "secrets.yaml")

		content := `
secrets:
  - username: user1
    secret: JBSWY3DPEHPK3PXP
    groups:
      - admin
  - username: user2
    secret: GEZDGNBVGY3TQOJQ
    disabled: true
`
		err := os.WriteFile(secretsFile, []byte(content), 0600)
		require.NoError(t, err)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets_file": secretsFile,
		})

		// Verify user1 can authenticate
		now := time.Now()
		code := generateTOTP("JBSWY3DPEHPK3PXP", now, 6, 30)
		user, err := a.Authenticate(context.Background(), "user1", code)
		require.NoError(t, err)
		assert.Equal(t, "user1", user.Username)
		assert.Contains(t, user.Groups, "admin")

		// Verify user2 is disabled
		code2 := generateTOTP("GEZDGNBVGY3TQOJQ", now, 6, 30)
		_, err = a.Authenticate(context.Background(), "user2", code2)
		assert.Error(t, err)
	})

	t.Run("inline secrets override file secrets", func(t *testing.T) {
		tempDir := t.TempDir()
		secretsFile := filepath.Join(tempDir, "secrets.yaml")

		content := `
secrets:
  - username: testuser
    secret: JBSWY3DPEHPK3PXP
    groups:
      - filegroup
`
		err := os.WriteFile(secretsFile, []byte(content), 0600)
		require.NoError(t, err)

		inlineSecret := "GEZDGNBVGY3TQOJQ"
		a := createTOTPAuthenticator(t, map[string]any{
			"secrets_file": secretsFile,
			"secrets": []map[string]any{
				{"username": "testuser", "secret": inlineSecret, "groups": []string{"inlinegroup"}},
			},
		})

		// Inline secret should override file secret
		now := time.Now()
		code := generateTOTP(inlineSecret, now, 6, 30)
		user, err := a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
		assert.Contains(t, user.Groups, "inlinegroup")
		assert.NotContains(t, user.Groups, "filegroup")
	})

	t.Run("skips entries with empty username", func(t *testing.T) {
		tempDir := t.TempDir()
		secretsFile := filepath.Join(tempDir, "secrets.yaml")

		content := `
secrets:
  - username: ""
    secret: JBSWY3DPEHPK3PXP
  - username: validuser
    secret: GEZDGNBVGY3TQOJQ
`
		err := os.WriteFile(secretsFile, []byte(content), 0600)
		require.NoError(t, err)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets_file": secretsFile,
		})

		// validuser should exist
		now := time.Now()
		code := generateTOTP("GEZDGNBVGY3TQOJQ", now, 6, 30)
		_, err = a.Authenticate(context.Background(), "validuser", code)
		require.NoError(t, err)
	})

	t.Run("skips entries with empty secret", func(t *testing.T) {
		tempDir := t.TempDir()
		secretsFile := filepath.Join(tempDir, "secrets.yaml")

		content := `
secrets:
  - username: user1
    secret: ""
  - username: user2
    secret: GEZDGNBVGY3TQOJQ
`
		err := os.WriteFile(secretsFile, []byte(content), 0600)
		require.NoError(t, err)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets_file": secretsFile,
		})

		// user1 should not exist
		_, err = a.Authenticate(context.Background(), "user1", "123456")
		assert.Error(t, err)

		// user2 should exist
		now := time.Now()
		code := generateTOTP("GEZDGNBVGY3TQOJQ", now, 6, 30)
		_, err = a.Authenticate(context.Background(), "user2", code)
		require.NoError(t, err)
	})

	t.Run("normalizes secrets from file", func(t *testing.T) {
		tempDir := t.TempDir()
		secretsFile := filepath.Join(tempDir, "secrets.yaml")

		content := `
secrets:
  - username: testuser
    secret: "jbsw y3dp ehpk 3pxp"
`
		err := os.WriteFile(secretsFile, []byte(content), 0600)
		require.NoError(t, err)

		a := createTOTPAuthenticator(t, map[string]any{
			"secrets_file": secretsFile,
		})

		now := time.Now()
		code := generateTOTP("JBSWY3DPEHPK3PXP", now, 6, 30)
		_, err = a.Authenticate(context.Background(), "testuser", code)
		require.NoError(t, err)
	})

	t.Run("error on invalid YAML", func(t *testing.T) {
		tempDir := t.TempDir()
		secretsFile := filepath.Join(tempDir, "secrets.yaml")

		err := os.WriteFile(secretsFile, []byte("invalid: yaml: content: ["), 0600)
		require.NoError(t, err)

		p := &plugin{}
		_, err = p.Create(map[string]any{
			"secrets_file": secretsFile,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load secrets file")
	})
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestAuthenticator_ConcurrentAccess(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	a := createTOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret},
		},
	})

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Authenticate
			now := time.Now()
			code := generateTOTP(secret, now, 6, 30)
			_, _ = a.Authenticate(context.Background(), "testuser", code)

			// Add user
			newSecret := fmt.Sprintf("JBSWY3DPEHPK3PX%c", 'A'+id%26)
			_ = a.AddUser(fmt.Sprintf("user%d", id), newSecret, nil)

			// Remove user
			a.RemoveUser(fmt.Sprintf("user%d", id))

			// Generate secret
			_, _ = a.GenerateSecret()

			// Get current code
			_, _ = a.GetCurrentCode("testuser")
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// =============================================================================
// Edge Case Tests for Invalid Internal State
// =============================================================================

func TestAuthenticator_ValidateCode_InvalidStoredSecret(t *testing.T) {
	// This tests the edge case where a stored secret is somehow corrupted
	// and cannot be decoded (e.g., manual tampering)
	a := createTOTPAuthenticator(t, nil)

	// Directly set an invalid secret (bypassing validation)
	a.mu.Lock()
	a.secrets["testuser"] = &userSecret{
		Username: "testuser",
		Secret:   "INVALID!!!SECRET",
	}
	a.mu.Unlock()

	// Attempt to authenticate - should fail gracefully
	_, err := a.Authenticate(context.Background(), "testuser", "123456")
	assert.Error(t, err)
}

func TestAuthenticator_GetCurrentCode_InvalidStoredSecret(t *testing.T) {
	// This tests the edge case where a stored secret is somehow corrupted
	a := createTOTPAuthenticator(t, nil)

	// Directly set an invalid secret (bypassing validation)
	a.mu.Lock()
	a.secrets["testuser"] = &userSecret{
		Username: "testuser",
		Secret:   "INVALID!!!SECRET",
	}
	a.mu.Unlock()

	// Attempt to get current code - should return error
	_, err := a.GetCurrentCode("testuser")
	assert.Error(t, err)
}

// =============================================================================
// Registration Tests
// =============================================================================

func TestPluginRegistration(t *testing.T) {
	plugin, ok := auth.GetPlugin("totp")
	require.True(t, ok, "totp plugin should be registered")
	assert.Equal(t, "totp", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}
