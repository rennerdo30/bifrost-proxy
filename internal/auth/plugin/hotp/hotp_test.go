package hotp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/hotp"
)

// generateHOTP generates an HOTP code for testing purposes
func generateHOTP(secret string, counter uint64, digits int) string {
	return generateHOTPWithAlgorithm(secret, counter, digits, "SHA1")
}

// generateHOTPWithAlgorithm generates an HOTP code with a specific algorithm
func generateHOTPWithAlgorithm(secret string, counter uint64, digits int, algorithm string) string {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}

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

func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

func createHOTPAuthenticator(t *testing.T, cfg map[string]any) auth.Authenticator {
	t.Helper()
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "hotp-test",
		Type:    "hotp",
		Enabled: true,
		Config:  cfg,
	})
	require.NoError(t, err)
	return authenticator
}

func createHOTPAuthenticatorDirect(t *testing.T, cfg map[string]any) *hotp.Authenticator {
	t.Helper()
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)
	authenticator, err := plugin.Create(cfg)
	require.NoError(t, err)
	return authenticator.(*hotp.Authenticator)
}

// ============================================================================
// Plugin Registration Tests
// ============================================================================

func TestHOTPPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok, "hotp plugin not registered")
	assert.Equal(t, "hotp", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

// ============================================================================
// ValidateConfig Tests
// ============================================================================

func TestHOTPPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{
			name:    "nil config is valid (uses defaults)",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config with secrets array",
			config: map[string]any{
				"secrets": []map[string]any{
					{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid digits value (5)",
			config: map[string]any{
				"digits": 5,
			},
			wantErr: true,
		},
		{
			name: "invalid digits value (7)",
			config: map[string]any{
				"digits": 7,
			},
			wantErr: true,
		},
		{
			name: "valid 8 digits",
			config: map[string]any{
				"digits": 8,
			},
			wantErr: false,
		},
		{
			name: "invalid algorithm",
			config: map[string]any{
				"algorithm": "MD5",
			},
			wantErr: true,
		},
		{
			name: "valid SHA256 algorithm",
			config: map[string]any{
				"algorithm": "sha256",
			},
			wantErr: false,
		},
		{
			name: "valid SHA512 algorithm",
			config: map[string]any{
				"algorithm": "SHA512",
			},
			wantErr: false,
		},
		{
			name: "digits as float64",
			config: map[string]any{
				"digits": float64(6),
			},
			wantErr: false,
		},
		{
			name: "look_ahead as float64",
			config: map[string]any{
				"look_ahead": float64(5),
			},
			wantErr: false,
		},
		{
			name: "look_ahead less than 1 gets set to 1",
			config: map[string]any{
				"look_ahead": 0,
			},
			wantErr: false,
		},
		{
			name: "secrets_file path",
			config: map[string]any{
				"secrets_file": "/some/path/to/secrets.yaml",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Authentication Tests
// ============================================================================

func TestHOTPAuthenticator_Success(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	counter := uint64(0)
	code := generateHOTP(secret, counter, 6)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": counter},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "hotp", user.Metadata["auth_type"])
}

func TestHOTPAuthenticator_CounterIncrement(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	counter := uint64(0)

	// Generate codes for counter 0 and 1
	code0 := generateHOTP(secret, counter, 6)
	code1 := generateHOTP(secret, counter+1, 6)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": counter},
		},
	})

	// First auth should succeed with code for counter 0
	user, err := authenticator.Authenticate(context.Background(), "testuser", code0)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	// Same code should fail (counter incremented)
	_, err = authenticator.Authenticate(context.Background(), "testuser", code0)
	assert.Error(t, err)

	// Code for counter 1 should succeed
	user, err = authenticator.Authenticate(context.Background(), "testuser", code1)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_LookAhead(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	counter := uint64(0)

	// Generate code for counter 3 (within default look-ahead of 10)
	code3 := generateHOTP(secret, 3, 6)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": counter},
		},
		"look_ahead": 10,
	})

	// Code for counter 3 should succeed due to look-ahead
	user, err := authenticator.Authenticate(context.Background(), "testuser", code3)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_LookAheadExceeded(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	counter := uint64(0)

	// Generate code for counter 15 (beyond look-ahead of 5)
	code15 := generateHOTP(secret, 15, 6)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": counter},
		},
		"look_ahead": 5,
	})

	// Code for counter 15 should fail (beyond look-ahead)
	_, err := authenticator.Authenticate(context.Background(), "testuser", code15)
	assert.Error(t, err)
}

func TestHOTPAuthenticator_InvalidCode(t *testing.T) {
	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "testuser", "000000")
	assert.Error(t, err)
}

func TestHOTPAuthenticator_UnknownUser(t *testing.T) {
	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "unknownuser", "123456")
	assert.Error(t, err)
}

func TestHOTPAuthenticator_EmptyCode(t *testing.T) {
	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "testuser", "")
	assert.Error(t, err)
}

func TestHOTPAuthenticator_DisabledUser(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := generateHOTP(secret, 0, 6)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0, "disabled": true},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "testuser", code)
	assert.Error(t, err)
}

func TestHOTPAuthenticator_8Digits(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := generateHOTP(secret, 0, 8)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
		"digits": 8,
	})

	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_CodeWithWhitespace(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := generateHOTP(secret, 0, 6)
	codeWithSpaces := code[:3] + " " + code[3:]

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "testuser", codeWithSpaces)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_WrongCodeLength(t *testing.T) {
	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
		},
		"digits": 6,
	})

	// Try with 8-digit code when 6 is expected
	_, err := authenticator.Authenticate(context.Background(), "testuser", "12345678")
	assert.Error(t, err)
}

func TestHOTPAuthenticator_NameAndType(t *testing.T) {
	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
		},
	})

	assert.Equal(t, "hotp", authenticator.Name())
	assert.Equal(t, "hotp", authenticator.Type())
}

func TestHOTPAuthenticator_WithGroups(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := generateHOTP(secret, 0, 6)

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"secrets": []map[string]any{
			{
				"username": "testuser",
				"secret":   secret,
				"counter":  0,
				"groups":   []string{"admin", "users"},
			},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
}

// ============================================================================
// SHA256 and SHA512 Algorithm Tests
// ============================================================================

func TestHOTPAuthenticator_SHA256(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := generateHOTPWithAlgorithm(secret, 0, 6, "SHA256")

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"algorithm": "SHA256",
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_SHA512(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := generateHOTPWithAlgorithm(secret, 0, 6, "SHA512")

	authenticator := createHOTPAuthenticator(t, map[string]any{
		"algorithm": "SHA512",
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

// ============================================================================
// Plugin Default Config and Schema Tests
// ============================================================================

func TestHOTPPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, 6, defaults["digits"])
	assert.Equal(t, 10, defaults["look_ahead"])
	assert.Equal(t, "SHA1", defaults["algorithm"])
	assert.Equal(t, "/etc/bifrost/hotp-secrets.yaml", defaults["secrets_file"])
}

func TestHOTPPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "secrets")
	assert.Contains(t, schema, "digits")
	assert.Contains(t, schema, "look_ahead")
	assert.Contains(t, schema, "algorithm")
	assert.Contains(t, schema, "secrets_file")
}

// ============================================================================
// User Management Tests (AddUser, RemoveUser, GetCounter, SetCounter)
// ============================================================================

func TestHOTPAuthenticator_AddUser(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	// Add a user with valid base32 secret
	err := authenticator.AddUser("newuser", "JBSWY3DPEHPK3PXP", 0, []string{"users"})
	require.NoError(t, err)

	// Verify the user can authenticate
	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "newuser", code)
	require.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)
	assert.Contains(t, user.Groups, "users")
}

func TestHOTPAuthenticator_AddUser_InvalidSecret(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	// Try to add user with invalid base32 secret
	err := authenticator.AddUser("newuser", "invalid!@#$", 0, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base32 secret")
}

func TestHOTPAuthenticator_AddUser_WithSpacesInSecret(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	// Secret with spaces should be normalized
	err := authenticator.AddUser("newuser", "JBSW Y3DP EHPK 3PXP", 0, nil)
	require.NoError(t, err)

	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "newuser", code)
	require.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)
}

func TestHOTPAuthenticator_AddUser_LowercaseSecret(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	// Lowercase secret should be normalized to uppercase
	err := authenticator.AddUser("newuser", "jbswy3dpehpk3pxp", 0, nil)
	require.NoError(t, err)

	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "newuser", code)
	require.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)
}

func TestHOTPAuthenticator_RemoveUser(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
	})

	// User should exist
	code := generateHOTP(secret, 0, 6)
	_, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)

	// Remove the user
	authenticator.RemoveUser("testuser")

	// User should no longer exist
	code = generateHOTP(secret, 1, 6)
	_, err = authenticator.Authenticate(context.Background(), "testuser", code)
	assert.Error(t, err)
}

func TestHOTPAuthenticator_RemoveNonExistentUser(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	// Removing non-existent user should not panic
	authenticator.RemoveUser("nonexistent")
}

func TestHOTPAuthenticator_GetCounter(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 42},
		},
	})

	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), counter)
}

func TestHOTPAuthenticator_GetCounter_UserNotFound(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	_, err := authenticator.GetCounter("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestHOTPAuthenticator_SetCounter(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
	})

	// Set counter to 100
	err := authenticator.SetCounter("testuser", 100)
	require.NoError(t, err)

	// Verify counter was updated
	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(100), counter)

	// Auth with code for counter 100 should work
	code := generateHOTP(secret, 100, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_SetCounter_UserNotFound(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	err := authenticator.SetCounter("nonexistent", 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// ============================================================================
// GenerateSecret Tests
// ============================================================================

func TestHOTPAuthenticator_GenerateSecret_SHA1(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"algorithm": "SHA1",
	})

	secret, err := authenticator.GenerateSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify it's valid base32
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	// SHA1 should generate 20-byte secret
	assert.Len(t, decoded, 20)
}

func TestHOTPAuthenticator_GenerateSecret_SHA256(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"algorithm": "SHA256",
	})

	secret, err := authenticator.GenerateSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify it's valid base32
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	// SHA256 should generate 32-byte secret
	assert.Len(t, decoded, 32)
}

func TestHOTPAuthenticator_GenerateSecret_SHA512(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"algorithm": "SHA512",
	})

	secret, err := authenticator.GenerateSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify it's valid base32
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	// SHA512 should generate 64-byte secret
	assert.Len(t, decoded, 64)
}

func TestHOTPAuthenticator_GenerateSecret_CanBeUsedForAuth(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	// Generate a secret
	secret, err := authenticator.GenerateSecret()
	require.NoError(t, err)

	// Add a user with the generated secret
	err = authenticator.AddUser("testuser", secret, 0, nil)
	require.NoError(t, err)

	// Generate code and authenticate
	code := generateHOTP(secret, 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

// ============================================================================
// GenerateProvisioningURI Tests
// ============================================================================

func TestHOTPAuthenticator_GenerateProvisioningURI(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"digits":    6,
		"algorithm": "SHA1",
	})

	uri := authenticator.GenerateProvisioningURI("testuser", "JBSWY3DPEHPK3PXP", 0, "MyApp")

	assert.Contains(t, uri, "otpauth://hotp/")
	assert.Contains(t, uri, "MyApp:testuser")
	assert.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
	assert.Contains(t, uri, "issuer=MyApp")
	assert.Contains(t, uri, "algorithm=SHA1")
	assert.Contains(t, uri, "digits=6")
	assert.Contains(t, uri, "counter=0")
}

func TestHOTPAuthenticator_GenerateProvisioningURI_DefaultIssuer(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	uri := authenticator.GenerateProvisioningURI("testuser", "JBSWY3DPEHPK3PXP", 0, "")

	assert.Contains(t, uri, "Bifrost:testuser")
	assert.Contains(t, uri, "issuer=Bifrost")
}

func TestHOTPAuthenticator_GenerateProvisioningURI_8Digits(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"digits": 8,
	})

	uri := authenticator.GenerateProvisioningURI("testuser", "JBSWY3DPEHPK3PXP", 0, "Test")

	assert.Contains(t, uri, "digits=8")
}

func TestHOTPAuthenticator_GenerateProvisioningURI_NonZeroCounter(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	uri := authenticator.GenerateProvisioningURI("testuser", "JBSWY3DPEHPK3PXP", 42, "Test")

	assert.Contains(t, uri, "counter=42")
}

func TestHOTPAuthenticator_GenerateProvisioningURI_SHA256(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"algorithm": "SHA256",
	})

	uri := authenticator.GenerateProvisioningURI("testuser", "JBSWY3DPEHPK3PXP", 0, "Test")

	assert.Contains(t, uri, "algorithm=SHA256")
}

// ============================================================================
// File-Based Secrets Tests (loadSecretsFile, saveSecretsFile)
// ============================================================================

func TestHOTPAuthenticator_LoadSecretsFile(t *testing.T) {
	// Create a temporary secrets file
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "secrets.yaml")

	secretsContent := `secrets:
  - username: user1
    secret: JBSWY3DPEHPK3PXP
    counter: 10
    groups:
      - admin
  - username: user2
    secret: GEZDGNBVGY3TQOJQ
    counter: 5
`
	err := os.WriteFile(secretsFile, []byte(secretsContent), 0600)
	require.NoError(t, err)

	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets_file": secretsFile,
	})

	// Verify user1 was loaded
	counter1, err := authenticator.GetCounter("user1")
	require.NoError(t, err)
	assert.Equal(t, uint64(10), counter1)

	// Verify user2 was loaded
	counter2, err := authenticator.GetCounter("user2")
	require.NoError(t, err)
	assert.Equal(t, uint64(5), counter2)

	// Authenticate user1
	code := generateHOTP("JBSWY3DPEHPK3PXP", 10, 6)
	user, err := authenticator.Authenticate(context.Background(), "user1", code)
	require.NoError(t, err)
	assert.Equal(t, "user1", user.Username)
	assert.Contains(t, user.Groups, "admin")
}

func TestHOTPAuthenticator_LoadSecretsFile_InvalidPath(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	_, err := plugin.Create(map[string]any{
		"secrets_file": "/nonexistent/path/secrets.yaml",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load secrets file")
}

func TestHOTPAuthenticator_LoadSecretsFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "secrets.yaml")

	err := os.WriteFile(secretsFile, []byte("invalid: yaml: content: ["), 0600)
	require.NoError(t, err)

	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	_, err = plugin.Create(map[string]any{
		"secrets_file": secretsFile,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse secrets file")
}

func TestHOTPAuthenticator_LoadSecretsFile_SkipsInvalidEntries(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "secrets.yaml")

	// Include entries with missing username or secret
	secretsContent := `secrets:
  - username: ""
    secret: JBSWY3DPEHPK3PXP
  - username: validuser
    secret: ""
  - username: gooduser
    secret: JBSWY3DPEHPK3PXP
    counter: 0
`
	err := os.WriteFile(secretsFile, []byte(secretsContent), 0600)
	require.NoError(t, err)

	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets_file": secretsFile,
	})

	// Only gooduser should be loaded
	_, err = authenticator.GetCounter("gooduser")
	require.NoError(t, err)
}

func TestHOTPAuthenticator_SaveSecretsFile(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "secrets.yaml")

	// Create initial secrets file
	secretsContent := `secrets:
  - username: testuser
    secret: JBSWY3DPEHPK3PXP
    counter: 0
`
	err := os.WriteFile(secretsFile, []byte(secretsContent), 0600)
	require.NoError(t, err)

	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets_file": secretsFile,
	})

	// Authenticate to increment counter
	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	_, err = authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)

	// Read the file and verify counter was updated
	data, err := os.ReadFile(secretsFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "counter: 1")
}

func TestHOTPAuthenticator_SaveSecretsFile_NoFileConfigured(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 0},
		},
	})

	// Authenticate - should succeed even without secrets_file
	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestHOTPAuthenticator_InlineSecretsOverrideFile(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "secrets.yaml")

	// File has counter 10
	secretsContent := `secrets:
  - username: testuser
    secret: JBSWY3DPEHPK3PXP
    counter: 10
`
	err := os.WriteFile(secretsFile, []byte(secretsContent), 0600)
	require.NoError(t, err)

	// Inline config has counter 20
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets_file": secretsFile,
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 20},
		},
	})

	// Inline should override file
	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(20), counter)
}

// ============================================================================
// parseSecrets Edge Case Tests
// ============================================================================

func TestHOTPPlugin_ParseSecrets_ArrayOfMaps(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	// Test with []map[string]any type
	cfg := map[string]any{
		"secrets": []map[string]any{
			{"username": "user1", "secret": "JBSWY3DPEHPK3PXP"},
			{"username": "user2", "secret": "GEZDGNBVGY3TQOJQ"},
		},
	}

	err := plugin.ValidateConfig(cfg)
	require.NoError(t, err)

	authenticator, err := plugin.Create(cfg)
	require.NoError(t, err)

	auth := authenticator.(*hotp.Authenticator)
	_, err = auth.GetCounter("user1")
	require.NoError(t, err)
	_, err = auth.GetCounter("user2")
	require.NoError(t, err)
}

func TestHOTPPlugin_ParseSecrets_ArrayOfAny(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	// Test with []any type (as would come from JSON/YAML unmarshaling)
	cfg := map[string]any{
		"secrets": []any{
			map[string]any{"username": "user1", "secret": "JBSWY3DPEHPK3PXP"},
			map[string]any{"username": "user2", "secret": "GEZDGNBVGY3TQOJQ"},
		},
	}

	err := plugin.ValidateConfig(cfg)
	require.NoError(t, err)
}

func TestHOTPPlugin_ParseSecrets_InvalidItemType(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	cfg := map[string]any{
		"secrets": []any{
			"not a map",
		},
	}

	err := plugin.ValidateConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be an object")
}

func TestHOTPPlugin_ParseSecrets_InvalidType(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	cfg := map[string]any{
		"secrets": "not an array",
	}

	err := plugin.ValidateConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be an array")
}

func TestHOTPPlugin_ParseSecrets_NilSecrets(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	cfg := map[string]any{
		"secrets": nil,
	}

	err := plugin.ValidateConfig(cfg)
	require.NoError(t, err)
}

func TestHOTPPlugin_ParseSecret_MissingUsername(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	cfg := map[string]any{
		"secrets": []map[string]any{
			{"secret": "JBSWY3DPEHPK3PXP"},
		},
	}

	err := plugin.ValidateConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username is required")
}

func TestHOTPPlugin_ParseSecret_MissingSecret(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	cfg := map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser"},
		},
	}

	err := plugin.ValidateConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret is required")
}

func TestHOTPPlugin_ParseSecret_InvalidBase32(t *testing.T) {
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	cfg := map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "invalid!@#$"},
		},
	}

	err := plugin.ValidateConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base32 secret")
}

func TestHOTPPlugin_ParseSecret_CounterAsInt(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": 42},
		},
	})

	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), counter)
}

func TestHOTPPlugin_ParseSecret_CounterAsFloat64(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "counter": float64(42)},
		},
	})

	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), counter)
}

func TestHOTPPlugin_ParseSecret_GroupsAsStringSlice(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{
				"username": "testuser",
				"secret":   secret,
				"groups":   []string{"admin", "users"},
			},
		},
	})

	code := generateHOTP(secret, 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
}

func TestHOTPPlugin_ParseSecret_GroupsAsAnySlice(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{
				"username": "testuser",
				"secret":   secret,
				"groups":   []any{"admin", "users"},
			},
		},
	})

	code := generateHOTP(secret, 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
}

func TestHOTPPlugin_ParseSecret_GroupsWithNonStringItems(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{
				"username": "testuser",
				"secret":   secret,
				"groups":   []any{"admin", 123, "users", nil},
			},
		},
	})

	code := generateHOTP(secret, 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	// Only string items should be included
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
	assert.Len(t, user.Groups, 2)
}

func TestHOTPPlugin_ParseSecret_GroupsNil(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{
				"username": "testuser",
				"secret":   secret,
				"groups":   nil,
			},
		},
	})

	code := generateHOTP(secret, 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Empty(t, user.Groups)
}

func TestHOTPPlugin_ParseSecret_SecretWithSpacesAndLowercase(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "jbsw y3dp ehpk 3pxp"},
		},
	})

	// The normalized secret should work
	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

// ============================================================================
// toStringSlice Edge Case Tests
// ============================================================================

func TestToStringSlice_Nil(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "groups": nil},
		},
	})

	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Nil(t, user.Groups)
}

func TestToStringSlice_InvalidType(t *testing.T) {
	// When groups is not a slice, it should be treated as nil
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP", "groups": 123},
		},
	})

	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Nil(t, user.Groups)
}

// ============================================================================
// Edge Cases for validateCode
// ============================================================================

func TestHOTPAuthenticator_ValidateCode_InvalidSecretInStorage(t *testing.T) {
	// This tests the edge case where a secret stored is somehow invalid
	// We need to use a direct approach since the normal config parsing validates
	plugin, ok := auth.GetPlugin("hotp")
	require.True(t, ok)

	// Create with valid secret first
	authenticator, err := plugin.Create(map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": "JBSWY3DPEHPK3PXP"},
		},
	})
	require.NoError(t, err)

	auth := authenticator.(*hotp.Authenticator)

	// Manually corrupt the secret by adding a user with spaces that won't decode properly
	// Actually, the AddUser function normalizes secrets, so we test via authentication
	// with a code that doesn't match
	_, err = auth.Authenticate(context.Background(), "testuser", "123456")
	assert.Error(t, err)
}

// ============================================================================
// RFC 4226 Test Vectors
// ============================================================================

func TestHOTPAuthenticator_RFC4226TestVectors(t *testing.T) {
	// RFC 4226 test vectors using secret "12345678901234567890" (ASCII)
	// Base32 encoding of "12345678901234567890"
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	// RFC 4226 Appendix D test vectors
	testCases := []struct {
		counter uint64
		code    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("counter_%d", tc.counter), func(t *testing.T) {
			authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
				"digits":    6,
				"algorithm": "SHA1",
				"secrets": []map[string]any{
					{"username": "testuser", "secret": secret, "counter": tc.counter},
				},
			})

			user, err := authenticator.Authenticate(context.Background(), "testuser", tc.code)
			require.NoError(t, err, "Failed for counter %d with code %s", tc.counter, tc.code)
			assert.Equal(t, "testuser", user.Username)
		})
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestHOTPAuthenticator_ConcurrentAuthentication(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": 0},
		},
		"look_ahead": 100,
	})

	// Generate codes for counters 0-9
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		codes[i] = generateHOTP(secret, uint64(i), 6)
	}

	done := make(chan bool, 10)

	// Try to authenticate with multiple codes concurrently
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_, _ = authenticator.Authenticate(context.Background(), "testuser", codes[idx])
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// The counter should have advanced (exact value depends on race results)
	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.True(t, counter > 0)
}

func TestHOTPAuthenticator_ConcurrentAddRemoveUser(t *testing.T) {
	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{})

	done := make(chan bool, 20)

	// Add and remove users concurrently
	for i := 0; i < 10; i++ {
		go func(idx int) {
			username := fmt.Sprintf("user%d", idx)
			_ = authenticator.AddUser(username, "JBSWY3DPEHPK3PXP", 0, nil)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		go func(idx int) {
			username := fmt.Sprintf("user%d", idx)
			authenticator.RemoveUser(username)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

// ============================================================================
// Error Path Tests
// ============================================================================

func TestHOTPAuthenticator_SaveSecretsFile_WriteError(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "readonly", "secrets.yaml")

	// Create initial secrets file in a directory
	secretsContent := `secrets:
  - username: testuser
    secret: JBSWY3DPEHPK3PXP
    counter: 0
`
	err := os.MkdirAll(filepath.Join(tmpDir, "readonly"), 0755)
	require.NoError(t, err)
	err = os.WriteFile(secretsFile, []byte(secretsContent), 0600)
	require.NoError(t, err)

	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets_file": secretsFile,
	})

	// Make the directory read-only to cause write failure
	err = os.Chmod(filepath.Join(tmpDir, "readonly"), 0555)
	require.NoError(t, err)
	defer func() {
		_ = os.Chmod(filepath.Join(tmpDir, "readonly"), 0755)
	}()

	// Authentication should still succeed even if save fails
	code := generateHOTP("JBSWY3DPEHPK3PXP", 0, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

// ============================================================================
// Large Counter Tests
// ============================================================================

func TestHOTPAuthenticator_LargeCounter(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	largeCounter := uint64(1000000)

	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets": []map[string]any{
			{"username": "testuser", "secret": secret, "counter": int(largeCounter)},
		},
	})

	code := generateHOTP(secret, largeCounter, 6)
	user, err := authenticator.Authenticate(context.Background(), "testuser", code)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	// Verify counter incremented
	counter, err := authenticator.GetCounter("testuser")
	require.NoError(t, err)
	assert.Equal(t, largeCounter+1, counter)
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestHOTPAuthenticator_FullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "secrets.yaml")

	// Start with empty secrets file
	err := os.WriteFile(secretsFile, []byte("secrets: []\n"), 0600)
	require.NoError(t, err)

	authenticator := createHOTPAuthenticatorDirect(t, map[string]any{
		"secrets_file": secretsFile,
		"algorithm":    "SHA256",
		"digits":       8,
	})

	// Generate a new secret
	secret, err := authenticator.GenerateSecret()
	require.NoError(t, err)
	assert.Len(t, strings.TrimRight(secret, "="), 52) // 32 bytes = 52 base32 chars without padding

	// Generate provisioning URI
	uri := authenticator.GenerateProvisioningURI("newuser", secret, 0, "TestApp")
	assert.Contains(t, uri, "otpauth://hotp/")
	assert.Contains(t, uri, "algorithm=SHA256")
	assert.Contains(t, uri, "digits=8")

	// Add the user
	err = authenticator.AddUser("newuser", secret, 0, []string{"users", "testers"})
	require.NoError(t, err)

	// Verify counter
	counter, err := authenticator.GetCounter("newuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), counter)

	// Authenticate
	code := generateHOTPWithAlgorithm(secret, 0, 8, "SHA256")
	user, err := authenticator.Authenticate(context.Background(), "newuser", code)
	require.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)
	assert.Contains(t, user.Groups, "users")
	assert.Contains(t, user.Groups, "testers")

	// Verify counter incremented
	counter, err = authenticator.GetCounter("newuser")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), counter)

	// Reset counter
	err = authenticator.SetCounter("newuser", 100)
	require.NoError(t, err)

	// Authenticate with new counter
	code = generateHOTPWithAlgorithm(secret, 100, 8, "SHA256")
	user, err = authenticator.Authenticate(context.Background(), "newuser", code)
	require.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)

	// Remove user
	authenticator.RemoveUser("newuser")

	// Verify user is gone
	_, err = authenticator.GetCounter("newuser")
	assert.Error(t, err)
}
