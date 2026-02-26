package mfa_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/mfa"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/totp"
)

// generateTOTP generates a TOTP code for testing purposes
//
//nolint:unparam // secret is always totpSecret in tests but kept for test readability
func generateTOTP(secret string, timestamp time.Time) string {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}

	counter := uint64(timestamp.Unix()) / 30
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
	code = code % 1000000

	return fmt.Sprintf("%06d", code)
}

func TestMFAWrapperPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok, "mfa_wrapper plugin not registered")
	assert.Equal(t, "mfa_wrapper", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

func TestMFAWrapperPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{
			name:    "nil config should error",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing primary_provider should error",
			config: map[string]any{
				"mfa_type": "totp",
			},
			wantErr: true,
		},
		{
			name: "valid config with primary_provider",
			config: map[string]any{
				"primary_provider": "ldap-main",
				"mfa_type":         "totp",
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

func TestMFAWrapperPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, "ldap-main", defaults["primary_provider"])
	assert.Equal(t, "totp", defaults["mfa_type"])
	assert.Equal(t, "always", defaults["mfa_required"])
	assert.Equal(t, "concatenated", defaults["password_format"])
}

func TestMFAWrapperPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "primary_provider")
	assert.Contains(t, schema, "mfa_type")
	assert.Contains(t, schema, "mfa_required")
	assert.Contains(t, schema, "password_format")
}

func TestMFAWrapperPlugin_ValidateConfig_InlineProviders(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	err = plugin.ValidateConfig(map[string]any{
		"primary": map[string]any{
			"mode": "native",
			"native": map[string]any{
				"users": []map[string]any{
					{
						"username":      "testuser",
						"password_hash": passwordHash,
					},
				},
			},
		},
		"secondary": map[string]any{
			"mode": "totp",
			"totp": map[string]any{
				"secrets": map[string]any{
					"testuser": "JBSWY3DPEHPK3PXP",
				},
			},
		},
	})
	assert.NoError(t, err)
}

func TestMFAWrapperPlugin_Create_InlineProviders(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	authenticator, err := plugin.Create(map[string]any{
		"primary": map[string]any{
			"mode": "native",
			"native": map[string]any{
				"users": []map[string]any{
					{
						"username":      "testuser",
						"password_hash": passwordHash,
					},
				},
			},
		},
		"secondary": map[string]any{
			"mode": "totp",
			"totp": map[string]any{
				"secrets": map[string]any{
					"testuser": "JBSWY3DPEHPK3PXP",
				},
			},
		},
		"otp_separator": ":",
	})
	require.NoError(t, err)

	code := generateTOTP("JBSWY3DPEHPK3PXP", time.Now())
	user, err := authenticator.Authenticate(context.Background(), "testuser", "password:"+code)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "mfa_wrapper", user.Metadata["auth_type"])
}

// Helper to create authenticators for testing the wrapper directly
//
//nolint:unparam // totpSecret is always the same in tests but kept for test readability
func createTestAuthenticators(t *testing.T, passwordHash, totpSecret string) (auth.Authenticator, auth.Authenticator) {
	t.Helper()
	factory := auth.NewFactory()

	// Create primary (native) authenticator
	primary, err := factory.Create(auth.ProviderConfig{
		Name:    "primary",
		Type:    "native",
		Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{
					"username":      "testuser",
					"password_hash": passwordHash,
				},
			},
		},
	})
	require.NoError(t, err)

	// Create MFA (TOTP) authenticator
	mfaAuth, err := factory.Create(auth.ProviderConfig{
		Name:    "totp",
		Type:    "totp",
		Enabled: true,
		Config: map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": totpSecret},
			},
		},
	})
	require.NoError(t, err)

	return primary, mfaAuth
}

func TestMFAWrapper_ConcatenatedFormat(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test with concatenated password+OTP
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password"+totpCode)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "mfa_wrapper", user.Metadata["auth_type"])
}

func TestMFAWrapper_SeparatedFormat(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatSeparated,
		Separator:       ":",
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test with separated password:OTP
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password:"+totpCode)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestMFAWrapper_WrongPassword(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test with wrong password
	_, err = wrapper.Authenticate(context.Background(), "testuser", "wrongpassword"+totpCode)
	assert.Error(t, err)
}

func TestMFAWrapper_WrongOTP(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test with wrong OTP
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password000000")
	assert.Error(t, err)
}

func TestMFAWrapper_MFANeverRequired(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModePerUser, // Per-user mode with no users configured = MFA not required
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test with just password (user not enrolled in MFA)
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestMFAWrapper_NameAndType(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModePerUser,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	assert.Equal(t, "mfa_wrapper", wrapper.Name())
	assert.Equal(t, "mfa_wrapper", wrapper.Type())
}

func TestMFAWrapper_ShortPassword(t *testing.T) {
	passwordHash, err := auth.HashPassword("pass")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Password too short to contain 6-digit OTP
	_, err = wrapper.Authenticate(context.Background(), "testuser", "12345")
	assert.Error(t, err)
}

func TestMFAWrapper_NilConfig(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	_, err = mfa.NewWrapper(nil, primary, mfaAuth)
	assert.Error(t, err)
}

func TestMFAWrapper_NilPrimary(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	_, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	_, err = mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
	}, nil, mfaAuth)
	assert.Error(t, err)
}

func TestMFAWrapper_NilMFA(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, _ := createTestAuthenticators(t, passwordHash, totpSecret)

	_, err = mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
	}, primary, nil)
	assert.Error(t, err)
}

// Test pendingWrapper methods
func TestPendingWrapper_Authenticate(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	// Create a pendingWrapper via the plugin
	authenticator, err := plugin.Create(map[string]any{
		"primary_provider": "ldap-main",
		"mfa_type":         "totp",
	})
	require.NoError(t, err)

	// Authenticate should return an error because it's not fully configured
	_, err = authenticator.Authenticate(context.Background(), "user", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not fully configured")
}

func TestPendingWrapper_Name(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	authenticator, err := plugin.Create(map[string]any{
		"primary_provider": "ldap-main",
	})
	require.NoError(t, err)

	assert.Equal(t, "mfa_wrapper", authenticator.Name())
}

func TestPendingWrapper_Type(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	authenticator, err := plugin.Create(map[string]any{
		"primary_provider": "ldap-main",
	})
	require.NoError(t, err)

	assert.Equal(t, "mfa_wrapper", authenticator.Type())
}

// Interface to access GetConfig on pendingWrapper
type configGetter interface {
	GetConfig() *mfa.Config
}

func TestPendingWrapper_GetConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	authenticator, err := plugin.Create(map[string]any{
		"primary_provider": "my-ldap",
		"mfa_type":         "hotp",
		"mfa_code_length":  8,
	})
	require.NoError(t, err)

	// Check if it implements configGetter
	cg, ok := authenticator.(configGetter)
	require.True(t, ok, "authenticator should implement GetConfig")

	config := cg.GetConfig()
	assert.NotNil(t, config)
	assert.Equal(t, "my-ldap", config.PrimaryProvider)
	assert.Equal(t, "hotp", config.MFAType)
	assert.Equal(t, 8, config.MFACodeLength)
}

// Test parsePluginConfig edge cases
func TestParsePluginConfig_MFAGroups(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	err := plugin.ValidateConfig(map[string]any{
		"primary_provider": "ldap-main",
		"mfa_required":     "group_based",
		"mfa_groups":       []any{"admins", "developers", "security"},
	})
	assert.NoError(t, err)
}

func TestParsePluginConfig_MFACodeLengthFloat64(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	// JSON unmarshaling often converts numbers to float64
	err := plugin.ValidateConfig(map[string]any{
		"primary_provider": "ldap-main",
		"mfa_code_length":  float64(8),
	})
	assert.NoError(t, err)
}

func TestParsePluginConfig_InvalidPasswordFormat(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	err := plugin.ValidateConfig(map[string]any{
		"primary_provider": "ldap-main",
		"password_format":  "invalid_format",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password_format")
}

func TestParsePluginConfig_InvalidMFARequired(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	err := plugin.ValidateConfig(map[string]any{
		"primary_provider": "ldap-main",
		"mfa_required":     "invalid_mode",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mfa_required")
}

func TestParsePluginConfig_MFAProvider(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	// mfa_provider should override mfa_type
	authenticator, err := plugin.Create(map[string]any{
		"primary_provider": "ldap-main",
		"mfa_type":         "totp",
		"mfa_provider":     "custom-totp",
	})
	require.NoError(t, err)

	cg, ok := authenticator.(configGetter)
	require.True(t, ok)

	config := cg.GetConfig()
	assert.Equal(t, "custom-totp", config.MFAType)
}

func TestParsePluginConfig_CustomSeparator(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	authenticator, err := plugin.Create(map[string]any{
		"primary_provider": "ldap-main",
		"password_format":  "separated",
		"separator":        "|",
	})
	require.NoError(t, err)

	cg, ok := authenticator.(configGetter)
	require.True(t, ok)

	config := cg.GetConfig()
	assert.Equal(t, "|", config.Separator)
}

func TestParsePluginConfig_AllMFAModes(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	tests := []struct {
		mode    string
		wantErr bool
	}{
		{"always", false},
		{"per_user", false},
		{"group_based", false},
		{"ALWAYS", false},      // Test case insensitivity
		{"Per_User", false},    // Test case insensitivity
		{"GROUP_BASED", false}, // Test case insensitivity
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			err := plugin.ValidateConfig(map[string]any{
				"primary_provider": "ldap-main",
				"mfa_required":     tt.mode,
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParsePluginConfig_AllPasswordFormats(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	tests := []struct {
		format  string
		wantErr bool
	}{
		{"concatenated", false},
		{"separated", false},
		{"CONCATENATED", false}, // Test case insensitivity
		{"Separated", false},    // Test case insensitivity
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			err := plugin.ValidateConfig(map[string]any{
				"primary_provider": "ldap-main",
				"password_format":  tt.format,
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test wrapper user management methods
func TestMFAWrapper_EnableDisableMFA(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModePerUser,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Initially MFA should not be enabled
	assert.False(t, wrapper.IsMFAEnabled("testuser"))

	// Enable MFA
	wrapper.EnableMFA("testuser")
	assert.True(t, wrapper.IsMFAEnabled("testuser"))

	// Disable MFA
	wrapper.DisableMFA("testuser")
	assert.False(t, wrapper.IsMFAEnabled("testuser"))
}

func TestMFAWrapper_SetMFAUsers(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModePerUser,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Set MFA users
	wrapper.SetMFAUsers([]string{"user1", "user2", "user3"})

	assert.True(t, wrapper.IsMFAEnabled("user1"))
	assert.True(t, wrapper.IsMFAEnabled("user2"))
	assert.True(t, wrapper.IsMFAEnabled("user3"))
	assert.False(t, wrapper.IsMFAEnabled("user4"))

	// Replace with new list
	wrapper.SetMFAUsers([]string{"user4", "user5"})
	assert.False(t, wrapper.IsMFAEnabled("user1"))
	assert.False(t, wrapper.IsMFAEnabled("user2"))
	assert.True(t, wrapper.IsMFAEnabled("user4"))
	assert.True(t, wrapper.IsMFAEnabled("user5"))
}

// Test wrapper authenticator getters
func TestMFAWrapper_GetAuthenticators(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	assert.Same(t, primary, wrapper.GetPrimaryAuthenticator())
	assert.Same(t, mfaAuth, wrapper.GetMFAAuthenticator())
}

// Test MFAModeGroupBased
func TestMFAWrapper_GroupBasedMFA(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	factory := auth.NewFactory()

	// Create primary authenticator with a user in groups
	primary, err := factory.Create(auth.ProviderConfig{
		Name:    "primary",
		Type:    "native",
		Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{
					"username":      "admin",
					"password_hash": passwordHash,
					"groups":        []string{"admins", "developers"},
				},
				{
					"username":      "regularuser",
					"password_hash": passwordHash,
					"groups":        []string{"users"},
				},
			},
		},
	})
	require.NoError(t, err)

	// Create MFA authenticator
	mfaAuth, err := factory.Create(auth.ProviderConfig{
		Name:    "totp",
		Type:    "totp",
		Enabled: true,
		Config: map[string]any{
			"secrets": []map[string]any{
				{"username": "admin", "secret": totpSecret},
				{"username": "regularuser", "secret": totpSecret},
			},
		},
	})
	require.NoError(t, err)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeGroupBased,
		MFAGroups:       []string{"admins", "security"},
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Admin user (in 'admins' group) should require MFA
	_, err = wrapper.Authenticate(context.Background(), "admin", "password")
	assert.Error(t, err) // MFA required but not provided

	// Admin with MFA code should succeed
	user, err := wrapper.Authenticate(context.Background(), "admin", "password"+totpCode)
	require.NoError(t, err)
	assert.Equal(t, "admin", user.Username)

	// Regular user (not in 'admins' or 'security') should NOT require MFA
	user, err = wrapper.Authenticate(context.Background(), "regularuser", "password")
	require.NoError(t, err)
	assert.Equal(t, "regularuser", user.Username)
}

// Test MFA required but no code provided (ErrMFARequired)
func TestMFAWrapper_MFARequiredNoCode(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Password only, no OTP appended - should fail with MFA required error
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password")
	assert.Error(t, err)
	assert.ErrorIs(t, err, mfa.ErrMFARequired)
}

// Test separated format with wrong code length
func TestMFAWrapper_SeparatedFormatWrongCodeLength(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatSeparated,
		Separator:       ":",
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Code is wrong length (5 instead of 6), should be treated as no code
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password:12345")
	assert.Error(t, err)
}

// Test separated format with no separator in password
func TestMFAWrapper_SeparatedFormatNoSeparator(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatSeparated,
		Separator:       ":",
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// No separator in password - should be treated as no code
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password")
	assert.Error(t, err)
}

// Test concatenated format with non-numeric suffix
func TestMFAWrapper_ConcatenatedFormatNonNumericSuffix(t *testing.T) {
	passwordHash, err := auth.HashPassword("password123abc")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Suffix is not numeric ("123abc"), so entire string is treated as password
	// This means MFA required but not provided
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password123abc")
	assert.Error(t, err)
}

// Test NewWrapper with defaults
func TestMFAWrapper_NewWrapperDefaults(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	// Create with minimal config to test defaults
	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		// No Separator, MFACodeLength, PasswordFormat, MFARequired set
	}, primary, mfaAuth)
	require.NoError(t, err)
	assert.NotNil(t, wrapper)
}

// Test PerUser mode with MFA enabled
func TestMFAWrapper_PerUserModeWithMFAEnabled(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModePerUser,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Enable MFA for user
	wrapper.EnableMFA("testuser")

	// User with MFA enabled should require MFA
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password")
	assert.Error(t, err)

	// With valid MFA code should succeed
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password"+totpCode)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "true", user.Metadata["mfa_verified"])
}

// Test plugin.Create error path
func TestMFAWrapperPlugin_CreateError(t *testing.T) {
	plugin, ok := auth.GetPlugin("mfa_wrapper")
	require.True(t, ok)

	// Test with nil config - should error
	_, err := plugin.Create(nil)
	assert.Error(t, err)

	// Test with missing primary_provider - should error
	_, err = plugin.Create(map[string]any{
		"mfa_type": "totp",
	})
	assert.Error(t, err)

	// Test with invalid mfa_required - should error
	_, err = plugin.Create(map[string]any{
		"primary_provider": "ldap",
		"mfa_required":     "invalid_mode",
	})
	assert.Error(t, err)

	// Test with invalid password_format - should error
	_, err = plugin.Create(map[string]any{
		"primary_provider": "ldap",
		"password_format":  "invalid_format",
	})
	assert.Error(t, err)
}

// Test splitPassword with unknown password format (default case)
func TestMFAWrapper_SplitPasswordUnknownFormat(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	// Create wrapper with an unknown password format
	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormat("unknown_format"), // Invalid format
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Authenticate should fail because splitPassword returns error for unknown format
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown password format")
}

// Test isMFARequired with unknown MFA mode (default case)
func TestMFAWrapper_UnknownMFAMode(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	// Create wrapper with an unknown MFA mode
	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAMode("unknown_mode"), // Invalid mode - default case returns true
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Unknown mode defaults to requiring MFA (returns true)
	// So without MFA code, it should fail
	_, err = wrapper.Authenticate(context.Background(), "testuser", "password")
	assert.Error(t, err)

	// With valid MFA code should succeed
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password"+totpCode)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

// Test Authenticate with nil metadata on userInfo
func TestMFAWrapper_AuthenticateNilMetadata(t *testing.T) {
	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	// Create a mock authenticator that returns nil metadata
	factory := auth.NewFactory()

	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	// Create primary authenticator that returns user without metadata
	primary, err := factory.Create(auth.ProviderConfig{
		Name:    "primary",
		Type:    "native",
		Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{
					"username":      "testuser",
					"password_hash": passwordHash,
					// No groups or metadata
				},
			},
		},
	})
	require.NoError(t, err)

	// Create MFA authenticator
	mfaAuth, err := factory.Create(auth.ProviderConfig{
		Name:    "totp",
		Type:    "totp",
		Enabled: true,
		Config: map[string]any{
			"secrets": []map[string]any{
				{"username": "testuser", "secret": totpSecret},
			},
		},
	})
	require.NoError(t, err)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Authenticate should initialize metadata
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password"+totpCode)
	require.NoError(t, err)
	assert.NotNil(t, user.Metadata)
	assert.Equal(t, "true", user.Metadata["mfa_verified"])
}

// Test separated format with custom multi-char separator
func TestMFAWrapper_SeparatedFormatMultiCharSeparator(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	totpCode := generateTOTP(totpSecret, time.Now())

	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModeAlways,
		PasswordFormat:  mfa.PasswordFormatSeparated,
		Separator:       "::",
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test with multi-char separator
	user, err := wrapper.Authenticate(context.Background(), "testuser", "password::"+totpCode)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

// Test concurrent MFA user operations
func TestMFAWrapper_ConcurrentMFAUserOperations(t *testing.T) {
	passwordHash, err := auth.HashPassword("password")
	require.NoError(t, err)

	totpSecret := "JBSWY3DPEHPK3PXP"
	primary, mfaAuth := createTestAuthenticators(t, passwordHash, totpSecret)

	wrapper, err := mfa.NewWrapper(&mfa.Config{
		PrimaryProvider: "primary",
		MFAType:         "totp",
		MFARequired:     mfa.MFAModePerUser,
		PasswordFormat:  mfa.PasswordFormatConcatenated,
		MFACodeLength:   6,
	}, primary, mfaAuth)
	require.NoError(t, err)

	// Test concurrent access (should not panic due to mutex)
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		username := fmt.Sprintf("user%d", i)
		go func(u string) {
			wrapper.EnableMFA(u)
			_ = wrapper.IsMFAEnabled(u)
			wrapper.DisableMFA(u)
			done <- true
		}(username)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
