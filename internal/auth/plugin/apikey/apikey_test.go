package apikey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/apikey"
)

func createAPIKeyAuthenticator(t *testing.T, cfg map[string]any) auth.Authenticator {
	t.Helper()
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "apikey-test",
		Type:    "apikey",
		Enabled: true,
		Config:  cfg,
	})
	require.NoError(t, err)
	return authenticator
}

// createAPIKeyAuthenticatorTyped creates an authenticator and returns the concrete type for testing internal methods.
func createAPIKeyAuthenticatorTyped(t *testing.T, cfg map[string]any) *apikey.Authenticator {
	t.Helper()
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "apikey-test",
		Type:    "apikey",
		Enabled: true,
		Config:  cfg,
	})
	require.NoError(t, err)
	return authenticator.(*apikey.Authenticator)
}

func TestAPIKeyPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("apikey")
	require.True(t, ok, "apikey plugin not registered")
	assert.Equal(t, "apikey", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

func TestAPIKeyPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("apikey")
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
			name:    "empty keys list should error",
			config:  map[string]any{"keys": []map[string]any{}},
			wantErr: true,
		},
		{
			name: "valid config with plain key",
			config: map[string]any{
				"keys": []map[string]any{
					{"key_plain": "sk_test_123", "name": "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "key missing both key_plain and key_hash",
			config: map[string]any{
				"keys": []map[string]any{
					{"name": "test"},
				},
			},
			wantErr: true,
		},
		{
			name: "key missing name",
			config: map[string]any{
				"keys": []map[string]any{
					{"key_plain": "sk_test_123"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing keys field",
			config: map[string]any{
				"header_name": "X-API-Key",
			},
			wantErr: true,
		},
		{
			name: "keys field is not an array",
			config: map[string]any{
				"keys": "not-an-array",
			},
			wantErr: true,
		},
		{
			name: "keys array contains non-object",
			config: map[string]any{
				"keys": []any{"not-an-object"},
			},
			wantErr: true,
		},
		{
			name: "invalid expires_at format",
			config: map[string]any{
				"keys": []map[string]any{
					{
						"name":       "test",
						"key_plain":  "sk_test_123",
						"expires_at": "not-a-date",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid config with expiration date",
			config: map[string]any{
				"keys": []map[string]any{
					{
						"name":       "test",
						"key_plain":  "sk_test_123",
						"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with disabled key",
			config: map[string]any{
				"keys": []map[string]any{
					{
						"name":      "test",
						"key_plain": "sk_test_123",
						"disabled":  true,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with custom header",
			config: map[string]any{
				"header_name": "Authorization",
				"keys": []map[string]any{
					{"key_plain": "sk_test_123", "name": "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with key_hash",
			config: map[string]any{
				"keys": []map[string]any{
					{
						"name":     "test",
						"key_hash": "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4tEVnGX3Z7XqmJzS",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with groups as []any",
			config: map[string]any{
				"keys": []any{
					map[string]any{
						"name":      "test",
						"key_plain": "sk_test_123",
						"groups":    []any{"admin", "users"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with groups as []string",
			config: map[string]any{
				"keys": []map[string]any{
					{
						"name":      "test",
						"key_plain": "sk_test_123",
						"groups":    []string{"admin", "users"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with nil groups",
			config: map[string]any{
				"keys": []map[string]any{
					{
						"name":      "test",
						"key_plain": "sk_test_123",
						"groups":    nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty header_name uses default",
			config: map[string]any{
				"header_name": "",
				"keys": []map[string]any{
					{"key_plain": "sk_test_123", "name": "test"},
				},
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

func TestAPIKeyAuthenticator_Success(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_plain": "sk_live_testkey123",
				"name":      "Test API Key",
				"groups":    []string{"api", "readonly"},
			},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_live_testkey123")
	require.NoError(t, err)
	assert.Equal(t, "Test API Key", user.Username)
	assert.Contains(t, user.Groups, "api")
	assert.Contains(t, user.Groups, "readonly")
	assert.Equal(t, "apikey", user.Metadata["auth_type"])
}

func TestAPIKeyAuthenticator_WithBcryptHash(t *testing.T) {
	// Hash the API key using bcrypt
	keyHash, err := auth.HashPassword("sk_hashed_key")
	require.NoError(t, err)

	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_hash": keyHash,
				"name":     "Hashed Key",
			},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_hashed_key")
	require.NoError(t, err)
	assert.Equal(t, "Hashed Key", user.Username)
}

func TestAPIKeyAuthenticator_InvalidKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_plain": "sk_valid_key",
				"name":      "Valid Key",
			},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "", "sk_invalid_key")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_ExpiredKey(t *testing.T) {
	// Create a key that expired yesterday
	expiredTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_plain":  "sk_expired_key",
				"name":       "Expired Key",
				"expires_at": expiredTime,
			},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "", "sk_expired_key")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_DisabledKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_plain": "sk_disabled_key",
				"name":      "Disabled Key",
				"disabled":  true,
			},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "", "sk_disabled_key")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_EmptyPassword(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_test", "name": "Test"},
		},
	})

	_, err := authenticator.Authenticate(context.Background(), "", "")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_NameAndType(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_test", "name": "Test"},
		},
	})

	assert.Equal(t, "apikey", authenticator.Name())
	assert.Equal(t, "apikey", authenticator.Type())
}

func TestAPIKeyPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("apikey")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, "X-API-Key", defaults["header_name"])
}

func TestAPIKeyPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("apikey")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "keys")
	assert.Contains(t, schema, "header_name")
}

func TestAPIKeyAuthenticator_HeaderName(t *testing.T) {
	// Test default header name
	t.Run("default header name", func(t *testing.T) {
		authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
			"keys": []map[string]any{
				{"key_plain": "sk_test", "name": "Test"},
			},
		})
		assert.Equal(t, "X-API-Key", authenticator.HeaderName())
	})

	// Test custom header name
	t.Run("custom header name", func(t *testing.T) {
		authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
			"header_name": "Authorization",
			"keys": []map[string]any{
				{"key_plain": "sk_test", "name": "Test"},
			},
		})
		assert.Equal(t, "Authorization", authenticator.HeaderName())
	})
}

func TestAPIKeyAuthenticator_AddKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_existing", "name": "Existing"},
		},
	})

	// Initially, the new key should not authenticate
	_, err := authenticator.Authenticate(context.Background(), "", "sk_new_key")
	assert.Error(t, err)

	// Add a new key dynamically
	authenticator.AddKey(&apikey.APIKey{
		Name:     "New Key",
		KeyPlain: "sk_new_key",
		Groups:   []string{"dynamic"},
	})

	// Now the new key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_new_key")
	require.NoError(t, err)
	assert.Equal(t, "New Key", user.Username)
	assert.Contains(t, user.Groups, "dynamic")
}

func TestAPIKeyAuthenticator_RemoveKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_removable", "name": "Removable"},
		},
	})

	// Initially, the key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_removable")
	require.NoError(t, err)
	assert.Equal(t, "Removable", user.Username)

	// Remove the key
	authenticator.RemoveKey("Removable")

	// Now the key should not authenticate
	_, err = authenticator.Authenticate(context.Background(), "", "sk_removable")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_DisableKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_disable_test", "name": "DisableTest"},
		},
	})

	// Initially, the key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_disable_test")
	require.NoError(t, err)
	assert.Equal(t, "DisableTest", user.Username)

	// Disable the key
	disabled := authenticator.DisableKey("DisableTest")
	assert.True(t, disabled)

	// Now the key should not authenticate
	_, err = authenticator.Authenticate(context.Background(), "", "sk_disable_test")
	assert.Error(t, err)

	// Disabling non-existent key should return false
	disabled = authenticator.DisableKey("NonExistent")
	assert.False(t, disabled)
}

func TestAPIKeyAuthenticator_EnableKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_enable_test", "name": "EnableTest", "disabled": true},
		},
	})

	// Initially, the key should not authenticate (disabled)
	_, err := authenticator.Authenticate(context.Background(), "", "sk_enable_test")
	assert.Error(t, err)

	// Enable the key
	enabled := authenticator.EnableKey("EnableTest")
	assert.True(t, enabled)

	// Now the key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_enable_test")
	require.NoError(t, err)
	assert.Equal(t, "EnableTest", user.Username)

	// Enabling non-existent key should return false
	enabled = authenticator.EnableKey("NonExistent")
	assert.False(t, enabled)
}

func TestAPIKeyAuthenticator_AuthenticateByName(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_test_key", "name": "TestKey", "groups": []string{"admin"}},
			{"key_plain": "sk_other_key", "name": "OtherKey", "groups": []string{"user"}},
		},
	})

	// Authenticate by key name
	user, err := authenticator.Authenticate(context.Background(), "TestKey", "sk_test_key")
	require.NoError(t, err)
	assert.Equal(t, "TestKey", user.Username)
	assert.Contains(t, user.Groups, "admin")

	// Wrong password for the named key
	_, err = authenticator.Authenticate(context.Background(), "TestKey", "sk_wrong_key")
	assert.Error(t, err)

	// Non-existent key name
	_, err = authenticator.Authenticate(context.Background(), "NonExistent", "sk_test_key")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_MultipleKeys(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_key_one", "name": "KeyOne", "groups": []string{"group1"}},
			{"key_plain": "sk_key_two", "name": "KeyTwo", "groups": []string{"group2"}},
			{"key_plain": "sk_key_three", "name": "KeyThree", "groups": []string{"group3"}},
		},
	})

	// All keys should authenticate without username (iterating through all)
	user, err := authenticator.Authenticate(context.Background(), "", "sk_key_one")
	require.NoError(t, err)
	assert.Equal(t, "KeyOne", user.Username)

	user, err = authenticator.Authenticate(context.Background(), "", "sk_key_two")
	require.NoError(t, err)
	assert.Equal(t, "KeyTwo", user.Username)

	user, err = authenticator.Authenticate(context.Background(), "", "sk_key_three")
	require.NoError(t, err)
	assert.Equal(t, "KeyThree", user.Username)

	// Non-matching key should fail
	_, err = authenticator.Authenticate(context.Background(), "", "sk_nonexistent")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_MixedHashAndPlainKeys(t *testing.T) {
	// Hash the API key using bcrypt
	keyHash, err := auth.HashPassword("sk_hashed")
	require.NoError(t, err)

	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_plain", "name": "PlainKey"},
			{"key_hash": keyHash, "name": "HashedKey"},
		},
	})

	// Plain key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_plain")
	require.NoError(t, err)
	assert.Equal(t, "PlainKey", user.Username)

	// Hashed key should authenticate
	user, err = authenticator.Authenticate(context.Background(), "", "sk_hashed")
	require.NoError(t, err)
	assert.Equal(t, "HashedKey", user.Username)
}

func TestAPIKeyAuthenticator_InvalidBcryptHash(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_hash": "invalid-hash-format", "name": "InvalidHash"},
		},
	})

	// Authentication should fail with invalid hash
	_, err := authenticator.Authenticate(context.Background(), "", "sk_any_key")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_FutureExpiration(t *testing.T) {
	// Create a key that expires in the future
	futureTime := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_plain":  "sk_future_key",
				"name":       "Future Key",
				"expires_at": futureTime,
			},
		},
	})

	// Key should still authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_future_key")
	require.NoError(t, err)
	assert.Equal(t, "Future Key", user.Username)
}

func TestAPIKeyAuthenticator_GroupsAsAnySlice(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []any{
			map[string]any{
				"key_plain": "sk_test",
				"name":      "TestKey",
				"groups":    []any{"admin", "users"},
			},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_test")
	require.NoError(t, err)
	assert.Equal(t, "TestKey", user.Username)
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
}

func TestAPIKeyAuthenticator_NoGroupsMetadata(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_test", "name": "TestKey"},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_test")
	require.NoError(t, err)
	assert.Equal(t, "TestKey", user.Username)
	assert.Empty(t, user.Groups)
	assert.Equal(t, "apikey", user.Metadata["auth_type"])
}

func TestAPIKeyPlugin_Create_Error(t *testing.T) {
	plugin, ok := auth.GetPlugin("apikey")
	require.True(t, ok)

	// Create with invalid config should error
	_, err := plugin.Create(nil)
	assert.Error(t, err)

	// Create with empty keys should error
	_, err = plugin.Create(map[string]any{"keys": []map[string]any{}})
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_ConcurrentAccess(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_concurrent", "name": "ConcurrentKey"},
			{"key_plain": "sk_stable", "name": "StableKey"},
		},
	})

	// Test concurrent authentication against a stable key that won't be modified
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			user, err := authenticator.Authenticate(context.Background(), "", "sk_stable")
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, "StableKey", user.Username)
			}
		}()
	}

	// Test concurrent add/remove/enable/disable operations on different keys
	// These operations should not panic or cause race conditions
	go func() {
		defer func() { done <- true }()
		authenticator.AddKey(&apikey.APIKey{Name: "Dynamic1", KeyPlain: "sk_dyn1"})
	}()
	go func() {
		defer func() { done <- true }()
		authenticator.DisableKey("ConcurrentKey")
	}()
	go func() {
		defer func() { done <- true }()
		authenticator.EnableKey("ConcurrentKey")
	}()
	go func() {
		defer func() { done <- true }()
		authenticator.RemoveKey("Dynamic1")
	}()

	// Wait for all goroutines
	for i := 0; i < 14; i++ {
		<-done
	}
}

func TestToSliceOfMaps_NilInput(t *testing.T) {
	// Test nil keys field (should result in empty slice)
	plugin, ok := auth.GetPlugin("apikey")
	require.True(t, ok)

	// This tests the case where keys is nil
	err := plugin.ValidateConfig(map[string]any{"keys": nil})
	// Should error because at least one key is required
	assert.Error(t, err)
}

func TestToSliceOfMaps_DirectMapSlice(t *testing.T) {
	// Test direct []map[string]any conversion
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_direct", "name": "DirectKey"},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_direct")
	require.NoError(t, err)
	assert.Equal(t, "DirectKey", user.Username)
}

func TestToStringSlice_NonStringItems(t *testing.T) {
	// Test with []any containing non-string items
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []any{
			map[string]any{
				"key_plain": "sk_test",
				"name":      "TestKey",
				"groups":    []any{"valid", 123, "also_valid"}, // Contains non-string
			},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_test")
	require.NoError(t, err)
	// Non-string items should be skipped
	assert.Contains(t, user.Groups, "valid")
	assert.Contains(t, user.Groups, "also_valid")
	assert.NotContains(t, user.Groups, 123)
}

func TestToStringSlice_NonSliceValue(t *testing.T) {
	// Test with groups being a non-slice value
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{
				"key_plain": "sk_test",
				"name":      "TestKey",
				"groups":    "not-a-slice", // Invalid type, should result in nil groups
			},
		},
	})

	user, err := authenticator.Authenticate(context.Background(), "", "sk_test")
	require.NoError(t, err)
	// Groups should be empty when given invalid type
	assert.Empty(t, user.Groups)
}

func TestAPIKeyAuthenticator_WithAddedHashedKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_existing", "name": "Existing"},
		},
	})

	// Add a new key with hash
	keyHash, err := auth.HashPassword("sk_new_hashed")
	require.NoError(t, err)

	authenticator.AddKey(&apikey.APIKey{
		Name:    "NewHashedKey",
		KeyHash: keyHash,
		Groups:  []string{"hashed-group"},
	})

	// The new hashed key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_new_hashed")
	require.NoError(t, err)
	assert.Equal(t, "NewHashedKey", user.Username)
	assert.Contains(t, user.Groups, "hashed-group")
}

func TestAPIKeyAuthenticator_AddKeyWithExpiration(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_existing", "name": "Existing"},
		},
	})

	// Add a key with past expiration
	pastTime := time.Now().Add(-1 * time.Hour)
	authenticator.AddKey(&apikey.APIKey{
		Name:      "ExpiredDynamic",
		KeyPlain:  "sk_expired_dynamic",
		ExpiresAt: &pastTime,
	})

	// The expired key should not authenticate
	_, err := authenticator.Authenticate(context.Background(), "", "sk_expired_dynamic")
	assert.Error(t, err)

	// Add a key with future expiration
	futureTime := time.Now().Add(1 * time.Hour)
	authenticator.AddKey(&apikey.APIKey{
		Name:      "ValidDynamic",
		KeyPlain:  "sk_valid_dynamic",
		ExpiresAt: &futureTime,
	})

	// The valid key should authenticate
	user, err := authenticator.Authenticate(context.Background(), "", "sk_valid_dynamic")
	require.NoError(t, err)
	assert.Equal(t, "ValidDynamic", user.Username)
}

func TestAPIKeyAuthenticator_AddDisabledKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_existing", "name": "Existing"},
		},
	})

	// Add a disabled key
	authenticator.AddKey(&apikey.APIKey{
		Name:     "DisabledDynamic",
		KeyPlain: "sk_disabled_dynamic",
		Disabled: true,
	})

	// The disabled key should not authenticate
	_, err := authenticator.Authenticate(context.Background(), "", "sk_disabled_dynamic")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_RemoveNonExistentKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_existing", "name": "Existing"},
		},
	})

	// Remove a non-existent key (should not panic)
	authenticator.RemoveKey("NonExistent")

	// Existing key should still work
	user, err := authenticator.Authenticate(context.Background(), "", "sk_existing")
	require.NoError(t, err)
	assert.Equal(t, "Existing", user.Username)
}

func TestAPIKeyAuthenticator_AuthenticateByNameWithWrongKey(t *testing.T) {
	authenticator := createAPIKeyAuthenticator(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_key_one", "name": "KeyOne"},
			{"key_plain": "sk_key_two", "name": "KeyTwo"},
		},
	})

	// Try to authenticate with KeyOne's name but KeyTwo's password
	_, err := authenticator.Authenticate(context.Background(), "KeyOne", "sk_key_two")
	assert.Error(t, err)
}

func TestAPIKeyAuthenticator_ValidateKeyWithNoKeyHashOrPlain(t *testing.T) {
	// This tests the edge case where a key might somehow have neither hash nor plain
	authenticator := createAPIKeyAuthenticatorTyped(t, map[string]any{
		"keys": []map[string]any{
			{"key_plain": "sk_existing", "name": "Existing"},
		},
	})

	// Add a key with no hash or plain (edge case)
	authenticator.AddKey(&apikey.APIKey{
		Name:   "NoKey",
		Groups: []string{"test"},
	})

	// Try to authenticate - should fail because no key to compare
	_, err := authenticator.Authenticate(context.Background(), "NoKey", "any_password")
	assert.Error(t, err)
}

func TestAPIKeyPlugin_CreateSuccess(t *testing.T) {
	plugin, ok := auth.GetPlugin("apikey")
	require.True(t, ok)

	// Create with valid config should succeed
	authenticator, err := plugin.Create(map[string]any{
		"header_name": "Custom-Header",
		"keys": []map[string]any{
			{"key_plain": "sk_test", "name": "TestKey", "groups": []string{"admin"}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	// Verify the authenticator works
	user, err := authenticator.Authenticate(context.Background(), "", "sk_test")
	require.NoError(t, err)
	assert.Equal(t, "TestKey", user.Username)
}
