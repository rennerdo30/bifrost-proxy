// Package none provides tests for the "none" authentication plugin.
package none_test

import (
	"context"
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/none"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginRegistration verifies that the plugin is registered via init().
func TestPluginRegistration(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok, "none plugin should be registered")
	assert.NotNil(t, plugin)
}

// TestPluginType verifies the plugin Type() method.
func TestPluginType(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	assert.Equal(t, "none", plugin.Type())
}

// TestPluginDescription verifies the plugin Description() method.
func TestPluginDescription(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	description := plugin.Description()
	assert.NotEmpty(t, description)
	assert.Equal(t, "No authentication - allows all requests", description)
}

// TestPluginCreate verifies that Create() successfully creates an authenticator.
func TestPluginCreate(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

// TestPluginCreateWithEmptyConfig verifies Create() works with empty config.
func TestPluginCreateWithEmptyConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(map[string]any{})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

// TestPluginCreateWithArbitraryConfig verifies Create() works with any config.
func TestPluginCreateWithArbitraryConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	// Even with arbitrary config, none authenticator should be created successfully
	authenticator, err := plugin.Create(map[string]any{
		"some_field": "some_value",
		"number":     42,
		"nested":     map[string]any{"key": "value"},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

// TestPluginValidateConfig verifies that ValidateConfig() always returns nil.
func TestPluginValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	tests := []struct {
		name   string
		config map[string]any
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: map[string]any{},
		},
		{
			name: "arbitrary config",
			config: map[string]any{
				"key1": "value1",
				"key2": 123,
			},
		},
		{
			name: "nested config",
			config: map[string]any{
				"nested": map[string]any{
					"deep": "value",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			assert.NoError(t, err, "ValidateConfig should always return nil for none plugin")
		})
	}
}

// TestPluginDefaultConfig verifies that DefaultConfig() returns nil.
func TestPluginDefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.Nil(t, defaults, "DefaultConfig should return nil for none plugin")
}

// TestPluginConfigSchema verifies the ConfigSchema() method.
func TestPluginConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "$schema")
	assert.Contains(t, schema, "json-schema.org")
	assert.Contains(t, schema, "type")
	assert.Contains(t, schema, "object")
	assert.Contains(t, schema, "additionalProperties")
	assert.Contains(t, schema, "description")
}

// TestAuthenticatorAuthenticate verifies that Authenticate() always succeeds.
func TestAuthenticatorAuthenticate(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	user, err := authenticator.Authenticate(context.Background(), "anyuser", "anypass")
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "anonymous", user.Username)
}

// TestAuthenticatorAuthenticateEmptyCredentials verifies Authenticate() with empty credentials.
func TestAuthenticatorAuthenticateEmptyCredentials(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	user, err := authenticator.Authenticate(context.Background(), "", "")
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "anonymous", user.Username)
}

// TestAuthenticatorAuthenticateVariousInputs verifies Authenticate() with various inputs.
func TestAuthenticatorAuthenticateVariousInputs(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "empty credentials",
			username: "",
			password: "",
		},
		{
			name:     "username only",
			username: "admin",
			password: "",
		},
		{
			name:     "password only",
			username: "",
			password: "secret",
		},
		{
			name:     "both credentials",
			username: "admin",
			password: "secret",
		},
		{
			name:     "special characters",
			username: "user@domain.com",
			password: "p@$$w0rd!#$%",
		},
		{
			name:     "unicode username",
			username: "用户名",
			password: "密码",
		},
		{
			name:     "very long username",
			username: "a" + string(make([]byte, 1000)),
			password: "pass",
		},
		{
			name:     "whitespace credentials",
			username: "   ",
			password: "   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := authenticator.Authenticate(context.Background(), tt.username, tt.password)
			require.NoError(t, err, "Authenticate should always succeed for none authenticator")
			assert.NotNil(t, user)
			assert.Equal(t, "anonymous", user.Username)
		})
	}
}

// TestAuthenticatorAuthenticateWithCancelledContext verifies Authenticate() handles cancelled contexts.
func TestAuthenticatorAuthenticateWithCancelledContext(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// None authenticator should still succeed even with cancelled context
	// since it doesn't use the context for anything
	user, err := authenticator.Authenticate(ctx, "user", "pass")
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "anonymous", user.Username)
}

// TestAuthenticatorName verifies the Name() method.
func TestAuthenticatorName(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	assert.Equal(t, "none", authenticator.Name())
}

// TestAuthenticatorType verifies the Type() method.
func TestAuthenticatorType(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	assert.Equal(t, "none", authenticator.Type())
}

// TestFactoryCreate verifies creating authenticator through the factory.
func TestFactoryCreate(t *testing.T) {
	factory := auth.NewFactory()

	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "none-test",
		Type:    "none",
		Enabled: true,
		Config:  nil,
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
	assert.Equal(t, "none", authenticator.Type())
}

// TestFactoryCreateWithConfig verifies factory create with config map.
func TestFactoryCreateWithConfig(t *testing.T) {
	factory := auth.NewFactory()

	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "none-test",
		Type:    "none",
		Enabled: true,
		Config:  map[string]any{"ignored": "value"},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

// TestUserInfoFields verifies the UserInfo returned by Authenticate().
func TestUserInfoFields(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	authenticator, err := plugin.Create(nil)
	require.NoError(t, err)

	user, err := authenticator.Authenticate(context.Background(), "test", "test")
	require.NoError(t, err)

	// Verify the returned UserInfo structure
	assert.Equal(t, "anonymous", user.Username)
	// None authenticator returns minimal UserInfo without groups, email, etc.
	assert.Empty(t, user.Groups)
	assert.Empty(t, user.Email)
	assert.Empty(t, user.FullName)
	assert.Empty(t, user.Metadata)
}

// TestMultipleAuthenticatorInstances verifies multiple instances work independently.
func TestMultipleAuthenticatorInstances(t *testing.T) {
	plugin, ok := auth.GetPlugin("none")
	require.True(t, ok)

	auth1, err := plugin.Create(nil)
	require.NoError(t, err)

	auth2, err := plugin.Create(nil)
	require.NoError(t, err)

	// Both should work independently
	user1, err := auth1.Authenticate(context.Background(), "user1", "pass1")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", user1.Username)

	user2, err := auth2.Authenticate(context.Background(), "user2", "pass2")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", user2.Username)
}

// TestPluginInRegistry verifies plugin appears in registry listings.
func TestPluginInRegistry(t *testing.T) {
	plugins := auth.ListPlugins()
	assert.Contains(t, plugins, "none")

	allPlugins := auth.GetAllPlugins()
	_, exists := allPlugins["none"]
	assert.True(t, exists)
}

// TestPluginInfo verifies GetPluginInfo returns correct information.
func TestPluginInfo(t *testing.T) {
	info, ok := auth.GetPluginInfo("none")
	require.True(t, ok)

	assert.Equal(t, "none", info.Name)
	assert.Equal(t, "none", info.Type)
	assert.Equal(t, "No authentication - allows all requests", info.Description)
	assert.Nil(t, info.DefaultConfig)
	assert.NotEmpty(t, info.ConfigSchema)
}
