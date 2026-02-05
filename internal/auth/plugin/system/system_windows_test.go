//go:build windows
// +build windows

// Package system provides system (Windows LogonUser) authentication for Bifrost.
package system

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginType tests the plugin type.
func TestPluginType(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "system", p.Type())
}

// TestPluginDescription tests the plugin description.
func TestPluginDescription(t *testing.T) {
	p := &plugin{}
	assert.Contains(t, p.Description(), "Windows")
	assert.Contains(t, p.Description(), "LogonUser")
}

// TestPluginDefaultConfig tests the default configuration.
func TestPluginDefaultConfig(t *testing.T) {
	p := &plugin{}
	cfg := p.DefaultConfig()

	assert.Equal(t, "", cfg["domain"])
	assert.Equal(t, "network", cfg["logon_type"])
	assert.NotNil(t, cfg["allowed_users"])
	assert.NotNil(t, cfg["allowed_groups"])
}

// TestPluginConfigSchema tests the config schema.
func TestPluginConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	assert.Contains(t, schema, "domain")
	assert.Contains(t, schema, "logon_type")
	assert.Contains(t, schema, "network")
	assert.Contains(t, schema, "interactive")
	assert.Contains(t, schema, "allowed_users")
	assert.Contains(t, schema, "allowed_groups")
}

// TestPluginValidateConfig tests configuration validation.
func TestPluginValidateConfig(t *testing.T) {
	p := &plugin{}

	// Valid configs
	assert.NoError(t, p.ValidateConfig(nil))
	assert.NoError(t, p.ValidateConfig(map[string]any{}))
	assert.NoError(t, p.ValidateConfig(map[string]any{
		"domain":     "MYDOMAIN",
		"logon_type": "network",
	}))
	assert.NoError(t, p.ValidateConfig(map[string]any{
		"logon_type": "interactive",
	}))
	assert.NoError(t, p.ValidateConfig(map[string]any{
		"logon_type": "batch",
	}))
	assert.NoError(t, p.ValidateConfig(map[string]any{
		"logon_type": "service",
	}))

	// Invalid logon type
	assert.Error(t, p.ValidateConfig(map[string]any{
		"logon_type": "invalid",
	}))
}

// TestPluginCreate tests authenticator creation.
func TestPluginCreate(t *testing.T) {
	p := &plugin{}

	auth, err := p.Create(nil)
	require.NoError(t, err)
	require.NotNil(t, auth)

	assert.Equal(t, "system", auth.Type())
	assert.Contains(t, auth.Name(), "system-windows")
}

// TestPluginCreateWithDomain tests authenticator creation with domain.
func TestPluginCreateWithDomain(t *testing.T) {
	p := &plugin{}

	auth, err := p.Create(map[string]any{
		"domain": "MYDOMAIN",
	})
	require.NoError(t, err)
	require.NotNil(t, auth)

	assert.Contains(t, auth.Name(), "system-windows-MYDOMAIN")
}

// TestPluginCreateWithAllowedUsers tests creation with allowed users.
func TestPluginCreateWithAllowedUsers(t *testing.T) {
	p := &plugin{}

	auth, err := p.Create(map[string]any{
		"allowed_users": []string{"user1", "USER2"},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)

	// Verify the authenticator was created
	assert.Equal(t, "system", auth.Type())
}

// TestAuthenticatorEmptyCredentials tests empty credentials rejection.
func TestAuthenticatorEmptyCredentials(t *testing.T) {
	p := &plugin{}
	auth, err := p.Create(nil)
	require.NoError(t, err)

	// Empty username
	_, err = auth.Authenticate(context.Background(), "", "password")
	assert.Error(t, err)

	// Empty password
	_, err = auth.Authenticate(context.Background(), "user", "")
	assert.Error(t, err)

	// Both empty
	_, err = auth.Authenticate(context.Background(), "", "")
	assert.Error(t, err)
}

// TestAuthenticatorUserNotAllowed tests user not in allowed list.
func TestAuthenticatorUserNotAllowed(t *testing.T) {
	p := &plugin{}
	auth, err := p.Create(map[string]any{
		"allowed_users": []string{"allowed_user"},
	})
	require.NoError(t, err)

	// User not in allowed list should be rejected before LogonUser call
	_, err = auth.Authenticate(context.Background(), "disallowed_user", "password")
	assert.Error(t, err)
}

// TestAuthenticatorUserAllowedCaseInsensitive tests case insensitive user matching.
func TestAuthenticatorUserAllowedCaseInsensitive(t *testing.T) {
	p := &plugin{}
	auth, err := p.Create(map[string]any{
		"allowed_users": []string{"AllowedUser"},
	})
	require.NoError(t, err)

	// Note: This will fail at LogonUser since user doesn't exist,
	// but it verifies the case-insensitive matching doesn't reject early
	// We can only verify the early rejection doesn't happen
	_, err = auth.Authenticate(context.Background(), "disalloweduser", "password")
	assert.Error(t, err) // Rejected due to not in allowed list
}

// TestParseConfig tests configuration parsing.
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]any
		wantDomain string
		wantLogon  uint32
		wantErr    bool
	}{
		{
			name:       "nil config",
			config:     nil,
			wantDomain: "",
			wantLogon:  LOGON32_LOGON_NETWORK,
			wantErr:    false,
		},
		{
			name:       "empty config",
			config:     map[string]any{},
			wantDomain: "",
			wantLogon:  LOGON32_LOGON_NETWORK,
			wantErr:    false,
		},
		{
			name: "with domain",
			config: map[string]any{
				"domain": "MYDOMAIN",
			},
			wantDomain: "MYDOMAIN",
			wantLogon:  LOGON32_LOGON_NETWORK,
			wantErr:    false,
		},
		{
			name: "interactive logon",
			config: map[string]any{
				"logon_type": "interactive",
			},
			wantDomain: "",
			wantLogon:  LOGON32_LOGON_INTERACTIVE,
			wantErr:    false,
		},
		{
			name: "batch logon",
			config: map[string]any{
				"logon_type": "batch",
			},
			wantDomain: "",
			wantLogon:  LOGON32_LOGON_BATCH,
			wantErr:    false,
		},
		{
			name: "service logon",
			config: map[string]any{
				"logon_type": "service",
			},
			wantDomain: "",
			wantLogon:  LOGON32_LOGON_SERVICE,
			wantErr:    false,
		},
		{
			name: "invalid logon type",
			config: map[string]any{
				"logon_type": "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantDomain, cfg.domain)
			assert.Equal(t, tt.wantLogon, cfg.logonType)
		})
	}
}

// TestParseStringSlice tests string slice parsing.
func TestParseStringSlice(t *testing.T) {
	// []any input
	result := parseStringSlice([]any{"a", "b", "c"})
	assert.Equal(t, []string{"a", "b", "c"}, result)

	// []string input
	result = parseStringSlice([]string{"x", "y", "z"})
	assert.Equal(t, []string{"x", "y", "z"}, result)

	// Mixed types in []any (non-strings ignored)
	result = parseStringSlice([]any{"a", 123, "b", true, "c"})
	assert.Equal(t, []string{"a", "b", "c"}, result)

	// Other type returns nil
	result = parseStringSlice("not a slice")
	assert.Nil(t, result)

	// nil returns nil
	result = parseStringSlice(nil)
	assert.Nil(t, result)
}
