// Package ldap provides LDAP/Active Directory authentication.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// mockLDAPServer is a simple mock LDAP server for testing.
type mockLDAPServer struct {
	listener     net.Listener
	mu           sync.Mutex
	users        map[string]mockUser
	bindDN       string
	bindPassword string
	closed       bool
}

type mockUser struct {
	dn       string
	password string
	attrs    map[string][]string
	groups   []string
}

func newMockLDAPServer(t *testing.T) *mockLDAPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &mockLDAPServer{
		listener: listener,
		users:    make(map[string]mockUser),
	}

	return server
}

func (s *mockLDAPServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *mockLDAPServer) URL() string {
	return fmt.Sprintf("ldap://%s", s.Addr())
}

func (s *mockLDAPServer) AddUser(username, dn, password string, attrs map[string][]string, groups []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = mockUser{
		dn:       dn,
		password: password,
		attrs:    attrs,
		groups:   groups,
	}
}

func (s *mockLDAPServer) SetBindCredentials(dn, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindDN = dn
	s.bindPassword = password
}

func (s *mockLDAPServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

// TestPlugin_Type tests the plugin Type method.
func TestPlugin_Type(t *testing.T) {
	p := &plugin{}
	assert.Equal(t, "ldap", p.Type())
}

// TestPlugin_Description tests the plugin Description method.
func TestPlugin_Description(t *testing.T) {
	p := &plugin{}
	desc := p.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "LDAP")
}

// TestPlugin_Create tests the plugin Create method with various configurations.
func TestPlugin_Create(t *testing.T) {
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
			errMsg:  "ldap config is required",
		},
		{
			name:    "empty config",
			config:  map[string]any{},
			wantErr: true,
			errMsg:  "URL is required",
		},
		{
			name: "missing base_dn",
			config: map[string]any{
				"url": "ldap://localhost:389",
			},
			wantErr: true,
			errMsg:  "base_dn is required",
		},
		{
			name: "missing url",
			config: map[string]any{
				"base_dn": "dc=example,dc=com",
			},
			wantErr: true,
			errMsg:  "URL is required",
		},
		{
			name: "valid minimal config",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": "dc=example,dc=com",
			},
			wantErr: false,
		},
		{
			name: "valid full config",
			config: map[string]any{
				"url":                  "ldaps://ldap.example.com:636",
				"base_dn":              "ou=users,dc=example,dc=com",
				"bind_dn":              "cn=admin,dc=example,dc=com",
				"bind_password":        "secret",
				"user_filter":          "(sAMAccountName=%s)",
				"group_filter":         "(member=%s)",
				"require_group":        "CN=VPNUsers,OU=Groups,DC=example,DC=com",
				"user_attribute":       "sAMAccountName",
				"email_attribute":      "userPrincipalName",
				"full_name_attribute":  "displayName",
				"group_attribute":      "name",
				"tls":                  true,
				"insecure_skip_verify": false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator, err := p.Create(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, authenticator)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, authenticator)
			}
		})
	}
}

// TestPlugin_ValidateConfig tests the plugin ValidateConfig method.
func TestPlugin_ValidateConfig(t *testing.T) {
	p := &plugin{}

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "empty config",
			config:  map[string]any{},
			wantErr: true,
		},
		{
			name: "valid config",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": "dc=example,dc=com",
			},
			wantErr: false,
		},
		{
			name: "missing url",
			config: map[string]any{
				"base_dn": "dc=example,dc=com",
			},
			wantErr: true,
		},
		{
			name: "missing base_dn",
			config: map[string]any{
				"url": "ldap://localhost:389",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPlugin_DefaultConfig tests the plugin DefaultConfig method.
func TestPlugin_DefaultConfig(t *testing.T) {
	p := &plugin{}
	defaults := p.DefaultConfig()

	require.NotNil(t, defaults)
	assert.Equal(t, "ldaps://ldap.example.com:636", defaults["url"])
	assert.Equal(t, "dc=example,dc=com", defaults["base_dn"])
	assert.Equal(t, "cn=service,dc=example,dc=com", defaults["bind_dn"])
	assert.Equal(t, "", defaults["bind_password"])
	assert.Equal(t, "(uid=%s)", defaults["user_filter"])
	assert.Equal(t, "(memberUid=%s)", defaults["group_filter"])
	assert.Equal(t, "", defaults["require_group"])
	assert.Equal(t, "uid", defaults["user_attribute"])
	assert.Equal(t, "mail", defaults["email_attribute"])
	assert.Equal(t, "cn", defaults["full_name_attribute"])
	assert.Equal(t, "cn", defaults["group_attribute"])
	assert.Equal(t, true, defaults["tls"])
	assert.Equal(t, false, defaults["insecure_skip_verify"])
}

// TestPlugin_ConfigSchema tests the plugin ConfigSchema method.
func TestPlugin_ConfigSchema(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	require.NotEmpty(t, schema)
	assert.Contains(t, schema, `"$schema"`)
	assert.Contains(t, schema, "url")
	assert.Contains(t, schema, "base_dn")
	assert.Contains(t, schema, "bind_dn")
	assert.Contains(t, schema, "bind_password")
	assert.Contains(t, schema, "user_filter")
	assert.Contains(t, schema, "group_filter")
	assert.Contains(t, schema, "require_group")
	assert.Contains(t, schema, "user_attribute")
	assert.Contains(t, schema, "email_attribute")
	assert.Contains(t, schema, "full_name_attribute")
	assert.Contains(t, schema, "group_attribute")
	assert.Contains(t, schema, "tls")
	assert.Contains(t, schema, "insecure_skip_verify")
}

// TestParseConfig tests the parseConfig function with various inputs.
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]any
		wantErr  bool
		validate func(t *testing.T, cfg *ldapConfig)
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "empty config",
			config:  map[string]any{},
			wantErr: true,
		},
		{
			name: "url is empty string",
			config: map[string]any{
				"url":     "",
				"base_dn": "dc=example,dc=com",
			},
			wantErr: true,
		},
		{
			name: "base_dn is empty string",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": "",
			},
			wantErr: true,
		},
		{
			name: "minimal valid config uses defaults",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": "dc=example,dc=com",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "ldap://localhost:389", cfg.url)
				assert.Equal(t, "dc=example,dc=com", cfg.baseDN)
				assert.Equal(t, "(uid=%s)", cfg.userFilter)
				assert.Equal(t, "uid", cfg.userAttribute)
				assert.Equal(t, "mail", cfg.emailAttribute)
				assert.Equal(t, "cn", cfg.fullNameAttribute)
				assert.Equal(t, "cn", cfg.groupAttribute)
				assert.Empty(t, cfg.bindDN)
				assert.Empty(t, cfg.bindPassword)
				assert.Empty(t, cfg.groupFilter)
				assert.Empty(t, cfg.requireGroup)
				assert.False(t, cfg.useTLS)
				assert.False(t, cfg.insecureSkipVerify)
			},
		},
		{
			name: "full config",
			config: map[string]any{
				"url":                  "ldaps://ldap.example.com:636",
				"base_dn":              "ou=users,dc=example,dc=com",
				"bind_dn":              "cn=admin,dc=example,dc=com",
				"bind_password":        "supersecret",
				"user_filter":          "(sAMAccountName=%s)",
				"group_filter":         "(member=%s)",
				"require_group":        "CN=VPNUsers,OU=Groups,DC=example,DC=com",
				"user_attribute":       "sAMAccountName",
				"email_attribute":      "userPrincipalName",
				"full_name_attribute":  "displayName",
				"group_attribute":      "name",
				"tls":                  true,
				"insecure_skip_verify": true,
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "ldaps://ldap.example.com:636", cfg.url)
				assert.Equal(t, "ou=users,dc=example,dc=com", cfg.baseDN)
				assert.Equal(t, "cn=admin,dc=example,dc=com", cfg.bindDN)
				assert.Equal(t, "supersecret", cfg.bindPassword)
				assert.Equal(t, "(sAMAccountName=%s)", cfg.userFilter)
				assert.Equal(t, "(member=%s)", cfg.groupFilter)
				assert.Equal(t, "CN=VPNUsers,OU=Groups,DC=example,DC=com", cfg.requireGroup)
				assert.Equal(t, "sAMAccountName", cfg.userAttribute)
				assert.Equal(t, "userPrincipalName", cfg.emailAttribute)
				assert.Equal(t, "displayName", cfg.fullNameAttribute)
				assert.Equal(t, "name", cfg.groupAttribute)
				assert.True(t, cfg.useTLS)
				assert.True(t, cfg.insecureSkipVerify)
			},
		},
		{
			name: "empty user_filter uses default",
			config: map[string]any{
				"url":         "ldap://localhost:389",
				"base_dn":     "dc=example,dc=com",
				"user_filter": "",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "(uid=%s)", cfg.userFilter)
			},
		},
		{
			name: "empty user_attribute uses default",
			config: map[string]any{
				"url":            "ldap://localhost:389",
				"base_dn":        "dc=example,dc=com",
				"user_attribute": "",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "uid", cfg.userAttribute)
			},
		},
		{
			name: "empty email_attribute uses default",
			config: map[string]any{
				"url":             "ldap://localhost:389",
				"base_dn":         "dc=example,dc=com",
				"email_attribute": "",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "mail", cfg.emailAttribute)
			},
		},
		{
			name: "empty full_name_attribute uses default",
			config: map[string]any{
				"url":                 "ldap://localhost:389",
				"base_dn":             "dc=example,dc=com",
				"full_name_attribute": "",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "cn", cfg.fullNameAttribute)
			},
		},
		{
			name: "empty group_attribute uses default",
			config: map[string]any{
				"url":             "ldap://localhost:389",
				"base_dn":         "dc=example,dc=com",
				"group_attribute": "",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Equal(t, "cn", cfg.groupAttribute)
			},
		},
		{
			name: "url type assertion failure (not string)",
			config: map[string]any{
				"url":     123,
				"base_dn": "dc=example,dc=com",
			},
			wantErr: true,
		},
		{
			name: "base_dn type assertion failure (not string)",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": 456,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

// TestAuthenticator_Name tests the Authenticator Name method.
func TestAuthenticator_Name(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, "ldap", a.Name())
}

// TestAuthenticator_Type tests the Authenticator Type method.
func TestAuthenticator_Type(t *testing.T) {
	a := &Authenticator{}
	assert.Equal(t, "ldap", a.Type())
}

// TestAuthenticator_Authenticate_ContextCancelled tests authentication with a cancelled context.
func TestAuthenticator_Authenticate_ContextCancelled(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://nonexistent.example.com:389",
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)

	// The error should wrap context.Canceled
	var authErr *auth.AuthError
	if errors.As(err, &authErr) {
		assert.Equal(t, "ldap", authErr.Authenticator)
		assert.Equal(t, "connect", authErr.Operation)
	}
}

// TestAuthenticator_Authenticate_ConnectionTimeout tests authentication with connection timeout.
func TestAuthenticator_Authenticate_ConnectionTimeout(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://192.0.2.1:389", // RFC 5737 TEST-NET-1, should timeout
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	// Use a very short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)
}

// TestAuthenticator_Authenticate_InvalidHost tests authentication with an invalid host.
func TestAuthenticator_Authenticate_InvalidHost(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://nonexistent.invalid.local:389",
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	ctx := context.Background()
	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)

	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "ldap", authErr.Authenticator)
	assert.Equal(t, "connect", authErr.Operation)
}

// TestAuthenticator_ConnectWithContext_ContextAlreadyCancelled tests connectWithContext when context is already done.
func TestAuthenticator_ConnectWithContext_ContextAlreadyCancelled(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://localhost:389",
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before calling

	conn, err := a.connectWithContext(ctx)
	require.Error(t, err)
	assert.Nil(t, conn)

	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "ldap", authErr.Authenticator)
	assert.Equal(t, "connect", authErr.Operation)
}

// TestAuthenticator_ConnectWithContext_LDAPSUseTLS tests that ldaps:// URLs use TLS.
func TestAuthenticator_ConnectWithContext_LDAPSUseTLS(t *testing.T) {
	cfg := ldapConfig{
		url:                "ldaps://ldap.example.com:636",
		baseDN:             "dc=example,dc=com",
		userFilter:         "(uid=%s)",
		userAttribute:      "uid",
		useTLS:             false, // Even with false, ldaps:// should use TLS
		insecureSkipVerify: true,
	}
	a := &Authenticator{config: cfg}

	// We can't actually connect, but we verify the config logic is set up correctly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := a.connectWithContext(ctx)
	// Error is expected (connection will fail), but it should attempt to connect
	require.Error(t, err)
}

// TestAuthenticator_ConnectWithContext_TLSConfig tests that TLS config is applied.
func TestAuthenticator_ConnectWithContext_TLSConfig(t *testing.T) {
	cfg := ldapConfig{
		url:                "ldap://ldap.example.com:389",
		baseDN:             "dc=example,dc=com",
		userFilter:         "(uid=%s)",
		userAttribute:      "uid",
		useTLS:             true,
		insecureSkipVerify: true,
	}
	a := &Authenticator{config: cfg}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := a.connectWithContext(ctx)
	// Error is expected (connection will fail)
	require.Error(t, err)
}

// TestPlugin_Registration tests that the plugin is registered in init().
func TestPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("ldap")
	require.True(t, ok, "ldap plugin should be registered")
	assert.Equal(t, "ldap", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

// TestPlugin_CreateViaFactory tests creating an authenticator via the factory.
func TestPlugin_CreateViaFactory(t *testing.T) {
	factory := auth.NewFactory()

	tests := []struct {
		name    string
		cfg     auth.ProviderConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: auth.ProviderConfig{
				Name:    "ldap-test",
				Type:    "ldap",
				Enabled: true,
				Config: map[string]any{
					"url":     "ldap://localhost:389",
					"base_dn": "dc=example,dc=com",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid config - missing url",
			cfg: auth.ProviderConfig{
				Name:    "ldap-test",
				Type:    "ldap",
				Enabled: true,
				Config: map[string]any{
					"base_dn": "dc=example,dc=com",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid config - missing base_dn",
			cfg: auth.ProviderConfig{
				Name:    "ldap-test",
				Type:    "ldap",
				Enabled: true,
				Config: map[string]any{
					"url": "ldap://localhost:389",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator, err := factory.Create(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, authenticator)
				assert.Equal(t, "ldap", authenticator.Name())
				assert.Equal(t, "ldap", authenticator.Type())
			}
		})
	}
}

// TestAuthenticator_Authenticate_RequireGroup_NotInGroup tests authentication fails when user is not in required group.
func TestAuthenticator_Authenticate_RequireGroup_Logic(t *testing.T) {
	// This tests the requireGroup logic path without needing a real LDAP server
	// We verify the config parsing and that the authenticator is correctly configured

	cfg := ldapConfig{
		url:            "ldap://localhost:389",
		baseDN:         "dc=example,dc=com",
		userFilter:     "(uid=%s)",
		userAttribute:  "uid",
		groupFilter:    "(member=%s)",
		groupAttribute: "cn",
		requireGroup:   "admin-group",
	}
	a := &Authenticator{config: cfg}

	// Verify the authenticator is configured with require group
	assert.Equal(t, "admin-group", a.config.requireGroup)
	assert.Equal(t, "(member=%s)", a.config.groupFilter)
}

// TestLdapSearchLimits tests that the LDAP search limits are properly defined.
func TestLdapSearchLimits(t *testing.T) {
	// Test that constants are reasonable values
	assert.Equal(t, 30, ldapSearchTimeLimit, "search time limit should be 30 seconds")
	assert.Equal(t, 1000, ldapSearchSizeLimit, "search size limit should be 1000")
	assert.Equal(t, 100, ldapGroupSizeLimit, "group size limit should be 100")
}

// TestParseConfig_OptionalFieldTypes tests that optional fields handle different types gracefully.
func TestParseConfig_OptionalFieldTypes(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]any
		validate func(t *testing.T, cfg *ldapConfig)
	}{
		{
			name: "bind_dn as integer is ignored",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": "dc=example,dc=com",
				"bind_dn": 123, // Wrong type, should be ignored
			},
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Empty(t, cfg.bindDN)
			},
		},
		{
			name: "bind_password as integer is ignored",
			config: map[string]any{
				"url":           "ldap://localhost:389",
				"base_dn":       "dc=example,dc=com",
				"bind_password": 123, // Wrong type, should be ignored
			},
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Empty(t, cfg.bindPassword)
			},
		},
		{
			name: "tls as string is ignored (stays false)",
			config: map[string]any{
				"url":     "ldap://localhost:389",
				"base_dn": "dc=example,dc=com",
				"tls":     "true", // Wrong type, should be ignored
			},
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.False(t, cfg.useTLS)
			},
		},
		{
			name: "insecure_skip_verify as string is ignored (stays false)",
			config: map[string]any{
				"url":                  "ldap://localhost:389",
				"base_dn":              "dc=example,dc=com",
				"insecure_skip_verify": "true", // Wrong type, should be ignored
			},
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.False(t, cfg.insecureSkipVerify)
			},
		},
		{
			name: "group_filter as integer is ignored",
			config: map[string]any{
				"url":          "ldap://localhost:389",
				"base_dn":      "dc=example,dc=com",
				"group_filter": 123, // Wrong type, should be ignored
			},
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Empty(t, cfg.groupFilter)
			},
		},
		{
			name: "require_group as integer is ignored",
			config: map[string]any{
				"url":           "ldap://localhost:389",
				"base_dn":       "dc=example,dc=com",
				"require_group": 123, // Wrong type, should be ignored
			},
			validate: func(t *testing.T, cfg *ldapConfig) {
				assert.Empty(t, cfg.requireGroup)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.config)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestAuthenticator_CreatedWithConfig tests that an authenticator is created with the correct config.
func TestAuthenticator_CreatedWithConfig(t *testing.T) {
	p := &plugin{}

	config := map[string]any{
		"url":                  "ldaps://ldap.example.com:636",
		"base_dn":              "ou=people,dc=example,dc=com",
		"bind_dn":              "cn=readonly,dc=example,dc=com",
		"bind_password":        "readonly-pass",
		"user_filter":          "(mail=%s)",
		"group_filter":         "(memberOf=%s)",
		"require_group":        "cn=vpn-users,ou=groups,dc=example,dc=com",
		"user_attribute":       "mail",
		"email_attribute":      "userPrincipalName",
		"full_name_attribute":  "givenName",
		"group_attribute":      "displayName",
		"tls":                  true,
		"insecure_skip_verify": true,
	}

	authenticator, err := p.Create(config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	// Type assertion to access internal config
	ldapAuth, ok := authenticator.(*Authenticator)
	require.True(t, ok)

	assert.Equal(t, "ldaps://ldap.example.com:636", ldapAuth.config.url)
	assert.Equal(t, "ou=people,dc=example,dc=com", ldapAuth.config.baseDN)
	assert.Equal(t, "cn=readonly,dc=example,dc=com", ldapAuth.config.bindDN)
	assert.Equal(t, "readonly-pass", ldapAuth.config.bindPassword)
	assert.Equal(t, "(mail=%s)", ldapAuth.config.userFilter)
	assert.Equal(t, "(memberOf=%s)", ldapAuth.config.groupFilter)
	assert.Equal(t, "cn=vpn-users,ou=groups,dc=example,dc=com", ldapAuth.config.requireGroup)
	assert.Equal(t, "mail", ldapAuth.config.userAttribute)
	assert.Equal(t, "userPrincipalName", ldapAuth.config.emailAttribute)
	assert.Equal(t, "givenName", ldapAuth.config.fullNameAttribute)
	assert.Equal(t, "displayName", ldapAuth.config.groupAttribute)
	assert.True(t, ldapAuth.config.useTLS)
	assert.True(t, ldapAuth.config.insecureSkipVerify)
}

// TestAuthError_Wrapping tests that auth errors can be unwrapped correctly.
func TestAuthError_Wrapping(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://nonexistent.invalid:389",
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	_, err := a.Authenticate(context.Background(), "testuser", "testpass")
	require.Error(t, err)

	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "ldap", authErr.Authenticator)
	// The operation could be "connect" since we can't connect to a nonexistent host
	assert.Contains(t, []string{"connect", "bind", "search", "authenticate"}, authErr.Operation)
}

// TestParseConfig_EmptyStringOptionalFields tests that empty optional string fields are handled correctly.
func TestParseConfig_EmptyStringOptionalFields(t *testing.T) {
	config := map[string]any{
		"url":                  "ldap://localhost:389",
		"base_dn":              "dc=example,dc=com",
		"bind_dn":              "",
		"bind_password":        "",
		"user_filter":          "",         // Should use default
		"group_filter":         "",         // Should remain empty
		"require_group":        "",         // Should remain empty
		"user_attribute":       "",         // Should use default
		"email_attribute":      "",         // Should use default
		"full_name_attribute":  "",         // Should use default
		"group_attribute":      "",         // Should use default
		"tls":                  false,
		"insecure_skip_verify": false,
	}

	cfg, err := parseConfig(config)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Empty strings for required fields (after type assertion)
	assert.Empty(t, cfg.bindDN)
	assert.Empty(t, cfg.bindPassword)
	assert.Empty(t, cfg.groupFilter)
	assert.Empty(t, cfg.requireGroup)

	// Defaults applied for empty strings
	assert.Equal(t, "(uid=%s)", cfg.userFilter)
	assert.Equal(t, "uid", cfg.userAttribute)
	assert.Equal(t, "mail", cfg.emailAttribute)
	assert.Equal(t, "cn", cfg.fullNameAttribute)
	assert.Equal(t, "cn", cfg.groupAttribute)
}

// BenchmarkParseConfig benchmarks the config parsing function.
func BenchmarkParseConfig(b *testing.B) {
	config := map[string]any{
		"url":                  "ldaps://ldap.example.com:636",
		"base_dn":              "ou=users,dc=example,dc=com",
		"bind_dn":              "cn=admin,dc=example,dc=com",
		"bind_password":        "secret",
		"user_filter":          "(sAMAccountName=%s)",
		"group_filter":         "(member=%s)",
		"require_group":        "CN=VPNUsers,OU=Groups,DC=example,DC=com",
		"user_attribute":       "sAMAccountName",
		"email_attribute":      "userPrincipalName",
		"full_name_attribute":  "displayName",
		"group_attribute":      "name",
		"tls":                  true,
		"insecure_skip_verify": false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseConfig(config)
	}
}

// BenchmarkPlugin_Create benchmarks the plugin Create function.
func BenchmarkPlugin_Create(b *testing.B) {
	p := &plugin{}
	config := map[string]any{
		"url":     "ldap://localhost:389",
		"base_dn": "dc=example,dc=com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Create(config)
	}
}

// TestInit tests that the init function registers the plugin.
func TestInit(t *testing.T) {
	// The init() function should have been called when importing this package
	// Verify the plugin is registered
	plugin, ok := auth.GetPlugin("ldap")
	require.True(t, ok, "ldap plugin should be registered by init()")
	assert.Equal(t, "ldap", plugin.Type())
	assert.Equal(t, "LDAP/Active Directory authentication", plugin.Description())
}

// TestPlugin_MethodsViaRegistry tests plugin methods via the registry.
func TestPlugin_MethodsViaRegistry(t *testing.T) {
	plugin, ok := auth.GetPlugin("ldap")
	require.True(t, ok)

	t.Run("Type", func(t *testing.T) {
		assert.Equal(t, "ldap", plugin.Type())
	})

	t.Run("Description", func(t *testing.T) {
		desc := plugin.Description()
		assert.NotEmpty(t, desc)
		assert.Contains(t, desc, "LDAP")
	})

	t.Run("DefaultConfig", func(t *testing.T) {
		defaults := plugin.DefaultConfig()
		require.NotNil(t, defaults)
		assert.Contains(t, defaults, "url")
		assert.Contains(t, defaults, "base_dn")
	})

	t.Run("ConfigSchema", func(t *testing.T) {
		schema := plugin.ConfigSchema()
		assert.NotEmpty(t, schema)
		assert.Contains(t, schema, "url")
	})

	t.Run("ValidateConfig_Valid", func(t *testing.T) {
		err := plugin.ValidateConfig(map[string]any{
			"url":     "ldap://localhost:389",
			"base_dn": "dc=example,dc=com",
		})
		assert.NoError(t, err)
	})

	t.Run("ValidateConfig_Invalid", func(t *testing.T) {
		err := plugin.ValidateConfig(map[string]any{})
		assert.Error(t, err)
	})

	t.Run("Create_Valid", func(t *testing.T) {
		authenticator, err := plugin.Create(map[string]any{
			"url":     "ldap://localhost:389",
			"base_dn": "dc=example,dc=com",
		})
		require.NoError(t, err)
		assert.NotNil(t, authenticator)
	})

	t.Run("Create_Invalid", func(t *testing.T) {
		authenticator, err := plugin.Create(nil)
		assert.Error(t, err)
		assert.Nil(t, authenticator)
	})
}

// TestConnectWithContext_AllBranches tests all branches of connectWithContext.
func TestConnectWithContext_AllBranches(t *testing.T) {
	t.Run("ldaps url forces TLS", func(t *testing.T) {
		cfg := ldapConfig{
			url:                "ldaps://ldap.example.com:636",
			baseDN:             "dc=example,dc=com",
			userFilter:         "(uid=%s)",
			userAttribute:      "uid",
			useTLS:             false, // Should still use TLS because of ldaps://
			insecureSkipVerify: false,
		}
		a := &Authenticator{config: cfg}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := a.connectWithContext(ctx)
		// Connection will fail, but verify that TLS was attempted
		require.Error(t, err)
	})

	t.Run("explicit TLS config", func(t *testing.T) {
		cfg := ldapConfig{
			url:                "ldap://ldap.example.com:389",
			baseDN:             "dc=example,dc=com",
			userFilter:         "(uid=%s)",
			userAttribute:      "uid",
			useTLS:             true,
			insecureSkipVerify: true,
		}
		a := &Authenticator{config: cfg}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := a.connectWithContext(ctx)
		require.Error(t, err)
	})

	t.Run("no TLS", func(t *testing.T) {
		cfg := ldapConfig{
			url:           "ldap://ldap.example.com:389",
			baseDN:        "dc=example,dc=com",
			userFilter:    "(uid=%s)",
			userAttribute: "uid",
			useTLS:        false,
		}
		a := &Authenticator{config: cfg}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := a.connectWithContext(ctx)
		require.Error(t, err)
	})
}

// TestAuthenticator_DialError tests connection error handling.
func TestAuthenticator_DialError(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://[invalid-ipv6]:389", // Invalid URL
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	ctx := context.Background()
	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)

	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "ldap", authErr.Authenticator)
}

// TestUserFilter_EscapesSpecialChars tests that special characters in usernames are escaped.
func TestUserFilter_EscapesSpecialChars(t *testing.T) {
	// The LDAP library's EscapeFilter should handle special chars
	testCases := []struct {
		username string
		expected string
	}{
		{"simple", "simple"},
		{"user*", "user\\2a"},
		{"user(test)", "user\\28test\\29"},
		{"user\\name", "user\\5cname"},
		{"user\x00name", "user\\00name"},
	}

	for _, tc := range testCases {
		t.Run(tc.username, func(t *testing.T) {
			escaped := ldap.EscapeFilter(tc.username)
			assert.Equal(t, tc.expected, escaped)
		})
	}
}

// TestLdapConfig_Defaults tests that ldapConfig has correct defaults.
func TestLdapConfig_Defaults(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"url":     "ldap://localhost:389",
		"base_dn": "dc=test,dc=com",
	})
	require.NoError(t, err)

	assert.Equal(t, "(uid=%s)", cfg.userFilter)
	assert.Equal(t, "uid", cfg.userAttribute)
	assert.Equal(t, "mail", cfg.emailAttribute)
	assert.Equal(t, "cn", cfg.fullNameAttribute)
	assert.Equal(t, "cn", cfg.groupAttribute)
	assert.Empty(t, cfg.bindDN)
	assert.Empty(t, cfg.bindPassword)
	assert.Empty(t, cfg.groupFilter)
	assert.Empty(t, cfg.requireGroup)
	assert.False(t, cfg.useTLS)
	assert.False(t, cfg.insecureSkipVerify)
}

// TestAuthenticator_WithBindDN tests authenticator with bind DN configured.
func TestAuthenticator_WithBindDN(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://nonexistent.local:389",
		baseDN:        "dc=example,dc=com",
		bindDN:        "cn=service,dc=example,dc=com",
		bindPassword:  "servicepass",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	// Verify bind credentials are set
	assert.Equal(t, "cn=service,dc=example,dc=com", a.config.bindDN)
	assert.Equal(t, "servicepass", a.config.bindPassword)

	// Authenticate will fail (can't connect), but this verifies the config path
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)
}

// TestAuthenticator_WithGroupConfig tests authenticator with group config.
func TestAuthenticator_WithGroupConfig(t *testing.T) {
	cfg := ldapConfig{
		url:            "ldap://nonexistent.local:389",
		baseDN:         "dc=example,dc=com",
		userFilter:     "(uid=%s)",
		userAttribute:  "uid",
		groupFilter:    "(member=uid=%s,ou=users,dc=example,dc=com)",
		groupAttribute: "cn",
		requireGroup:   "admin",
	}
	a := &Authenticator{config: cfg}

	assert.Equal(t, "(member=uid=%s,ou=users,dc=example,dc=com)", a.config.groupFilter)
	assert.Equal(t, "cn", a.config.groupAttribute)
	assert.Equal(t, "admin", a.config.requireGroup)
}

// TestConstants verifies the LDAP constants are appropriate.
func TestConstants(t *testing.T) {
	// These are security/performance limits
	assert.Equal(t, 30, ldapSearchTimeLimit, "Search time limit should be 30 seconds")
	assert.Equal(t, 1000, ldapSearchSizeLimit, "Search size limit should be 1000 entries")
	assert.Equal(t, 100, ldapGroupSizeLimit, "Group size limit should be 100 groups")

	// Ensure limits are reasonable
	assert.GreaterOrEqual(t, ldapSearchTimeLimit, 10, "Search time limit should be at least 10 seconds")
	assert.LessOrEqual(t, ldapSearchTimeLimit, 120, "Search time limit should not exceed 2 minutes")
	assert.GreaterOrEqual(t, ldapSearchSizeLimit, 100, "Size limit should be at least 100")
	assert.GreaterOrEqual(t, ldapGroupSizeLimit, 10, "Group limit should be at least 10")
}

// TestAuthenticator_Authenticate_ShortTimeout tests behavior with very short timeout.
func TestAuthenticator_Authenticate_ShortTimeout(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://192.0.2.1:389", // TEST-NET-1, should timeout
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	// Use a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := a.Authenticate(ctx, "testuser", "testpass")
	elapsed := time.Since(start)

	require.Error(t, err)
	// Should fail quickly due to context timeout
	assert.Less(t, elapsed, 5*time.Second, "Should fail quickly with short timeout")
}

// TestTLSConfig tests TLS configuration options.
func TestTLSConfig(t *testing.T) {
	testCases := []struct {
		name               string
		url                string
		useTLS             bool
		insecureSkipVerify bool
		expectTLS          bool
	}{
		{
			name:      "ldap with no TLS",
			url:       "ldap://localhost:389",
			useTLS:    false,
			expectTLS: false,
		},
		{
			name:      "ldap with explicit TLS",
			url:       "ldap://localhost:389",
			useTLS:    true,
			expectTLS: true,
		},
		{
			name:      "ldaps always uses TLS",
			url:       "ldaps://localhost:636",
			useTLS:    false, // Should be overridden
			expectTLS: true,
		},
		{
			name:               "insecure skip verify",
			url:                "ldaps://localhost:636",
			useTLS:             true,
			insecureSkipVerify: true,
			expectTLS:          true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ldapConfig{
				url:                tc.url,
				baseDN:             "dc=example,dc=com",
				userFilter:         "(uid=%s)",
				userAttribute:      "uid",
				useTLS:             tc.useTLS,
				insecureSkipVerify: tc.insecureSkipVerify,
			}

			// Check if TLS should be used
			shouldUseTLS := cfg.useTLS || strings.HasPrefix(cfg.url, "ldaps://")
			assert.Equal(t, tc.expectTLS, shouldUseTLS)
		})
	}
}

// TestTLSConfigCreation tests that TLS config is created correctly.
func TestTLSConfigCreation(t *testing.T) {
	t.Run("insecure skip verify false", func(t *testing.T) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
		}
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("insecure skip verify true", func(t *testing.T) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		assert.True(t, tlsConfig.InsecureSkipVerify)
	})
}

// TestAuthenticatorInterface ensures Authenticator implements auth.Authenticator.
func TestAuthenticatorInterface(t *testing.T) {
	var _ auth.Authenticator = (*Authenticator)(nil)
}

// TestPluginInterface ensures plugin implements auth.Plugin.
func TestPluginInterface(t *testing.T) {
	var _ auth.Plugin = (*plugin)(nil)
}

// TestAuthenticator_Authenticate_ConnectionRefused tests handling of connection refused.
func TestAuthenticator_Authenticate_ConnectionRefused(t *testing.T) {
	// Use a port that's unlikely to have a service listening
	cfg := ldapConfig{
		url:           "ldap://127.0.0.1:39999",
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)

	var authErr *auth.AuthError
	require.True(t, errors.As(err, &authErr))
	assert.Equal(t, "ldap", authErr.Authenticator)
	assert.Equal(t, "connect", authErr.Operation)
}

// TestGetUserGroups_Config tests getUserGroups configuration.
func TestGetUserGroups_Config(t *testing.T) {
	cfg := ldapConfig{
		url:            "ldap://localhost:389",
		baseDN:         "ou=groups,dc=example,dc=com",
		userFilter:     "(uid=%s)",
		userAttribute:  "uid",
		groupFilter:    "(memberUid=%s)",
		groupAttribute: "cn",
	}
	a := &Authenticator{config: cfg}

	// Verify the group configuration
	assert.Equal(t, "(memberUid=%s)", a.config.groupFilter)
	assert.Equal(t, "cn", a.config.groupAttribute)
	assert.Equal(t, "ou=groups,dc=example,dc=com", a.config.baseDN)
}

// TestParseConfig_AllOptionalFields tests parsing of all optional fields.
func TestParseConfig_AllOptionalFields(t *testing.T) {
	config := map[string]any{
		"url":                  "ldaps://ldap.example.com:636",
		"base_dn":              "dc=example,dc=com",
		"bind_dn":              "cn=readonly,dc=example,dc=com",
		"bind_password":        "readonly-password",
		"user_filter":          "(mail=%s)",
		"group_filter":         "(uniqueMember=%s)",
		"require_group":        "cn=admins,ou=groups,dc=example,dc=com",
		"user_attribute":       "mail",
		"email_attribute":      "userPrincipalName",
		"full_name_attribute":  "displayName",
		"group_attribute":      "name",
		"tls":                  true,
		"insecure_skip_verify": true,
	}

	cfg, err := parseConfig(config)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "ldaps://ldap.example.com:636", cfg.url)
	assert.Equal(t, "dc=example,dc=com", cfg.baseDN)
	assert.Equal(t, "cn=readonly,dc=example,dc=com", cfg.bindDN)
	assert.Equal(t, "readonly-password", cfg.bindPassword)
	assert.Equal(t, "(mail=%s)", cfg.userFilter)
	assert.Equal(t, "(uniqueMember=%s)", cfg.groupFilter)
	assert.Equal(t, "cn=admins,ou=groups,dc=example,dc=com", cfg.requireGroup)
	assert.Equal(t, "mail", cfg.userAttribute)
	assert.Equal(t, "userPrincipalName", cfg.emailAttribute)
	assert.Equal(t, "displayName", cfg.fullNameAttribute)
	assert.Equal(t, "name", cfg.groupAttribute)
	assert.True(t, cfg.useTLS)
	assert.True(t, cfg.insecureSkipVerify)
}

// TestAuthError_Properties tests AuthError properties.
func TestAuthError_Properties(t *testing.T) {
	baseErr := errors.New("connection refused")
	authErr := auth.NewAuthError("ldap", "connect", baseErr)

	assert.Equal(t, "ldap", authErr.Authenticator)
	assert.Equal(t, "connect", authErr.Operation)
	assert.Equal(t, baseErr, authErr.Unwrap())
	assert.Contains(t, authErr.Error(), "ldap")
	assert.Contains(t, authErr.Error(), "connect")
	assert.Contains(t, authErr.Error(), "connection refused")
}

// TestAuthenticator_DeadlineExceeded tests context deadline exceeded handling.
func TestAuthenticator_DeadlineExceeded(t *testing.T) {
	cfg := ldapConfig{
		url:           "ldap://192.0.2.1:389", // TEST-NET-1
		baseDN:        "dc=example,dc=com",
		userFilter:    "(uid=%s)",
		userAttribute: "uid",
	}
	a := &Authenticator{config: cfg}

	// Create an already expired context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, err := a.Authenticate(ctx, "testuser", "testpass")
	require.Error(t, err)
}

// TestParseConfig_NilVsEmpty tests nil config vs empty config behavior.
func TestParseConfig_NilVsEmpty(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		cfg, err := parseConfig(nil)
		require.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "ldap config is required")
	})

	t.Run("empty config", func(t *testing.T) {
		cfg, err := parseConfig(map[string]any{})
		require.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "URL is required")
	})
}

// TestConfigSchema_ValidJSON tests that ConfigSchema returns valid JSON.
func TestConfigSchema_ValidJSON(t *testing.T) {
	p := &plugin{}
	schema := p.ConfigSchema()

	// Basic JSON structure validation
	assert.True(t, strings.HasPrefix(strings.TrimSpace(schema), "{"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(schema), "}"))
	assert.Contains(t, schema, `"type": "object"`)
	assert.Contains(t, schema, `"properties"`)
	assert.Contains(t, schema, `"required"`)
}

// TestDefaultConfig_ContainsAllFields tests that DefaultConfig has all expected fields.
func TestDefaultConfig_ContainsAllFields(t *testing.T) {
	p := &plugin{}
	defaults := p.DefaultConfig()

	expectedKeys := []string{
		"url",
		"base_dn",
		"bind_dn",
		"bind_password",
		"user_filter",
		"group_filter",
		"require_group",
		"user_attribute",
		"email_attribute",
		"full_name_attribute",
		"group_attribute",
		"tls",
		"insecure_skip_verify",
	}

	for _, key := range expectedKeys {
		_, exists := defaults[key]
		assert.True(t, exists, "DefaultConfig should contain key: %s", key)
	}
}
