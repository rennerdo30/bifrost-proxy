package auth_test

import (
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ldap"
)

func createLDAPAuthenticator(t *testing.T, config map[string]any) (auth.Authenticator, error) {
	t.Helper()
	factory := auth.NewFactory()
	return factory.Create(auth.ProviderConfig{
		Name:    "ldap-test",
		Type:    "ldap",
		Enabled: true,
		Config:  config,
	})
}

func TestLDAPAuthenticator_MissingURL(t *testing.T) {
	_, err := createLDAPAuthenticator(t, map[string]any{
		"base_dn": "dc=example,dc=com",
	})
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestLDAPAuthenticator_MissingBaseDN(t *testing.T) {
	_, err := createLDAPAuthenticator(t, map[string]any{
		"url": "ldap://localhost:389",
	})
	if err == nil {
		t.Fatal("expected error for missing base_dn")
	}
}

func TestLDAPAuthenticator_ValidConfig(t *testing.T) {
	authenticator, err := createLDAPAuthenticator(t, map[string]any{
		"url":     "ldap://localhost:389",
		"base_dn": "dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("failed to create LDAP authenticator: %v", err)
	}

	if authenticator.Name() != "ldap" {
		t.Errorf("expected Name()=ldap, got %s", authenticator.Name())
	}
	if authenticator.Type() != "ldap" {
		t.Errorf("expected Type()=ldap, got %s", authenticator.Type())
	}
}

func TestLDAPAuthenticator_CustomConfig(t *testing.T) {
	authenticator, err := createLDAPAuthenticator(t, map[string]any{
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
	})
	if err != nil {
		t.Fatalf("failed to create LDAP authenticator with custom config: %v", err)
	}

	if authenticator == nil {
		t.Fatal("authenticator should not be nil")
	}
}

func TestLDAPPlugin_Registration(t *testing.T) {
	// Verify LDAP plugin is registered
	plugin, ok := auth.GetPlugin("ldap")
	if !ok {
		t.Fatal("ldap plugin not registered")
	}
	if plugin.Type() != "ldap" {
		t.Errorf("expected plugin type ldap, got %s", plugin.Type())
	}
	if plugin.Description() == "" {
		t.Error("plugin description should not be empty")
	}
}

func TestLDAPPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("ldap")
	if !ok {
		t.Fatal("ldap plugin not registered")
	}

	// Test invalid config - missing required fields
	err := plugin.ValidateConfig(map[string]any{})
	if err == nil {
		t.Error("expected validation error for empty config")
	}

	// Test valid config
	err = plugin.ValidateConfig(map[string]any{
		"url":     "ldap://localhost:389",
		"base_dn": "dc=example,dc=com",
	})
	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestLDAPPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("ldap")
	if !ok {
		t.Fatal("ldap plugin not registered")
	}

	defaults := plugin.DefaultConfig()
	if defaults == nil {
		t.Fatal("default config should not be nil")
	}

	// Check some expected default keys exist
	if _, ok := defaults["url"]; !ok {
		t.Error("default config should have 'url' key")
	}
	if _, ok := defaults["base_dn"]; !ok {
		t.Error("default config should have 'base_dn' key")
	}
}

func TestLDAPPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("ldap")
	if !ok {
		t.Fatal("ldap plugin not registered")
	}

	schema := plugin.ConfigSchema()
	if schema == "" {
		t.Error("config schema should not be empty")
	}
}

// Note: Testing actual LDAP authentication requires an LDAP server.
// These tests cover configuration validation and plugin registration.
// Integration tests with a real LDAP server would be in a separate test file
// with a build tag like //go:build integration
