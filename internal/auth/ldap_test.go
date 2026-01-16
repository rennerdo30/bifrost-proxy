package auth

import (
	"testing"
)

func TestNewLDAPAuthenticator_MissingURL(t *testing.T) {
	cfg := LDAPConfig{
		BaseDN: "dc=example,dc=com",
	}

	_, err := NewLDAPAuthenticator(cfg)
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestNewLDAPAuthenticator_MissingBaseDN(t *testing.T) {
	cfg := LDAPConfig{
		URL: "ldap://localhost:389",
	}

	_, err := NewLDAPAuthenticator(cfg)
	if err == nil {
		t.Fatal("expected error for missing base_dn")
	}
}

func TestNewLDAPAuthenticator_Defaults(t *testing.T) {
	cfg := LDAPConfig{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	auth, err := NewLDAPAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator failed: %v", err)
	}

	// Check defaults are applied
	if auth.config.UserFilter != "(uid=%s)" {
		t.Errorf("expected default UserFilter=(uid=%%s), got %s", auth.config.UserFilter)
	}
	if auth.config.UserAttribute != "uid" {
		t.Errorf("expected default UserAttribute=uid, got %s", auth.config.UserAttribute)
	}
	if auth.config.EmailAttribute != "mail" {
		t.Errorf("expected default EmailAttribute=mail, got %s", auth.config.EmailAttribute)
	}
	if auth.config.FullNameAttribute != "cn" {
		t.Errorf("expected default FullNameAttribute=cn, got %s", auth.config.FullNameAttribute)
	}
	if auth.config.GroupAttribute != "cn" {
		t.Errorf("expected default GroupAttribute=cn, got %s", auth.config.GroupAttribute)
	}
}

func TestNewLDAPAuthenticator_CustomConfig(t *testing.T) {
	cfg := LDAPConfig{
		URL:               "ldaps://ldap.example.com:636",
		BaseDN:            "ou=users,dc=example,dc=com",
		BindDN:            "cn=admin,dc=example,dc=com",
		BindPassword:      "secret",
		UserFilter:        "(sAMAccountName=%s)",
		GroupFilter:       "(member=%s)",
		RequireGroup:      "CN=VPNUsers,OU=Groups,DC=example,DC=com",
		UserAttribute:     "sAMAccountName",
		EmailAttribute:    "userPrincipalName",
		FullNameAttribute: "displayName",
		GroupAttribute:    "name",
		TLS:               true,
	}

	auth, err := NewLDAPAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator failed: %v", err)
	}

	if auth.config.URL != "ldaps://ldap.example.com:636" {
		t.Error("URL not set correctly")
	}
	if auth.config.UserFilter != "(sAMAccountName=%s)" {
		t.Error("UserFilter not preserved")
	}
	if auth.config.RequireGroup != "CN=VPNUsers,OU=Groups,DC=example,DC=com" {
		t.Error("RequireGroup not set")
	}
}

func TestLDAPAuthenticator_Name(t *testing.T) {
	cfg := LDAPConfig{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	auth, _ := NewLDAPAuthenticator(cfg)
	if auth.Name() != "ldap" {
		t.Errorf("expected Name()=ldap, got %s", auth.Name())
	}
}

func TestLDAPAuthenticator_Type(t *testing.T) {
	cfg := LDAPConfig{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	auth, _ := NewLDAPAuthenticator(cfg)
	if auth.Type() != "ldap" {
		t.Errorf("expected Type()=ldap, got %s", auth.Type())
	}
}

func TestLDAPConfig_StructFields(t *testing.T) {
	cfg := LDAPConfig{
		URL:                "ldap://localhost:389",
		BaseDN:             "dc=example,dc=com",
		BindDN:             "cn=admin",
		BindPassword:       "secret",
		UserFilter:         "(uid=%s)",
		GroupFilter:        "(memberUid=%s)",
		RequireGroup:       "admin",
		UserAttribute:      "uid",
		EmailAttribute:     "mail",
		FullNameAttribute:  "cn",
		GroupAttribute:     "cn",
		TLS:                true,
		InsecureSkipVerify: true,
	}

	if cfg.URL != "ldap://localhost:389" {
		t.Error("URL field mismatch")
	}
	if cfg.BaseDN != "dc=example,dc=com" {
		t.Error("BaseDN field mismatch")
	}
	if !cfg.TLS {
		t.Error("TLS field mismatch")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify field mismatch")
	}
}

func TestLdapSearchLimits(t *testing.T) {
	// Verify constants are set to reasonable values
	if ldapSearchTimeLimit < 1 {
		t.Error("ldapSearchTimeLimit should be at least 1 second")
	}
	if ldapSearchSizeLimit < 1 {
		t.Error("ldapSearchSizeLimit should be at least 1")
	}
	if ldapGroupSizeLimit < 1 {
		t.Error("ldapGroupSizeLimit should be at least 1")
	}
}

// Note: Testing actual LDAP authentication requires an LDAP server.
// These tests cover configuration validation and defaults.
// Integration tests with a real LDAP server would be in a separate test file
// with a build tag like //go:build integration
