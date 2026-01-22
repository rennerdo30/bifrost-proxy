// Package ldap provides LDAP/Active Directory authentication.
package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// LDAP search limits to prevent resource exhaustion
const (
	ldapSearchTimeLimit = 30   // seconds
	ldapSearchSizeLimit = 1000 // max entries
	ldapGroupSizeLimit  = 100  // max groups per user
)

func init() {
	auth.RegisterPlugin("ldap", &plugin{})
}

// plugin implements the auth.Plugin interface for LDAP authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "ldap"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "LDAP/Active Directory authentication"
}

// Create creates a new LDAPAuthenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	return &Authenticator{config: *cfg}, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"url":                  "ldaps://ldap.example.com:636",
		"base_dn":              "dc=example,dc=com",
		"bind_dn":              "cn=service,dc=example,dc=com",
		"bind_password":        "",
		"user_filter":          "(uid=%s)",
		"group_filter":         "(memberUid=%s)",
		"require_group":        "",
		"user_attribute":       "uid",
		"email_attribute":      "mail",
		"full_name_attribute":  "cn",
		"group_attribute":      "cn",
		"tls":                  true,
		"insecure_skip_verify": false,
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "url": {
      "type": "string",
      "description": "LDAP server URL (ldap:// or ldaps://)"
    },
    "base_dn": {
      "type": "string",
      "description": "Base DN for searches"
    },
    "bind_dn": {
      "type": "string",
      "description": "DN to bind as for searches (optional)"
    },
    "bind_password": {
      "type": "string",
      "description": "Password for bind DN"
    },
    "user_filter": {
      "type": "string",
      "description": "LDAP filter to find users (use %s for username)"
    },
    "group_filter": {
      "type": "string",
      "description": "LDAP filter to find user groups (use %s for username)"
    },
    "require_group": {
      "type": "string",
      "description": "Required group membership for authentication"
    },
    "user_attribute": {
      "type": "string",
      "description": "Attribute for username (default: uid)"
    },
    "email_attribute": {
      "type": "string",
      "description": "Attribute for email (default: mail)"
    },
    "full_name_attribute": {
      "type": "string",
      "description": "Attribute for full name (default: cn)"
    },
    "group_attribute": {
      "type": "string",
      "description": "Attribute for group name (default: cn)"
    },
    "tls": {
      "type": "boolean",
      "description": "Use TLS (default: true for ldaps://)"
    },
    "insecure_skip_verify": {
      "type": "boolean",
      "description": "Skip TLS certificate verification (not recommended)"
    }
  },
  "required": ["url", "base_dn"]
}`
}

type ldapConfig struct {
	url                string
	baseDN             string
	bindDN             string
	bindPassword       string
	userFilter         string
	groupFilter        string
	requireGroup       string
	userAttribute      string
	emailAttribute     string
	fullNameAttribute  string
	groupAttribute     string
	useTLS             bool
	insecureSkipVerify bool
}

func parseConfig(config map[string]any) (*ldapConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("ldap config is required")
	}

	cfg := &ldapConfig{
		userFilter:        "(uid=%s)",
		userAttribute:     "uid",
		emailAttribute:    "mail",
		fullNameAttribute: "cn",
		groupAttribute:    "cn",
	}

	// Required fields
	url, _ := config["url"].(string)
	if url == "" {
		return nil, auth.NewAuthError("ldap", "config", fmt.Errorf("URL is required"))
	}
	cfg.url = url

	baseDN, _ := config["base_dn"].(string)
	if baseDN == "" {
		return nil, auth.NewAuthError("ldap", "config", fmt.Errorf("base_dn is required"))
	}
	cfg.baseDN = baseDN

	// Optional fields
	if bindDN, ok := config["bind_dn"].(string); ok {
		cfg.bindDN = bindDN
	}
	if bindPassword, ok := config["bind_password"].(string); ok {
		cfg.bindPassword = bindPassword
	}
	if userFilter, ok := config["user_filter"].(string); ok && userFilter != "" {
		cfg.userFilter = userFilter
	}
	if groupFilter, ok := config["group_filter"].(string); ok {
		cfg.groupFilter = groupFilter
	}
	if requireGroup, ok := config["require_group"].(string); ok {
		cfg.requireGroup = requireGroup
	}
	if userAttribute, ok := config["user_attribute"].(string); ok && userAttribute != "" {
		cfg.userAttribute = userAttribute
	}
	if emailAttribute, ok := config["email_attribute"].(string); ok && emailAttribute != "" {
		cfg.emailAttribute = emailAttribute
	}
	if fullNameAttribute, ok := config["full_name_attribute"].(string); ok && fullNameAttribute != "" {
		cfg.fullNameAttribute = fullNameAttribute
	}
	if groupAttribute, ok := config["group_attribute"].(string); ok && groupAttribute != "" {
		cfg.groupAttribute = groupAttribute
	}
	if tlsVal, ok := config["tls"].(bool); ok {
		cfg.useTLS = tlsVal
	}
	if insecure, ok := config["insecure_skip_verify"].(bool); ok {
		cfg.insecureSkipVerify = insecure
	}

	return cfg, nil
}

// Authenticator provides LDAP authentication.
type Authenticator struct {
	config ldapConfig
}

// Authenticate validates credentials against LDAP.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	// Connect to LDAP with context for timeout/cancellation
	conn, err := a.connectWithContext(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account if configured
	if a.config.bindDN != "" {
		if err := conn.Bind(a.config.bindDN, a.config.bindPassword); err != nil {
			return nil, auth.NewAuthError("ldap", "bind", auth.ErrConnectionFailed)
		}
	}

	// Search for user with time limit to prevent resource exhaustion
	filter := fmt.Sprintf(a.config.userFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		a.config.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,                   // Size limit (only need 1 user)
		ldapSearchTimeLimit, // Time limit in seconds
		false,
		filter,
		[]string{a.config.userAttribute, a.config.emailAttribute, a.config.fullNameAttribute, "dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, auth.NewAuthError("ldap", "search", err)
	}

	if len(result.Entries) == 0 {
		return nil, auth.NewAuthError("ldap", "authenticate", auth.ErrUserNotFound)
	}

	userEntry := result.Entries[0]
	userDN := userEntry.DN

	// Bind as user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return nil, auth.NewAuthError("ldap", "authenticate", auth.ErrInvalidCredentials)
	}

	// Get user groups if group filter is configured
	var groups []string
	if a.config.groupFilter != "" {
		groups, err = a.getUserGroups(conn, username)
		if err != nil {
			// Log error but don't fail auth
			groups = nil
		}
	}

	// Check required group
	if a.config.requireGroup != "" {
		found := false
		for _, g := range groups {
			if g == a.config.requireGroup {
				found = true
				break
			}
		}
		if !found {
			return nil, auth.NewAuthError("ldap", "authenticate", fmt.Errorf("user not in required group: %s", a.config.requireGroup))
		}
	}

	return &auth.UserInfo{
		Username: username,
		Email:    userEntry.GetAttributeValue(a.config.emailAttribute),
		FullName: userEntry.GetAttributeValue(a.config.fullNameAttribute),
		Groups:   groups,
	}, nil
}

// connectWithContext establishes a connection to the LDAP server with context support.
func (a *Authenticator) connectWithContext(ctx context.Context) (*ldap.Conn, error) {
	// Create a context-aware dialer
	dialer := &net.Dialer{
		Timeout: 30 * time.Second, // Connection timeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	// Build dial options
	dialOpts := []ldap.DialOpt{
		ldap.DialWithDialer(dialer),
	}

	// Add TLS config if needed
	if a.config.useTLS || strings.HasPrefix(a.config.url, "ldaps://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: a.config.insecureSkipVerify,
		}
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(tlsConfig))
	}

	// Check context before dialing
	select {
	case <-ctx.Done():
		return nil, auth.NewAuthError("ldap", "connect", ctx.Err())
	default:
	}

	conn, err := ldap.DialURL(a.config.url, dialOpts...)
	if err != nil {
		return nil, auth.NewAuthError("ldap", "connect", err)
	}

	return conn, nil
}

// getUserGroups retrieves groups for a user.
func (a *Authenticator) getUserGroups(conn *ldap.Conn, username string) ([]string, error) {
	filter := fmt.Sprintf(a.config.groupFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		a.config.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		ldapGroupSizeLimit,  // Size limit to prevent memory exhaustion
		ldapSearchTimeLimit, // Time limit in seconds
		false,
		filter,
		[]string{a.config.groupAttribute},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, entry := range result.Entries {
		groupName := entry.GetAttributeValue(a.config.groupAttribute)
		if groupName != "" {
			groups = append(groups, groupName)
		}
	}

	return groups, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "ldap"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "ldap"
}
