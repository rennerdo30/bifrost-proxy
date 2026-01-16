package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAP search limits to prevent resource exhaustion
const (
	ldapSearchTimeLimit = 30   // seconds
	ldapSearchSizeLimit = 1000 // max entries
	ldapGroupSizeLimit  = 100  // max groups per user
)

// LDAPAuthenticator provides LDAP authentication.
type LDAPAuthenticator struct {
	config LDAPConfig
}

// LDAPConfig holds LDAP authentication configuration.
type LDAPConfig struct {
	URL                string `yaml:"url"`
	BaseDN             string `yaml:"base_dn"`
	BindDN             string `yaml:"bind_dn"`
	BindPassword       string `yaml:"bind_password"`
	UserFilter         string `yaml:"user_filter"`         // e.g., "(uid=%s)"
	GroupFilter        string `yaml:"group_filter"`        // e.g., "(memberUid=%s)"
	RequireGroup       string `yaml:"require_group"`       // Optional group requirement
	UserAttribute      string `yaml:"user_attribute"`      // Default: "uid"
	EmailAttribute     string `yaml:"email_attribute"`     // Default: "mail"
	FullNameAttribute  string `yaml:"full_name_attribute"` // Default: "cn"
	GroupAttribute     string `yaml:"group_attribute"`     // Default: "cn"
	TLS                bool   `yaml:"tls"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// NewLDAPAuthenticator creates a new LDAP authenticator.
func NewLDAPAuthenticator(cfg LDAPConfig) (*LDAPAuthenticator, error) {
	if cfg.URL == "" {
		return nil, NewAuthError("ldap", "config", fmt.Errorf("URL is required"))
	}
	if cfg.BaseDN == "" {
		return nil, NewAuthError("ldap", "config", fmt.Errorf("base_dn is required"))
	}

	// Set defaults
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(uid=%s)"
	}
	if cfg.UserAttribute == "" {
		cfg.UserAttribute = "uid"
	}
	if cfg.EmailAttribute == "" {
		cfg.EmailAttribute = "mail"
	}
	if cfg.FullNameAttribute == "" {
		cfg.FullNameAttribute = "cn"
	}
	if cfg.GroupAttribute == "" {
		cfg.GroupAttribute = "cn"
	}

	return &LDAPAuthenticator{
		config: cfg,
	}, nil
}

// Authenticate validates credentials against LDAP.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	// Connect to LDAP with context for timeout/cancellation
	conn, err := a.connectWithContext(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account if configured
	if a.config.BindDN != "" {
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return nil, NewAuthError("ldap", "bind", ErrConnectionFailed)
		}
	}

	// Search for user with time limit to prevent resource exhaustion
	filter := fmt.Sprintf(a.config.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,                    // Size limit (only need 1 user)
		ldapSearchTimeLimit,  // Time limit in seconds
		false,
		filter,
		[]string{a.config.UserAttribute, a.config.EmailAttribute, a.config.FullNameAttribute, "dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, NewAuthError("ldap", "search", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewAuthError("ldap", "authenticate", ErrUserNotFound)
	}

	userEntry := result.Entries[0]
	userDN := userEntry.DN

	// Bind as user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return nil, NewAuthError("ldap", "authenticate", ErrInvalidCredentials)
	}

	// Get user groups if group filter is configured
	var groups []string
	if a.config.GroupFilter != "" {
		groups, err = a.getUserGroups(conn, username)
		if err != nil {
			// Log error but don't fail auth
			groups = nil
		}
	}

	// Check required group
	if a.config.RequireGroup != "" {
		found := false
		for _, g := range groups {
			if g == a.config.RequireGroup {
				found = true
				break
			}
		}
		if !found {
			return nil, NewAuthError("ldap", "authenticate", fmt.Errorf("user not in required group: %s", a.config.RequireGroup))
		}
	}

	return &UserInfo{
		Username: username,
		Email:    userEntry.GetAttributeValue(a.config.EmailAttribute),
		FullName: userEntry.GetAttributeValue(a.config.FullNameAttribute),
		Groups:   groups,
	}, nil
}

// connectWithContext establishes a connection to the LDAP server with context support.
func (a *LDAPAuthenticator) connectWithContext(ctx context.Context) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	// Create a context-aware dialer
	dialer := &net.Dialer{
		Timeout: 30 * time.Second, // Connection timeout
	}

	// Build dial options
	dialOpts := []ldap.DialOpt{
		ldap.DialWithDialer(dialer),
	}

	// Add TLS config if needed
	if a.config.TLS || strings.HasPrefix(a.config.URL, "ldaps://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: a.config.InsecureSkipVerify,
		}
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(tlsConfig))
	}

	// Check context before dialing
	select {
	case <-ctx.Done():
		return nil, NewAuthError("ldap", "connect", ctx.Err())
	default:
	}

	conn, err = ldap.DialURL(a.config.URL, dialOpts...)
	if err != nil {
		return nil, NewAuthError("ldap", "connect", err)
	}

	return conn, nil
}

// getUserGroups retrieves groups for a user.
func (a *LDAPAuthenticator) getUserGroups(conn *ldap.Conn, username string) ([]string, error) {
	filter := fmt.Sprintf(a.config.GroupFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		ldapGroupSizeLimit,   // Size limit to prevent memory exhaustion
		ldapSearchTimeLimit,  // Time limit in seconds
		false,
		filter,
		[]string{a.config.GroupAttribute},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, entry := range result.Entries {
		groupName := entry.GetAttributeValue(a.config.GroupAttribute)
		if groupName != "" {
			groups = append(groups, groupName)
		}
	}

	return groups, nil
}

// Name returns the authenticator name.
func (a *LDAPAuthenticator) Name() string {
	return "ldap"
}

// Type returns the authenticator type.
func (a *LDAPAuthenticator) Type() string {
	return "ldap"
}
