// Package kerberos provides Kerberos/SPNEGO authentication for Bifrost.
// It supports Windows domain authentication via GSSAPI/SPNEGO tokens.
package kerberos

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// ContextKey is a type for context keys used by this package.
type ContextKey string

const (
	// SPNEGOTokenContextKey is the context key for the SPNEGO token.
	SPNEGOTokenContextKey ContextKey = "kerberos_spnego_token" //nolint:gosec // G101: This is a context key name, not a credential
)

func init() {
	auth.RegisterPlugin("kerberos", &plugin{})
}

// plugin implements the auth.Plugin interface for Kerberos authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "kerberos"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "Kerberos/SPNEGO authentication for Windows domain integration"
}

// Create creates a new Kerberos authenticator from the configuration.
func (p *plugin) Create(cfg map[string]any) (auth.Authenticator, error) {
	c, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		config: c,
	}

	// Load keytab
	if err := authenticator.loadKeytab(); err != nil {
		return nil, err
	}

	// Load Kerberos config
	if err := authenticator.loadKrbConfig(); err != nil {
		return nil, err
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(cfg map[string]any) error {
	_, err := parseConfig(cfg)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"keytab_file":       "/etc/bifrost/server.keytab",
		"service_principal": "HTTP/proxy.example.com",
		"realm":             "EXAMPLE.COM",
		"krb5_config_file":  "/etc/krb5.conf",
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "keytab_file": {
      "type": "string",
      "description": "Path to the Kerberos keytab file"
    },
    "keytab_base64": {
      "type": "string",
      "description": "Base64-encoded keytab content (inline)"
    },
    "service_principal": {
      "type": "string",
      "description": "Service principal name (e.g., HTTP/proxy.example.com)"
    },
    "realm": {
      "type": "string",
      "description": "Kerberos realm (e.g., EXAMPLE.COM)"
    },
    "krb5_config_file": {
      "type": "string",
      "description": "Path to krb5.conf file",
      "default": "/etc/krb5.conf"
    },
    "krb5_config": {
      "type": "string",
      "description": "Inline krb5.conf content"
    },
    "kdc_servers": {
      "type": "array",
      "description": "List of KDC servers (overrides krb5.conf)",
      "items": {"type": "string"}
    },
    "strip_realm": {
      "type": "boolean",
      "description": "Strip realm from username (user@REALM -> user)",
      "default": true
    },
    "username_to_lowercase": {
      "type": "boolean",
      "description": "Convert username to lowercase",
      "default": true
    }
  },
  "required": ["service_principal"]
}`
}

// kerberosConfig represents the parsed configuration.
type kerberosConfig struct {
	KeytabFile          string
	KeytabBase64        string
	ServicePrincipal    string
	Realm               string
	Krb5ConfigFile      string
	Krb5Config          string
	KDCServers          []string
	StripRealm          bool
	UsernameToLowercase bool
}

// parseConfig parses the configuration map.
func parseConfig(cfg map[string]any) (*kerberosConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kerberos auth config is required")
	}

	c := &kerberosConfig{
		Krb5ConfigFile:      "/etc/krb5.conf",
		StripRealm:          true,
		UsernameToLowercase: true,
	}

	if keytabFile, ok := cfg["keytab_file"].(string); ok {
		c.KeytabFile = keytabFile
	}

	if keytabBase64, ok := cfg["keytab_base64"].(string); ok {
		c.KeytabBase64 = keytabBase64
	}

	if c.KeytabFile == "" && c.KeytabBase64 == "" {
		return nil, fmt.Errorf("kerberos config: either 'keytab_file' or 'keytab_base64' is required")
	}

	if servicePrincipal, ok := cfg["service_principal"].(string); ok {
		c.ServicePrincipal = servicePrincipal
	}

	if c.ServicePrincipal == "" {
		return nil, fmt.Errorf("kerberos config: 'service_principal' is required")
	}

	if realm, ok := cfg["realm"].(string); ok {
		c.Realm = realm
	}

	if krb5ConfigFile, ok := cfg["krb5_config_file"].(string); ok {
		c.Krb5ConfigFile = krb5ConfigFile
	}

	if krb5Config, ok := cfg["krb5_config"].(string); ok {
		c.Krb5Config = krb5Config
	}

	if kdcServers, ok := cfg["kdc_servers"].([]any); ok {
		for _, s := range kdcServers {
			if server, ok := s.(string); ok {
				c.KDCServers = append(c.KDCServers, server)
			}
		}
	}

	if stripRealm, ok := cfg["strip_realm"].(bool); ok {
		c.StripRealm = stripRealm
	}

	if usernameToLowercase, ok := cfg["username_to_lowercase"].(bool); ok {
		c.UsernameToLowercase = usernameToLowercase
	}

	return c, nil
}

// Authenticator provides Kerberos/SPNEGO authentication.
type Authenticator struct {
	config    *kerberosConfig
	kt        *keytab.Keytab
	krbConfig *config.Config
	mu        sync.RWMutex
}

// Authenticate validates a Kerberos ticket.
// For SPNEGO/Negotiate auth, the SPNEGO token should be passed via context.
// The password parameter can contain a base64-encoded SPNEGO token for convenience.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	// First, check if SPNEGO token is in context
	if token, ok := ctx.Value(SPNEGOTokenContextKey).([]byte); ok && len(token) > 0 {
		return a.validateSPNEGOToken(token)
	}

	// Try to use password as base64-encoded SPNEGO token
	if password != "" && strings.HasPrefix(password, "YII") {
		// Looks like base64-encoded SPNEGO token
		token, err := base64.StdEncoding.DecodeString(password)
		if err == nil {
			return a.validateSPNEGOToken(token)
		}
	}

	// Try standard Kerberos authentication with username/password
	if username != "" && password != "" {
		return a.authenticateWithPassword(ctx, username, password)
	}

	return nil, auth.NewAuthError("kerberos", "authenticate", auth.ErrInvalidCredentials)
}

// validateSPNEGOToken validates a SPNEGO token and extracts user info.
// Note: Full SPNEGO validation requires HTTP handler integration.
// This is a placeholder for direct token validation.
func (a *Authenticator) validateSPNEGOToken(token []byte) (*auth.UserInfo, error) {
	a.mu.RLock()
	kt := a.kt
	a.mu.RUnlock()

	// Create SPNEGO service for HTTP handler integration
	// For direct validation, we need to use the HTTP middleware approach
	_ = spnego.SPNEGOService(kt)
	_ = token

	// SPNEGO tokens should be validated through HTTP middleware
	// Direct token validation is not supported in this simplified implementation
	return nil, auth.NewAuthError("kerberos", "spnego",
		fmt.Errorf("SPNEGO token validation requires HTTP handler integration; use SPNEGOKRB5Authenticate middleware"))
}

// authenticateWithPassword performs Kerberos authentication with username and password.
func (a *Authenticator) authenticateWithPassword(_ context.Context, username, password string) (*auth.UserInfo, error) {
	a.mu.RLock()
	krbConfig := a.krbConfig
	a.mu.RUnlock()

	// Extract realm from username if present
	realm := a.config.Realm
	if idx := strings.Index(username, "@"); idx >= 0 {
		realm = username[idx+1:]
		username = username[:idx]
	}

	// Create Kerberos client
	cl := client.NewWithPassword(username, realm, password, krbConfig)

	// Try to login
	if err := cl.Login(); err != nil {
		return nil, auth.NewAuthError("kerberos", "password", fmt.Errorf("authentication failed: %w", err))
	}
	defer cl.Destroy()

	// Apply username transformations
	transformedUsername := a.transformUsername(username, realm)

	slog.Debug("Kerberos password authentication successful",
		"username", transformedUsername,
		"realm", realm,
	)

	return &auth.UserInfo{
		Username: transformedUsername,
		Metadata: map[string]string{
			"auth_type": "kerberos",
			"realm":     realm,
		},
	}, nil
}

// transformUsername applies configured transformations to the username.
func (a *Authenticator) transformUsername(username, realm string) string {
	if !a.config.StripRealm && realm != "" {
		username = username + "@" + realm
	}

	if a.config.UsernameToLowercase {
		username = strings.ToLower(username)
	}

	return username
}

// loadKeytab loads the keytab file or content.
func (a *Authenticator) loadKeytab() error {
	var ktData []byte

	if a.config.KeytabBase64 != "" {
		var err error
		ktData, err = base64.StdEncoding.DecodeString(a.config.KeytabBase64)
		if err != nil {
			return fmt.Errorf("failed to decode keytab base64: %w", err)
		}
	} else {
		var err error
		ktData, err = os.ReadFile(a.config.KeytabFile)
		if err != nil {
			return fmt.Errorf("failed to read keytab file: %w", err)
		}
	}

	kt := keytab.New()
	if err := kt.Unmarshal(ktData); err != nil {
		return fmt.Errorf("failed to parse keytab: %w", err)
	}

	a.kt = kt
	return nil
}

// loadKrbConfig loads the Kerberos configuration.
func (a *Authenticator) loadKrbConfig() error {
	var krbConfig *config.Config
	var err error

	if a.config.Krb5Config != "" {
		krbConfig, err = config.NewFromString(a.config.Krb5Config)
	} else if a.config.Krb5ConfigFile != "" {
		krbConfig, err = config.Load(a.config.Krb5ConfigFile)
	} else {
		// Create minimal config
		cfgStr := fmt.Sprintf(`[libdefaults]
  default_realm = %s

[realms]
  %s = {
    kdc = %s
  }`, a.config.Realm, a.config.Realm, strings.Join(a.config.KDCServers, "\n    kdc = "))

		krbConfig, err = config.NewFromString(cfgStr)
	}

	if err != nil {
		return fmt.Errorf("failed to load Kerberos config: %w", err)
	}

	// Override KDC servers if specified
	if len(a.config.KDCServers) > 0 && a.config.Realm != "" {
		if krbConfig.Realms == nil {
			krbConfig.Realms = make([]config.Realm, 0)
		}

		found := false
		for i, r := range krbConfig.Realms {
			if r.Realm == a.config.Realm {
				krbConfig.Realms[i].KDC = a.config.KDCServers
				found = true
				break
			}
		}

		if !found {
			krbConfig.Realms = append(krbConfig.Realms, config.Realm{
				Realm: a.config.Realm,
				KDC:   a.config.KDCServers,
			})
		}
	}

	a.krbConfig = krbConfig
	return nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "kerberos"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "kerberos"
}

// GetServicePrincipal returns the configured service principal.
func (a *Authenticator) GetServicePrincipal() string {
	return a.config.ServicePrincipal
}

// GetRealm returns the configured realm.
func (a *Authenticator) GetRealm() string {
	return a.config.Realm
}

// ReloadKeytab reloads the keytab from the configured source.
func (a *Authenticator) ReloadKeytab() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loadKeytab()
}
