// Package mfa provides multi-factor authentication wrapper for Bifrost.
package mfa

import (
	"fmt"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("mfa_wrapper", &plugin{})
}

// plugin implements the auth.Plugin interface for MFA wrapper.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "mfa_wrapper"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "Multi-factor authentication wrapper for combining primary auth with TOTP/HOTP"
}

// Create creates a new MFA wrapper from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	if hasInlineProviders(config) {
		return p.createInlineWrapper(config)
	}

	// Validate the by-name configuration so misconfigurations are reported,
	// then fail closed: resolving providers by name (primary_provider /
	// mfa_provider) requires a registry of already-constructed, named
	// authenticators that this plugin does not have access to at Create time.
	// Returning a wrapper that rejects every login would be a silent, surprising
	// failure, so we reject the configuration explicitly and tell the operator
	// how to make it work (inline primary/secondary blocks).
	if _, err := parsePluginConfig(config, true); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("mfa_wrapper: referencing auth providers by name " +
		"(primary_provider/mfa_provider) is not supported; configure the wrapper " +
		"with inline 'primary' and 'secondary' blocks instead")
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	if hasInlineProviders(config) {
		_, _, err := parseInlineAuthenticatorConfig(config, "primary")
		if err != nil {
			return err
		}
		secondaryMode, _, err := parseInlineAuthenticatorConfig(config, "secondary")
		if err != nil {
			return err
		}
		wrapperCfg := copyMap(config)
		if _, ok := wrapperCfg["primary_provider"]; !ok {
			wrapperCfg["primary_provider"] = "primary"
		}
		if _, ok := wrapperCfg["mfa_type"]; !ok {
			wrapperCfg["mfa_type"] = secondaryMode
		}
		if _, ok := wrapperCfg["mfa_provider"]; !ok {
			wrapperCfg["mfa_provider"] = secondaryMode
		}
		_, err = parsePluginConfig(wrapperCfg, false)
		return err
	}

	_, err := parsePluginConfig(config, true)
	return err
}

// DefaultConfig returns the default configuration.
//
// The wrapper is created from inline 'primary' and 'secondary' authenticator
// blocks (each with its own 'mode' and 'config'); referencing pre-registered
// providers by name is not supported by Create(), so the default template only
// advertises the inline format.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"primary": map[string]any{
			"mode": "ldap",
			"config": map[string]any{
				"url":     "ldap://ldap.example.com:389",
				"base_dn": "ou=users,dc=example,dc=com",
			},
		},
		"secondary": map[string]any{
			"mode": "totp",
			"config": map[string]any{
				"secrets": map[string]any{},
			},
		},
		"mfa_required":    "always",
		"password_format": "separated",
		"separator":       ":",
		"mfa_code_length": 6,
	}
}

// ConfigSchema returns the JSON schema for configuration.
//
// It describes the inline block format accepted by Create(): a required
// 'primary' authenticator block and a required 'secondary' (MFA) authenticator
// block, each carrying its own plugin 'mode' and 'config'.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "primary": {
      "type": "object",
      "description": "Primary (first-factor) authenticator, e.g. native/ldap/oauth",
      "properties": {
        "mode": {"type": "string", "description": "Primary plugin type (e.g. ldap, native)"},
        "config": {"type": "object", "description": "Plugin-specific configuration for the primary authenticator"}
      },
      "required": ["mode"]
    },
    "secondary": {
      "type": "object",
      "description": "Secondary (MFA) authenticator",
      "properties": {
        "mode": {"type": "string", "description": "MFA plugin type", "enum": ["totp", "hotp"]},
        "config": {"type": "object", "description": "Plugin-specific configuration for the MFA authenticator"}
      },
      "required": ["mode"]
    },
    "mfa_required": {
      "type": "string",
      "description": "When MFA is required",
      "enum": ["always", "per_user", "group_based"],
      "default": "always"
    },
    "mfa_groups": {
      "type": "array",
      "description": "Groups that require MFA (for group_based mode)",
      "items": {"type": "string"}
    },
    "mfa_users": {
      "type": "array",
      "description": "Users that require MFA (for per_user mode)",
      "items": {"type": "string"}
    },
    "password_format": {
      "type": "string",
      "description": "How password and MFA code are combined",
      "enum": ["concatenated", "separated"],
      "default": "concatenated"
    },
    "separator": {
      "type": "string",
      "description": "Separator for password:code format",
      "default": ":"
    },
    "mfa_code_length": {
      "type": "integer",
      "description": "Expected length of MFA codes",
      "default": 6
    }
  },
  "required": ["primary", "secondary"]
}`
}

// parsePluginConfig parses the plugin configuration.
func parsePluginConfig(config map[string]any, requirePrimaryProvider bool) (*Config, error) {
	if config == nil {
		return nil, fmt.Errorf("mfa_wrapper config is required")
	}

	cfg := &Config{
		MFARequired:    MFAModeAlways,
		PasswordFormat: PasswordFormatConcatenated,
		Separator:      ":",
		MFACodeLength:  6,
	}

	if primaryProvider, ok := config["primary_provider"].(string); ok {
		cfg.PrimaryProvider = primaryProvider
	}

	if cfg.PrimaryProvider == "" && requirePrimaryProvider {
		return nil, fmt.Errorf("mfa_wrapper config: 'primary_provider' is required")
	}

	if mfaType, ok := config["mfa_type"].(string); ok {
		cfg.MFAType = mfaType
	}

	if mfaProvider, ok := config["mfa_provider"].(string); ok && mfaProvider != "" {
		cfg.MFAType = mfaProvider
	}

	if cfg.MFAType == "" {
		cfg.MFAType = "totp" // Default to TOTP
	}

	if mfaRequired, ok := config["mfa_required"].(string); ok {
		switch strings.ToLower(mfaRequired) {
		case "always":
			cfg.MFARequired = MFAModeAlways
		case "per_user":
			cfg.MFARequired = MFAModePerUser
		case "group_based":
			cfg.MFARequired = MFAModeGroupBased
		default:
			return nil, fmt.Errorf("mfa_wrapper config: invalid mfa_required value: %s", mfaRequired)
		}
	}

	if mfaGroups, ok := config["mfa_groups"].([]any); ok {
		for _, g := range mfaGroups {
			if group, ok := g.(string); ok {
				cfg.MFAGroups = append(cfg.MFAGroups, group)
			}
		}
	} else if mfaGroups, ok := config["mfa_groups"].([]string); ok {
		cfg.MFAGroups = append(cfg.MFAGroups, mfaGroups...)
	}

	if passwordFormat, ok := config["password_format"].(string); ok {
		switch strings.ToLower(passwordFormat) {
		case "concatenated":
			cfg.PasswordFormat = PasswordFormatConcatenated
		case "separated":
			cfg.PasswordFormat = PasswordFormatSeparated
		default:
			return nil, fmt.Errorf("mfa_wrapper config: invalid password_format value: %s", passwordFormat)
		}
	}

	if separator, ok := config["separator"].(string); ok && separator != "" {
		cfg.Separator = separator
	}

	if mfaCodeLength, ok := config["mfa_code_length"].(int); ok {
		cfg.MFACodeLength = mfaCodeLength
	} else if mfaCodeLength, ok := config["mfa_code_length"].(float64); ok {
		cfg.MFACodeLength = int(mfaCodeLength)
	}

	return cfg, nil
}

func hasInlineProviders(config map[string]any) bool {
	if config == nil {
		return false
	}
	_, okPrimary := toMap(config["primary"])
	_, okSecondary := toMap(config["secondary"])
	return okPrimary && okSecondary
}

func (p *plugin) createInlineWrapper(config map[string]any) (auth.Authenticator, error) {
	primaryMode, primaryConfig, err := parseInlineAuthenticatorConfig(config, "primary")
	if err != nil {
		return nil, err
	}
	secondaryMode, secondaryConfig, err := parseInlineAuthenticatorConfig(config, "secondary")
	if err != nil {
		return nil, err
	}

	wrapperCfgInput := copyMap(config)
	if _, ok := wrapperCfgInput["primary_provider"]; !ok {
		wrapperCfgInput["primary_provider"] = primaryMode
	}
	if _, ok := wrapperCfgInput["mfa_type"]; !ok {
		wrapperCfgInput["mfa_type"] = secondaryMode
	}
	if _, ok := wrapperCfgInput["mfa_provider"]; !ok {
		wrapperCfgInput["mfa_provider"] = secondaryMode
	}
	if separator, ok := wrapperCfgInput["otp_separator"].(string); ok && separator != "" {
		if _, exists := wrapperCfgInput["separator"]; !exists {
			wrapperCfgInput["separator"] = separator
		}
		if _, exists := wrapperCfgInput["password_format"]; !exists {
			wrapperCfgInput["password_format"] = "separated"
		}
	}

	wrapperCfg, err := parsePluginConfig(wrapperCfgInput, false)
	if err != nil {
		return nil, err
	}

	primaryAuth, err := createInlineAuthenticator(primaryMode, primaryConfig)
	if err != nil {
		return nil, fmt.Errorf("mfa_wrapper primary provider %q: %w", primaryMode, err)
	}
	mfaAuth, err := createInlineAuthenticator(secondaryMode, secondaryConfig)
	if err != nil {
		return nil, fmt.Errorf("mfa_wrapper secondary provider %q: %w", secondaryMode, err)
	}

	wrapper, err := NewWrapper(wrapperCfg, primaryAuth, mfaAuth)
	if err != nil {
		return nil, err
	}

	if mfaUsersRaw, ok := config["mfa_users"]; ok {
		wrapper.SetMFAUsers(toStringSlice(mfaUsersRaw))
	}

	return wrapper, nil
}

func parseInlineAuthenticatorConfig(config map[string]any, key string) (string, map[string]any, error) {
	block, ok := toMap(config[key])
	if !ok {
		return "", nil, fmt.Errorf("mfa_wrapper config: '%s' block is required", key)
	}

	mode, _ := block["mode"].(string) //nolint:errcheck // Empty string is handled below
	if mode == "" {
		return "", nil, fmt.Errorf("mfa_wrapper config: '%s.mode' is required", key)
	}

	authConfig := map[string]any{}
	if cfg, ok := toMap(block["config"]); ok {
		for k, v := range cfg {
			authConfig[k] = v
		}
	}
	if legacyCfg, ok := toMap(block[mode]); ok {
		for k, v := range legacyCfg {
			authConfig[k] = v
		}
	}

	normalizeOTPSecrets(mode, authConfig)
	return mode, authConfig, nil
}

func createInlineAuthenticator(mode string, config map[string]any) (auth.Authenticator, error) {
	plugin, ok := auth.GetPlugin(mode)
	if !ok {
		return nil, fmt.Errorf("unknown auth plugin type: %s", mode)
	}
	if err := plugin.ValidateConfig(config); err != nil {
		return nil, err
	}
	return plugin.Create(config)
}

func normalizeOTPSecrets(mode string, config map[string]any) {
	if mode != "totp" && mode != "hotp" {
		return
	}

	secretsMap, ok := toMap(config["secrets"])
	if !ok {
		return
	}

	secrets := make([]map[string]any, 0, len(secretsMap))
	for username, raw := range secretsMap {
		secret, ok := raw.(string)
		if !ok || username == "" || secret == "" {
			continue
		}
		secrets = append(secrets, map[string]any{
			"username": username,
			"secret":   secret,
		})
	}
	config["secrets"] = secrets
}

func toMap(v any) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}

	if m, ok := v.(map[any]any); ok {
		converted := make(map[string]any, len(m))
		for k, value := range m {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			converted[ks] = value
		}
		return converted, true
	}

	return nil, false
}

func copyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}

	if values, ok := v.([]string); ok {
		return values
	}

	rawValues, ok := v.([]any)
	if !ok {
		return nil
	}

	result := make([]string, 0, len(rawValues))
	for _, raw := range rawValues {
		value, ok := raw.(string)
		if ok {
			result = append(result, value)
		}
	}
	return result
}
