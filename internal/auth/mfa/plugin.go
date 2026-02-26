// Package mfa provides multi-factor authentication wrapper for Bifrost.
package mfa

import (
	"context"
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

	cfg, err := parsePluginConfig(config, true)
	if err != nil {
		return nil, err
	}

	// This plugin requires external setup of primary and MFA authenticators
	// Return a placeholder that must be configured later
	return &pendingWrapper{config: cfg}, nil
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
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"primary_provider": "ldap-main",
		"mfa_type":         "totp",
		"mfa_required":     "always",
		"password_format":  "concatenated",
		"mfa_code_length":  6,
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "primary_provider": {
      "type": "string",
      "description": "Name of the primary authentication provider"
    },
    "mfa_type": {
      "type": "string",
      "description": "Type of MFA provider (totp, hotp)",
      "enum": ["totp", "hotp"]
    },
    "mfa_provider": {
      "type": "string",
      "description": "Name of the MFA provider (if different from mfa_type)"
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
  "required": ["primary_provider"]
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

// pendingWrapper is a placeholder for an MFA wrapper that needs its providers set.
type pendingWrapper struct {
	config *Config
}

// Authenticate returns an error indicating the wrapper needs configuration.
func (w *pendingWrapper) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	return nil, fmt.Errorf("MFA wrapper not fully configured: use inline primary/secondary config")
}

// Name returns the authenticator name.
func (w *pendingWrapper) Name() string {
	return "mfa_wrapper"
}

// Type returns the authenticator type.
func (w *pendingWrapper) Type() string {
	return "mfa_wrapper"
}

// GetConfig returns the parsed configuration.
func (w *pendingWrapper) GetConfig() *Config {
	return w.config
}
