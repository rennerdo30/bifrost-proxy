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
// Note: This requires the primary and MFA providers to already be created.
// For proper initialization, use the Factory.CreateWithProviders method.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parsePluginConfig(config)
	if err != nil {
		return nil, err
	}

	// This plugin requires external setup of primary and MFA authenticators
	// Return a placeholder that must be configured later
	return &pendingWrapper{config: cfg}, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parsePluginConfig(config)
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
func parsePluginConfig(config map[string]any) (*Config, error) {
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

	if cfg.PrimaryProvider == "" {
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

// pendingWrapper is a placeholder for an MFA wrapper that needs its providers set.
type pendingWrapper struct {
	config *Config
}

// Authenticate returns an error indicating the wrapper needs configuration.
func (w *pendingWrapper) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	return nil, fmt.Errorf("MFA wrapper not fully configured: use Factory.CreateWithProviders")
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
