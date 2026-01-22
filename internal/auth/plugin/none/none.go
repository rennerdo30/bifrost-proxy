// Package none provides the "none" authentication plugin which allows all requests.
package none

import (
	"context"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("none", &plugin{})
}

// plugin implements the auth.Plugin interface for the "none" authenticator.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "none"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "No authentication - allows all requests"
}

// Create creates a new NoneAuthenticator.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	return &Authenticator{}, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	// None authenticator has no configuration
	return nil
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return nil
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {},
  "additionalProperties": false,
  "description": "No configuration required for 'none' authentication"
}`
}

// Authenticator allows all requests without authentication.
type Authenticator struct{}

// Authenticate always succeeds for none auth.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	return &auth.UserInfo{
		Username: "anonymous",
	}, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "none"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "none"
}
