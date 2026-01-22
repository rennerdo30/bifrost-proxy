package auth

// Plugin is the interface for authentication plugins.
// Each plugin is responsible for creating and configuring its authenticator type.
type Plugin interface {
	// Type returns the plugin type identifier (e.g., "native", "ldap", "oauth").
	Type() string

	// Description returns a human-readable description of the plugin.
	Description() string

	// Create creates an authenticator instance from the given configuration.
	// The config map contains plugin-specific configuration values.
	Create(config map[string]any) (Authenticator, error)

	// ValidateConfig validates the configuration without creating an authenticator.
	// Returns an error if the configuration is invalid.
	ValidateConfig(config map[string]any) error

	// DefaultConfig returns the default configuration for this plugin.
	DefaultConfig() map[string]any

	// ConfigSchema returns a JSON schema describing the configuration options.
	// This can be used for documentation and validation by UI tools.
	// Returns an empty string if no schema is available.
	ConfigSchema() string
}
