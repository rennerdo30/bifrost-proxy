package auth

import (
	"fmt"
	"sort"
)

// ProviderConfig represents a single authentication provider configuration.
type ProviderConfig struct {
	// Name is a unique identifier for this provider instance.
	Name string `yaml:"name" json:"name"`

	// Type is the plugin type (e.g., "native", "ldap", "oauth").
	Type string `yaml:"type" json:"type"`

	// Enabled indicates whether this provider is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Priority determines the order in which providers are tried (lower = first).
	Priority int `yaml:"priority" json:"priority"`

	// Config contains plugin-specific configuration.
	Config map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
}

// Factory creates authenticators from provider configurations.
type Factory struct{}

// NewFactory creates a new authenticator factory.
func NewFactory() *Factory {
	return &Factory{}
}

// Create creates a single authenticator from a provider configuration.
func (f *Factory) Create(cfg ProviderConfig) (Authenticator, error) {
	if cfg.Type == "" {
		return nil, fmt.Errorf("provider type is required")
	}

	plugin, ok := GetPlugin(cfg.Type)
	if !ok {
		return nil, fmt.Errorf("unknown auth plugin type: %s (available: %v)", cfg.Type, ListPlugins())
	}

	// Validate the configuration
	if err := plugin.ValidateConfig(cfg.Config); err != nil {
		return nil, fmt.Errorf("invalid config for %s provider %q: %w", cfg.Type, cfg.Name, err)
	}

	// Create the authenticator
	auth, err := plugin.Create(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s provider %q: %w", cfg.Type, cfg.Name, err)
	}

	return auth, nil
}

// CreateChain creates a chain authenticator from multiple provider configurations.
// Providers are sorted by priority (lowest first) and only enabled providers are included.
func (f *Factory) CreateChain(providers []ProviderConfig) (Authenticator, error) {
	if len(providers) == 0 {
		// No providers configured, use the "none" plugin if available
		if nonePlugin, ok := GetPlugin("none"); ok {
			return nonePlugin.Create(nil)
		}
		return nil, fmt.Errorf("no auth providers configured and 'none' plugin not available")
	}

	// Sort by priority (lowest first)
	sorted := make([]ProviderConfig, len(providers))
	copy(sorted, providers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	// Create chain
	chain := NewChainAuthenticator()
	enabledCount := 0

	for _, cfg := range sorted {
		if !cfg.Enabled {
			continue
		}

		auth, err := f.Create(cfg)
		if err != nil {
			return nil, fmt.Errorf("create provider %q: %w", cfg.Name, err)
		}

		chain.AddAuthenticator(cfg.Name, cfg.Priority, auth)
		enabledCount++
	}

	// If no enabled providers, return "none" authenticator
	if enabledCount == 0 {
		if nonePlugin, ok := GetPlugin("none"); ok {
			return nonePlugin.Create(nil)
		}
		return nil, fmt.Errorf("no enabled auth providers and 'none' plugin not available")
	}

	// If only one provider, return it directly (no need for chain)
	if enabledCount == 1 {
		return chain, nil
	}

	return chain, nil
}

// ValidateProviders validates a list of provider configurations without creating authenticators.
func (f *Factory) ValidateProviders(providers []ProviderConfig) error {
	names := make(map[string]bool)

	for i, cfg := range providers {
		// Check for duplicate names
		if cfg.Name == "" {
			return fmt.Errorf("provider at index %d: name is required", i)
		}
		if names[cfg.Name] {
			return fmt.Errorf("duplicate provider name: %s", cfg.Name)
		}
		names[cfg.Name] = true

		// Check type
		if cfg.Type == "" {
			return fmt.Errorf("provider %q: type is required", cfg.Name)
		}

		plugin, ok := GetPlugin(cfg.Type)
		if !ok {
			return fmt.Errorf("provider %q: unknown type %q (available: %v)", cfg.Name, cfg.Type, ListPlugins())
		}

		// Validate config
		if err := plugin.ValidateConfig(cfg.Config); err != nil {
			return fmt.Errorf("provider %q: %w", cfg.Name, err)
		}
	}

	return nil
}
