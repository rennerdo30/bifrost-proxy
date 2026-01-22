package auth

import (
	"log/slog"
	"sort"
	"sync"
)

// Global plugin registry
var (
	registryMu sync.RWMutex
	plugins    = make(map[string]Plugin)
)

// RegisterPlugin registers a plugin with the given name.
// This is typically called from init() functions in plugin packages.
// If a plugin with the same name is already registered, it will be overwritten.
func RegisterPlugin(name string, p Plugin) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := plugins[name]; exists {
		slog.Warn("auth plugin already registered, overwriting",
			"name", name,
			"type", p.Type(),
		)
	}

	plugins[name] = p
	slog.Debug("auth plugin registered",
		"name", name,
		"type", p.Type(),
		"description", p.Description(),
	)
}

// GetPlugin returns a plugin by name.
// Returns nil and false if the plugin is not found.
func GetPlugin(name string) (Plugin, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	p, ok := plugins[name]
	return p, ok
}

// ListPlugins returns a sorted list of all registered plugin names.
func ListPlugins() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetAllPlugins returns a map of all registered plugins.
func GetAllPlugins() map[string]Plugin {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// Return a copy to prevent modification
	result := make(map[string]Plugin, len(plugins))
	for name, p := range plugins {
		result[name] = p
	}
	return result
}

// PluginInfo contains information about a registered plugin.
type PluginInfo struct {
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Description   string         `json:"description"`
	DefaultConfig map[string]any `json:"default_config,omitempty"`
	ConfigSchema  string         `json:"config_schema,omitempty"`
}

// GetPluginInfo returns information about a specific plugin.
func GetPluginInfo(name string) (*PluginInfo, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	p, ok := plugins[name]
	if !ok {
		return nil, false
	}

	return &PluginInfo{
		Name:          name,
		Type:          p.Type(),
		Description:   p.Description(),
		DefaultConfig: p.DefaultConfig(),
		ConfigSchema:  p.ConfigSchema(),
	}, true
}

// ListPluginInfo returns information about all registered plugins.
func ListPluginInfo() []PluginInfo {
	registryMu.RLock()
	defer registryMu.RUnlock()

	infos := make([]PluginInfo, 0, len(plugins))
	for name, p := range plugins {
		infos = append(infos, PluginInfo{
			Name:          name,
			Type:          p.Type(),
			Description:   p.Description(),
			DefaultConfig: p.DefaultConfig(),
			ConfigSchema:  p.ConfigSchema(),
		})
	}

	// Sort by name for consistent ordering
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})

	return infos
}
