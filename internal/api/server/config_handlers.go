package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// ConfigMeta describes which config sections are hot-reloadable.
type ConfigMeta struct {
	Section       string `json:"section"`
	HotReloadable bool   `json:"hot_reloadable"`
	Description   string `json:"description"`
}

// ConfigSaveRequest represents a config save request.
type ConfigSaveRequest struct {
	Config       config.ServerConfig `json:"config"`
	CreateBackup bool                `json:"create_backup"`
}

// ConfigSaveResponse represents the response after saving config.
type ConfigSaveResponse struct {
	Success         bool              `json:"success"`
	Message         string            `json:"message"`
	BackupPath      string            `json:"backup_path,omitempty"`
	RequiresRestart bool              `json:"requires_restart"`
	ChangedSections []string          `json:"changed_sections"`
	Errors          []ValidationError `json:"errors,omitempty"`
}

// ValidationError represents a config validation error.
type ValidationError struct {
	Section string `json:"section"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// Hot-reloadable sections
var hotReloadableSections = map[string]bool{
	"routes":     true,
	"rate_limit": true,
}

// handleGetConfigMeta returns metadata about config sections.
func (a *API) handleGetConfigMeta(w http.ResponseWriter, r *http.Request) {
	meta := []ConfigMeta{
		{Section: "server", HotReloadable: false, Description: "Server listeners and timeouts"},
		{Section: "backends", HotReloadable: false, Description: "Backend connection configurations"},
		{Section: "routes", HotReloadable: true, Description: "Routing rules"},
		{Section: "auth", HotReloadable: false, Description: "Authentication settings"},
		{Section: "rate_limit", HotReloadable: true, Description: "Rate limiting configuration"},
		{Section: "access_log", HotReloadable: false, Description: "Access logging settings"},
		{Section: "metrics", HotReloadable: false, Description: "Prometheus metrics settings"},
		{Section: "logging", HotReloadable: false, Description: "Application logging"},
		{Section: "web_ui", HotReloadable: false, Description: "Web UI settings"},
		{Section: "api", HotReloadable: false, Description: "API settings"},
		{Section: "health_check", HotReloadable: false, Description: "Health check defaults"},
	}
	a.writeJSON(w, http.StatusOK, meta)
}

// handleGetFullConfig returns the full config for editing.
func (a *API) handleGetFullConfig(w http.ResponseWriter, r *http.Request) {
	if a.getFullConfig == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Full config retrieval not available",
		})
		return
	}

	cfg := a.getFullConfig()
	a.writeJSON(w, http.StatusOK, cfg)
}

// handleSaveConfig saves the config to file.
func (a *API) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	if a.saveConfig == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, ConfigSaveResponse{
			Success: false,
			Message: "Config save not available",
		})
		return
	}

	var req ConfigSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, ConfigSaveResponse{
			Success: false,
			Message: "Invalid request body",
			Errors:  []ValidationError{{Message: err.Error()}},
		})
		return
	}

	// Validate configuration
	if err := req.Config.Validate(); err != nil {
		a.writeJSON(w, http.StatusBadRequest, ConfigSaveResponse{
			Success: false,
			Message: "Configuration validation failed",
			Errors:  []ValidationError{{Section: "general", Message: err.Error()}},
		})
		return
	}

	// Create backup if requested
	var backupPath string
	if req.CreateBackup && a.configPath != "" {
		var err error
		backupPath, err = config.Backup(a.configPath)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, ConfigSaveResponse{
				Success: false,
				Message: "Failed to create backup",
				Errors:  []ValidationError{{Message: err.Error()}},
			})
			return
		}
	}

	// Detect changed sections
	var changedSections []string
	var requiresRestart bool
	if a.getFullConfig != nil {
		currentConfig := a.getFullConfig()
		changedSections = detectChangedSections(currentConfig, &req.Config)
		requiresRestart = hasRestartRequiredChanges(changedSections)
	}

	// Save config
	if err := a.saveConfig(&req.Config); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, ConfigSaveResponse{
			Success: false,
			Message: "Failed to save configuration",
			Errors:  []ValidationError{{Message: err.Error()}},
		})
		return
	}

	// Auto-reload if only hot-reloadable sections changed
	if !requiresRestart && len(changedSections) > 0 && a.reloadConfig != nil {
		_ = a.reloadConfig() // Ignore error, config is already saved
	}

	// Broadcast config change via WebSocket
	if a.wsHub != nil {
		a.wsHub.Broadcast(EventConfigSaved, map[string]interface{}{
			"changed_sections": changedSections,
			"requires_restart": requiresRestart,
		})
	}

	a.writeJSON(w, http.StatusOK, ConfigSaveResponse{
		Success:         true,
		Message:         "Configuration saved successfully",
		BackupPath:      backupPath,
		RequiresRestart: requiresRestart,
		ChangedSections: changedSections,
	})
}

// handleValidateConfig validates config without saving.
func (a *API) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"valid":   false,
			"message": "Invalid request body",
			"errors":  []ValidationError{{Message: err.Error()}},
		})
		return
	}

	if err := cfg.Validate(); err != nil {
		a.writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   false,
			"message": "Configuration validation failed",
			"errors":  []ValidationError{{Section: "general", Message: err.Error()}},
		})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "Configuration is valid",
	})
}

// detectChangedSections compares two configs and returns changed sections.
func detectChangedSections(current, new *config.ServerConfig) []string {
	changed := []string{}

	if !reflect.DeepEqual(current.Server, new.Server) {
		changed = append(changed, "server")
	}
	if !reflect.DeepEqual(current.Backends, new.Backends) {
		changed = append(changed, "backends")
	}
	if !reflect.DeepEqual(current.Routes, new.Routes) {
		changed = append(changed, "routes")
	}
	if !reflect.DeepEqual(current.Auth, new.Auth) {
		changed = append(changed, "auth")
	}
	if !reflect.DeepEqual(current.RateLimit, new.RateLimit) {
		changed = append(changed, "rate_limit")
	}
	if !reflect.DeepEqual(current.AccessLog, new.AccessLog) {
		changed = append(changed, "access_log")
	}
	if !reflect.DeepEqual(current.Metrics, new.Metrics) {
		changed = append(changed, "metrics")
	}
	if !reflect.DeepEqual(current.Logging, new.Logging) {
		changed = append(changed, "logging")
	}
	if !reflect.DeepEqual(current.WebUI, new.WebUI) {
		changed = append(changed, "web_ui")
	}
	if !reflect.DeepEqual(current.API, new.API) {
		changed = append(changed, "api")
	}

	return changed
}

// hasRestartRequiredChanges checks if any changed section requires restart.
func hasRestartRequiredChanges(sections []string) bool {
	for _, section := range sections {
		if !hotReloadableSections[section] {
			return true
		}
	}
	return false
}

// EventConfigSaved is broadcast when config is saved.
const EventConfigSaved = "config.saved"

// setWebSocketHub sets the WebSocket hub for broadcasting events.
func (a *API) setWebSocketHub(hub *WebSocketHub) {
	a.wsHub = hub
}

// handleGetConfigTimestamp returns the config file modification time.
func (a *API) handleGetConfigTimestamp(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
