package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// Config section names. These are the canonical identifiers shared by the
// save/validate responses, the /config/meta endpoint and the Web UI, and they
// match the `yaml`/`json` tags of the corresponding config.ServerConfig fields.
// Every top-level field of config.ServerConfig must have a constant here —
// TestConfigSectionsCoverServerConfig enforces that.
const (
	SectionServer        = "server"
	SectionBackends      = "backends"
	SectionRoutes        = "routes"
	SectionAuth          = "auth"
	SectionRateLimit     = "rate_limit"
	SectionAccessControl = "access_control"
	SectionAccessLog     = "access_log"
	SectionMetrics       = "metrics"
	SectionLogging       = "logging"
	SectionWebUI         = "web_ui"
	SectionAPI           = "api"
	SectionHealthCheck   = "health_check"
	SectionAutoUpdate    = "auto_update"
	SectionCache         = "cache"
	SectionNetwork       = "network"
	SectionSession       = "session"
	SectionMITM          = "mitm"
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
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	BackupPath string `json:"backup_path,omitempty"`
	// RequiresRestart is true when at least one changed section cannot be
	// applied by ReloadConfig, i.e. RestartRequiredSections is non-empty.
	RequiresRestart bool     `json:"requires_restart"`
	ChangedSections []string `json:"changed_sections"`
	// HotReloadedSections lists the changed sections that were applied to the
	// running server without a restart. Populated so the Web UI never has to
	// re-derive hot-reloadability client-side (where it can drift).
	HotReloadedSections []string `json:"hot_reloaded_sections"`
	// RestartRequiredSections lists the changed sections that were written to
	// disk but only take effect after a server restart.
	RestartRequiredSections []string          `json:"restart_required_sections"`
	Errors                  []ValidationError `json:"errors,omitempty"`
}

// ValidationError represents a config validation error.
type ValidationError struct {
	Section string `json:"section"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// hotReloadableSections lists the config sections that Server.ReloadConfig can
// apply to the running server without a restart. Keep this in sync with the
// sections actually handled in (*server.Server).ReloadConfig — currently
// routes, rate_limit (incl. bandwidth), access_control, and cache (rules only).
// Everything else genuinely requires a restart, so it must NOT be listed here.
var hotReloadableSections = map[string]bool{
	SectionRoutes:        true,
	SectionRateLimit:     true,
	SectionAccessControl: true,
	SectionCache:         true,
}

// configSectionDescriptions describes every config section for /config/meta.
// The hot-reloadable flag is NOT duplicated here — it is derived from
// hotReloadableSections so the two can never disagree.
var configSectionDescriptions = []struct {
	Section     string
	Description string
}{
	{SectionServer, "Server listeners and timeouts"},
	{SectionBackends, "Backend connection configurations"},
	{SectionRoutes, "Routing rules"},
	{SectionAuth, "Authentication settings"},
	{SectionRateLimit, "Rate limiting and bandwidth configuration"},
	{SectionAccessControl, "IP whitelist/blacklist rules"},
	{SectionAccessLog, "Access logging settings"},
	{SectionMetrics, "Prometheus metrics settings"},
	{SectionLogging, "Application logging"},
	{SectionWebUI, "Web UI settings"},
	{SectionAPI, "API settings"},
	{SectionHealthCheck, "Health check defaults"},
	{SectionAutoUpdate, "Automatic update settings"},
	{SectionCache, "Response cache rules (storage changes require restart)"},
	{SectionNetwork, "Network dial/keepalive/connection settings"},
	{SectionSession, "Session store settings"},
	{SectionMITM, "MITM inspection settings"},
}

// handleGetConfigMeta returns metadata about config sections.
func (a *API) handleGetConfigMeta(w http.ResponseWriter, r *http.Request) {
	meta := make([]ConfigMeta, 0, len(configSectionDescriptions))
	for _, d := range configSectionDescriptions {
		meta = append(meta, ConfigMeta{
			Section:       d.Section,
			HotReloadable: hotReloadableSections[d.Section],
			Description:   d.Description,
		})
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

	// Detect changed sections and split them into hot-reloadable vs
	// restart-required so the client does not have to re-derive it.
	changedSections := []string{}
	hotReloadedSections := []string{}
	restartRequiredSections := []string{}
	var requiresRestart bool
	if a.getFullConfig != nil {
		currentConfig := a.getFullConfig()
		changedSections = detectChangedSections(currentConfig, &req.Config)
		hotReloadedSections, restartRequiredSections = splitChangedSections(changedSections)
		requiresRestart = len(restartRequiredSections) > 0
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

	// Auto-reload whenever at least one hot-reloadable section changed.
	//
	// This deliberately also runs for "mixed" saves that additionally touch a
	// restart-required section: ReloadConfig re-reads the file and applies only
	// the sections it knows how to apply, so skipping it would leave e.g. a new
	// access_control blocklist unenforced just because the same save also
	// changed a listener port.
	reloadError := ""
	if len(hotReloadedSections) > 0 && a.reloadConfig != nil {
		if err := a.reloadConfig(); err != nil {
			// Log error but don't fail - config is already saved
			slog.Error("failed to auto-reload config after save",
				"error", err,
				"hot_reloadable_sections", hotReloadedSections,
			)
			reloadError = err.Error()
			// The reload failed, so nothing was actually applied to the running
			// server; every changed section now needs a restart. Report that
			// rather than claiming sections were hot-reloaded.
			restartRequiredSections = append(restartRequiredSections, hotReloadedSections...)
			hotReloadedSections = []string{}
			requiresRestart = len(restartRequiredSections) > 0
		} else {
			slog.Debug("auto-reloaded config after save",
				"hot_reloaded_sections", hotReloadedSections,
				"restart_required_sections", restartRequiredSections,
			)
		}
	}

	// Broadcast config change via WebSocket
	if a.wsHub != nil {
		a.wsHub.Broadcast(EventConfigSaved, map[string]interface{}{
			"changed_sections":          changedSections,
			"requires_restart":          requiresRestart,
			"hot_reloaded_sections":     hotReloadedSections,
			"restart_required_sections": restartRequiredSections,
		})
	}

	response := ConfigSaveResponse{
		Success:                 true,
		Message:                 "Configuration saved successfully",
		BackupPath:              backupPath,
		RequiresRestart:         requiresRestart,
		ChangedSections:         changedSections,
		HotReloadedSections:     hotReloadedSections,
		RestartRequiredSections: restartRequiredSections,
	}
	if reloadError != "" {
		response.Message = "Configuration saved but reload failed"
		response.Errors = []ValidationError{{Section: "reload", Message: reloadError}}
	}
	a.writeJSON(w, http.StatusOK, response)
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

// configSectionComparators maps each config section to the pair of values that
// must be compared to decide whether that section changed. Driving
// detectChangedSections off a table (rather than a hand-written if-chain) means
// a newly added ServerConfig section shows up as a missing table entry, which
// TestConfigSectionsCoverServerConfig turns into a build-time-visible failure
// instead of a silently unreported — and therefore never applied — section.
var configSectionComparators = []struct {
	Section string
	Values  func(c *config.ServerConfig) any
}{
	{SectionServer, func(c *config.ServerConfig) any { return c.Server }},
	{SectionBackends, func(c *config.ServerConfig) any { return c.Backends }},
	{SectionRoutes, func(c *config.ServerConfig) any { return c.Routes }},
	{SectionAuth, func(c *config.ServerConfig) any { return c.Auth }},
	{SectionRateLimit, func(c *config.ServerConfig) any { return c.RateLimit }},
	{SectionAccessControl, func(c *config.ServerConfig) any { return c.AccessControl }},
	{SectionAccessLog, func(c *config.ServerConfig) any { return c.AccessLog }},
	{SectionMetrics, func(c *config.ServerConfig) any { return c.Metrics }},
	{SectionLogging, func(c *config.ServerConfig) any { return c.Logging }},
	{SectionWebUI, func(c *config.ServerConfig) any { return c.WebUI }},
	{SectionAPI, func(c *config.ServerConfig) any { return c.API }},
	{SectionHealthCheck, func(c *config.ServerConfig) any { return c.HealthCheck }},
	{SectionAutoUpdate, func(c *config.ServerConfig) any { return c.AutoUpdate }},
	{SectionCache, func(c *config.ServerConfig) any { return c.Cache }},
	{SectionNetwork, func(c *config.ServerConfig) any { return c.Network }},
	{SectionSession, func(c *config.ServerConfig) any { return c.Session }},
	{SectionMITM, func(c *config.ServerConfig) any { return c.MITM }},
}

// detectChangedSections compares two configs and returns changed sections, in
// the canonical section order of configSectionComparators.
func detectChangedSections(current, new *config.ServerConfig) []string {
	changed := []string{}
	for _, c := range configSectionComparators {
		if !reflect.DeepEqual(c.Values(current), c.Values(new)) {
			changed = append(changed, c.Section)
		}
	}
	return changed
}

// splitChangedSections partitions changed sections into those that
// (*server.Server).ReloadConfig applies without a restart and those that only
// take effect after a restart.
func splitChangedSections(sections []string) (hotReloaded, restartRequired []string) {
	hotReloaded = []string{}
	restartRequired = []string{}
	for _, section := range sections {
		if hotReloadableSections[section] {
			hotReloaded = append(hotReloaded, section)
		} else {
			restartRequired = append(restartRequired, section)
		}
	}
	return hotReloaded, restartRequired
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
func (a *API) handleGetConfigTimestamp(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
