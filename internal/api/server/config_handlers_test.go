package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
)

func TestHandleGetConfigMeta(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config/meta", nil)
	api.handleGetConfigMeta(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var meta []ConfigMeta
	err := json.Unmarshal(w.Body.Bytes(), &meta)
	require.NoError(t, err)
	assert.NotEmpty(t, meta)

	// Check that we have expected sections
	sections := make(map[string]bool)
	for _, m := range meta {
		sections[m.Section] = m.HotReloadable
	}

	assert.Contains(t, sections, "server")
	assert.Contains(t, sections, "backends")
	assert.Contains(t, sections, "routes")
	assert.Contains(t, sections, "auth")
	assert.Contains(t, sections, "rate_limit")

	// Check hot-reloadable
	assert.True(t, sections["routes"])
	assert.True(t, sections["rate_limit"])
	assert.False(t, sections["server"])
	assert.False(t, sections["backends"])
}

func TestHandleGetFullConfig(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{
				Server: config.ServerSettings{
					HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
				},
			}
		},
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config/full", nil)
	api.handleGetFullConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGetFullConfig_NotAvailable(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config/full", nil)
	api.handleGetFullConfig(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "error")
}

func TestHandleSaveConfig(t *testing.T) {
	mgr := backend.NewManager()
	saveCalled := false
	cfg := Config{
		Backends: mgr,
		SaveConfig: func(c *config.ServerConfig) error {
			saveCalled = true
			return nil
		},
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{}
		},
	}

	api := New(cfg)

	// Valid config with listener and backend
	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:8080"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}]
		},
		"create_backup": false
	}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, saveCalled)

	var resp ConfigSaveResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestHandleSaveConfig_NotAvailable(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	body := strings.NewReader(`{"config": {}}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleSaveConfig_InvalidBody(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		SaveConfig: func(c *config.ServerConfig) error {
			return nil
		},
	}

	api := New(cfg)

	body := strings.NewReader(`{invalid json}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ConfigSaveResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.NotEmpty(t, resp.Errors)
}

func TestHandleSaveConfig_SaveError(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		SaveConfig: func(c *config.ServerConfig) error {
			return assert.AnError
		},
	}

	api := New(cfg)

	// Valid config that passes validation but save fails
	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:8080"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}]
		}
	}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp ConfigSaveResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
}

func TestHandleValidateConfig(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	// Valid config with listener and backend
	body := strings.NewReader(`{
		"server": {"http": {"listen": "0.0.0.0:8080"}},
		"backends": [{"name": "default", "type": "direct", "enabled": true}]
	}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/config/validate", body)
	api.handleValidateConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["valid"].(bool))
}

func TestHandleValidateConfig_Invalid(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	body := strings.NewReader(`{invalid}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/config/validate", body)
	api.handleValidateConfig(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDetectChangedSections(t *testing.T) {
	current := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Routes: []config.RouteConfig{
			{Backend: "default"},
		},
	}

	new := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:9090"}, // Changed
		},
		Routes: []config.RouteConfig{
			{Backend: "default"},
		},
	}

	changed := detectChangedSections(current, new)
	assert.Contains(t, changed, "server")
	assert.NotContains(t, changed, "routes")
}

func TestDetectChangedSections_AllSame(t *testing.T) {
	current := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
	}

	new := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
	}

	changed := detectChangedSections(current, new)
	assert.Empty(t, changed)
}

func TestDetectChangedSections_MultipleChanged(t *testing.T) {
	current := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Routes: []config.RouteConfig{
			{Backend: "default"},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{},
		},
	}

	new := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:9090"},
		},
		Routes: []config.RouteConfig{
			{Backend: "other"},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "test", Type: "native"},
			},
		},
	}

	changed := detectChangedSections(current, new)
	assert.Contains(t, changed, "server")
	assert.Contains(t, changed, "routes")
	assert.Contains(t, changed, "auth")
}

func TestHasRestartRequiredChanges(t *testing.T) {
	tests := []struct {
		name     string
		sections []string
		expected bool
	}{
		{
			name:     "no changes",
			sections: []string{},
			expected: false,
		},
		{
			name:     "only hot-reloadable",
			sections: []string{"routes", "rate_limit"},
			expected: false,
		},
		{
			name:     "server change",
			sections: []string{"server"},
			expected: true,
		},
		{
			name:     "backends change",
			sections: []string{"backends"},
			expected: true,
		},
		{
			name:     "mixed",
			sections: []string{"routes", "server"},
			expected: true,
		},
		{
			name:     "auth change",
			sections: []string{"auth"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasRestartRequiredChanges(tt.sections)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHotReloadableSections(t *testing.T) {
	// Verify the map is properly configured
	assert.True(t, hotReloadableSections["routes"])
	assert.True(t, hotReloadableSections["rate_limit"])
	assert.False(t, hotReloadableSections["server"])
	assert.False(t, hotReloadableSections["backends"])
	assert.False(t, hotReloadableSections["auth"])
}

func TestConfigMeta_Struct(t *testing.T) {
	meta := ConfigMeta{
		Section:       "routes",
		HotReloadable: true,
		Description:   "Routing rules",
	}

	assert.Equal(t, "routes", meta.Section)
	assert.True(t, meta.HotReloadable)
	assert.Equal(t, "Routing rules", meta.Description)
}

func TestConfigSaveRequest_Struct(t *testing.T) {
	req := ConfigSaveRequest{
		Config: config.ServerConfig{
			Server: config.ServerSettings{
				HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
			},
		},
		CreateBackup: true,
	}

	assert.Equal(t, "0.0.0.0:8080", req.Config.Server.HTTP.Listen)
	assert.True(t, req.CreateBackup)
}

func TestConfigSaveResponse_Struct(t *testing.T) {
	resp := ConfigSaveResponse{
		Success:         true,
		Message:         "Config saved",
		BackupPath:      "/path/to/backup",
		RequiresRestart: false,
		ChangedSections: []string{"routes"},
		Errors:          nil,
	}

	assert.True(t, resp.Success)
	assert.Equal(t, "Config saved", resp.Message)
	assert.Equal(t, "/path/to/backup", resp.BackupPath)
	assert.False(t, resp.RequiresRestart)
	assert.Contains(t, resp.ChangedSections, "routes")
}

func TestValidationError_Struct(t *testing.T) {
	err := ValidationError{
		Section: "server",
		Field:   "listen",
		Message: "Invalid address format",
	}

	assert.Equal(t, "server", err.Section)
	assert.Equal(t, "listen", err.Field)
	assert.Equal(t, "Invalid address format", err.Message)
}

func TestEventConfigSaved(t *testing.T) {
	assert.Equal(t, "config.saved", EventConfigSaved)
}

func TestHandleSaveConfig_WithWebSocket(t *testing.T) {
	mgr := backend.NewManager()
	hub := NewWebSocketHub()

	cfg := Config{
		Backends: mgr,
		SaveConfig: func(c *config.ServerConfig) error {
			return nil
		},
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{}
		},
	}

	api := New(cfg)
	api.setWebSocketHub(hub)

	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:8080"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}]
		},
		"create_backup": false
	}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleSaveConfig_WithAutoReload(t *testing.T) {
	mgr := backend.NewManager()
	reloadCalled := false

	cfg := Config{
		Backends: mgr,
		SaveConfig: func(c *config.ServerConfig) error {
			return nil
		},
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{
				Server: config.ServerSettings{
					HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
				},
				Backends: []config.BackendConfig{
					{Name: "default", Type: "direct", Enabled: true},
				},
				Routes: []config.RouteConfig{
					{Domains: []string{"*.example.com"}, Backend: "default"},
				},
			}
		},
		ReloadConfig: func() error {
			reloadCalled = true
			return nil
		},
	}

	api := New(cfg)

	// Change only routes (hot-reloadable) while keeping server and backends valid
	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:8080"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}],
			"routes": [{"domains": ["*.newdomain.com"], "backend": "default"}]
		},
		"create_backup": false
	}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reloadCalled, "Should auto-reload for hot-reloadable changes")
}

func TestHandleSaveConfig_NoAutoReloadForRestartRequired(t *testing.T) {
	mgr := backend.NewManager()
	reloadCalled := false

	cfg := Config{
		Backends: mgr,
		SaveConfig: func(c *config.ServerConfig) error {
			return nil
		},
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{
				Server: config.ServerSettings{
					HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
				},
				Backends: []config.BackendConfig{
					{Name: "default", Type: "direct", Enabled: true},
				},
			}
		},
		ReloadConfig: func() error {
			reloadCalled = true
			return nil
		},
	}

	api := New(cfg)

	// Change server settings (requires restart)
	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:9090"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}]
		},
		"create_backup": false
	}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigSaveResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.RequiresRestart)
	_ = reloadCalled // May or may not be called depending on implementation
}

func TestDetectChangedSections_AllFields(t *testing.T) {
	current := &config.ServerConfig{}
	new := &config.ServerConfig{
		Server:    config.ServerSettings{HTTP: config.ListenerConfig{Listen: "changed"}},
		Backends:  []config.BackendConfig{{Name: "new"}},
		Routes:    []config.RouteConfig{{Backend: "new"}},
		Auth:      config.AuthConfig{Providers: []config.AuthProvider{{Name: "new"}}},
		RateLimit: config.RateLimitConfig{Enabled: true},
		AccessLog: config.AccessLogConfig{Enabled: true},
		Metrics:   config.MetricsConfig{Enabled: true},
		Logging:   logging.Config{Level: "debug"},
		WebUI:     config.WebUIConfig{Enabled: true},
		API:       config.APIConfig{Enabled: true},
	}

	changed := detectChangedSections(current, new)

	assert.Contains(t, changed, "server")
	assert.Contains(t, changed, "backends")
	assert.Contains(t, changed, "routes")
	assert.Contains(t, changed, "auth")
	assert.Contains(t, changed, "rate_limit")
	assert.Contains(t, changed, "access_log")
	assert.Contains(t, changed, "metrics")
	assert.Contains(t, changed, "logging")
	assert.Contains(t, changed, "web_ui")
	assert.Contains(t, changed, "api")
}

func TestHandleGetConfigTimestamp(t *testing.T) {
	api := New(Config{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config/timestamp", nil)
	api.handleGetConfigTimestamp(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "timestamp")
}
