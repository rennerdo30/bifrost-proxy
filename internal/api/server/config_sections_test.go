package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// sectionTestBaseConfig returns a minimal, valid config used as the "current"
// side of every detectChangedSections case below.
func sectionTestBaseConfig() *config.ServerConfig {
	return &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}
}

// TestDetectChangedSections_EachSectionDetected asserts that mutating exactly
// one config section reports exactly that section — for every section of
// ServerConfig. This is the regression guard for the class of bug where a
// section was omitted from the detection chain, so that changes to it were
// written to disk, reported as changed_sections=[] / requires_restart=false and
// never applied to the running server (originally observed for access_control
// and cache, which made an operator-added IP block silently unenforced).
func TestDetectChangedSections_EachSectionDetected(t *testing.T) {
	tests := []struct {
		section string
		mutate  func(c *config.ServerConfig)
	}{
		{SectionServer, func(c *config.ServerConfig) {
			c.Server.HTTP.Listen = "0.0.0.0:9999"
		}},
		{SectionBackends, func(c *config.ServerConfig) {
			c.Backends = append(c.Backends, config.BackendConfig{Name: "extra", Type: "direct"})
		}},
		{SectionRoutes, func(c *config.ServerConfig) {
			c.Routes = []config.RouteConfig{{Name: "r", Domains: []string{"*"}, Backend: "default"}}
		}},
		{SectionAuth, func(c *config.ServerConfig) {
			c.Auth.Providers = []config.AuthProvider{{Name: "p", Type: "native"}}
		}},
		{SectionRateLimit, func(c *config.ServerConfig) {
			c.RateLimit.Enabled = true
			c.RateLimit.RequestsPerSecond = 42
		}},
		{SectionAccessControl, func(c *config.ServerConfig) {
			c.AccessControl.Blacklist = []string{"10.0.0.0/8"}
		}},
		{SectionAccessLog, func(c *config.ServerConfig) {
			c.AccessLog.Enabled = true
			c.AccessLog.Output = "/var/log/bifrost/access.log"
		}},
		{SectionMetrics, func(c *config.ServerConfig) {
			c.Metrics.Enabled = true
			c.Metrics.Listen = "0.0.0.0:9191"
		}},
		{SectionLogging, func(c *config.ServerConfig) {
			c.Logging.Level = "debug"
		}},
		{SectionWebUI, func(c *config.ServerConfig) {
			c.WebUI.Enabled = true
			c.WebUI.Listen = "0.0.0.0:8181"
		}},
		{SectionAPI, func(c *config.ServerConfig) {
			c.API.Enabled = true
			c.API.Listen = "0.0.0.0:8282"
		}},
		{SectionHealthCheck, func(c *config.ServerConfig) {
			c.HealthCheck.Type = "tcp"
			c.HealthCheck.Target = "127.0.0.1:80"
		}},
		{SectionAutoUpdate, func(c *config.ServerConfig) {
			c.AutoUpdate.Enabled = true
			c.AutoUpdate.Channel = "stable"
		}},
		{SectionCache, func(c *config.ServerConfig) {
			c.Cache.Enabled = true
		}},
		{SectionNetwork, func(c *config.ServerConfig) {
			c.Network.MaxConnections = 1234
		}},
		{SectionSession, func(c *config.ServerConfig) {
			c.Session.Store = "redis"
		}},
		{SectionMITM, func(c *config.ServerConfig) {
			c.MITM.Enabled = true
			c.MITM.CACertFile = "/etc/bifrost/ca.pem"
		}},
		{SectionMesh, func(c *config.ServerConfig) {
			c.Mesh.StatePath = "/var/lib/bifrost/mesh.json"
		}},
	}

	// Every section must be exercised; a new ServerConfig section without a
	// case here is a gap in this guard.
	require.Len(t, tests, len(configSectionComparators),
		"every config section needs a detectChangedSections case")

	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			current := sectionTestBaseConfig()
			updated := sectionTestBaseConfig()
			tt.mutate(updated)

			require.NotEqual(t, current, updated, "mutate must actually change the config")

			changed := detectChangedSections(current, updated)
			assert.Equal(t, []string{tt.section}, changed,
				"mutating %s must report exactly that section", tt.section)
		})
	}
}

// TestConfigSectionsCoverServerConfig walks config.ServerConfig by reflection
// and asserts every top-level section is wired into the comparator table and
// the /config/meta description table, and that neither table (nor the
// hot-reloadable map) carries a stale section. Adding a section to ServerConfig
// without registering it now fails here instead of silently becoming an
// unreported, never-applied section.
func TestConfigSectionsCoverServerConfig(t *testing.T) {
	comparators := make(map[string]bool, len(configSectionComparators))
	for _, c := range configSectionComparators {
		comparators[c.Section] = true
	}
	descriptions := make(map[string]bool, len(configSectionDescriptions))
	for _, d := range configSectionDescriptions {
		descriptions[d.Section] = true
	}

	typ := reflect.TypeOf(config.ServerConfig{})
	seen := make(map[string]bool, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		require.NotEmpty(t, name, "ServerConfig.%s needs a json tag", field.Name)
		seen[name] = true

		assert.True(t, comparators[name],
			"config section %q (ServerConfig.%s) is missing from configSectionComparators; "+
				"changes to it would be saved but never detected or applied", name, field.Name)
		assert.True(t, descriptions[name],
			"config section %q (ServerConfig.%s) is missing from configSectionDescriptions",
			name, field.Name)
	}

	for section := range comparators {
		assert.True(t, seen[section], "configSectionComparators has stale section %q", section)
	}
	for section := range descriptions {
		assert.True(t, seen[section], "configSectionDescriptions has stale section %q", section)
	}
	for section := range hotReloadableSections {
		assert.True(t, seen[section], "hotReloadableSections has stale section %q", section)
	}
}

func TestSplitChangedSections(t *testing.T) {
	tests := []struct {
		name            string
		sections        []string
		wantHot         []string
		wantRestart     []string
		wantNeedRestart bool
	}{
		{
			name:        "no changes",
			sections:    []string{},
			wantHot:     []string{},
			wantRestart: []string{},
		},
		{
			name:        "all hot-reloadable",
			sections:    []string{SectionRoutes, SectionRateLimit, SectionAccessControl, SectionCache},
			wantHot:     []string{SectionRoutes, SectionRateLimit, SectionAccessControl, SectionCache},
			wantRestart: []string{},
		},
		{
			name: "all restart-required",
			sections: []string{
				SectionServer, SectionNetwork, SectionSession,
				SectionMITM, SectionHealthCheck, SectionAutoUpdate,
			},
			wantHot: []string{},
			wantRestart: []string{
				SectionServer, SectionNetwork, SectionSession,
				SectionMITM, SectionHealthCheck, SectionAutoUpdate,
			},
			wantNeedRestart: true,
		},
		{
			name:            "mixed keeps both lists and order",
			sections:        []string{SectionServer, SectionRoutes, SectionAuth, SectionCache},
			wantHot:         []string{SectionRoutes, SectionCache},
			wantRestart:     []string{SectionServer, SectionAuth},
			wantNeedRestart: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hot, restart := splitChangedSections(tt.sections)
			assert.Equal(t, tt.wantHot, hot)
			assert.Equal(t, tt.wantRestart, restart)
			assert.Equal(t, tt.wantNeedRestart, hasRestartRequiredChanges(tt.sections))
			assert.Equal(t, tt.wantNeedRestart, len(restart) > 0,
				"requires_restart must equal restart_required_sections being non-empty")
		})
	}
}

// TestHandleGetConfigMeta_HotReloadableDerived asserts /config/meta reports the
// same hot-reloadability the save path uses, rather than a hand-maintained copy
// that can drift from it.
func TestHandleGetConfigMeta_HotReloadableDerived(t *testing.T) {
	api := New(Config{Backends: backend.NewManager()})

	w := httptest.NewRecorder()
	api.handleGetConfigMeta(w, httptest.NewRequest("GET", "/api/v1/config/meta", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var meta []ConfigMeta
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))
	require.Len(t, meta, len(configSectionComparators))

	for _, m := range meta {
		assert.Equal(t, hotReloadableSections[m.Section], m.HotReloadable,
			"meta hot_reloadable for %q must match hotReloadableSections", m.Section)
		assert.NotEmpty(t, m.Description, "section %q needs a description", m.Section)
	}
}

// TestHandleSaveConfig_MixedSaveStillHotReloads covers a single save touching
// both a hot-reloadable and a restart-required section. The hot-reloadable part
// must still be applied to the running server — previously the reload was
// skipped whenever anything required a restart, so e.g. a new IP blocklist
// stayed unenforced — and the response must say which sections landed and which
// are still pending a restart.
func TestHandleSaveConfig_MixedSaveStillHotReloads(t *testing.T) {
	reloadCalls := 0
	api := New(Config{
		Backends:      backend.NewManager(),
		SaveConfig:    func(_ *config.ServerConfig) error { return nil },
		GetFullConfig: sectionTestBaseConfig,
		ReloadConfig: func() error {
			reloadCalls++
			return nil
		},
	})

	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:9999"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}],
			"access_control": {"blacklist": ["10.0.0.0/8"]}
		},
		"create_backup": false
	}`)
	w := httptest.NewRecorder()
	api.handleSaveConfig(w, httptest.NewRequest("PUT", "/api/v1/config", body))

	require.Equal(t, http.StatusOK, w.Code)

	var resp ConfigSaveResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.ElementsMatch(t, []string{SectionServer, SectionAccessControl}, resp.ChangedSections)
	assert.Equal(t, []string{SectionAccessControl}, resp.HotReloadedSections)
	assert.Equal(t, []string{SectionServer}, resp.RestartRequiredSections)
	assert.True(t, resp.RequiresRestart, "the listener change still needs a restart")
	assert.Equal(t, 1, reloadCalls,
		"access_control must be hot-applied even though the same save changed a listener")
}

// TestHandleSaveConfig_ReloadFailureReportsRestart asserts that when the
// auto-reload fails the response stops claiming sections were hot-reloaded and
// tells the operator a restart is needed instead.
func TestHandleSaveConfig_ReloadFailureReportsRestart(t *testing.T) {
	api := New(Config{
		Backends:      backend.NewManager(),
		SaveConfig:    func(_ *config.ServerConfig) error { return nil },
		GetFullConfig: sectionTestBaseConfig,
		ReloadConfig:  func() error { return assert.AnError },
	})

	body := strings.NewReader(`{
		"config": {
			"server": {"http": {"listen": "0.0.0.0:7080"}},
			"backends": [{"name": "default", "type": "direct", "enabled": true}],
			"access_control": {"blacklist": ["10.0.0.0/8"]}
		},
		"create_backup": false
	}`)
	w := httptest.NewRecorder()
	api.handleSaveConfig(w, httptest.NewRequest("PUT", "/api/v1/config", body))

	require.Equal(t, http.StatusOK, w.Code)

	var resp ConfigSaveResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Empty(t, resp.HotReloadedSections, "reload failed, so nothing was applied")
	assert.Equal(t, []string{SectionAccessControl}, resp.RestartRequiredSections)
	assert.True(t, resp.RequiresRestart)
	require.Len(t, resp.Errors, 1)
	assert.Equal(t, "reload", resp.Errors[0].Section)
}
