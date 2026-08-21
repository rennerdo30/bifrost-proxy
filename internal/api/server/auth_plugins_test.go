package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"

	// Registering real plugins is the point: these tests assert what the API
	// does with the provider types the server binary actually offers.
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/mfa"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/system"
)

// newAuthValidationAPI returns an API whose save path is wired well enough to
// reach validation.
func newAuthValidationAPI(t *testing.T) *API {
	t.Helper()
	return New(Config{
		Backends:      backend.NewManager(),
		GetFullConfig: func() *config.ServerConfig { return &config.ServerConfig{} },
		SaveConfig:    func(*config.ServerConfig) error { return nil },
	})
}

// minimalValidConfig is a config that passes ServerConfig.Validate(), so the
// only thing under test is auth provider validation.
func minimalValidConfig(providers ...config.AuthProvider) config.ServerConfig {
	return config.ServerConfig{
		Server:   config.ServerSettings{HTTP: config.ListenerConfig{Listen: ":8080"}},
		Backends: []config.BackendConfig{{Name: "default", Type: "direct"}},
		Auth:     config.AuthConfig{Providers: providers},
	}
}

// postJSON issues a request against the API router with the CSRF header set.
func postJSON(t *testing.T, api *API, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(method, path, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	api.RouterWithWebSocket(nil).ServeHTTP(w, req)
	return w
}

// TestConfigValidate_RefusesNonFunctionalAuthProviders is the regression test
// for the gap that made the audit's auth findings so hard to notice.
//
// config.ServerConfig.Validate() only rejects the legacy `auth.mode` shapes; it
// knows nothing about provider types, because internal/config cannot reach the
// plugin registry. So the Web UI's save and validate endpoints accepted a
// provider that can never authenticate, wrote it to disk, answered "valid", and
// the failure only surfaced at the next restart.
func TestConfigValidate_RefusesNonFunctionalAuthProviders(t *testing.T) {
	cases := []struct {
		name     string
		provider config.AuthProvider
		wantMsg  string
	}{
		{
			name: "ntlm can never authenticate",
			provider: config.AuthProvider{
				Name: "corp-ntlm", Type: "ntlm", Enabled: true,
				Config: map[string]any{"domain": "CORP"},
			},
			wantMsg: "not implemented",
		},
		{
			name: "negotiate is middleware, not a provider",
			provider: config.AuthProvider{
				Name: "sso", Type: "negotiate", Enabled: true,
			},
			wantMsg: "auth.negotiate",
		},
		{
			name: "mfa_wrapper by-name format is unsupported",
			provider: config.AuthProvider{
				Name: "mfa", Type: "mfa_wrapper", Enabled: true,
				Config: map[string]any{"primary_provider": "native-main", "mfa_type": "totp"},
			},
			wantMsg: "inline",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newAuthValidationAPI(t)
			cfg := minimalValidConfig(tc.provider)

			// POST /config/validate must report it invalid...
			w := postJSON(t, api, http.MethodPost, "/api/v1/config/validate", cfg)
			require.Equal(t, http.StatusOK, w.Code)

			var validateResp struct {
				Valid  bool              `json:"valid"`
				Errors []ValidationError `json:"errors"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &validateResp))
			assert.False(t, validateResp.Valid, "validation must not pass")
			require.NotEmpty(t, validateResp.Errors)
			assert.Equal(t, authSection, validateResp.Errors[0].Section)
			assert.Contains(t, validateResp.Errors[0].Message, tc.wantMsg,
				"the error must explain what to do instead")

			// ...and PUT /config must refuse to save it at all.
			w = postJSON(t, api, http.MethodPut, "/api/v1/config/",
				ConfigSaveRequest{Config: cfg})
			require.Equal(t, http.StatusBadRequest, w.Code, "a config that cannot start must not be saved")

			var saveResp ConfigSaveResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &saveResp))
			assert.False(t, saveResp.Success)
			require.NotEmpty(t, saveResp.Errors)
			assert.Contains(t, saveResp.Errors[0].Message, tc.wantMsg)
		})
	}
}

// TestConfigValidate_AcceptsWorkingAndDisabledProviders guards against the fix
// over-reaching in two ways.
func TestConfigValidate_AcceptsWorkingAndDisabledProviders(t *testing.T) {
	t.Run("a functional provider still validates", func(t *testing.T) {
		api := newAuthValidationAPI(t)
		cfg := minimalValidConfig(config.AuthProvider{
			Name: "users", Type: "native", Enabled: true,
			Config: map[string]any{"users": []any{}},
		})

		w := postJSON(t, api, http.MethodPost, "/api/v1/config/validate", cfg)
		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Valid  bool              `json:"valid"`
			Errors []ValidationError `json:"errors"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Valid, "unexpected errors: %v", resp.Errors)
	})

	// Only enabled providers are checked, which matters for usability: an
	// operator whose saved config already contains an ntlm provider must be able
	// to disable it in the UI and save. If disabled providers were refused too,
	// there would be no way out of the bad state through the dashboard.
	t.Run("a disabled non-functional provider can still be saved", func(t *testing.T) {
		api := newAuthValidationAPI(t)
		cfg := minimalValidConfig(config.AuthProvider{
			Name: "corp-ntlm", Type: "ntlm", Enabled: false,
			Config: map[string]any{"domain": "CORP"},
		})

		w := postJSON(t, api, http.MethodPost, "/api/v1/config/validate", cfg)
		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Valid  bool              `json:"valid"`
			Errors []ValidationError `json:"errors"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Valid, "disabling must be a way out, not another dead end: %v", resp.Errors)
	})
}

// TestConfigValidate_NegotiateBlock covers auth.negotiate, the one part of the
// auth config that does not go through auth.Factory — SPNEGO is middleware wired
// separately from the provider chain. Without an explicit check the save path
// still accepted a negotiate block that fails at startup.
func TestConfigValidate_NegotiateBlock(t *testing.T) {
	cases := []struct {
		name      string
		providers []config.AuthProvider
		negotiate *config.NegotiateConfig
		wantMsg   string // empty means it must validate
	}{
		{
			name:      "disabled negotiate is not checked",
			negotiate: &config.NegotiateConfig{Enabled: false, KerberosProvider: "nope"},
		},
		{
			name:      "enabled with no provider at all",
			negotiate: &config.NegotiateConfig{Enabled: true},
			wantMsg:   "neither kerberos_provider nor ntlm_provider",
		},
		{
			name:      "allow_ntlm without an ntlm_provider",
			negotiate: &config.NegotiateConfig{Enabled: true, KerberosProvider: "krb", AllowNTLM: true},
			wantMsg:   "allow_ntlm",
		},
		{
			name:      "reference to a provider that does not exist",
			negotiate: &config.NegotiateConfig{Enabled: true, KerberosProvider: "missing"},
			wantMsg:   "unknown provider",
		},
		{
			name: "reference to a provider of the wrong type",
			providers: []config.AuthProvider{
				{Name: "krb", Type: "native", Enabled: true, Config: map[string]any{"users": []any{}}},
			},
			negotiate: &config.NegotiateConfig{Enabled: true, KerberosProvider: "krb"},
			wantMsg:   "expected \"kerberos\"",
		},
		{
			name: "reference to a disabled provider",
			providers: []config.AuthProvider{
				{Name: "krb", Type: "kerberos", Enabled: false},
			},
			negotiate: &config.NegotiateConfig{Enabled: true, KerberosProvider: "krb"},
			wantMsg:   "not enabled",
		},
		{
			// The headline case: NTLM fallback cannot work, so a negotiate block
			// depending on it must fail here rather than at the next restart.
			name: "reference to an ntlm provider",
			providers: []config.AuthProvider{
				{Name: "ntlm", Type: "ntlm", Enabled: true, Config: map[string]any{"domain": "CORP"}},
			},
			negotiate: &config.NegotiateConfig{Enabled: true, NTLMProvider: "ntlm", AllowNTLM: true},
			wantMsg:   "not implemented",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newAuthValidationAPI(t)
			cfg := minimalValidConfig(tc.providers...)
			cfg.Auth.Negotiate = tc.negotiate

			w := postJSON(t, api, http.MethodPost, "/api/v1/config/validate", cfg)
			require.Equal(t, http.StatusOK, w.Code)

			var resp struct {
				Valid  bool              `json:"valid"`
				Errors []ValidationError `json:"errors"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			if tc.wantMsg == "" {
				assert.True(t, resp.Valid, "unexpected errors: %v", resp.Errors)
				return
			}
			assert.False(t, resp.Valid)
			require.NotEmpty(t, resp.Errors)
			assert.Equal(t, authSection, resp.Errors[0].Section)
			assert.Contains(t, resp.Errors[0].Message, tc.wantMsg)
		})
	}
}

// TestHandleListAuthPlugins covers the endpoint the dashboard uses to label
// providers honestly instead of carrying a hand-maintained list that drifts from
// the code and cannot express build-dependent truths.
func TestHandleListAuthPlugins(t *testing.T) {
	api := newAuthValidationAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/plugins", nil)
	w := httptest.NewRecorder()
	api.RouterWithWebSocket(nil).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Plugins []auth.PluginInfo `json:"plugins"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Plugins)

	byName := make(map[string]auth.PluginInfo, len(resp.Plugins))
	for _, p := range resp.Plugins {
		byName[p.Name] = p
		assert.NotEmpty(t, p.Availability.State, "every plugin must report an availability state")
	}

	// NTLM must be reported as a permanent dead end, with a reason.
	ntlmInfo, ok := byName["ntlm"]
	require.True(t, ok, "ntlm should be listed so the UI can mark it unusable")
	assert.Equal(t, auth.AvailabilityUnimplemented, ntlmInfo.Availability.State)
	assert.NotEmpty(t, ntlmInfo.Availability.Reason)

	// A working provider must not be flagged.
	nativeInfo, ok := byName["native"]
	require.True(t, ok)
	assert.Equal(t, auth.AvailabilityAvailable, nativeInfo.Availability.State)

	// mfa_wrapper is registered and must be discoverable — the hand-maintained
	// TypeScript list omitted it entirely.
	_, ok = byName["mfa_wrapper"]
	assert.True(t, ok, "mfa_wrapper is registered and must be listed")
}
