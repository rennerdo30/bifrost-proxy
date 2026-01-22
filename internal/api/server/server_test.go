package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/health"
)

func TestNew(t *testing.T) {
	cfg := Config{
		Token: "test-token",
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.Equal(t, "test-token", api.token)
}

func TestNew_DefaultPorts(t *testing.T) {
	cfg := Config{
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{}
		},
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.NotNil(t, api.pacGenerator)
}

func TestNew_CustomPorts(t *testing.T) {
	cfg := Config{
		ProxyPort:  "9090",
		SOCKS5Port: "9091",
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{}
		},
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.NotNil(t, api.pacGenerator)
}

func TestNew_RequestLogSize(t *testing.T) {
	cfg := Config{
		EnableRequestLog: true,
		RequestLogSize:   500,
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.NotNil(t, api.requestLog)
	assert.True(t, api.requestLog.IsEnabled())
}

func TestAPI_Router(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()
	require.NotNil(t, handler)
}

func TestAPI_Router_WithAuth(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		Token:    "secret-token",
	}

	api := New(cfg)
	handler := api.Router()
	require.NotNil(t, handler)

	// Without auth
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// With auth
	req = httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_AuthMiddleware_QueryParam(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		Token:    "secret-token",
	}

	api := New(cfg)
	handler := api.Router()

	// With token in query param
	req := httptest.NewRequest("GET", "/api/v1/health?token=secret-token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleHealth(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp["status"])
	assert.NotEmpty(t, resp["time"])
}

func TestAPI_HandleHealth_Degraded(t *testing.T) {
	mgr := backend.NewManager()
	healthMgr := health.NewManager()

	cfg := Config{
		Backends:      mgr,
		HealthManager: healthMgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleVersion(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestAPI_HandleStatus(t *testing.T) {
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	mgr.Add(directBackend)

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "running", resp["status"])
	assert.Equal(t, float64(1), resp["backends"])
}

func TestAPI_HandleStats(t *testing.T) {
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	directBackend.Start(context.Background())
	defer directBackend.Stop(context.Background())
	mgr.Add(directBackend)

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "total_connections")
	assert.Contains(t, resp, "active_connections")
	assert.Contains(t, resp, "bytes_sent")
	assert.Contains(t, resp, "backends")
}

func TestAPI_HandleListBackends(t *testing.T) {
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-backend"})
	mgr.Add(directBackend)

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/backends", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "test-backend", resp[0]["name"])
}

func TestAPI_HandleGetBackend(t *testing.T) {
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-backend"})
	mgr.Add(directBackend)

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/backends/test-backend", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test-backend", resp["name"])
}

func TestAPI_HandleGetBackend_NotFound(t *testing.T) {
	mgr := backend.NewManager()

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/backends/nonexistent", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPI_HandleGetBackendStats(t *testing.T) {
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-backend"})
	mgr.Add(directBackend)

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/backends/test-backend/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetBackendStats_NotFound(t *testing.T) {
	mgr := backend.NewManager()

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/backends/nonexistent/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPI_HandleGetConfig(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		GetConfig: func() interface{} {
			return map[string]string{"key": "value"}
		},
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["key"])
}

func TestAPI_HandleGetConfig_NotAvailable(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleReloadConfig(t *testing.T) {
	mgr := backend.NewManager()
	reloadCalled := false
	cfg := Config{
		Backends: mgr,
		ReloadConfig: func() error {
			reloadCalled = true
			return nil
		},
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reloadCalled)
}

func TestAPI_HandleReloadConfig_NotAvailable(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAPI_HandleGetRequests(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: true,
		RequestLogSize:   100,
	}

	api := New(cfg)

	// Add some entries
	api.requestLog.Add(RequestLogEntry{
		Method: "GET",
		Host:   "example.com",
	})

	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	req := httptest.NewRequest("GET", "/api/v1/requests", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["enabled"].(bool))
}

func TestAPI_HandleGetRequests_WithLimit(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: true,
	}

	api := New(cfg)

	for i := 0; i < 10; i++ {
		api.requestLog.Add(RequestLogEntry{
			Method: "GET",
			Host:   "example.com",
		})
	}

	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	req := httptest.NewRequest("GET", "/api/v1/requests?limit=5", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetRequests_WithSince(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: true,
	}

	api := New(cfg)

	for i := 0; i < 5; i++ {
		api.requestLog.Add(RequestLogEntry{
			Method: "GET",
			Host:   "example.com",
		})
	}

	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	req := httptest.NewRequest("GET", "/api/v1/requests?since=3", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetRequests_Disabled(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: false,
	}

	api := New(cfg)
	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	req := httptest.NewRequest("GET", "/api/v1/requests", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["enabled"].(bool))
}

func TestAPI_HandleGetRequestStats(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: true,
	}

	api := New(cfg)
	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	req := httptest.NewRequest("GET", "/api/v1/requests/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleClearRequests(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: true,
	}

	api := New(cfg)

	api.requestLog.Add(RequestLogEntry{
		Method: "GET",
		Host:   "example.com",
	})

	// Use RouterWithWebSocket to get the requests routes
	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	req := httptest.NewRequest("DELETE", "/api/v1/requests", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify cleared
	entries := api.requestLog.GetAll()
	assert.Empty(t, entries)
}

func TestAPI_RequestLog(t *testing.T) {
	cfg := Config{
		EnableRequestLog: true,
	}

	api := New(cfg)
	assert.NotNil(t, api.RequestLog())
}

func TestAPI_RouterWithWebSocket(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{}
		},
	}

	api := New(cfg)
	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)
	require.NotNil(t, handler)
}

func TestAPI_RouterWithWebSocket_NilHub(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)
	handler := api.RouterWithWebSocket(nil)
	require.NotNil(t, handler)
}

// CORS is tested through the router directly rather than the internal middleware

func TestWriteJSON(t *testing.T) {
	api := New(Config{})
	w := httptest.NewRecorder()

	api.writeJSON(w, http.StatusOK, map[string]string{"test": "value"})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["test"])
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Backends:         nil,
		HealthManager:    nil,
		Token:            "test",
		GetConfig:        func() interface{} { return nil },
		GetFullConfig:    func() *config.ServerConfig { return nil },
		ReloadConfig:     func() error { return nil },
		SaveConfig:       func(*config.ServerConfig) error { return nil },
		ConfigPath:       "/path/to/config",
		ProxyHost:        "localhost",
		ProxyPort:        "8080",
		SOCKS5Port:       "1080",
		EnableRequestLog: true,
		RequestLogSize:   1000,
	}

	assert.Equal(t, "test", cfg.Token)
	assert.Equal(t, "/path/to/config", cfg.ConfigPath)
	assert.Equal(t, "localhost", cfg.ProxyHost)
}

func TestAPI_HandleHealth_WithHealthManager(t *testing.T) {
	mgr := backend.NewManager()
	healthMgr := health.NewManager()

	// Just create a basic backend
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	directBackend.Start(context.Background())
	defer directBackend.Stop(context.Background())
	mgr.Add(directBackend)

	cfg := Config{
		Backends:      mgr,
		HealthManager: healthMgr,
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleReloadConfig_Error(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		ReloadConfig: func() error {
			return assert.AnError
		},
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAPI_HandleGetRequestStats_NilLog(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	// Set requestLog to nil for this test
	api.requestLog = nil

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/requests/stats", nil)
	api.handleGetRequestStats(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_SetWebSocketHub(t *testing.T) {
	api := New(Config{})
	hub := NewWebSocketHub()

	api.setWebSocketHub(hub)
	assert.Equal(t, hub, api.wsHub)
}

func TestAPI_HandleGetConfigTimestamp(t *testing.T) {
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

func TestAPI_PAC_Routes(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{
				Routes: []config.RouteConfig{
					{
						Domains: []string{"*.google.com"},
						Backend: "default",
					},
				},
			}
		},
	}

	api := New(cfg)
	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	// Test proxy.pac
	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "proxy-autoconfig")

	// Test wpad.dat
	req = httptest.NewRequest("GET", "/wpad.dat", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_AuthMiddleware_NoBearer(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		Token:    "secret-token",
	}

	api := New(cfg)
	handler := api.Router()

	// Token without Bearer prefix
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "secret-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleClearRequests_NilLog(t *testing.T) {
	api := New(Config{})
	api.requestLog = nil

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/requests", nil)
	api.handleClearRequests(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStaticHandler(t *testing.T) {
	handler := StaticHandler()
	require.NotNil(t, handler)

	// Test that it handles requests (even if embedded FS is empty)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Will return 404 or 200 depending on embedded content
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

// Server API doesn't have CORS middleware built-in like the client API

// Test request log nil handling in handleGetRequests
func TestAPI_HandleGetRequests_NilLog(t *testing.T) {
	api := New(Config{})
	api.requestLog = nil

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/requests", nil)
	api.handleGetRequests(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["enabled"].(bool))
}

// Test with empty backends
func TestAPI_HandleStats_EmptyBackends(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/stats", nil)
	api.handleStats(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	backends := resp["backends"].(map[string]interface{})
	assert.Equal(t, float64(0), backends["total"])
}

// Test with malformed token prefix
func TestAPI_AuthMiddleware_ShortToken(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		Token:    "secret",
	}

	api := New(cfg)
	handler := api.Router()

	// Token that is less than 7 characters
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "short")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// Test handleListBackends with started backend
func TestAPI_HandleListBackends_WithStats(t *testing.T) {
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-backend"})
	directBackend.Start(context.Background())
	defer directBackend.Stop(context.Background())
	mgr.Add(directBackend)

	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/backends", nil)
	api.handleListBackends(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Contains(t, resp[0], "stats")
}

func TestAPI_HandleStatus_WithVersion(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	api.handleStatus(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "version")
}

// Test router with auth and websocket
func TestAPI_RouterWithWebSocket_WithAuth(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		Token:    "secret-token",
	}

	api := New(cfg)
	hub := NewWebSocketHub()
	handler := api.RouterWithWebSocket(hub)

	// API should require auth
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// With auth
	req = httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// Test API routes are added correctly
func TestAPI_AddAPIRoutes(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends:         mgr,
		EnableRequestLog: true,
	}

	api := New(cfg)
	handler := api.Router()

	// Test basic routes exist (requests routes are only via RouterWithWebSocket)
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/health"},
		{"GET", "/api/v1/version"},
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/stats"},
		{"GET", "/api/v1/backends"},
		{"GET", "/api/v1/config"},
		{"GET", "/api/v1/config/meta"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Route should exist (not 404)
		assert.NotEqual(t, http.StatusNotFound, w.Code,
			"Route %s %s should exist", route.method, route.path)
	}
}

func TestAPI_HandleGetFullConfig(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		GetFullConfig: func() *config.ServerConfig {
			return &config.ServerConfig{
				Server: config.ServerSettings{
					HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
				},
			}
		},
	}

	api := New(cfg)
	handler := api.Router()

	req := httptest.NewRequest("GET", "/api/v1/config/full", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetFullConfig_NotAvailable(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/config/full", nil)
	api.handleGetFullConfig(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAPI_HandleValidateConfig(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	body := strings.NewReader(`{"server": {"listen": "0.0.0.0:7080"}}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/config/validate", body)
	api.handleValidateConfig(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleValidateConfig_InvalidJSON(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
	}

	api := New(cfg)

	body := strings.NewReader(`{invalid json}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/config/validate", body)
	api.handleValidateConfig(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleSaveConfig_NotAvailable(t *testing.T) {
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

func TestAPI_HandleSaveConfig_InvalidBody(t *testing.T) {
	mgr := backend.NewManager()
	cfg := Config{
		Backends: mgr,
		SaveConfig: func(*config.ServerConfig) error {
			return nil
		},
	}

	api := New(cfg)

	body := strings.NewReader(`{invalid}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/config", body)
	api.handleSaveConfig(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
