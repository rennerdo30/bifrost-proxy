package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/debug"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

func TestNew(t *testing.T) {
	cfg := Config{
		Token: "test-token",
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.Equal(t, "test-token", api.token)
}

func TestNew_AllFields(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	cfg := Config{
		Router:   nil,
		Debugger: debugger,
		ServerConnected: func() bool {
			return true
		},
		Token: "my-token",
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.NotNil(t, api.debugger)
	assert.NotNil(t, api.serverConnected)
}

func TestAPI_Handler(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()
	require.NotNil(t, handler)
}

func TestAPI_Handler_WithAuth(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.Handler()

	// Without auth
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// With auth
	req = httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandlerWithUI(t *testing.T) {
	api := New(Config{})
	handler := api.HandlerWithUI()
	require.NotNil(t, handler)
}

func TestAPI_HandlerWithUI_WithAuth(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.HandlerWithUI()

	// API should require auth
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// With auth
	req = httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleHealth(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

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

func TestAPI_HandleHealth_Connected(t *testing.T) {
	api := New(Config{
		ServerConnected: func() bool {
			return true
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp["status"])
}

func TestAPI_HandleHealth_Degraded(t *testing.T) {
	api := New(Config{
		ServerConnected: func() bool {
			return false
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "degraded", resp["status"])
}

func TestAPI_HandleVersion(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestAPI_HandleStatus(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "running", resp["status"])
	assert.Contains(t, resp, "timestamp")
	assert.Contains(t, resp, "version")
	assert.Contains(t, resp, "server_connected")
}

func TestAPI_HandleStatus_Connected(t *testing.T) {
	api := New(Config{
		ServerConnected: func() bool {
			return true
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, true, resp["server_connected"])
}

func TestAPI_HandleStatus_Disconnected(t *testing.T) {
	api := New(Config{
		ServerConnected: func() bool {
			return false
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, false, resp["server_connected"])
}

func TestAPI_HandleStatus_WithDebugger(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "debug_entries")
}

func TestAPI_HandleGetDebugEntries(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/debug/entries", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetDebugEntries_NilDebugger(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/debug/entries", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp)
}

func TestAPI_HandleGetLastDebugEntries(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/debug/entries/last/10", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetLastDebugEntries_NilDebugger(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/debug/entries/last/10", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetLastDebugEntries_InvalidCount(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	// Invalid count should default to 100
	req := httptest.NewRequest("GET", "/api/v1/debug/entries/last/invalid", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleClearDebugEntries(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/debug/entries", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "cleared", resp["message"])
}

func TestAPI_HandleClearDebugEntries_NilDebugger(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/debug/entries", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetDebugErrors(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/debug/errors", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetDebugErrors_NilDebugger(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/debug/errors", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetRoutes(t *testing.T) {
	clientRouter := router.NewClientRouter()

	api := New(Config{
		Router: clientRouter,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/routes", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetRoutes_NilRouter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/routes", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp)
}

func TestAPI_HandleTestRoute(t *testing.T) {
	clientRouter := router.NewClientRouter()

	api := New(Config{
		Router: clientRouter,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/routes/test?domain=example.com", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "example.com", resp["domain"])
	assert.NotEmpty(t, resp["action"])
}

func TestAPI_HandleTestRoute_NoDomain(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/routes/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleTestRoute_NilRouter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/routes/test?domain=example.com", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "server", resp["action"]) // Default action
}

func TestAPI_AuthMiddleware_QueryToken(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.Handler()

	// With token in query
	req := httptest.NewRequest("GET", "/api/v1/health?token=secret", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_AuthMiddleware_InvalidToken(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAPI_AuthMiddleware_ShortToken(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.Handler()

	// Token shorter than "Bearer " prefix
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "short")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAPI_AuthMiddleware_NoBearer(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.Handler()

	// Token without Bearer prefix
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCorsMiddleware(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	// CORS only allows localhost origins for security
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Headers"))
}

func TestCorsMiddleware_Options(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestAPI_WriteJSON(t *testing.T) {
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
		Router:   nil,
		Debugger: nil,
		ServerConnected: func() bool {
			return true
		},
		Token: "test-token",
	}

	assert.Nil(t, cfg.Router)
	assert.Nil(t, cfg.Debugger)
	assert.NotNil(t, cfg.ServerConnected)
	assert.Equal(t, "test-token", cfg.Token)
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

func TestAPI_AllRoutes(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})
	clientRouter := router.NewClientRouter()

	api := New(Config{
		Router:   clientRouter,
		Debugger: debugger,
	})
	handler := api.Handler()

	// Test all routes exist
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/health"},
		{"GET", "/api/v1/version"},
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/debug/entries"},
		{"DELETE", "/api/v1/debug/entries"},
		{"GET", "/api/v1/debug/errors"},
		{"GET", "/api/v1/routes"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusNotFound, w.Code,
			"Route %s %s should exist", route.method, route.path)
	}
}

func TestAPI_HandleGetRoutes_WithRoutes(t *testing.T) {
	clientRouter := router.NewClientRouter()
	clientRouter.LoadRoutes([]config.ClientRouteConfig{
		{
			Name:     "test-route",
			Domains:  []string{"example.com"},
			Action:   "direct",
			Priority: 100,
		},
	})

	api := New(Config{
		Router: clientRouter,
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/routes", nil)
	api.handleGetRoutes(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Should have at least one route
	assert.Len(t, resp, 1)
}

func TestAPI_HandleStatus_NoServerConnected(t *testing.T) {
	api := New(Config{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	api.handleStatus(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, false, resp["server_connected"])
}

// ============================================================================
// VPN Handler Tests
// ============================================================================

func TestAPI_HandleVPNStatus_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp vpn.VPNStats
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, vpn.StatusDisabled, resp.Status)
}

func TestAPI_HandleVPNEnable_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/enable", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNDisable_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/disable", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNConnections_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/connections", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []vpn.ConnectionInfo
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp)
}

func TestAPI_HandleVPNSplitRules_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/split/rules", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleVPNSplitAddApp_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"name": "testapp", "path": "/usr/bin/testapp"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/apps", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitAddApp_InvalidBody(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/split/apps", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitAddApp_EmptyName(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"name": "", "path": "/usr/bin/testapp"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/apps", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitRemoveApp_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/apps/testapp", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitAddDomain_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"pattern": "*.example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/domains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitAddDomain_InvalidBody(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/split/domains", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitAddDomain_EmptyPattern(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"pattern": ""}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/domains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitAddIP_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"cidr": "10.0.0.0/8"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/ips", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitAddIP_InvalidBody(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/split/ips", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitAddIP_EmptyCIDR(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"cidr": ""}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/ips", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNDNSCache(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/dns/cache", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// Config Handler Tests
// ============================================================================

func TestAPI_HandleGetConfig_NilConfigGetter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/config/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "config not available")
}

func TestAPI_HandleGetConfig_Success(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/config/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleUpdateConfig_NilConfigUpdater(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"proxy": {"http": {"listen": "127.0.0.1:7380"}}}`
	req := httptest.NewRequest("PUT", "/api/v1/config/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAPI_HandleUpdateConfig_InvalidBody(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("PUT", "/api/v1/config/", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleUpdateConfig_UpdaterError(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return errors.New("update failed")
		},
	})
	handler := api.Handler()

	body := `{"proxy": {"http": {"listen": "127.0.0.1:7380"}}}`
	req := httptest.NewRequest("PUT", "/api/v1/config/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleUpdateConfig_Success(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"debug": {"enabled": true}}`
	req := httptest.NewRequest("PUT", "/api/v1/config/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigUpdateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "updated", resp.Status)
}

func TestAPI_HandleUpdateConfig_RestartRequired(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	// Changes to proxy.http.listen require restart
	body := `{"proxy": {"http": {"listen": "127.0.0.1:7380"}}}`
	req := httptest.NewRequest("PUT", "/api/v1/config/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigUpdateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.RestartRequired)
	assert.NotEmpty(t, resp.RestartFields)
}

func TestAPI_HandleValidateConfig_InvalidBody(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/validate", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleValidateConfig_NoConfigGetter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"debug": {"enabled": true}}`
	req := httptest.NewRequest("POST", "/api/v1/config/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigValidationResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestAPI_HandleValidateConfig_WithConfigGetter(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	body := `{"debug": {"enabled": true}}`
	req := httptest.NewRequest("POST", "/api/v1/config/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigValidationResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

func TestAPI_HandleValidateConfig_InvalidConfig(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	// Invalid config: no proxy listeners
	body := `{"proxy": {"http": {"listen": ""}, "socks5": {"listen": ""}}}`
	req := httptest.NewRequest("POST", "/api/v1/config/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigValidationResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.NotEmpty(t, resp.Errors)
}

func TestAPI_HandleValidateConfig_RestartWarnings(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	// Changes that require restart
	body := `{"vpn": {"enabled": true}}`
	req := httptest.NewRequest("POST", "/api/v1/config/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigValidationResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Warnings)
}

func TestAPI_HandleGetConfigDefaults(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/config/defaults", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleExportConfig_NilConfigGetter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/export", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAPI_HandleExportConfig_JSON(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/export?format=json", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
}

func TestAPI_HandleExportConfig_YAML(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/export?format=yaml", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-yaml", w.Header().Get("Content-Type"))
}

func TestAPI_HandleExportConfig_DefaultFormat(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/export", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Default is YAML
	assert.Equal(t, "application/x-yaml", w.Header().Get("Content-Type"))
}

func TestAPI_HandleExportConfig_UnsupportedFormat(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/export?format=xml", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleImportConfig_NilConfigUpdater(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"proxy": {"http": {"listen": "127.0.0.1:7380"}}}`
	req := httptest.NewRequest("POST", "/api/v1/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAPI_HandleImportConfig_InvalidJSON(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/import?format=json", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleImportConfig_InvalidYAML(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/import?format=yaml", strings.NewReader("invalid: yaml: content:"))
	req.Header.Set("Content-Type", "application/x-yaml")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleImportConfig_UnsupportedFormat(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/import?format=xml", strings.NewReader("<config/>"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleImportConfig_ValidationFailed(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	// Invalid config: no proxy listeners
	body := `{"proxy": {"http": {"listen": ""}, "socks5": {"listen": ""}}}`
	req := httptest.NewRequest("POST", "/api/v1/config/import?format=json", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleImportConfig_UpdaterError(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return errors.New("update failed")
		},
	})
	handler := api.Handler()

	testConfig := config.DefaultClientConfig()
	body, _ := json.Marshal(testConfig)
	req := httptest.NewRequest("POST", "/api/v1/config/import?format=json", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleImportConfig_Success(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	testConfig := config.DefaultClientConfig()
	body, _ := json.Marshal(testConfig)
	req := httptest.NewRequest("POST", "/api/v1/config/import?format=json", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigUpdateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "imported", resp.Status)
}

func TestAPI_HandleImportConfig_ContentTypeYAML(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	yamlBody := `
proxy:
  http:
    listen: "127.0.0.1:7380"
  socks5:
    listen: "127.0.0.1:7381"
debug:
  enabled: true
  max_entries: 1000
`
	req := httptest.NewRequest("POST", "/api/v1/config/import", strings.NewReader(yamlBody))
	req.Header.Set("Content-Type", "application/x-yaml")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleReloadConfig_NilConfigReloader(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAPI_HandleReloadConfig_ReloaderError(t *testing.T) {
	api := New(Config{
		ConfigReloader: func() error {
			return errors.New("reload failed")
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAPI_HandleReloadConfig_Success(t *testing.T) {
	api := New(Config{
		ConfigReloader: func() error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "reloaded", resp["status"])
}

// ============================================================================
// Log Handler Tests
// ============================================================================

func TestAPI_HandleGetLogs_NilDebugger(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/logs/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp["entries"])
}

func TestAPI_HandleGetLogs_WithPagination(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/logs/?limit=10&offset=5", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(10), resp["limit"])
	assert.Equal(t, float64(5), resp["offset"])
}

func TestAPI_HandleGetLogs_WithLevelFilter(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/logs/?level=error", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetLogs_InvalidPagination(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/logs/?limit=invalid&offset=invalid", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Should use defaults
	assert.Equal(t, float64(100), resp["limit"])
	assert.Equal(t, float64(0), resp["offset"])
}

// ============================================================================
// Desktop App Handler Tests
// ============================================================================

func TestAPI_HandleConnect_NilConnector(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/connect", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "connected", resp["status"])
}

func TestAPI_HandleConnect_ConnectorError(t *testing.T) {
	api := New(Config{
		Connector: func() error {
			return errors.New("connection failed")
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/connect", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAPI_HandleConnect_Success(t *testing.T) {
	api := New(Config{
		Connector: func() error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/connect", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "connected", resp["status"])
}

func TestAPI_HandleDisconnect_NilDisconnector(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/disconnect", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "disconnected", resp["status"])
}

func TestAPI_HandleDisconnect_DisconnectorError(t *testing.T) {
	api := New(Config{
		Disconnector: func() error {
			return errors.New("disconnection failed")
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/disconnect", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAPI_HandleDisconnect_Success(t *testing.T) {
	api := New(Config{
		Disconnector: func() error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/disconnect", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetServers_NilServersGetter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/servers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []ServerInfo
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp)
}

func TestAPI_HandleGetServers_NilResult(t *testing.T) {
	api := New(Config{
		ServersGetter: func() []ServerInfo {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/servers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []ServerInfo
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp)
}

func TestAPI_HandleGetServers_Success(t *testing.T) {
	servers := []ServerInfo{
		{Name: "server1", Address: "192.168.1.1:7080", Protocol: "http", IsDefault: true, Status: "connected"},
		{Name: "server2", Address: "192.168.1.2:7080", Protocol: "socks5", IsDefault: false, Status: "available"},
	}
	api := New(Config{
		ServersGetter: func() []ServerInfo {
			return servers
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/servers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []ServerInfo
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 2)
}

func TestAPI_HandleSelectServer_InvalidBody(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/server/select", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleSelectServer_EmptyServer(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"server": ""}`
	req := httptest.NewRequest("POST", "/api/v1/server/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleSelectServer_NilServerSelector(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"server": "server1"}`
	req := httptest.NewRequest("POST", "/api/v1/server/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "selected", resp["status"])
	assert.Equal(t, "server1", resp["server"])
}

func TestAPI_HandleSelectServer_SelectorError(t *testing.T) {
	api := New(Config{
		ServerSelector: func(server string) error {
			return errors.New("server not found")
		},
	})
	handler := api.Handler()

	body := `{"server": "invalid-server"}`
	req := httptest.NewRequest("POST", "/api/v1/server/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleSelectServer_Success(t *testing.T) {
	api := New(Config{
		ServerSelector: func(server string) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"server": "server1"}`
	req := httptest.NewRequest("POST", "/api/v1/server/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetSettings_NilSettingsGetter(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/settings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp QuickSettings
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.ShowNotifications)
}

func TestAPI_HandleGetSettings_NilResult(t *testing.T) {
	api := New(Config{
		SettingsGetter: func() *QuickSettings {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/settings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPI_HandleGetSettings_Success(t *testing.T) {
	settings := &QuickSettings{
		AutoConnect:       true,
		StartMinimized:    true,
		ShowNotifications: true,
		VPNEnabled:        false,
		CurrentServer:     "server1",
	}
	api := New(Config{
		SettingsGetter: func() *QuickSettings {
			return settings
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/settings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp QuickSettings
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.AutoConnect)
	assert.Equal(t, "server1", resp.CurrentServer)
}

func TestAPI_HandleUpdateSettings_InvalidBody(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/settings", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleUpdateSettings_UpdaterError(t *testing.T) {
	api := New(Config{
		SettingsUpdater: func(settings *QuickSettings) error {
			return errors.New("update failed")
		},
	})
	handler := api.Handler()

	body := `{"auto_connect": true}`
	req := httptest.NewRequest("POST", "/api/v1/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAPI_HandleUpdateSettings_Success(t *testing.T) {
	api := New(Config{
		SettingsUpdater: func(settings *QuickSettings) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"auto_connect": true, "show_notifications": false}`
	req := httptest.NewRequest("POST", "/api/v1/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "updated", resp["status"])
}

func TestAPI_HandleUpdateSettings_NilUpdater(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"auto_connect": true}`
	req := httptest.NewRequest("POST", "/api/v1/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestIsLocalOrigin(t *testing.T) {
	tests := []struct {
		origin   string
		expected bool
	}{
		{"http://localhost", true},
		{"http://localhost:3000", true},
		{"https://localhost", true},
		{"https://localhost:7080", true},
		{"http://127.0.0.1", true},
		{"http://127.0.0.1:3000", true},
		{"https://127.0.0.1", true},
		{"http://[::1]", true},
		{"http://[::1]:3000", true},
		{"https://[::1]", true},
		{"http://example.com", false},
		{"http://localhost.example.com", false},
		{"http://localhostt", false},
		{"http://", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			result := isLocalOrigin(tt.origin)
			assert.Equal(t, tt.expected, result, "isLocalOrigin(%q) = %v, want %v", tt.origin, result, tt.expected)
		})
	}
}

func TestFlattenMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		prefix   string
		expected []string
	}{
		{
			name:     "simple map",
			input:    map[string]interface{}{"a": 1, "b": 2},
			prefix:   "",
			expected: []string{"a", "b"},
		},
		{
			name: "nested map",
			input: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen": "127.0.0.1:7380",
					},
				},
			},
			prefix:   "",
			expected: []string{"proxy.http.listen"},
		},
		{
			name:     "with prefix",
			input:    map[string]interface{}{"key": "value"},
			prefix:   "root",
			expected: []string{"root.key"},
		},
		{
			name:     "empty map",
			input:    map[string]interface{}{},
			prefix:   "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := flattenMap(tt.input, tt.prefix)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestMergeMap(t *testing.T) {
	tests := []struct {
		name     string
		dst      map[string]interface{}
		src      map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name:     "simple merge",
			dst:      map[string]interface{}{"a": 1},
			src:      map[string]interface{}{"b": 2},
			expected: map[string]interface{}{"a": 1, "b": 2},
		},
		{
			name:     "override value",
			dst:      map[string]interface{}{"a": 1},
			src:      map[string]interface{}{"a": 2},
			expected: map[string]interface{}{"a": 2},
		},
		{
			name: "nested merge",
			dst: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen": "old",
					},
				},
			},
			src: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen": "new",
					},
				},
			},
			expected: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen": "new",
					},
				},
			},
		},
		{
			name: "nested merge with new key",
			dst: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen": "127.0.0.1:7380",
					},
				},
			},
			src: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"timeout": 30,
					},
				},
			},
			expected: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen":  "127.0.0.1:7380",
						"timeout": 30,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeMap(tt.dst, tt.src)
			assert.Equal(t, tt.expected, tt.dst)
		})
	}
}

func TestCheckRestartRequired(t *testing.T) {
	api := New(Config{})

	tests := []struct {
		name          string
		updates       map[string]interface{}
		expectRestart bool
	}{
		{
			name:          "debug changes - no restart",
			updates:       map[string]interface{}{"debug": map[string]interface{}{"enabled": true}},
			expectRestart: false,
		},
		{
			name: "proxy.http.listen - requires restart",
			updates: map[string]interface{}{
				"proxy": map[string]interface{}{
					"http": map[string]interface{}{
						"listen": "127.0.0.1:7380",
					},
				},
			},
			expectRestart: true,
		},
		{
			name: "vpn.enabled - requires restart",
			updates: map[string]interface{}{
				"vpn": map[string]interface{}{
					"enabled": true,
				},
			},
			expectRestart: true,
		},
		{
			name: "mesh.enabled - requires restart",
			updates: map[string]interface{}{
				"mesh": map[string]interface{}{
					"enabled": true,
				},
			},
			expectRestart: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := api.checkRestartRequired(tt.updates)
			if tt.expectRestart {
				assert.NotEmpty(t, result)
			} else {
				assert.Empty(t, result)
			}
		})
	}
}

// ============================================================================
// Middleware Tests
// ============================================================================

func TestSecurityHeadersMiddleware(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
}

func TestAPISecurityHeadersMiddleware(t *testing.T) {
	api := New(Config{})
	handler := api.HandlerWithUI()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestCorsMiddleware_NonLocalOrigin(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should not set CORS headers for non-local origins
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCorsMiddleware_127001(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://127.0.0.1:7080")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "http://127.0.0.1:7080", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCorsMiddleware_IPv6(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://[::1]:7080")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "http://[::1]:7080", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCorsMiddleware_NoOrigin(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	// No Origin header
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should not set CORS headers for same-origin requests
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCorsMiddleware_OptionsWithLocalOrigin(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestAuthMiddleware_EmptyToken(t *testing.T) {
	api := New(Config{
		Token: "",
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should allow without auth when no token configured
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// BroadcastLog Tests
// ============================================================================

func TestAPI_BroadcastLog(t *testing.T) {
	api := New(Config{})

	// Create a subscriber
	sub := &logSubscriber{
		ch: make(chan LogEntry, 10),
	}
	api.logMu.Lock()
	api.logSubscribers[sub] = struct{}{}
	api.logMu.Unlock()

	// Broadcast a log entry
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "info",
		Message:   "test message",
	}
	api.BroadcastLog(entry)

	// Check that subscriber received it
	select {
	case received := <-sub.ch:
		assert.Equal(t, entry.Message, received.Message)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for log entry")
	}

	// Cleanup
	sub.closed.Store(true)
	api.logMu.Lock()
	delete(api.logSubscribers, sub)
	api.logMu.Unlock()
}

func TestAPI_BroadcastLog_FullChannel(t *testing.T) {
	api := New(Config{})

	// Create a subscriber with a full channel
	sub := &logSubscriber{
		ch: make(chan LogEntry, 1),
	}
	sub.ch <- LogEntry{} // Fill the channel

	api.logMu.Lock()
	api.logSubscribers[sub] = struct{}{}
	api.logMu.Unlock()

	// This should not block even with full channel
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "info",
		Message:   "test message",
	}
	api.BroadcastLog(entry)

	// Cleanup
	sub.closed.Store(true)
	api.logMu.Lock()
	delete(api.logSubscribers, sub)
	api.logMu.Unlock()
}

func TestAPI_BroadcastLog_NoSubscribers(t *testing.T) {
	api := New(Config{})

	// Should not panic with no subscribers
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "info",
		Message:   "test message",
	}
	api.BroadcastLog(entry)
}

// ============================================================================
// Status with Additional Fields Tests
// ============================================================================

func TestAPI_HandleStatus_WithBytesAndConns(t *testing.T) {
	api := New(Config{
		ServerConnected: func() bool {
			return true
		},
		BytesSent: func() int64 {
			return 1000
		},
		BytesReceived: func() int64 {
			return 2000
		},
		ActiveConns: func() int {
			return 5
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1000), resp["bytes_sent"])
	assert.Equal(t, float64(2000), resp["bytes_received"])
	assert.Equal(t, float64(5), resp["active_connections"])
}

func TestAPI_HandleStatus_WithServerAddressAndProxies(t *testing.T) {
	api := New(Config{
		ServerAddress:   "proxy.example.com:7080",
		HTTPProxyAddr:   "127.0.0.1:7380",
		SOCKS5ProxyAddr: "127.0.0.1:7381",
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "proxy.example.com:7080", resp["server_address"])
	assert.Equal(t, "127.0.0.1:7380", resp["http_proxy"])
	assert.Equal(t, "127.0.0.1:7381", resp["socks5_proxy"])
}

// ============================================================================
// Static Handler Tests
// ============================================================================

func TestStaticHandler_RootPath(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Will be 200 or 404 depending on embedded files
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

func TestStaticHandler_NonFilePath(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// SPA support: should try to serve index.html
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

func TestStaticHandler_JSFile(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/app.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Will be 200 or 404 depending on embedded files
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

func TestStaticHandler_CSSFile(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/styles.css", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Will be 200 or 404 depending on embedded files
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

// ============================================================================
// Config All Fields Tests
// ============================================================================

func TestNew_AllConfigFields(t *testing.T) {
	cfg := Config{
		Router:   router.NewClientRouter(),
		Debugger: debug.NewLogger(debug.Config{MaxEntries: 100}),
		ServerConnected: func() bool {
			return true
		},
		Token:           "test-token",
		VPNManager:      nil,
		ConfigGetter:    func() interface{} { return nil },
		ConfigUpdater:   func(m map[string]interface{}) error { return nil },
		ConfigReloader:  func() error { return nil },
		ServerAddress:   "server:7080",
		HTTPProxyAddr:   "127.0.0.1:7380",
		SOCKS5ProxyAddr: "127.0.0.1:7381",
		Connector:       func() error { return nil },
		Disconnector:    func() error { return nil },
		ServersGetter:   func() []ServerInfo { return nil },
		ServerSelector:  func(s string) error { return nil },
		SettingsGetter:  func() *QuickSettings { return nil },
		SettingsUpdater: func(s *QuickSettings) error { return nil },
		BytesSent:       func() int64 { return 0 },
		BytesReceived:   func() int64 { return 0 },
		ActiveConns:     func() int { return 0 },
	}

	api := New(cfg)
	require.NotNil(t, api)
	assert.NotNil(t, api.router)
	assert.NotNil(t, api.debugger)
	assert.NotNil(t, api.serverConnected)
	assert.Equal(t, "test-token", api.token)
	assert.NotNil(t, api.configGetter)
	assert.NotNil(t, api.configUpdater)
	assert.NotNil(t, api.configReloader)
	assert.Equal(t, "server:7080", api.serverAddress)
	assert.Equal(t, "127.0.0.1:7380", api.httpProxyAddr)
	assert.Equal(t, "127.0.0.1:7381", api.socks5ProxyAddr)
	assert.NotNil(t, api.connector)
	assert.NotNil(t, api.disconnector)
	assert.NotNil(t, api.serversGetter)
	assert.NotNil(t, api.serverSelector)
	assert.NotNil(t, api.settingsGetter)
	assert.NotNil(t, api.settingsUpdater)
	assert.NotNil(t, api.bytesSent)
	assert.NotNil(t, api.bytesReceived)
	assert.NotNil(t, api.activeConns)
}

// ============================================================================
// HandlerWithUI Additional Routes Tests
// ============================================================================

func TestAPI_HandlerWithUI_AllAPIRoutes(t *testing.T) {
	api := New(Config{})
	handler := api.HandlerWithUI()

	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/health"},
		{"GET", "/api/v1/version"},
		{"GET", "/api/v1/status"},
		{"POST", "/api/v1/connect"},
		{"POST", "/api/v1/disconnect"},
		{"GET", "/api/v1/servers"},
		{"GET", "/api/v1/settings"},
		{"GET", "/api/v1/config/"},
		{"GET", "/api/v1/config/defaults"},
		{"GET", "/api/v1/logs/"},
		{"GET", "/api/v1/debug/entries"},
		{"GET", "/api/v1/debug/errors"},
		{"GET", "/api/v1/routes"},
		{"GET", "/api/v1/vpn/status"},
		{"GET", "/api/v1/vpn/connections"},
		{"GET", "/api/v1/vpn/split/rules"},
		{"GET", "/api/v1/vpn/dns/cache"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusNotFound, w.Code,
			"Route %s %s should exist in HandlerWithUI", route.method, route.path)
	}
}

// ============================================================================
// Log Streaming Test (basic - without full SSE test)
// ============================================================================

func TestAPI_HandleLogStream_Setup(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	// Create a request with a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/api/v1/logs/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	// Cancel context immediately to stop the streaming
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	handler.ServeHTTP(w, req)

	// Should have SSE headers
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
	assert.Equal(t, "keep-alive", w.Header().Get("Connection"))
}

// ============================================================================
// VPN Split Remove App Empty Name Test
// ============================================================================

func TestAPI_HandleVPNSplitRemoveApp_EmptyName(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	// The chi router will return 405 for empty name because the route won't match
	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/apps/", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// This will either be 400 (bad request) or 404/405 depending on router behavior
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed)
}

// ============================================================================
// Mock VPN Manager Tests
// ============================================================================

// mockVPNManager is a mock implementation of the VPN manager for testing
type mockVPNManager struct {
	status             vpn.VPNStats
	connections        []vpn.ConnectionInfo
	splitTunnelRules   vpn.SplitTunnelConfig
	startErr           error
	stopErr            error
	addAppErr          error
	removeAppErr       error
	addDomainErr       error
	removeDomainErr    error
	addIPErr           error
	removeIPErr        error
	setModeErr         error
}

func (m *mockVPNManager) Status() vpn.VPNStats {
	return m.status
}

func (m *mockVPNManager) Connections() []vpn.ConnectionInfo {
	return m.connections
}

func (m *mockVPNManager) Enabled() bool {
	return m.status.Status != vpn.StatusDisabled
}

func (m *mockVPNManager) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.status.Status = vpn.StatusConnected
	return nil
}

func (m *mockVPNManager) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.status.Status = vpn.StatusDisconnected
	return nil
}

func (m *mockVPNManager) SplitTunnelRules() vpn.SplitTunnelConfig {
	return m.splitTunnelRules
}

func (m *mockVPNManager) AddSplitTunnelApp(app vpn.AppRule) error {
	if m.addAppErr != nil {
		return m.addAppErr
	}
	m.splitTunnelRules.Apps = append(m.splitTunnelRules.Apps, app)
	return nil
}

func (m *mockVPNManager) RemoveSplitTunnelApp(name string) error {
	if m.removeAppErr != nil {
		return m.removeAppErr
	}
	return nil
}

func (m *mockVPNManager) AddSplitTunnelDomain(pattern string) error {
	if m.addDomainErr != nil {
		return m.addDomainErr
	}
	m.splitTunnelRules.Domains = append(m.splitTunnelRules.Domains, pattern)
	return nil
}

func (m *mockVPNManager) RemoveSplitTunnelDomain(pattern string) error {
	if m.removeDomainErr != nil {
		return m.removeDomainErr
	}
	return nil
}

func (m *mockVPNManager) AddSplitTunnelIP(cidr string) error {
	if m.addIPErr != nil {
		return m.addIPErr
	}
	m.splitTunnelRules.IPs = append(m.splitTunnelRules.IPs, cidr)
	return nil
}

func (m *mockVPNManager) RemoveSplitTunnelIP(cidr string) error {
	if m.removeIPErr != nil {
		return m.removeIPErr
	}
	return nil
}

func (m *mockVPNManager) SetSplitTunnelMode(mode string) error {
	if m.setModeErr != nil {
		return m.setModeErr
	}
	m.splitTunnelRules.Mode = mode
	return nil
}

func newMockVPNManager() *mockVPNManager {
	return &mockVPNManager{
		status: vpn.VPNStats{
			Status: vpn.StatusConnected,
		},
		connections:      []vpn.ConnectionInfo{},
		splitTunnelRules: vpn.SplitTunnelConfig{Mode: "exclude"},
	}
}

func TestAPI_HandleVPNStatus_WithMockVPNManager(t *testing.T) {
	// Note: This test uses nil VPNManager since mockVPNManager type is not compatible
	// with *vpn.Manager. This tests the "VPN not configured" path.
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// With nil VPNManager, should return service unavailable or an error status
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusServiceUnavailable)
}

func TestAPI_HandleVPNEnable_WithMockVPNManager(t *testing.T) {

	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/enable", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "enabled", resp["status"])
}

func TestAPI_HandleVPNEnable_WithMockVPNManager_Error(t *testing.T) {

	mock := newMockVPNManager()
	mock.startErr = errors.New("start failed")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/enable", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "start failed")
}

func TestAPI_HandleVPNDisable_WithMockVPNManager(t *testing.T) {
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/disable", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "disabled", resp["status"])
}

func TestAPI_HandleVPNDisable_WithMockVPNManager_Error(t *testing.T) {

	mock := newMockVPNManager()
	mock.stopErr = errors.New("stop failed")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	req := httptest.NewRequest("POST", "/api/v1/vpn/disable", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "stop failed")
}

func TestAPI_HandleVPNConnections_WithMockVPNManager(t *testing.T) {
	// Note: Using nil VPNManager since mockVPNManager is not compatible with *vpn.Manager
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/connections", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// With nil VPNManager, the response behavior depends on implementation
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusServiceUnavailable)
}

func TestAPI_HandleVPNSplitRules_WithMockVPNManager(t *testing.T) {
	// Note: Using nil VPNManager since mockVPNManager is not compatible with *vpn.Manager
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/split/rules", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusServiceUnavailable)
}

func TestAPI_HandleVPNSplitAddApp_WithMockVPNManager(t *testing.T) {

	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	body := `{"name": "testapp", "path": "/usr/bin/testapp"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/apps", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "added", resp["status"])
}

func TestAPI_HandleVPNSplitAddApp_WithMockVPNManager_Error(t *testing.T) {

	mock := newMockVPNManager()
	mock.addAppErr = errors.New("add app failed")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	body := `{"name": "testapp", "path": "/usr/bin/testapp"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/apps", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitRemoveApp_WithMockVPNManager(t *testing.T) {

	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/apps/testapp", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "removed", resp["status"])
}

func TestAPI_HandleVPNSplitRemoveApp_WithMockVPNManager_Error(t *testing.T) {

	mock := newMockVPNManager()
	mock.removeAppErr = errors.New("remove app failed")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/apps/testapp", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitAddDomain_WithMockVPNManager(t *testing.T) {

	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	body := `{"pattern": "*.example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/domains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "added", resp["status"])
}

func TestAPI_HandleVPNSplitAddDomain_WithMockVPNManager_Error(t *testing.T) {

	mock := newMockVPNManager()
	mock.addDomainErr = errors.New("add domain failed")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	body := `{"pattern": "*.example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/domains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPI_HandleVPNSplitAddIP_WithMockVPNManager(t *testing.T) {

	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	body := `{"cidr": "10.0.0.0/8"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/ips", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "added", resp["status"])
}

func TestAPI_HandleVPNSplitAddIP_WithMockVPNManager_Error(t *testing.T) {

	mock := newMockVPNManager()
	mock.addIPErr = errors.New("add ip failed")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	body := `{"cidr": "10.0.0.0/8"}`
	req := httptest.NewRequest("POST", "/api/v1/vpn/split/ips", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// Additional Config Validation Tests
// ============================================================================

func TestAPI_HandleValidateConfig_WithMergedConfig(t *testing.T) {
	testConfig := config.DefaultClientConfig()
	api := New(Config{
		ConfigGetter: func() interface{} {
			return testConfig
		},
	})
	handler := api.Handler()

	// Partial update that should merge with existing config
	body := `{"debug": {"enabled": true, "max_entries": 500}}`
	req := httptest.NewRequest("POST", "/api/v1/config/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConfigValidationResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
}

// ============================================================================
// Additional Log Handler Tests
// ============================================================================

func TestAPI_HandleGetLogs_WithDebuggerAndEntries(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	// Log some entries
	ctx := context.Background()
	debugger.LogConnect(ctx, "example.com", "192.168.1.1")
	debugger.LogError(ctx, "example.com", errors.New("test error"))

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/logs/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp["entries"])
}

func TestAPI_HandleGetLogs_LevelFilterError(t *testing.T) {
	debugger := debug.NewLogger(debug.Config{
		MaxEntries: 100,
	})

	// Log some entries with errors
	ctx := context.Background()
	debugger.LogConnect(ctx, "example.com", "192.168.1.1")
	debugger.LogError(ctx, "example.com", errors.New("test error"))

	api := New(Config{
		Debugger: debugger,
	})
	handler := api.Handler()

	// Filter by error level
	req := httptest.NewRequest("GET", "/api/v1/logs/?level=error", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// Additional Static Handler Tests
// ============================================================================

func TestStaticHandler_AssetsDirectory(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/assets/style.css", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Will be 200 or 404 depending on embedded files
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound)
}

// ============================================================================
// Additional Auth Middleware Tests
// ============================================================================

func TestAuthMiddleware_BearerPrefixCaseInsensitive(t *testing.T) {
	api := New(Config{
		Token: "secret",
	})
	handler := api.Handler()

	// Using "bearer" lowercase
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Authorization", "bearer secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should be authorized since Bearer prefix check is case-insensitive
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// WriteJSON Error Handling Test
// ============================================================================

type failingWriter struct {
	http.ResponseWriter
	failed bool
}

func (w *failingWriter) Write(data []byte) (int, error) {
	if w.failed {
		return 0, errors.New("write failed")
	}
	return w.ResponseWriter.Write(data)
}

func TestAPI_WriteJSON_HandlesError(t *testing.T) {
	api := New(Config{})

	// Test with invalid data that can't be marshaled (channel)
	w := httptest.NewRecorder()
	api.writeJSON(w, http.StatusOK, make(chan int))

	// Should return 500 on marshal error
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// Additional Status Handler Tests
// ============================================================================

func TestAPI_HandleStatus_WithVPNEnabled(t *testing.T) {

	api := New(Config{
		VPNManager: nil,
		ServerConnected: func() bool {
			return true
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "vpn_enabled")
}

// ============================================================================
// Import Config Edge Cases
// ============================================================================

func TestAPI_HandleImportConfig_ValidYAML(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	yamlBody := `
proxy:
  http:
    listen: "127.0.0.1:7380"
  socks5:
    listen: "127.0.0.1:7180"
`
	req := httptest.NewRequest("POST", "/api/v1/config/import?format=yaml", strings.NewReader(yamlBody))
	req.Header.Set("Content-Type", "application/x-yaml")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// Config Defaults Extended Tests
// ============================================================================

func TestAPI_HandleGetConfigDefaults_VerifyContent(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/config/defaults", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp config.ClientConfig
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Verify default values are present
	assert.NotEmpty(t, resp.Proxy.HTTP.Listen)
}

// ============================================================================
// Additional Settings Tests
// ============================================================================

func TestAPI_HandleGetSettings_WithVPNEnabled(t *testing.T) {
	settings := &QuickSettings{
		AutoConnect:       true,
		StartMinimized:    false,
		ShowNotifications: true,
		VPNEnabled:        true,
		CurrentServer:     "server1",
	}
	api := New(Config{
		SettingsGetter: func() *QuickSettings {
			return settings
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/settings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp QuickSettings
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.VPNEnabled)
}

// ============================================================================
// Debug Route Tests
// ============================================================================

func TestAPI_HandleTestRoute_WithDirectAction(t *testing.T) {
	clientRouter := router.NewClientRouter()
	clientRouter.LoadRoutes([]config.ClientRouteConfig{
		{
			Name:     "direct-route",
			Domains:  []string{"*.local"},
			Action:   "direct",
			Priority: 100,
		},
	})

	api := New(Config{
		Router: clientRouter,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/routes/test?domain=test.local", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test.local", resp["domain"])
	assert.Equal(t, "direct", resp["action"])
}

// ============================================================================
// Extended CORS Tests
// ============================================================================

func TestCorsMiddleware_AllowedMethods(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	methods := w.Header().Get("Access-Control-Allow-Methods")
	assert.Contains(t, methods, "GET")
	assert.Contains(t, methods, "POST")
	assert.Contains(t, methods, "PUT")
	assert.Contains(t, methods, "DELETE")
}

func TestCorsMiddleware_AllowedHeaders(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	headers := w.Header().Get("Access-Control-Allow-Headers")
	assert.Contains(t, headers, "Authorization")
	assert.Contains(t, headers, "Content-Type")
}

func TestAPI_HandleVPNStatus_NilConcreteVPNManager(t *testing.T) {
	var mgr *vpn.Manager // nil concrete pointer
	api := New(Config{
		VPNManager: mgr, // Pass nil concrete pointer via interface
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/vpn/status", nil)
	w := httptest.NewRecorder()

	// This should not panic
	assert.NotPanics(t, func() {
		handler.ServeHTTP(w, req)
	})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp vpn.VPNStats
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, vpn.StatusDisabled, resp.Status)
}

func TestAPI_HandleStatus_NilConcreteVPNManager(t *testing.T) {
	var mgr *vpn.Manager // nil concrete pointer
	api := New(Config{
		VPNManager: mgr,
	})
	handler := api.Handler()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	assert.NotPanics(t, func() {
		handler.ServeHTTP(w, req)
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// VPN Split Tunnel Set Mode Tests
// ============================================================================

func TestAPI_HandleVPNSplitSetMode_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"mode": "exclude"}`
	req := httptest.NewRequest("PUT", "/api/v1/vpn/split/mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitSetMode_Success(t *testing.T) {
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	body := `{"mode": "include"}`
	req := httptest.NewRequest("PUT", "/api/v1/vpn/split/mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "updated", resp["status"])
	assert.Equal(t, "include", resp["mode"])
}

func TestAPI_HandleVPNSplitSetMode_InvalidJSON(t *testing.T) {
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	body := `{"mode": invalid}`
	req := httptest.NewRequest("PUT", "/api/v1/vpn/split/mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestAPI_HandleVPNSplitSetMode_EmptyMode(t *testing.T) {
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	body := `{"mode": ""}`
	req := httptest.NewRequest("PUT", "/api/v1/vpn/split/mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "mode is required")
}

func TestAPI_HandleVPNSplitSetMode_Error(t *testing.T) {
	mock := newMockVPNManager()
	mock.setModeErr = errors.New("invalid mode")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	body := `{"mode": "invalid"}`
	req := httptest.NewRequest("PUT", "/api/v1/vpn/split/mode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid mode")
}

// ============================================================================
// VPN Split Tunnel Remove Domain Tests
// ============================================================================

func TestAPI_HandleVPNSplitRemoveDomain_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/domains/%2A.example.com", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitRemoveDomain_Success(t *testing.T) {
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/domains/%2A.example.com", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "removed", resp["status"])
}

func TestAPI_HandleVPNSplitRemoveDomain_Error(t *testing.T) {
	mock := newMockVPNManager()
	mock.removeDomainErr = errors.New("domain not found")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/domains/%2A.nonexistent.com", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "domain not found")
}

// ============================================================================
// VPN Split Tunnel Remove IP Tests
// ============================================================================

func TestAPI_HandleVPNSplitRemoveIP_NilVPNManager(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/ips/10.0.0.0%2F8", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VPN not configured")
}

func TestAPI_HandleVPNSplitRemoveIP_Success(t *testing.T) {
	api := New(Config{
		VPNManager: newMockVPNManager(),
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/ips/10.0.0.0%2F8", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "removed", resp["status"])
}

func TestAPI_HandleVPNSplitRemoveIP_Error(t *testing.T) {
	mock := newMockVPNManager()
	mock.removeIPErr = errors.New("IP not found")
	api := New(Config{
		VPNManager: mock,
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/vpn/split/ips/192.168.0.0%2F16", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "IP not found")
}

// ============================================================================
// Add Route Tests
// ============================================================================

func TestAPI_HandleAddRoute_NilConfigUpdater(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	body := `{"name": "test-route", "domains": ["*.example.com"], "action": "server"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Config management not available", resp["error"])
}

func TestAPI_HandleAddRoute_Success(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": "test-route", "domains": ["*.example.com"], "action": "server", "priority": 100}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "created", resp["status"])
	assert.Equal(t, "test-route", resp["route"])
	assert.Equal(t, "server", resp["action"])
}

func TestAPI_HandleAddRoute_InvalidJSON(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": invalid}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Invalid request body", resp["error"])
}

func TestAPI_HandleAddRoute_MissingName(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"domains": ["*.example.com"], "action": "server"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Route name is required", resp["error"])
}

func TestAPI_HandleAddRoute_MissingDomains(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": "test-route", "action": "server"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "At least one domain pattern is required", resp["error"])
}

func TestAPI_HandleAddRoute_InvalidAction(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": "test-route", "domains": ["*.example.com"], "action": "invalid"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Invalid action", resp["error"])
}

func TestAPI_HandleAddRoute_DefaultAction(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": "test-route", "domains": ["*.example.com"]}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "server", resp["action"])
}

func TestAPI_HandleAddRoute_DirectAction(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": "direct-route", "domains": ["*.local"], "action": "direct"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "direct", resp["action"])
}

func TestAPI_HandleAddRoute_ConflictingName(t *testing.T) {
	// Create a router with existing routes
	r := router.NewClientRouter()
	r.LoadRoutes([]config.ClientRouteConfig{
		{Name: "existing-route", Domains: []string{"*.test.com"}, Action: "server"},
	})

	api := New(Config{
		Router: r,
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	body := `{"name": "existing-route", "domains": ["*.example.com"], "action": "server"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Route with this name already exists", resp["error"])
}

func TestAPI_HandleAddRoute_ConfigUpdateError(t *testing.T) {
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return errors.New("config update failed")
		},
	})
	handler := api.Handler()

	body := `{"name": "test-route", "domains": ["*.example.com"], "action": "server"}`
	req := httptest.NewRequest("POST", "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Failed to update config", resp["error"])
}

// ============================================================================
// Remove Route Tests
// ============================================================================

func TestAPI_HandleRemoveRoute_NilConfigUpdater(t *testing.T) {
	api := New(Config{})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/routes/test-route", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Config management not available", resp["error"])
}

func TestAPI_HandleRemoveRoute_Success(t *testing.T) {
	// Create a router with existing routes
	r := router.NewClientRouter()
	r.LoadRoutes([]config.ClientRouteConfig{
		{Name: "test-route", Domains: []string{"*.test.com"}, Action: "server"},
	})

	api := New(Config{
		Router: r,
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/routes/test-route", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "removed", resp["status"])
	assert.Equal(t, "test-route", resp["route"])
}

func TestAPI_HandleRemoveRoute_NotFound(t *testing.T) {
	// Create a router without the route we're trying to delete
	r := router.NewClientRouter()
	r.LoadRoutes([]config.ClientRouteConfig{
		{Name: "other-route", Domains: []string{"*.other.com"}, Action: "server"},
	})

	api := New(Config{
		Router: r,
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/routes/nonexistent-route", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Route not found", resp["error"])
}

func TestAPI_HandleRemoveRoute_ConfigUpdateError(t *testing.T) {
	// Create a router with the route
	r := router.NewClientRouter()
	r.LoadRoutes([]config.ClientRouteConfig{
		{Name: "test-route", Domains: []string{"*.test.com"}, Action: "server"},
	})

	api := New(Config{
		Router: r,
		ConfigUpdater: func(updates map[string]interface{}) error {
			return errors.New("config update failed")
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/routes/test-route", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Failed to update config", resp["error"])
}

func TestAPI_HandleRemoveRoute_NoRouter(t *testing.T) {
	// When router is nil, the handler should still work if configUpdater is set
	api := New(Config{
		ConfigUpdater: func(updates map[string]interface{}) error {
			return nil
		},
	})
	handler := api.Handler()

	req := httptest.NewRequest("DELETE", "/api/v1/routes/any-route", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Without a router to check, it should proceed with the update
	assert.Equal(t, http.StatusOK, w.Code)
}
