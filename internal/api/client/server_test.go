package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/debug"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
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
	assert.Contains(t, resp, "time")
	assert.Contains(t, resp, "version")
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
	assert.Equal(t, "connected", resp["server_status"])
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
	assert.Equal(t, "disconnected", resp["server_status"])
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
	assert.Equal(t, "disconnected", resp["server_status"])
}
