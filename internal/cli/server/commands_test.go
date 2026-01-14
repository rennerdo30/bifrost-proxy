package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPIClient(t *testing.T) {
	client := NewAPIClient("http://localhost:8082", "test-token")
	assert.NotNil(t, client)
	assert.Equal(t, "http://localhost:8082", client.BaseURL)
	assert.Equal(t, "test-token", client.Token)
	assert.NotNil(t, client.Client)
}

func TestAPIClient_doRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/test", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "test-token")
	resp, err := client.doRequest("GET", "/api/v1/test", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIClient_doRequest_NoToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	resp, err := client.doRequest("GET", "/api/v1/test", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIClient_getJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","version":"1.0.0"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	var result map[string]interface{}
	err := client.getJSON("/api/v1/test", &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
	assert.Equal(t, "1.0.0", result["version"])
}

func TestAPIClient_getJSON_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	var result map[string]interface{}
	err := client.getJSON("/api/v1/test", &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API error")
}

func TestAPIClient_ShowStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/status", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "running",
			"version":  "1.0.0",
			"time":     "2024-01-01T00:00:00Z",
			"backends": 3,
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	require.NoError(t, err)
}

func TestAPIClient_ListBackends(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/backends", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":   "backend1",
				"type":   "direct",
				"healthy": true,
				"stats": map[string]interface{}{
					"active_connections": 5.0,
					"total_connections":  100.0,
				},
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListBackends()
	require.NoError(t, err)
}

func TestAPIClient_ShowBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/backends/test-backend", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":   "test-backend",
			"type":   "direct",
			"healthy": true,
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowBackend("test-backend")
	require.NoError(t, err)
}

func TestAPIClient_ReloadConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/config/reload", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ReloadConfig()
	require.NoError(t, err)
}

func TestAPIClient_ReloadConfig_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"reload failed"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ReloadConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reload failed")
}

func TestAPIClient_ShowStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/stats", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"connections": 100,
			"bytes_sent":  1024,
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStats()
	require.NoError(t, err)
}

func TestAPIClient_CheckHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.CheckHealth()
	require.NoError(t, err)
}

func TestAPIClient_CheckHealth_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "degraded",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.CheckHealth()
	require.NoError(t, err) // Should not error, just print status
}

func TestNewCommands(t *testing.T) {
	root := NewCommands()
	assert.NotNil(t, root)
	assert.Equal(t, "ctl", root.Use)
	assert.Equal(t, "Control a running Bifrost server", root.Short)
}
