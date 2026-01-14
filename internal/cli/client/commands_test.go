package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPIClient(t *testing.T) {
	client := NewAPIClient("http://localhost:3130", "test-token")
	assert.NotNil(t, client)
	assert.Equal(t, "http://localhost:3130", client.BaseURL)
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
			"status":        "running",
			"server_status": "connected",
			"version":        "1.0.0",
			"time":           "2024-01-01T00:00:00Z",
			"debug_entries": 42,
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	require.NoError(t, err)
}

func TestAPIClient_TailDebug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/debug/entries/last/20", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"timestamp":  "2024-01-01T00:00:00Z",
				"method":    "GET",
				"host":      "example.com",
				"status_code": 200,
				"duration_ms": 100,
				"route":     "direct",
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TailDebug(20)
	require.NoError(t, err)
}

func TestAPIClient_ClearDebug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/debug/entries", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ClearDebug()
	require.NoError(t, err)
}

func TestAPIClient_ClearDebug_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ClearDebug()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "clear failed")
}

func TestAPIClient_ShowErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/debug/errors", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"timestamp": "2024-01-01T00:00:00Z",
				"host":      "example.com",
				"error":     "connection failed",
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowErrors()
	require.NoError(t, err)
}

func TestAPIClient_ShowErrors_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowErrors()
	require.NoError(t, err)
}

func TestAPIClient_ListRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/routes", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":      "test-route",
				"patterns":  []string{"*.example.com"},
				"action":    "server",
				"priority":  10,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRoutes()
	require.NoError(t, err)
}

func TestAPIClient_TestRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/routes/test", r.URL.Path)
		assert.Equal(t, "domain=example.com", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"domain": "example.com",
			"action": "server",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TestRoute("example.com")
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

func TestNewCommands(t *testing.T) {
	root := NewCommands()
	assert.NotNil(t, root)
	assert.Equal(t, "ctl", root.Use)
	assert.Equal(t, "Control a running Bifrost client", root.Short)
}
