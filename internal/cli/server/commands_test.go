package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
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
				"name":    "backend1",
				"type":    "direct",
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
			"name":    "test-backend",
			"type":    "direct",
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

	// Check that all subcommands are present
	subcommands := root.Commands()
	assert.Len(t, subcommands, 6) // status, backend, config, rule, stats, health

	// Find and verify each command
	var statusCmd, backendCmd, configCmd, ruleCmd, statsCmd, healthCmd *cobra.Command
	for _, cmd := range subcommands {
		switch cmd.Use {
		case "status":
			statusCmd = cmd
		case "backend":
			backendCmd = cmd
		case "config":
			configCmd = cmd
		case "rule":
			ruleCmd = cmd
		case "stats":
			statsCmd = cmd
		case "health":
			healthCmd = cmd
		}
	}

	assert.NotNil(t, statusCmd)
	assert.NotNil(t, backendCmd)
	assert.NotNil(t, configCmd)
	assert.NotNil(t, ruleCmd)
	assert.NotNil(t, statsCmd)
	assert.NotNil(t, healthCmd)

	// Check backend subcommands
	backendSubcmds := backendCmd.Commands()
	assert.Len(t, backendSubcmds, 5) // list, show, add, remove, test

	// Check config subcommands
	configSubcmds := configCmd.Commands()
	assert.Len(t, configSubcmds, 1) // reload

	// Check rule subcommands
	ruleSubcmds := ruleCmd.Commands()
	assert.Len(t, ruleSubcmds, 3) // list, add, remove

	// Check persistent flags
	apiFlag := root.PersistentFlags().Lookup("api")
	assert.NotNil(t, apiFlag)
	assert.Equal(t, "http://localhost:8082", apiFlag.DefValue)

	tokenFlag := root.PersistentFlags().Lookup("token")
	assert.NotNil(t, tokenFlag)
	assert.Equal(t, "", tokenFlag.DefValue)
}

func TestNewCommands_StatusCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   "running",
				"version":  "1.0.0",
				"time":     "2024-01-01T00:00:00Z",
				"backends": 3,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "status"})
	err := root.Execute()
	assert.NoError(t, err)
}

func TestNewCommands_BackendListCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/backends" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "backend1", "type": "direct", "healthy": true},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "backend", "list"})
	err := root.Execute()
	assert.NoError(t, err)
}

func TestNewCommands_BackendShowCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/backends/test-backend" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name": "test-backend", "type": "direct", "healthy": true,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "backend", "show", "test-backend"})
	err := root.Execute()
	assert.NoError(t, err)
}

func TestNewCommands_BackendShowCommand_MissingArg(t *testing.T) {
	root := NewCommands()
	root.SetArgs([]string{"backend", "show"})
	// Suppress error output during test
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	assert.Error(t, err) // Should error due to missing required argument
}

func TestNewCommands_ConfigReloadCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/config/reload" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "config", "reload"})
	err := root.Execute()
	assert.NoError(t, err)
}

func TestNewCommands_StatsCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/stats" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"connections": 100,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "stats"})
	err := root.Execute()
	assert.NoError(t, err)
}

func TestNewCommands_HealthCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "healthy",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "health"})
	err := root.Execute()
	assert.NoError(t, err)
}

func TestNewCommands_WithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify token is passed
		assert.Equal(t, "Bearer my-secret-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "running",
			"version": "1.0.0",
			"time":    "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "--token", "my-secret-token", "status"})
	err := root.Execute()
	assert.NoError(t, err)
}

// Test doRequest with invalid URL that causes NewRequest to fail
func TestAPIClient_doRequest_InvalidMethod(t *testing.T) {
	client := NewAPIClient("http://localhost:8082", "")
	// Invalid method with control character will cause NewRequest to fail
	resp, err := client.doRequest("INVALID\x00METHOD", "/api/v1/test", nil)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Error(t, err)
}

// Test getJSON when doRequest fails (network error)
func TestAPIClient_getJSON_NetworkError(t *testing.T) {
	// Use invalid URL that will fail connection
	client := NewAPIClient("http://localhost:99999", "")
	var result map[string]interface{}
	err := client.getJSON("/api/v1/test", &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// Test ShowStatus without backends field
func TestAPIClient_ShowStatus_NoBackends(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "running",
			"version": "1.0.0",
			"time":    "2024-01-01T00:00:00Z",
			// No backends field
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	require.NoError(t, err)
}

// Test ShowStatus with backends as non-float64 value
func TestAPIClient_ShowStatus_BackendsNotFloat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "running",
			"version":  "1.0.0",
			"time":     "2024-01-01T00:00:00Z",
			"backends": "three", // String instead of number
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	require.NoError(t, err)
}

// Test ShowStatus with API error
func TestAPIClient_ShowStatus_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	assert.Error(t, err)
}

// Test ListBackends with nil stats
func TestAPIClient_ListBackends_NilStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":    "backend1",
				"type":    "direct",
				"healthy": true,
				// No stats field
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListBackends()
	require.NoError(t, err)
}

// Test ListBackends with stats that have wrong types
func TestAPIClient_ListBackends_StatsWrongTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":    "backend1",
				"type":    "direct",
				"healthy": true,
				"stats": map[string]interface{}{
					"active_connections": "five", // String instead of float64
					"total_connections":  nil,    // nil instead of number
				},
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListBackends()
	require.NoError(t, err)
}

// Test ListBackends with error
func TestAPIClient_ListBackends_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListBackends()
	assert.Error(t, err)
}

// Test ShowBackend with error
func TestAPIClient_ShowBackend_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"backend not found"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowBackend("nonexistent")
	assert.Error(t, err)
}

// Test ReloadConfig with network error
func TestAPIClient_ReloadConfig_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.ReloadConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// Test ShowStats with error
func TestAPIClient_ShowStats_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStats()
	assert.Error(t, err)
}

// Test CheckHealth with error
func TestAPIClient_CheckHealth_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.CheckHealth()
	assert.Error(t, err)
}

// Test AddBackend success
func TestAPIClient_AddBackend_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/backends", r.URL.Path)

		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "test-backend", req["name"])
		assert.Equal(t, "direct", req["type"])
		assert.Equal(t, true, req["enabled"])

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "created",
			"backend": "test-backend",
			"type":    "direct",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddBackend("test-backend", "direct", "{}", true)
	assert.NoError(t, err)
}

// Test AddBackend with invalid JSON config
func TestAPIClient_AddBackend_InvalidConfig(t *testing.T) {
	client := NewAPIClient("http://localhost:8082", "")
	err := client.AddBackend("test", "direct", "invalid json", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config JSON")
}

// Test AddBackend with server error
func TestAPIClient_AddBackend_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"backend already exists"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddBackend("test", "direct", "{}", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add backend")
}

// Test RemoveBackend success
func TestAPIClient_RemoveBackend_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/backends/test-backend", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "removed",
			"backend": "test-backend",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveBackend("test-backend")
	assert.NoError(t, err)
}

// Test RemoveBackend with server error
func TestAPIClient_RemoveBackend_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"backend not found"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveBackend("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove backend")
}

// Test TestBackend success
func TestAPIClient_TestBackend_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/backends/test-backend/test", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "success",
			"backend":  "test-backend",
			"target":   "google.com:443",
			"duration": "50ms",
			"healthy":  true,
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TestBackend("test-backend", "google.com:443", "10s")
	assert.NoError(t, err)
}

// Test TestBackend failure
func TestAPIClient_TestBackend_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "failed",
			"backend":  "test-backend",
			"target":   "unreachable.host:443",
			"error":    "connection refused",
			"duration": "10s",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TestBackend("test-backend", "unreachable.host:443", "10s")
	assert.NoError(t, err) // The command succeeds even if the test fails
}

// Test TestBackend network error
func TestAPIClient_TestBackend_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.TestBackend("test", "google.com:443", "10s")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// Test ListRules success
func TestAPIClient_ListRules_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/routes", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":     "anime",
				"domains":  []string{"*.crunchyroll.com"},
				"backend":  "germany",
				"priority": 100,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRules()
	assert.NoError(t, err)
}

// Test AddRule success
func TestAPIClient_AddRule_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/routes", r.URL.Path)

		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "anime", req["name"])
		assert.Equal(t, "germany", req["backend"])

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "created",
			"route":  "anime",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddRule("anime", "*.crunchyroll.com", "germany", 100)
	assert.NoError(t, err)
}

// Test AddRule with server error
func TestAPIClient_AddRule_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"rule already exists"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddRule("anime", "*.crunchyroll.com", "germany", 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add rule")
}

// Test RemoveRule success
func TestAPIClient_RemoveRule_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/routes/anime", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "removed",
			"route":  "anime",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveRule("anime")
	assert.NoError(t, err)
}

// Test RemoveRule not found
func TestAPIClient_RemoveRule_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"rule not found"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveRule("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove rule")
}

// Test ListRules with multiple backends field
func TestAPIClient_ListRules_MultipleBackends(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":     "load-balanced",
				"domains":  []interface{}{"*.example.com", "*.test.com"},
				"backends": []interface{}{"server1", "server2", "server3"},
				"priority": 50,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRules()
	assert.NoError(t, err)
}

// Test ListRules with empty domains
func TestAPIClient_ListRules_EmptyDomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":     "default",
				"domains":  []interface{}{},
				"backend":  "fallback",
				"priority": 0,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRules()
	assert.NoError(t, err)
}

// Test ListRules with nil backend
func TestAPIClient_ListRules_NilBackend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"name":     "no-backend",
				"domains":  []interface{}{"*.example.com"},
				"backend":  nil,
				"priority": 10,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRules()
	assert.NoError(t, err)
}

// Test ListRules error
func TestAPIClient_ListRules_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRules()
	assert.Error(t, err)
}

// Test AddRule with multiple domains
func TestAPIClient_AddRule_MultiDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)

		domains := req["domains"].([]interface{})
		assert.Len(t, domains, 3)
		assert.Equal(t, "*.a.com", domains[0])
		assert.Equal(t, "*.b.com", domains[1])
		assert.Equal(t, "*.c.com", domains[2])

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddRule("multi", "*.a.com, *.b.com, *.c.com", "backend", 10)
	assert.NoError(t, err)
}
