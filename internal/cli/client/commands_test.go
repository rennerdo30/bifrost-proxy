package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
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

// VPN Status Tests

func TestAPIClient_ShowVPNStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vpn/status", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "enabled",
			"uptime":               3600000000000, // 1 hour in nanoseconds
			"bytes_sent":           1024,
			"bytes_received":       2048,
			"active_connections":   5,
			"tunneled_connections": 3,
			"bypassed_connections": 2,
			"dns_queries":          100,
			"dns_cache_hits":       50,
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNStatus()
	require.NoError(t, err)
}

func TestAPIClient_ShowVPNStatus_WithError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "enabled",
			"uptime":               0,
			"bytes_sent":           0,
			"bytes_received":       0,
			"active_connections":   0,
			"tunneled_connections": 0,
			"bypassed_connections": 0,
			"last_error":           "connection timeout",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNStatus()
	require.NoError(t, err)
}

func TestAPIClient_ShowVPNStatus_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNStatus()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API error")
}

func TestAPIClient_EnableVPN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/vpn/enable", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.EnableVPN()
	require.NoError(t, err)
}

func TestAPIClient_EnableVPN_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"vpn enable failed"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.EnableVPN()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "enable failed")
}

func TestAPIClient_DisableVPN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/vpn/disable", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.DisableVPN()
	require.NoError(t, err)
}

func TestAPIClient_DisableVPN_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"vpn disable failed"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.DisableVPN()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disable failed")
}

// Split Tunnel Tests

func TestAPIClient_ListSplitTunnelRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vpn/split/rules", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": "exclude",
			"apps": []map[string]interface{}{
				{"name": "Firefox"},
				{"name": "Chrome"},
			},
			"domains":       []string{"*.example.com", "google.com"},
			"ips":           []string{"192.168.1.0/24", "10.0.0.0/8"},
			"always_bypass": []string{"localhost", "127.0.0.1"},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListSplitTunnelRules()
	require.NoError(t, err)
}

func TestAPIClient_ListSplitTunnelRules_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": "include",
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListSplitTunnelRules()
	require.NoError(t, err)
}

func TestAPIClient_ListSplitTunnelRules_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListSplitTunnelRules()
	assert.Error(t, err)
}

func TestAPIClient_AddSplitTunnelApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/vpn/split/apps", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelApp("Firefox")
	require.NoError(t, err)
}

func TestAPIClient_AddSplitTunnelApp_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelApp("Chrome")
	require.NoError(t, err)
}

func TestAPIClient_AddSplitTunnelApp_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"app not found"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelApp("InvalidApp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "add failed")
}

func TestAPIClient_RemoveSplitTunnelApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/vpn/split/apps/Firefox", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveSplitTunnelApp("Firefox")
	require.NoError(t, err)
}

func TestAPIClient_RemoveSplitTunnelApp_NoContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveSplitTunnelApp("Chrome")
	require.NoError(t, err)
}

func TestAPIClient_RemoveSplitTunnelApp_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"app not found"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.RemoveSplitTunnelApp("InvalidApp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "remove failed")
}

func TestAPIClient_AddSplitTunnelDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/vpn/split/domains", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelDomain("*.example.com")
	require.NoError(t, err)
}

func TestAPIClient_AddSplitTunnelDomain_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelDomain("google.com")
	require.NoError(t, err)
}

func TestAPIClient_AddSplitTunnelDomain_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid domain pattern"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelDomain("***invalid***")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "add failed")
}

func TestAPIClient_AddSplitTunnelIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/vpn/split/ips", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelIP("192.168.1.0/24")
	require.NoError(t, err)
}

func TestAPIClient_AddSplitTunnelIP_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelIP("10.0.0.0/8")
	require.NoError(t, err)
}

func TestAPIClient_AddSplitTunnelIP_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid CIDR"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.AddSplitTunnelIP("invalid-cidr")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "add failed")
}

// VPN Connections Tests

func TestAPIClient_ShowVPNConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vpn/connections", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"protocol":       "TCP",
				"local_addr":     "127.0.0.1:12345",
				"remote_addr":    "93.184.216.34:443",
				"action":         "tunnel",
				"start_time":     "2024-01-01T00:00:00Z",
				"bytes_sent":     1024,
				"bytes_received": 2048,
			},
			{
				"protocol":       "UDP",
				"local_addr":     "127.0.0.1:54321",
				"remote_addr":    "8.8.8.8:53",
				"action":         "bypass",
				"start_time":     "2024-01-01T00:00:00Z",
				"bytes_sent":     100,
				"bytes_received": 200,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNConnections()
	require.NoError(t, err)
}

func TestAPIClient_ShowVPNConnections_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNConnections()
	require.NoError(t, err)
}

func TestAPIClient_ShowVPNConnections_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNConnections()
	assert.Error(t, err)
}

// VPN DNS Cache Tests

func TestAPIClient_ShowVPNDNSCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vpn/dns/cache", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"domain":    "example.com",
				"addresses": []string{"93.184.216.34"},
				"expires":   "2099-01-01T00:00:00Z", // Future date for positive TTL
			},
			{
				"domain":    "google.com",
				"addresses": []string{"142.250.185.46", "142.250.185.78"},
				"expires":   "2020-01-01T00:00:00Z", // Past date for expired entry
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNDNSCache()
	require.NoError(t, err)
}

func TestAPIClient_ShowVPNDNSCache_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNDNSCache()
	require.NoError(t, err)
}

func TestAPIClient_ShowVPNDNSCache_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNDNSCache()
	assert.Error(t, err)
}

// Edge case and error tests

func TestAPIClient_doRequest_Error(t *testing.T) {
	// Invalid URL that will cause request creation failure
	client := NewAPIClient("://invalid-url", "test-token")
	_, err := client.doRequest("GET", "/api/v1/test", nil)
	assert.Error(t, err)
}

func TestAPIClient_doRequest_NetworkError(t *testing.T) {
	// Server that doesn't exist
	client := NewAPIClient("http://localhost:99999", "")
	_, err := client.doRequest("GET", "/api/v1/test", nil)
	assert.Error(t, err)
}

func TestAPIClient_getJSON_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	var result map[string]interface{}
	err := client.getJSON("/api/v1/test", &result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_ShowStatus_NoDebugEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "running",
			"server_status": "connected",
			"version":       "1.0.0",
			"time":          "2024-01-01T00:00:00Z",
			// no debug_entries field
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	require.NoError(t, err)
}

func TestAPIClient_ShowStatus_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowStatus()
	assert.Error(t, err)
}

func TestAPIClient_TailDebug_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TailDebug(20)
	assert.Error(t, err)
}

func TestAPIClient_TailDebug_InvalidTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"timestamp":   "invalid-timestamp",
				"method":      "GET",
				"host":        "example.com",
				"status_code": 200,
				"duration_ms": 100,
				"route":       "direct",
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TailDebug(20)
	require.NoError(t, err) // Should not error, just use empty timestamp
}

func TestAPIClient_ShowErrors_InvalidTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"timestamp": "invalid-timestamp",
				"host":      "example.com",
				"error":     "connection failed",
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowErrors()
	require.NoError(t, err) // Should not error, just use empty timestamp
}

func TestAPIClient_ShowErrors_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowErrors()
	assert.Error(t, err)
}

func TestAPIClient_ListRoutes_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ListRoutes()
	assert.Error(t, err)
}

func TestAPIClient_TestRoute_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.TestRoute("example.com")
	assert.Error(t, err)
}

func TestAPIClient_CheckHealth_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.CheckHealth()
	assert.Error(t, err)
}

func TestAPIClient_EnableVPN_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.EnableVPN()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_DisableVPN_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.DisableVPN()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_AddSplitTunnelApp_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.AddSplitTunnelApp("Firefox")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_RemoveSplitTunnelApp_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.RemoveSplitTunnelApp("Firefox")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_AddSplitTunnelDomain_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.AddSplitTunnelDomain("*.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_AddSplitTunnelIP_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.AddSplitTunnelIP("192.168.1.0/24")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_ClearDebug_NetworkError(t *testing.T) {
	client := NewAPIClient("http://localhost:99999", "")
	err := client.ClearDebug()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestAPIClient_ShowVPNConnections_InvalidStartTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"protocol":       "TCP",
				"local_addr":     "127.0.0.1:12345",
				"remote_addr":    "93.184.216.34:443",
				"action":         "tunnel",
				"start_time":     "invalid-time",
				"bytes_sent":     1024,
				"bytes_received": 2048,
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNConnections()
	require.NoError(t, err) // Should not error, just use empty duration
}

func TestAPIClient_ShowVPNDNSCache_InvalidExpires(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"domain":    "example.com",
				"addresses": []string{"93.184.216.34"},
				"expires":   "invalid-time",
			},
		})
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, "")
	err := client.ShowVPNDNSCache()
	require.NoError(t, err) // Should not error, just use empty TTL
}

// CLI Command Tests - execute commands with mock server

func TestNewCommands_StatusCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "running",
			"server_status": "connected",
			"version":       "1.0.0",
			"time":          "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "status"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_DebugTailCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "debug", "tail", "-n", "10"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_DebugClearCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "debug", "clear"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_DebugErrorsCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "debug", "errors"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_RoutesListCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "routes", "list"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_RoutesTestCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"domain": "example.com",
			"action": "server",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "routes", "test", "example.com"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_HealthCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "health"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNStatusCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "disabled",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "status"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNEnableCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "enable"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNDisableCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "disable"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNSplitListCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": "exclude",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "split", "list"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNSplitAddAppCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "split", "add-app", "Firefox"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNSplitRemoveAppCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "split", "remove-app", "Firefox"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNSplitAddDomainCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "split", "add-domain", "*.example.com"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNSplitAddIPCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "split", "add-ip", "192.168.1.0/24"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNConnectionsCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "connections"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_VPNDNSCacheCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "vpn", "dns-cache"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_WithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token-123", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
		})
	}))
	defer server.Close()

	root := NewCommands()
	root.SetArgs([]string{"--api", server.URL, "--token", "test-token-123", "health"})
	err := root.Execute()
	require.NoError(t, err)
}

func TestNewCommands_SubcommandStructure(t *testing.T) {
	root := NewCommands()

	// Test root command properties
	assert.Equal(t, "ctl", root.Use)
	assert.Equal(t, "Control a running Bifrost client", root.Short)

	// Test that subcommands exist
	subcommands := root.Commands()
	require.NotEmpty(t, subcommands)

	// Find specific commands
	var statusCmd, debugCmd, routesCmd, healthCmd, vpnCmd *cobra.Command
	for _, cmd := range subcommands {
		switch cmd.Use {
		case "status":
			statusCmd = cmd
		case "debug":
			debugCmd = cmd
		case "routes":
			routesCmd = cmd
		case "health":
			healthCmd = cmd
		case "vpn":
			vpnCmd = cmd
		}
	}

	assert.NotNil(t, statusCmd, "status command should exist")
	assert.NotNil(t, debugCmd, "debug command should exist")
	assert.NotNil(t, routesCmd, "routes command should exist")
	assert.NotNil(t, healthCmd, "health command should exist")
	assert.NotNil(t, vpnCmd, "vpn command should exist")

	// Test debug subcommands
	debugSubcmds := debugCmd.Commands()
	require.Len(t, debugSubcmds, 3, "debug should have 3 subcommands: tail, clear, errors")

	// Test routes subcommands
	routesSubcmds := routesCmd.Commands()
	require.Len(t, routesSubcmds, 2, "routes should have 2 subcommands: list, test")

	// Test vpn subcommands
	vpnSubcmds := vpnCmd.Commands()
	require.Len(t, vpnSubcmds, 6, "vpn should have 6 subcommands: status, enable, disable, split, connections, dns-cache")

	// Find split subcommand within vpn
	var splitCmd *cobra.Command
	for _, cmd := range vpnSubcmds {
		if cmd.Use == "split" {
			splitCmd = cmd
			break
		}
	}
	require.NotNil(t, splitCmd, "split command should exist within vpn")

	// Test split subcommands
	splitSubcmds := splitCmd.Commands()
	require.Len(t, splitSubcmds, 5, "split should have 5 subcommands: list, add-app, remove-app, add-domain, add-ip")
}

func TestNewCommands_Flags(t *testing.T) {
	root := NewCommands()

	// Test persistent flags
	apiFlag := root.PersistentFlags().Lookup("api")
	assert.NotNil(t, apiFlag, "api flag should exist")
	assert.Equal(t, "http://localhost:3130", apiFlag.DefValue)

	tokenFlag := root.PersistentFlags().Lookup("token")
	assert.NotNil(t, tokenFlag, "token flag should exist")
	assert.Equal(t, "", tokenFlag.DefValue)
}

func TestNewCommands_DebugTailFlag(t *testing.T) {
	root := NewCommands()

	// Find debug command and then tail subcommand
	var debugCmd *cobra.Command
	for _, cmd := range root.Commands() {
		if cmd.Use == "debug" {
			debugCmd = cmd
			break
		}
	}
	require.NotNil(t, debugCmd)

	var tailCmd *cobra.Command
	for _, cmd := range debugCmd.Commands() {
		if cmd.Use == "tail" {
			tailCmd = cmd
			break
		}
	}
	require.NotNil(t, tailCmd)

	// Check count flag
	countFlag := tailCmd.Flags().Lookup("count")
	assert.NotNil(t, countFlag, "count flag should exist on tail command")
	assert.Equal(t, "20", countFlag.DefValue)
}

func TestNewCommands_RoutesTestArgs(t *testing.T) {
	root := NewCommands()

	// Find routes command and test subcommand
	var routesCmd *cobra.Command
	for _, cmd := range root.Commands() {
		if cmd.Use == "routes" {
			routesCmd = cmd
			break
		}
	}
	require.NotNil(t, routesCmd)

	var testCmd *cobra.Command
	for _, cmd := range routesCmd.Commands() {
		if cmd.Use == "test [domain]" {
			testCmd = cmd
			break
		}
	}
	require.NotNil(t, testCmd)
	assert.Equal(t, "test [domain]", testCmd.Use)
}
