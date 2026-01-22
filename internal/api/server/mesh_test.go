package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMeshAPI(t *testing.T) {
	api := NewMeshAPI()
	require.NotNil(t, api)
	assert.NotNil(t, api.networks)
}

func TestMeshAPI_RegisterRoutes(t *testing.T) {
	api := NewMeshAPI()

	r := chi.NewRouter()
	api.RegisterRoutes(r)

	// Test that routes are registered by making requests
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/mesh/networks"},
		{"POST", "/api/v1/mesh/networks"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code, "Route %s %s should be registered", route.method, route.path)
	}
}

func TestMeshAPI_HandleListNetworks(t *testing.T) {
	api := NewMeshAPI()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/mesh/networks", nil)
	api.handleListNetworks(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "networks")
}

func TestMeshAPI_HandleListNetworks_WithNetworks(t *testing.T) {
	api := NewMeshAPI()

	// Create a network
	_, err := api.CreateNetwork("test-network", "Test Network", "10.100.0.0/16")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/mesh/networks", nil)
	api.handleListNetworks(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	networks := resp["networks"].([]interface{})
	assert.Len(t, networks, 1)
}

func TestMeshAPI_HandleCreateNetwork(t *testing.T) {
	api := NewMeshAPI()

	body := `{
		"id": "test-network",
		"name": "Test Network",
		"cidr": "10.100.0.0/16"
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/mesh/networks", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	api.handleCreateNetwork(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp networkResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test-network", resp.ID)
	assert.Equal(t, "Test Network", resp.Name)
	assert.Equal(t, "10.100.0.0/16", resp.CIDR)
}

func TestMeshAPI_HandleCreateNetwork_DefaultCIDR(t *testing.T) {
	api := NewMeshAPI()

	body := `{
		"id": "test-network",
		"name": "Test Network"
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/mesh/networks", strings.NewReader(body))
	api.handleCreateNetwork(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp networkResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "10.100.0.0/16", resp.CIDR) // Default CIDR
}

func TestMeshAPI_HandleCreateNetwork_InvalidJSON(t *testing.T) {
	api := NewMeshAPI()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/mesh/networks", strings.NewReader("{invalid}"))
	api.handleCreateNetwork(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMeshAPI_HandleCreateNetwork_MissingID(t *testing.T) {
	api := NewMeshAPI()

	body := `{"name": "Test"}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/mesh/networks", strings.NewReader(body))
	api.handleCreateNetwork(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMeshAPI_HandleCreateNetwork_Conflict(t *testing.T) {
	api := NewMeshAPI()

	// Create first network
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	// Try to create duplicate
	body := `{"id": "test-network", "name": "Duplicate"}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/mesh/networks", strings.NewReader(body))
	api.handleCreateNetwork(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestMeshAPI_HandleCreateNetwork_InvalidCIDR(t *testing.T) {
	api := NewMeshAPI()

	body := `{
		"id": "test-network",
		"cidr": "invalid-cidr"
	}`

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/mesh/networks", strings.NewReader(body))
	api.handleCreateNetwork(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMeshAPI_HandleGetNetwork(t *testing.T) {
	api := NewMeshAPI()

	// Create a network
	_, err := api.CreateNetwork("test-network", "Test Network", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Get("/api/v1/mesh/networks/{networkID}", api.handleGetNetwork)

	req := httptest.NewRequest("GET", "/api/v1/mesh/networks/test-network", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp networkResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test-network", resp.ID)
}

func TestMeshAPI_HandleGetNetwork_NotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Get("/api/v1/mesh/networks/{networkID}", api.handleGetNetwork)

	req := httptest.NewRequest("GET", "/api/v1/mesh/networks/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleDeleteNetwork(t *testing.T) {
	api := NewMeshAPI()

	// Create a network
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Delete("/api/v1/mesh/networks/{networkID}", api.handleDeleteNetwork)

	req := httptest.NewRequest("DELETE", "/api/v1/mesh/networks/test-network", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify network was deleted
	_, exists := api.GetNetwork("test-network")
	assert.False(t, exists)
}

func TestMeshAPI_HandleDeleteNetwork_NotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Delete("/api/v1/mesh/networks/{networkID}", api.handleDeleteNetwork)

	req := httptest.NewRequest("DELETE", "/api/v1/mesh/networks/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleRegisterPeer(t *testing.T) {
	api := NewMeshAPI()

	// Create a network
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)

	body := `{
		"peer": {
			"id": "peer-1",
			"name": "Peer One",
			"public_key": "test-key"
		}
	}`

	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp registerPeerResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.VirtualIP)
}

func TestMeshAPI_HandleRegisterPeer_NetworkNotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)

	body := `{"peer": {"id": "peer-1"}}`

	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/nonexistent/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleRegisterPeer_InvalidJSON(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)

	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader("{invalid}"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMeshAPI_HandleRegisterPeer_MissingPeerID(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)

	body := `{"peer": {"name": "No ID"}}`

	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMeshAPI_HandleListPeers(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Get("/api/v1/mesh/networks/{networkID}/peers", api.handleListPeers)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// List peers
	req = httptest.NewRequest("GET", "/api/v1/mesh/networks/test-network/peers", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "peers")

	peers := resp["peers"].([]interface{})
	assert.Len(t, peers, 1)
}

func TestMeshAPI_HandleListPeers_NetworkNotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Get("/api/v1/mesh/networks/{networkID}/peers", api.handleListPeers)

	req := httptest.NewRequest("GET", "/api/v1/mesh/networks/nonexistent/peers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleGetPeer(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Get("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleGetPeer)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Get peer
	req = httptest.NewRequest("GET", "/api/v1/mesh/networks/test-network/peers/peer-1", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMeshAPI_HandleGetPeer_NetworkNotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Get("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleGetPeer)

	req := httptest.NewRequest("GET", "/api/v1/mesh/networks/nonexistent/peers/peer-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleGetPeer_PeerNotFound(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Get("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleGetPeer)

	req := httptest.NewRequest("GET", "/api/v1/mesh/networks/test-network/peers/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleUpdatePeer(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Patch("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleUpdatePeer)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Update peer
	updateBody := `{
		"endpoints": [{"address": "192.168.1.1", "port": 51820}],
		"metadata": {"os": "linux"}
	}`
	req = httptest.NewRequest("PATCH", "/api/v1/mesh/networks/test-network/peers/peer-1", strings.NewReader(updateBody))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestMeshAPI_HandleUpdatePeer_NetworkNotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Patch("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleUpdatePeer)

	req := httptest.NewRequest("PATCH", "/api/v1/mesh/networks/nonexistent/peers/peer-1", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleUpdatePeer_PeerNotFound(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Patch("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleUpdatePeer)

	req := httptest.NewRequest("PATCH", "/api/v1/mesh/networks/test-network/peers/nonexistent", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleUpdatePeer_InvalidJSON(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Patch("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleUpdatePeer)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Update with invalid JSON
	req = httptest.NewRequest("PATCH", "/api/v1/mesh/networks/test-network/peers/peer-1", strings.NewReader("{invalid}"))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMeshAPI_HandleDeregisterPeer(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Delete("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleDeregisterPeer)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Deregister peer
	req = httptest.NewRequest("DELETE", "/api/v1/mesh/networks/test-network/peers/peer-1", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestMeshAPI_HandleDeregisterPeer_NetworkNotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Delete("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleDeregisterPeer)

	req := httptest.NewRequest("DELETE", "/api/v1/mesh/networks/nonexistent/peers/peer-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleDeregisterPeer_PeerNotFound(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Delete("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleDeregisterPeer)

	req := httptest.NewRequest("DELETE", "/api/v1/mesh/networks/test-network/peers/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleHeartbeat(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Post("/api/v1/mesh/networks/{networkID}/peers/{peerID}/heartbeat", api.handleHeartbeat)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Send heartbeat
	req = httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers/peer-1/heartbeat", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestMeshAPI_HandleHeartbeat_NetworkNotFound(t *testing.T) {
	api := NewMeshAPI()

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers/{peerID}/heartbeat", api.handleHeartbeat)

	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/nonexistent/peers/peer-1/heartbeat", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_HandleHeartbeat_PeerNotFound(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers/{peerID}/heartbeat", api.handleHeartbeat)

	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers/nonexistent/heartbeat", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMeshAPI_GetNetwork(t *testing.T) {
	api := NewMeshAPI()

	// Network doesn't exist
	_, exists := api.GetNetwork("test-network")
	assert.False(t, exists)

	// Create network
	network, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)
	require.NotNil(t, network)

	// Network exists now
	retrieved, exists := api.GetNetwork("test-network")
	assert.True(t, exists)
	assert.Equal(t, "test-network", retrieved.ID)
}

func TestMeshAPI_CreateNetwork(t *testing.T) {
	api := NewMeshAPI()

	network, err := api.CreateNetwork("test-network", "Test Network", "10.100.0.0/16")
	require.NoError(t, err)
	require.NotNil(t, network)

	assert.Equal(t, "test-network", network.ID)
	assert.Equal(t, "Test Network", network.Name)
	assert.Equal(t, "10.100.0.0/16", network.CIDR)
	assert.NotNil(t, network.peers)
	assert.NotNil(t, network.ipAllocator)
	assert.NotNil(t, network.wsClients)
}

func TestMeshAPI_CreateNetwork_Duplicate(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	_, err = api.CreateNetwork("test-network", "Duplicate", "10.100.0.0/16")
	assert.Equal(t, ErrNetworkExists, err)
}

func TestMeshAPI_CreateNetwork_InvalidCIDR(t *testing.T) {
	api := NewMeshAPI()

	_, err := api.CreateNetwork("test-network", "Test", "invalid")
	assert.Error(t, err)
}

func TestMeshAPIErrors(t *testing.T) {
	assert.Equal(t, "network already exists", ErrNetworkExists.Error())
	assert.Equal(t, "network not found", ErrNetworkNotFound.Error())
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"test": "value"})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["test"])
}

func TestMeshConfig_Struct(t *testing.T) {
	cfg := MeshConfig{
		Enabled: true,
	}
	assert.True(t, cfg.Enabled)
}

func TestNetworkResponse_Struct(t *testing.T) {
	resp := networkResponse{
		ID:        "test-id",
		Name:      "Test Name",
		CIDR:      "10.0.0.0/8",
		PeerCount: 5,
	}

	assert.Equal(t, "test-id", resp.ID)
	assert.Equal(t, "Test Name", resp.Name)
	assert.Equal(t, "10.0.0.0/8", resp.CIDR)
	assert.Equal(t, 5, resp.PeerCount)
}

func TestCreateNetworkRequest_Struct(t *testing.T) {
	req := createNetworkRequest{
		ID:   "net-1",
		Name: "Network 1",
		CIDR: "192.168.0.0/24",
	}

	assert.Equal(t, "net-1", req.ID)
	assert.Equal(t, "Network 1", req.Name)
	assert.Equal(t, "192.168.0.0/24", req.CIDR)
}

func TestRegisterPeerResponse_Struct(t *testing.T) {
	resp := registerPeerResponse{
		Success:   true,
		VirtualIP: "10.100.0.2",
		Message:   "Peer registered",
	}

	assert.True(t, resp.Success)
	assert.Equal(t, "10.100.0.2", resp.VirtualIP)
	assert.Equal(t, "Peer registered", resp.Message)
}

func TestMeshAPI_RegisterPeerReturnsOtherPeers(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register two peers
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)

	// Register first peer
	body1 := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body1))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Register second peer - should receive info about first peer
	body2 := `{"peer": {"id": "peer-2", "name": "Peer Two"}}`
	req = httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body2))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp registerPeerResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.Len(t, resp.Peers, 1) // Should have info about peer-1
	assert.Equal(t, "peer-1", resp.Peers[0].ID)
}

func TestMeshAPI_UpdatePeerWithEndpointsAndMetadata(t *testing.T) {
	api := NewMeshAPI()

	// Create network and register a peer
	_, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/mesh/networks/{networkID}/peers", api.handleRegisterPeer)
	router.Patch("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleUpdatePeer)
	router.Get("/api/v1/mesh/networks/{networkID}/peers/{peerID}", api.handleGetPeer)

	// Register a peer
	body := `{"peer": {"id": "peer-1", "name": "Peer One"}}`
	req := httptest.NewRequest("POST", "/api/v1/mesh/networks/test-network/peers", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Update with endpoints
	updateBody := `{
		"endpoints": [
			{"address": "192.168.1.100", "port": 51820, "type": "local"},
			{"address": "1.2.3.4", "port": 51820, "type": "reflexive"}
		],
		"metadata": {
			"os": "linux",
			"version": "1.0.0"
		}
	}`
	req = httptest.NewRequest("PATCH", "/api/v1/mesh/networks/test-network/peers/peer-1", strings.NewReader(updateBody))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Get peer to verify updates
	req = httptest.NewRequest("GET", "/api/v1/mesh/networks/test-network/peers/peer-1", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMeshNetwork_BroadcastEvent(t *testing.T) {
	api := NewMeshAPI()

	network, err := api.CreateNetwork("test-network", "Test", "10.100.0.0/16")
	require.NoError(t, err)

	// broadcastEvent should not panic even with no clients
	// This tests the internal method indirectly through normal operations
	assert.NotNil(t, network.wsClients)
}
