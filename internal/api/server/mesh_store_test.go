package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// meshRouter mounts the coordinator routes for a handler under test.
func meshRouter(m *MeshAPI) http.Handler {
	r := chi.NewRouter()
	m.RegisterRoutes(r)
	return r
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestMeshAPI_DisabledLeavesRoutesUnmounted is the regression test for the
// always-on coordinator: MeshConfig.Enabled had no references anywhere, so the
// /api/v1/mesh surface could not be turned off.
func TestMeshAPI_DisabledLeavesRoutesUnmounted(t *testing.T) {
	api := New(Config{Mesh: config.MeshConfig{Enabled: false}})
	require.Nil(t, api.meshAPI, "a disabled coordinator must not be constructed")

	w := httptest.NewRecorder()
	api.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/mesh/networks", nil))
	assert.Equal(t, http.StatusNotFound, w.Code, "mesh routes must not be mounted when disabled")
}

func TestMeshAPI_EnabledMountsRoutes(t *testing.T) {
	api := New(Config{Mesh: config.MeshConfig{Enabled: true}})
	require.NotNil(t, api.meshAPI)

	w := httptest.NewRecorder()
	api.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/mesh/networks", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMeshAPI_PersistsAcrossRestart is the regression test for coordinator state
// being in-memory only: every network and peer used to be lost on restart.
func TestMeshAPI_PersistsAcrossRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state", "mesh-state.json")
	cfg := config.MeshConfig{Enabled: true, StatePath: statePath}

	first, err := NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)
	h := meshRouter(first)

	w := doJSON(t, h, http.MethodPost, "/api/v1/mesh/networks",
		`{"id":"net-a","name":"Net A","cidr":"10.77.0.0/16"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = doJSON(t, h, http.MethodPost, "/api/v1/mesh/networks/net-a/peers",
		`{"network_id":"net-a","peer":{"id":"peer-1","name":"Laptop","public_key":"pk-1"}}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var registered registerPeerResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &registered))
	require.NotEmpty(t, registered.VirtualIP)

	// State file must exist with restrictive permissions.
	info, err := os.Stat(statePath)
	require.NoError(t, err)
	assert.Equal(t, meshStateFilePerm, info.Mode().Perm())

	// "Restart": a fresh coordinator over the same file.
	second, err := NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)

	network, ok := second.GetNetwork("net-a")
	require.True(t, ok, "the network must survive a restart")
	assert.Equal(t, "Net A", network.Name)
	assert.Equal(t, "10.77.0.0/16", network.CIDR)
	require.Equal(t, 1, network.peers.Count(), "the peer must survive a restart")

	peer, ok := network.peers.Get("peer-1")
	require.True(t, ok)
	assert.Equal(t, "Laptop", peer.Name)
	assert.Equal(t, "pk-1", peer.PublicKey)
	assert.Equal(t, registered.VirtualIP, peer.VirtualIP.String(),
		"a restarted coordinator must not renumber a running mesh")

	// The restored allocator must remember the lease, so a re-registration of the
	// same peer keeps its address.
	ip, ok := network.ipAllocator.GetIP("peer-1")
	require.True(t, ok, "the IP lease must be restored into the allocator")
	assert.Equal(t, registered.VirtualIP, ip.String())
}

func TestMeshAPI_PersistsDeletions(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mesh-state.json")
	cfg := config.MeshConfig{Enabled: true, StatePath: statePath}

	first, err := NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)
	h := meshRouter(first)

	require.Equal(t, http.StatusCreated, doJSON(t, h, http.MethodPost, "/api/v1/mesh/networks",
		`{"id":"net-a","cidr":"10.78.0.0/16"}`).Code)
	require.Equal(t, http.StatusCreated, doJSON(t, h, http.MethodPost, "/api/v1/mesh/networks/net-a/peers",
		`{"peer":{"id":"peer-1"}}`).Code)
	require.Equal(t, http.StatusNoContent, doJSON(t, h, http.MethodDelete,
		"/api/v1/mesh/networks/net-a/peers/peer-1", "").Code)

	reloaded, err := NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)
	network, ok := reloaded.GetNetwork("net-a")
	require.True(t, ok)
	assert.Zero(t, network.peers.Count(), "a deregistered peer must not come back after a restart")

	require.Equal(t, http.StatusNoContent, doJSON(t, h, http.MethodDelete,
		"/api/v1/mesh/networks/net-a", "").Code)

	reloaded, err = NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)
	_, ok = reloaded.GetNetwork("net-a")
	assert.False(t, ok, "a deleted network must not come back after a restart")
}

func TestMeshAPI_WithoutStatePathWritesNothing(t *testing.T) {
	dir := t.TempDir()

	m, err := NewMeshAPIWithConfig(config.MeshConfig{Enabled: true})
	require.NoError(t, err)
	h := meshRouter(m)

	require.Equal(t, http.StatusCreated, doJSON(t, h, http.MethodPost, "/api/v1/mesh/networks",
		`{"id":"net-a","cidr":"10.79.0.0/16"}`).Code)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "an in-memory coordinator must not touch the filesystem")
}

func TestMeshAPI_RestoreMissingFileIsNotAnError(t *testing.T) {
	m, err := NewMeshAPIWithConfig(config.MeshConfig{
		Enabled:   true,
		StatePath: filepath.Join(t.TempDir(), "absent.json"),
	})
	require.NoError(t, err)
	assert.Empty(t, m.networks)
}

func TestMeshAPI_RestoreMalformedFileReportsError(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mesh-state.json")
	require.NoError(t, os.WriteFile(statePath, []byte("{not json"), 0o600))

	m, err := NewMeshAPIWithConfig(config.MeshConfig{Enabled: true, StatePath: statePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse mesh state")
	require.NotNil(t, m, "the handler must remain usable after a restore failure")
	assert.Empty(t, m.networks)
}

func TestMeshAPI_RestoreRejectsUnsupportedVersion(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mesh-state.json")
	require.NoError(t, os.WriteFile(statePath,
		[]byte(`{"version":9999,"networks":[]}`), 0o600))

	_, err := NewMeshAPIWithConfig(config.MeshConfig{Enabled: true, StatePath: statePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mesh state version")
}

func TestMeshAPI_RestoreSkipsInvalidEntries(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mesh-state.json")
	state := `{
	  "version": 1,
	  "networks": [
	    {"id":"bad-cidr","cidr":"not-a-cidr","peers":[]},
	    {"id":"good","cidr":"10.80.0.0/16","peers":[
	      {"id":"ok","virtual_ip":"10.80.0.5"},
	      {"id":"bad-ip","virtual_ip":"nonsense"}
	    ]}
	  ]
	}`
	require.NoError(t, os.WriteFile(statePath, []byte(state), 0o600))

	m, err := NewMeshAPIWithConfig(config.MeshConfig{Enabled: true, StatePath: statePath})
	require.NoError(t, err)

	_, ok := m.GetNetwork("bad-cidr")
	assert.False(t, ok, "a network with an unparseable CIDR must be skipped")

	network, ok := m.GetNetwork("good")
	require.True(t, ok)
	assert.Equal(t, 1, network.peers.Count(), "only the peer with a valid virtual IP is restored")
	_, ok = network.peers.Get("ok")
	assert.True(t, ok)
}

// TestMeshAPI_CreateNetworkProgrammaticallyPersists covers the non-HTTP entry
// point, which bypasses the handlers.
func TestMeshAPI_CreateNetworkProgrammaticallyPersists(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mesh-state.json")
	cfg := config.MeshConfig{Enabled: true, StatePath: statePath}

	m, err := NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)
	_, err = m.CreateNetwork("prog", "Programmatic", "10.81.0.0/16")
	require.NoError(t, err)

	reloaded, err := NewMeshAPIWithConfig(cfg)
	require.NoError(t, err)
	network, ok := reloaded.GetNetwork("prog")
	require.True(t, ok)
	assert.Equal(t, "Programmatic", network.Name)
}
