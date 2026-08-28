package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiclient "github.com/rennerdo30/bifrost-proxy/internal/api/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func newSelectTestConfig() *config.ClientConfig {
	return &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "127.0.0.1:39990",
			Protocol: "http",
		},
		Servers: []config.NamedServer{
			{Name: "alpha", Address: "127.0.0.1:39991", Protocol: "http", IsDefault: true},
			{Name: "beta", Address: "127.0.0.1:39992", Protocol: "socks5", Username: "user", Password: "secret-credential"},
		},
	}
}

// Selecting a named server must reconfigure the live ServerConnection, not
// just mutate the config struct — a config-only mutation leaves every future
// dial on the old upstream while the UI reports the new one.
func TestClient_SelectServer_ReconfiguresLiveConnection(t *testing.T) {
	client, err := New(newSelectTestConfig())
	require.NoError(t, err)

	require.NoError(t, client.SelectServer("beta"))

	snap, _ := client.serverConn.snapshot()
	assert.Equal(t, "127.0.0.1:39992", snap.Address)
	assert.Equal(t, "socks5", snap.Protocol)
	assert.Equal(t, "user", snap.Username)
	assert.Equal(t, "secret-credential", snap.Password)

	assert.Equal(t, "127.0.0.1:39992", client.config.Server.Address)
	assert.Equal(t, "socks5", client.config.Server.Protocol)

	// Switching back to a credential-less server must clear the credentials.
	require.NoError(t, client.SelectServer("alpha"))
	snap, _ = client.serverConn.snapshot()
	assert.Equal(t, "127.0.0.1:39991", snap.Address)
	assert.Empty(t, snap.Username)
	assert.Empty(t, snap.Password)
}

func TestClient_SelectServer_UnknownNameErrors(t *testing.T) {
	client, err := New(newSelectTestConfig())
	require.NoError(t, err)

	before, _ := client.serverConn.snapshot()
	err = client.SelectServer("no-such-server")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-such-server")

	after, _ := client.serverConn.snapshot()
	assert.Equal(t, before.Address, after.Address, "a failed selection must not change the connection")
}

// The legacy single-server shape exposes one synthetic entry; selecting it is
// an idempotent success, and any other name is still an error.
func TestClient_SelectServer_LegacySingleServer(t *testing.T) {
	cfg := newSelectTestConfig()
	cfg.Servers = nil
	client, err := New(cfg)
	require.NoError(t, err)

	require.NoError(t, client.SelectServer(legacyDefaultServerName))
	require.Error(t, client.SelectServer("beta"))
}

func TestClient_Servers_ListsConfiguredWithoutCredentials(t *testing.T) {
	client, err := New(newSelectTestConfig())
	require.NoError(t, err)

	servers := client.Servers()
	require.Len(t, servers, 2)
	assert.Equal(t, "alpha", servers[0].Name)
	assert.Equal(t, "127.0.0.1:39991", servers[0].Address)
	assert.True(t, servers[0].IsDefault)
	assert.Equal(t, "beta", servers[1].Name)
	assert.Equal(t, serverStatusAvailable, servers[1].Status)

	// Credentials must not appear anywhere in the marshaled payload.
	encoded, err := json.Marshal(servers)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "secret-credential")
	assert.NotContains(t, string(encoded), "user")
}

func TestClient_Servers_SelectedEntryGetsProbedStatus(t *testing.T) {
	client, err := New(newSelectTestConfig())
	require.NoError(t, err)
	require.NoError(t, client.SelectServer("alpha"))

	servers := client.Servers()
	require.Len(t, servers, 2)
	// Nothing listens on the alpha address, so the honest status for the
	// selected entry is disconnected, never a fabricated "connected".
	assert.Equal(t, serverStatusDisconnected, servers[0].Status)
	assert.Equal(t, serverStatusAvailable, servers[1].Status)
}

func TestClient_Servers_LegacySingleServerFallback(t *testing.T) {
	cfg := newSelectTestConfig()
	cfg.Servers = nil
	client, err := New(cfg)
	require.NoError(t, err)

	servers := client.Servers()
	require.Len(t, servers, 1)
	assert.Equal(t, legacyDefaultServerName, servers[0].Name)
	assert.Equal(t, "127.0.0.1:39990", servers[0].Address)
	assert.True(t, servers[0].IsDefault)
}

// Selection must survive a restart: the choice is persisted through the same
// comment-preserving node path updateConfig uses, and a strict reload of the
// written file yields the selected server.
func TestClient_SelectServer_PersistsToConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	seed := `# top comment
proxy:
  http:
    listen: "127.0.0.1:0"
server:
  address: "127.0.0.1:39990"
  protocol: http
servers:
  - name: alpha
    address: "127.0.0.1:39991"
    protocol: http
    is_default: true
  - name: beta
    address: "127.0.0.1:39992"
    protocol: socks5
    username: user
    password: secret-credential
`
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	cfg := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &cfg))
	client, err := New(&cfg)
	require.NoError(t, err)
	client.SetConfigPath(path)

	require.NoError(t, client.SelectServer("beta"))

	reloaded := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &reloaded))
	assert.Equal(t, "127.0.0.1:39992", reloaded.Server.Address)
	assert.Equal(t, "socks5", reloaded.Server.Protocol)
	assert.Equal(t, "user", reloaded.Server.Username)
	assert.Equal(t, "secret-credential", reloaded.Server.Password)

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(written), "# top comment", "node path must preserve comments")
}

// The end-to-end regression for the audit blocker: a started client's real API
// handler — built with the production dependencies, not test stubs — must list
// the configured servers and apply a selection to the live connection. Before
// the wiring existed, the same requests returned [] and a 200 no-op.
func TestClient_Start_WiresServerEndpoints(t *testing.T) {
	cfg := newSelectTestConfig()
	cfg.API = config.APIConfig{
		Enabled: true,
		Listen:  "127.0.0.1:0",
	}
	client, err := New(cfg)
	require.NoError(t, err)

	require.NoError(t, client.Start(context.Background()))
	defer func() { require.NoError(t, client.Stop(context.Background())) }()

	handler := client.apiServer.Handler

	// GET /api/v1/servers reflects the configured list.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var servers []apiclient.ServerInfo
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &servers))
	require.Len(t, servers, 2)
	assert.Equal(t, "alpha", servers[0].Name)
	assert.Equal(t, "beta", servers[1].Name)

	// POST /api/v1/server/select actually reconfigures the connection.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/server/select",
		strings.NewReader(`{"server": "beta"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	snap, _ := client.serverConn.snapshot()
	assert.Equal(t, "127.0.0.1:39992", snap.Address)
	assert.Equal(t, "socks5", snap.Protocol)

	// An unknown server is a client error, not an acknowledged no-op.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/server/select",
		strings.NewReader(`{"server": "missing"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
