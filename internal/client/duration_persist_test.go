package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// The primary PUT path regression: a legacy numeric (nanosecond) duration in
// the request body used to decode as float64, persist as YAML scientific
// notation ("3e+11"), and make the next config load fail — a 200 response
// that bricked the reload. The whole chain must round-trip: PUT with numbers,
// file loads, values correct.
func TestConfigAPIUpdate_LegacyNumericDurationSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	seed := `proxy:
  http:
    listen: "127.0.0.1:0"
server:
  address: "127.0.0.1:39990"
vpn:
  enabled: false
  dns:
    cache_ttl: "5m"
mesh:
  enabled: false
  discovery:
    heartbeat_interval: "15s"
`
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	cfg := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &cfg))
	cfg.API = config.APIConfig{Enabled: true, Listen: "127.0.0.1:0"}
	// The default config enables the tray, which needs a real GUI session.
	cfg.Tray.Enabled = false
	cfg.Proxy.SOCKS5.Listen = "127.0.0.1:0"
	client, err := New(&cfg)
	require.NoError(t, err)
	client.SetConfigPath(path)

	require.NoError(t, client.Start(context.Background()))
	defer func() { require.NoError(t, client.Stop(context.Background())) }()

	body := `{
		"vpn": {"dns": {"cache_ttl": 300000000000}},
		"mesh": {"discovery": {"heartbeat_interval": 30000000000}}
	}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()
	client.apiServer.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The file the PUT wrote must not contain scientific notation…
	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(written), "e+", "nanosecond counts must persist as integers, not scientific notation")

	// …and must load with the correct values.
	reloaded := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &reloaded),
		"config written by the PUT endpoint must remain loadable")
	assert.Equal(t, 5*time.Minute, reloaded.VPN.DNS.CacheTTL.Duration())
	assert.Equal(t, 30*time.Second, reloaded.Mesh.Discovery.HeartbeatInterval.Duration())
}
