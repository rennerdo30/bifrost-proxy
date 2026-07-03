package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}
	c, err := New(cfg)
	require.NoError(t, err)
	return c
}

func TestReloadConfig_NoPath(t *testing.T) {
	c := newTestClient(t)
	err := c.reloadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no config file path")
}

func TestReloadConfig_InvalidFile(t *testing.T) {
	c := newTestClient(t)
	c.SetConfigPath(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	err := c.reloadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reload config")
}

func TestReloadConfig_HotAppliesRoutesAndServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")

	yaml := `proxy:
  http:
    listen: "127.0.0.1:7380"
server:
  address: "newserver:9999"
  protocol: "socks5"
  username: "alice"
  password: "secret"
  retry_count: 7
  retry_delay: "2s"
routes:
  - name: direct-example
    domains: ["example.com"]
    action: direct
    priority: 10
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))

	c := newTestClient(t)
	c.SetConfigPath(path)

	// Before reload the router has no routes, so everything defaults to server.
	assert.Equal(t, router.ActionServer, c.router.Match("example.com"))

	require.NoError(t, c.reloadConfig())

	// Routes were hot-applied.
	assert.Equal(t, router.ActionDirect, c.router.Match("example.com"))

	// In-memory config was replaced.
	assert.Equal(t, "newserver:9999", c.config.Server.Address)
	assert.Equal(t, "socks5", c.config.Server.Protocol)
	assert.Equal(t, 7, c.config.Server.RetryCount)

	// The live server connection was reconfigured.
	cfg, _ := c.serverConn.snapshot()
	assert.Equal(t, "newserver:9999", cfg.Address)
	assert.Equal(t, "socks5", cfg.Protocol)
	assert.Equal(t, "alice", cfg.Username)
	assert.Equal(t, "secret", cfg.Password)
	assert.Equal(t, 7, cfg.RetryCount)
	assert.Equal(t, 2*time.Second, cfg.RetryDelay)
}

func TestReloadConfig_InvalidConfigRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")

	// An invalid route action fails Validate() even after defaults are merged.
	yaml := `routes:
  - domains: ["x.com"]
    action: bogus
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))

	c := newTestClient(t)
	c.SetConfigPath(path)

	err := c.reloadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reload config")
}

func TestUpdateConfig_HotAppliesServerConn(t *testing.T) {
	c := newTestClient(t)

	err := c.updateConfig(map[string]interface{}{
		"server": map[string]interface{}{
			"address":     "hotserver:1234",
			"protocol":    "socks5",
			"username":    "bob",
			"password":    "pw",
			"retry_count": float64(5),
			"retry_delay": "3s",
		},
	})
	require.NoError(t, err)

	cfg, _ := c.serverConn.snapshot()
	assert.Equal(t, "hotserver:1234", cfg.Address)
	assert.Equal(t, "socks5", cfg.Protocol)
	assert.Equal(t, "bob", cfg.Username)
	assert.Equal(t, "pw", cfg.Password)
	assert.Equal(t, 5, cfg.RetryCount)
	assert.Equal(t, 3*time.Second, cfg.RetryDelay)
}

func TestStartHealthMonitor_NilConfigNoGoroutine(t *testing.T) {
	c := newTestClient(t)
	// No health check configured -> should be a no-op and not spawn a goroutine.
	c.startHealthMonitor(context.Background())

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wg.Wait blocked; a goroutine was spawned unexpectedly")
	}
}

func TestStartHealthMonitor_NoAddressNoGoroutine(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			HealthCheck: &config.HealthCheckConfig{
				Type:     "tcp",
				Interval: config.Duration(10 * time.Millisecond),
			},
		},
	}
	c, err := New(cfg)
	require.NoError(t, err)

	c.startHealthMonitor(context.Background())

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wg.Wait blocked; monitor started without a server address")
	}
}

func TestStartHealthMonitor_RunsAndStops(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "127.0.0.1:1", // unreachable
			HealthCheck: &config.HealthCheckConfig{
				Type:     "tcp",
				Interval: config.Duration(10 * time.Millisecond),
				Timeout:  config.Duration(50 * time.Millisecond),
			},
		},
	}
	c, err := New(cfg)
	require.NoError(t, err)

	c.startHealthMonitor(context.Background())

	// Let it tick at least once.
	time.Sleep(50 * time.Millisecond)

	// Closing done must terminate the monitor goroutine.
	close(c.done)

	terminated := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(terminated)
	}()
	select {
	case <-terminated:
	case <-time.After(2 * time.Second):
		t.Fatal("health monitor did not stop after done was closed")
	}
}
