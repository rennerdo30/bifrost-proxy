package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/updater"
)

// isolateUpdateState points the updater's default state path at a temporary
// directory so tests never touch the developer's real config directory.
func isolateUpdateState(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
}

func newAutoUpdateServer(t *testing.T, autoUpdate config.AutoUpdateConfig) *Server {
	t.Helper()
	s, err := New(&config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		AutoUpdate: autoUpdate,
	})
	require.NoError(t, err)
	return s
}

func TestServer_UpdaterConfig_Defaults(t *testing.T) {
	s := newAutoUpdateServer(t, config.AutoUpdateConfig{Enabled: true})

	cfg := s.updaterConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, defaultUpdateCheckInterval, cfg.CheckInterval,
		"an unset check_interval must fall back to the default")
	assert.Equal(t, updater.ChannelStable, cfg.Channel)
	assert.NotEmpty(t, cfg.GitHubOwner)
	assert.NotEmpty(t, cfg.GitHubRepo)
}

func TestServer_UpdaterConfig_HonoursChannelAndInterval(t *testing.T) {
	s := newAutoUpdateServer(t, config.AutoUpdateConfig{
		Enabled:       true,
		Channel:       string(updater.ChannelPrerelease),
		CheckInterval: config.Duration(6 * time.Hour),
	})

	cfg := s.updaterConfig()
	assert.Equal(t, updater.ChannelPrerelease, cfg.Channel)
	assert.Equal(t, 6*time.Hour, cfg.CheckInterval)
}

func TestServer_UpdaterConfig_ClampsTinyInterval(t *testing.T) {
	s := newAutoUpdateServer(t, config.AutoUpdateConfig{
		Enabled:       true,
		CheckInterval: config.Duration(time.Second),
	})

	assert.Equal(t, minUpdateCheckInterval, s.updaterConfig().CheckInterval,
		"a sub-minimum check_interval must be clamped so the daemon cannot hammer the releases API")
}

// TestServer_StartUpdater_WiredWhenEnabled is the regression test for the dead
// auto-update toggle: no daemon used to construct an Updater at all, so
// enabling auto_update had no runtime effect whatsoever.
func TestServer_StartUpdater_WiredWhenEnabled(t *testing.T) {
	isolateUpdateState(t)

	s := newAutoUpdateServer(t, config.AutoUpdateConfig{
		Enabled:       true,
		CheckInterval: config.Duration(2 * time.Hour),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	s.mu.RLock()
	u := s.updater
	s.mu.RUnlock()
	require.NotNil(t, u, "auto_update.enabled must start the background checker")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	require.NoError(t, s.Stop(stopCtx))

	s.mu.RLock()
	defer s.mu.RUnlock()
	assert.Nil(t, s.updater, "shutdown must release the background checker")
}

func TestServer_StartUpdater_NotWiredWhenDisabled(t *testing.T) {
	isolateUpdateState(t)

	s := newAutoUpdateServer(t, config.AutoUpdateConfig{Enabled: false})

	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Stop(stopCtx) //nolint:errcheck // test cleanup
	})

	s.mu.RLock()
	defer s.mu.RUnlock()
	assert.Nil(t, s.updater, "auto_update must stay inert when disabled")
}

// TestServer_StopUpdater_Idempotent guards the shutdown path against a nil
// updater (auto-update disabled) and repeated calls.
func TestServer_StopUpdater_Idempotent(t *testing.T) {
	s := newAutoUpdateServer(t, config.AutoUpdateConfig{})
	s.stopUpdater()
	s.stopUpdater()
}

func TestServerUpdateNotifier_DoesNotPanic(t *testing.T) {
	serverUpdateNotifier{}.NotifyUpdateAvailable(updater.UpdateInfo{
		CurrentVersion: "1.0.0",
		NewVersion:     "1.1.0",
		ReleaseURL:     "https://example.invalid/release",
	})
}
