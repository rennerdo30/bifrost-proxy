package server

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apiserver "github.com/rennerdo30/bifrost-proxy/internal/api/server"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// TestServer_ConcurrentReloadAndTraffic exercises the request-path readers
// (accessCheck / allowUser / rate-limit snapshot) concurrently with
// ReloadConfig swapping the underlying controllers/limiters. Run with -race to
// detect the data race the snapshot helpers fix.
func TestServer_ConcurrentReloadAndTraffic(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	base := config.DefaultServerConfig()
	base.Server.HTTP.Listen = "127.0.0.1:0"
	base.Backends = []config.BackendConfig{
		{Name: "default", Type: "direct", Enabled: true},
	}
	base.RateLimit = config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1000,
		BurstSize:         1000,
		PerIP:             true,
		PerUser:           true,
	}
	base.AccessControl = config.AccessControlConfig{
		Whitelist: []string{"127.0.0.0/8"},
	}
	require.NoError(t, config.Save(cfgPath, &base))

	s, err := New(&base)
	require.NoError(t, err)
	s.SetConfigPath(cfgPath)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers: hammer the request-path accessors that read the swappable fields.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.accessCheck("127.0.0.1")
					s.allowUser("alice", "127.0.0.1")
					_ = s.snapshotRateLimiterIP()
				}
			}
		}()
	}

	// Writer: repeatedly reload config, toggling whether access control and
	// per-user limiting are configured so the pointers actually get swapped.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			select {
			case <-stop:
				return
			default:
			}
			next := base
			if i%2 == 0 {
				next.AccessControl = config.AccessControlConfig{}
				next.RateLimit.PerUser = false
			}
			require.NoError(t, config.Save(cfgPath, &next))
			require.NoError(t, s.ReloadConfig())
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestServer_StopClosesNegotiateHandler verifies Stop releases the Negotiate
// handler's cleanup goroutine when one is configured. A second Close on the same
// handler panics (closing an already-closed channel), proving Stop closed it.
func TestServer_StopClosesNegotiateHandler(t *testing.T) {
	negCfg := config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "ntlm", Type: "ntlm", Enabled: true, Config: map[string]any{"domain": "EXAMPLE"}},
		},
		Negotiate: &config.NegotiateConfig{
			Enabled:      true,
			NTLMProvider: "ntlm",
			AllowNTLM:    true,
		},
	}
	h, err := buildNegotiateHandler(negCfg)
	require.NoError(t, err)
	require.NotNil(t, h)

	cfg := config.DefaultServerConfig()
	cfg.Server.HTTP.Listen = "127.0.0.1:0"
	cfg.Backends = []config.BackendConfig{
		{Name: "default", Type: "direct", Enabled: true},
	}

	s, err := New(&cfg)
	require.NoError(t, err)
	s.negotiateHandler = h

	require.NoError(t, s.Start(context.Background()))
	require.NoError(t, s.Stop(context.Background()))

	require.Panics(t, func() { _ = h.Close() },
		"Stop should have already closed the negotiate handler")
}

// TestServer_OnConnectPopulatesTracker verifies onConnect fills in the
// destination host/backend on the tracked connection and that closeTrackedConn
// removes it.
func TestServer_OnConnectPopulatesTracker(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.Server.HTTP.Listen = "127.0.0.1:0"
	cfg.Backends = []config.BackendConfig{
		{Name: "default", Type: "direct", Enabled: true},
	}

	s, err := New(&cfg)
	require.NoError(t, err)

	s.api = apiserver.New(apiserver.Config{Backends: s.backends})
	tracker := s.api.ConnectionTracker()
	require.NotNil(t, tracker)

	id := tracker.Add("127.0.0.1", "5555", "", "", "HTTP")
	ctx := withConnID(context.Background(), id)

	be, err := s.backends.Get("default")
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	s.onConnect(ctx, serverConn, "example.com:443", be)

	got, ok := tracker.Get(id)
	require.True(t, ok)
	require.Equal(t, "example.com:443", got.Host)
	require.Equal(t, "default", got.Backend)

	// closeTrackedConn must remove the connection (and not panic when wsHub nil).
	s.closeTrackedConn(id)
	_, ok = tracker.Get(id)
	require.False(t, ok)
}
