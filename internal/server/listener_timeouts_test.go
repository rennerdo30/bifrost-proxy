package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// listenerTimeoutFixture returns a config whose listener timeouts and
// network.dial_timeout are all distinct, so a value landing in the wrong field
// is unambiguous.
func listenerTimeoutFixture() *config.ServerConfig {
	dialTimeout := 3 * time.Second
	return &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{
				Listen:       "127.0.0.1:0",
				ReadTimeout:  config.Duration(11 * time.Second),
				WriteTimeout: config.Duration(12 * time.Second),
				IdleTimeout:  config.Duration(13 * time.Second),
			},
			SOCKS5: config.ListenerConfig{
				Listen:       "127.0.0.1:0",
				ReadTimeout:  config.Duration(21 * time.Second),
				WriteTimeout: config.Duration(22 * time.Second),
				IdleTimeout:  config.Duration(23 * time.Second),
			},
		},
		Network: config.NetworkConfig{
			DialTimeout: config.Duration(dialTimeout),
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}
}

// TestHTTPHandlerConfig_ListenerTimeoutsAreWired proves the HTTP listener's
// three timeouts reach the handler, and that the OUTBOUND dial timeout comes
// from network.dial_timeout rather than from read_timeout. Passing read_timeout
// as the dial timeout meant raising it to help a slow client instead lengthened
// backend connect attempts.
func TestHTTPHandlerConfig_ListenerTimeoutsAreWired(t *testing.T) {
	s, err := New(listenerTimeoutFixture())
	require.NoError(t, err)

	cfg := s.httpHandlerConfig(nil)

	assert.Equal(t, 11*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 12*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 13*time.Second, cfg.IdleTimeout)
	assert.Equal(t, 3*time.Second, cfg.DialTimeout,
		"outbound dial timeout must come from network.dial_timeout, not from the listener's read_timeout")
}

// TestSOCKS5HandlerConfig_ListenerTimeoutsAreWired proves the same for SOCKS5,
// whose listener previously read no timeout at all and whose dial timeout was
// hardcoded.
func TestSOCKS5HandlerConfig_ListenerTimeoutsAreWired(t *testing.T) {
	s, err := New(listenerTimeoutFixture())
	require.NoError(t, err)

	cfg := s.socks5HandlerConfig(nil)

	assert.Equal(t, 21*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 22*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 23*time.Second, cfg.IdleTimeout)
	assert.Equal(t, 3*time.Second, cfg.DialTimeout,
		"outbound dial timeout must come from network.dial_timeout")
}

// TestSanitizedConfig_ReportsAllListenerTimeouts checks the config API reports
// every listener timeout it now honors. Previously it echoed read_timeout and
// write_timeout while applying neither, which made an inert setting look
// applied.
func TestSanitizedConfig_ReportsAllListenerTimeouts(t *testing.T) {
	s, err := New(listenerTimeoutFixture())
	require.NoError(t, err)

	sanitized, ok := s.GetSanitizedConfig().(map[string]interface{})
	require.True(t, ok)
	server, ok := sanitized["server"].(map[string]interface{})
	require.True(t, ok)

	httpListener, ok := server["http"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "11s", httpListener["read_timeout"])
	assert.Equal(t, "12s", httpListener["write_timeout"])
	assert.Equal(t, "13s", httpListener["idle_timeout"])

	socks5Listener, ok := server["socks5"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "21s", socks5Listener["read_timeout"])
	assert.Equal(t, "22s", socks5Listener["write_timeout"])
	assert.Equal(t, "23s", socks5Listener["idle_timeout"])
}

// TestDefaultServerConfig_BoundsBothListeners checks both shipped listeners get
// a bounded handshake by default. Without SOCKS5 defaults a client could open a
// connection and hold a goroutine and a file descriptor without ever speaking.
func TestDefaultServerConfig_BoundsBothListeners(t *testing.T) {
	cfg := config.DefaultServerConfig()

	for name, listener := range map[string]config.ListenerConfig{
		"http":   cfg.Server.HTTP,
		"socks5": cfg.Server.SOCKS5,
	} {
		assert.Positive(t, listener.ReadTimeout.Duration(), "%s read_timeout", name)
		assert.Positive(t, listener.WriteTimeout.Duration(), "%s write_timeout", name)
		assert.Positive(t, listener.IdleTimeout.Duration(), "%s idle_timeout", name)
	}
}
