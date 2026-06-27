package backend

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func networkCfg() config.NetworkConfig {
	return config.NetworkConfig{
		PreferIPv6:  true,
		KeepAlive:   config.Duration(42 * time.Second),
		DialTimeout: config.Duration(11 * time.Second),
	}
}

func TestFactory_DirectAppliesNetwork(t *testing.T) {
	f := NewFactoryWithNetwork(networkCfg())
	b, err := f.Create(config.BackendConfig{Name: "d", Type: "direct"})
	require.NoError(t, err)
	db, ok := b.(*DirectBackend)
	require.True(t, ok)
	assert.Equal(t, 42*time.Second, db.dialer.KeepAlive)
	// Direct sets its own ConnectTimeout default (30s) so the network dial
	// timeout does not override it.
	assert.Equal(t, 30*time.Second, db.dialer.Timeout)
	assert.True(t, db.preferIPv6)
	assert.NotNil(t, db.dialer.Resolver)
}

func TestFactory_HTTPProxyAppliesNetwork(t *testing.T) {
	f := NewFactoryWithNetwork(networkCfg())
	b, err := f.Create(config.BackendConfig{
		Name: "h", Type: "http_proxy",
		Config: map[string]any{"address": "127.0.0.1:8080"},
	})
	require.NoError(t, err)
	hb, ok := b.(*HTTPProxyBackend)
	require.True(t, ok)
	assert.Equal(t, 42*time.Second, hb.dialer.KeepAlive)
	assert.True(t, hb.preferIPv6)
}

func TestFactory_SOCKS5AppliesNetwork(t *testing.T) {
	f := NewFactoryWithNetwork(networkCfg())
	b, err := f.Create(config.BackendConfig{
		Name: "s", Type: "socks5_proxy",
		Config: map[string]any{"address": "127.0.0.1:1080"},
	})
	require.NoError(t, err)
	sb, ok := b.(*SOCKS5ProxyBackend)
	require.True(t, ok)
	assert.Equal(t, 42*time.Second, sb.dialer.KeepAlive)
	assert.True(t, sb.preferIPv6)
}

func TestFactory_OpenVPNAppliesNetwork(t *testing.T) {
	f := NewFactoryWithNetwork(networkCfg())
	b, err := f.Create(config.BackendConfig{
		Name: "o", Type: "openvpn",
		Config: map[string]any{
			"config_content":     "client\nremote example.com 1194\n",
			"leak_proof_routing": true,
		},
	})
	require.NoError(t, err)
	ob, ok := b.(*OpenVPNBackend)
	require.True(t, ok)
	assert.True(t, ob.config.Network.PreferIPv6)
	assert.Equal(t, 42*time.Second, ob.config.Network.KeepAlive)
	assert.True(t, ob.config.LeakProofRouting)
}

func TestFactory_SetNetwork(t *testing.T) {
	f := NewFactory()
	assert.True(t, f.network.IsZero())
	f.SetNetwork(networkCfg())
	assert.False(t, f.network.IsZero())
	assert.Equal(t, 42*time.Second, f.network.KeepAlive)
}

func TestFactory_NoNetworkLeavesDefaults(t *testing.T) {
	f := NewFactory()
	b, err := f.Create(config.BackendConfig{Name: "d", Type: "direct"})
	require.NoError(t, err)
	db := b.(*DirectBackend)
	assert.False(t, db.preferIPv6)
	assert.Equal(t, 30*time.Second, db.dialer.KeepAlive) // direct default
}
