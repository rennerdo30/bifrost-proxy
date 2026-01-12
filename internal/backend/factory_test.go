package backend

import (
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	assert.NotNil(t, f)
}

func TestFactory_Create_Direct(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-direct",
		Type:    "direct",
		Enabled: true,
		Config: map[string]any{
			"connect_timeout": "5s",
			"keep_alive":      "30s",
			"local_addr":      "127.0.0.1",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-direct", backend.Name())
	assert.Equal(t, "direct", backend.Type())
}

func TestFactory_Create_Direct_NoConfig(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-direct",
		Type:    "direct",
		Enabled: true,
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-direct", backend.Name())
}

func TestFactory_Create_HTTPProxy(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-http",
		Type:    "http_proxy",
		Enabled: true,
		Config: map[string]any{
			"address":         "proxy.example.com:8080",
			"username":        "user",
			"password":        "pass",
			"connect_timeout": "10s",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-http", backend.Name())
	assert.Equal(t, "http_proxy", backend.Type())
}

func TestFactory_Create_HTTPProxy_MissingAddress(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-http",
		Type:    "http_proxy",
		Enabled: true,
		Config:  map[string]any{},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address")
}

func TestFactory_Create_SOCKS5Proxy(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-socks5",
		Type:    "socks5_proxy",
		Enabled: true,
		Config: map[string]any{
			"address":         "socks.example.com:1080",
			"username":        "user",
			"password":        "pass",
			"connect_timeout": "10s",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-socks5", backend.Name())
	assert.Equal(t, "socks5_proxy", backend.Type())
}

func TestFactory_Create_SOCKS5Proxy_MissingAddress(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-socks5",
		Type:    "socks5_proxy",
		Enabled: true,
		Config:  map[string]any{},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address")
}

func TestFactory_Create_WireGuard(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-wg",
		Type:    "wireguard",
		Enabled: true,
		Config: map[string]any{
			"private_key": "base64privatekey==",
			"address":     "10.0.0.2/24",
			"dns":         []any{"1.1.1.1", "8.8.8.8"},
			"mtu":         1420,
			"peer": map[string]any{
				"public_key":           "base64publickey==",
				"endpoint":             "vpn.example.com:51820",
				"preshared_key":        "base64psk==",
				"persistent_keepalive": 25,
				"allowed_ips":          []any{"0.0.0.0/0", "::/0"},
			},
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-wg", backend.Name())
	assert.Equal(t, "wireguard", backend.Type())
}

func TestFactory_Create_WireGuard_MissingPrivateKey(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-wg",
		Type:    "wireguard",
		Enabled: true,
		Config: map[string]any{
			"address": "10.0.0.2/24",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private_key")
}

func TestFactory_Create_WireGuard_MissingAddress(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-wg",
		Type:    "wireguard",
		Enabled: true,
		Config: map[string]any{
			"private_key": "base64privatekey==",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address")
}

func TestFactory_Create_OpenVPN(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-ovpn",
		Type:    "openvpn",
		Enabled: true,
		Config: map[string]any{
			"config_file":     "/etc/openvpn/client.conf",
			"auth_file":       "/etc/openvpn/auth.txt",
			"binary":          "/usr/sbin/openvpn",
			"management_addr": "127.0.0.1",
			"management_port": 7505,
			"connect_timeout": "30s",
			"extra_args":      []any{"--nobind", "--fast-io"},
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-ovpn", backend.Name())
	assert.Equal(t, "openvpn", backend.Type())
}

func TestFactory_Create_OpenVPN_MissingConfigFile(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-ovpn",
		Type:    "openvpn",
		Enabled: true,
		Config:  map[string]any{},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config_file")
}

func TestFactory_Create_InvalidType(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test",
		Type:    "invalid_type",
		Enabled: true,
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidBackendType)
}

func TestFactory_CreateAll(t *testing.T) {
	f := NewFactory()

	configs := []config.BackendConfig{
		{
			Name:    "direct1",
			Type:    "direct",
			Enabled: true,
		},
		{
			Name:    "direct2",
			Type:    "direct",
			Enabled: true,
		},
		{
			Name:    "disabled",
			Type:    "direct",
			Enabled: false, // Should be skipped
		},
	}

	manager, err := f.CreateAll(configs)
	require.NoError(t, err)
	assert.NotNil(t, manager)

	backends := manager.All()
	assert.Len(t, backends, 2)
}

func TestFactory_CreateAll_Empty(t *testing.T) {
	f := NewFactory()

	manager, err := f.CreateAll(nil)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Empty(t, manager.All())
}

func TestFactory_CreateAll_Error(t *testing.T) {
	f := NewFactory()

	configs := []config.BackendConfig{
		{
			Name:    "invalid",
			Type:    "invalid_type",
			Enabled: true,
		},
	}

	_, err := f.CreateAll(configs)
	assert.Error(t, err)
}

func TestFactory_CreateAll_DuplicateNames(t *testing.T) {
	f := NewFactory()

	configs := []config.BackendConfig{
		{
			Name:    "same-name",
			Type:    "direct",
			Enabled: true,
		},
		{
			Name:    "same-name",
			Type:    "direct",
			Enabled: true,
		},
	}

	_, err := f.CreateAll(configs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}
