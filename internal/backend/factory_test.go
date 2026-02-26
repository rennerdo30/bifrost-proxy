package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
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
			"address":         "proxy.example.com:7080",
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
			"address":         "socks.example.com:7180",
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

func TestFactory_Create_OpenVPN_WithInlineConfig(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-ovpn-inline",
		Type:    "openvpn",
		Enabled: true,
		Config: map[string]any{
			"config_content": "client\ndev tun\nremote vpn.example.com 1194\n",
			"username":       "myuser",
			"password":       "mypass",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-ovpn-inline", backend.Name())
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
	assert.Contains(t, err.Error(), "config_content")
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

	// With the resilient behavior, duplicate names are logged but don't cause total failure
	// The first backend is added, the second is skipped
	manager, err := f.CreateAll(configs)
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	// Only one backend should be added (the duplicate is skipped)
	assert.Len(t, manager.List(), 1)
}

// ============================================================================
// NordVPN Factory Tests
// ============================================================================

func TestFactory_Create_NordVPN_WireGuard(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-nordvpn-wg",
		Type:    "nordvpn",
		Enabled: true,
		Config: map[string]any{
			"access_token":     "my-private-key-base64",
			"protocol":         "wireguard",
			"country":          "US",
			"city":             "New York",
			"auto_select":      true,
			"max_load":         70,
			"refresh_interval": "5m",
			"features":         []any{"p2p", "double_vpn"},
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-nordvpn-wg", backend.Name())
	assert.Equal(t, "nordvpn", backend.Type())
}

func TestFactory_Create_NordVPN_NordLynx(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-nordvpn-lynx",
		Type:    "nordvpn",
		Enabled: true,
		Config: map[string]any{
			"access_token": "my-private-key-base64",
			"protocol":     "nordlynx",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-nordvpn-lynx", backend.Name())
}

func TestFactory_Create_NordVPN_OpenVPN(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-nordvpn-ovpn",
		Type:    "nordvpn",
		Enabled: true,
		Config: map[string]any{
			"username": "nord_username",
			"password": "nord_password",
			"protocol": "openvpn",
			"country":  "DE",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-nordvpn-ovpn", backend.Name())
}

func TestFactory_Create_NordVPN_MissingAccessToken(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-nordvpn",
		Type:    "nordvpn",
		Enabled: true,
		Config: map[string]any{
			"protocol": "wireguard",
			// Missing access_token
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_token")
}

func TestFactory_Create_NordVPN_DefaultProtocol(t *testing.T) {
	f := NewFactory()

	// No protocol specified, defaults to wireguard which requires access_token
	cfg := config.BackendConfig{
		Name:    "test-nordvpn",
		Type:    "nordvpn",
		Enabled: true,
		Config:  map[string]any{},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_token")
}

func TestFactory_Create_NordVPN_OpenVPN_MissingCredentials(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-nordvpn",
		Type:    "nordvpn",
		Enabled: true,
		Config: map[string]any{
			"protocol": "openvpn",
			"username": "user",
			// Missing password
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username")
	assert.Contains(t, err.Error(), "password")
}

// ============================================================================
// Mullvad Factory Tests
// ============================================================================

func TestFactory_Create_Mullvad(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-mullvad",
		Type:    "mullvad",
		Enabled: true,
		Config: map[string]any{
			"account_id":       "1234567890123456",
			"country":          "SE",
			"city":             "Stockholm",
			"protocol":         "wireguard",
			"auto_select":      true,
			"max_load":         80,
			"refresh_interval": "10m",
			"features":         []any{"streaming", "multihop"},
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-mullvad", backend.Name())
	assert.Equal(t, "mullvad", backend.Type())
}

func TestFactory_Create_Mullvad_MissingAccountID(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-mullvad",
		Type:    "mullvad",
		Enabled: true,
		Config:  map[string]any{},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account_id")
}

// ============================================================================
// PIA Factory Tests
// ============================================================================

func TestFactory_Create_PIA(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-pia",
		Type:    "pia",
		Enabled: true,
		Config: map[string]any{
			"username":         "p1234567",
			"password":         "pia_password",
			"country":          "US",
			"city":             "California",
			"protocol":         "wireguard",
			"auto_select":      true,
			"max_load":         75,
			"refresh_interval": "15m",
			"port_forwarding":  true,
			"features":         []any{"port_forwarding", "streaming"},
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-pia", backend.Name())
	assert.Equal(t, "pia", backend.Type())
}

func TestFactory_Create_PIA_MissingUsername(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-pia",
		Type:    "pia",
		Enabled: true,
		Config: map[string]any{
			"password": "pass",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username")
}

func TestFactory_Create_PIA_MissingPassword(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-pia",
		Type:    "pia",
		Enabled: true,
		Config: map[string]any{
			"username": "user",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password")
}

// ============================================================================
// ProtonVPN Factory Tests
// ============================================================================

func TestFactory_Create_ProtonVPN(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-protonvpn",
		Type:    "protonvpn",
		Enabled: true,
		Config: map[string]any{
			"username":         "proton_openvpn_user",
			"password":         "proton_openvpn_pass",
			"country":          "CH",
			"city":             "Zurich",
			"tier":             2,
			"protocol":         "openvpn",
			"auto_select":      true,
			"max_load":         60,
			"refresh_interval": "20m",
			"secure_core":      true,
			"features":         []any{"secure_core", "tor"},
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-protonvpn", backend.Name())
	assert.Equal(t, "protonvpn", backend.Type())
}

func TestFactory_Create_ProtonVPN_MissingUsername(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-protonvpn",
		Type:    "protonvpn",
		Enabled: true,
		Config: map[string]any{
			"password": "pass",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username")
}

func TestFactory_Create_ProtonVPN_MissingPassword(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-protonvpn",
		Type:    "protonvpn",
		Enabled: true,
		Config: map[string]any{
			"username": "user",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password")
}

func TestFactory_Create_ProtonVPN_WireGuardRequiresAPIAuthMode(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-protonvpn",
		Type:    "protonvpn",
		Enabled: true,
		Config: map[string]any{
			"username": "openvpn_user",
			"password": "openvpn_pass",
			"protocol": "wireguard",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires auth_mode='api'")
}

func TestFactory_Create_ProtonVPN_APIAuthModeWithWireGuard(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-protonvpn-api",
		Type:    "protonvpn",
		Enabled: true,
		Config: map[string]any{
			"auth_mode": "api",
			"username":  "proton_account_user",
			"password":  "proton_account_pass",
			"protocol":  "wireguard",
		},
	}

	backend, err := f.Create(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test-protonvpn-api", backend.Name())
	assert.Equal(t, "protonvpn", backend.Type())
}

func TestFactory_Create_ProtonVPN_APIAuthModeOpenVPNRejected(t *testing.T) {
	f := NewFactory()

	cfg := config.BackendConfig{
		Name:    "test-protonvpn-api-openvpn",
		Type:    "protonvpn",
		Enabled: true,
		Config: map[string]any{
			"auth_mode": "api",
			"username":  "proton_account_user",
			"password":  "proton_account_pass",
			"protocol":  "openvpn",
		},
	}

	_, err := f.Create(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "supports protocol='wireguard' only")
}
