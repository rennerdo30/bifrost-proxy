package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// One typo per backend type: every type the factory knows must reject it.
// This is the audit blocker — `connect_timeot` on a direct backend loaded
// silently and the timeout kept its default.
func TestBackendConfigKeys_TypoRejectedForEveryType(t *testing.T) {
	cases := map[string]map[string]any{
		"direct":       {"connect_timeot": "5s"},
		"http_proxy":   {"address": "x:1", "usernane": "u"},
		"socks5_proxy": {"address": "x:1", "connect_timeouts": "5s"},
		"wireguard":    {"private_key": "k", "address": "10.0.0.2/24", "mtus": 1420},
		"openvpn":      {"config_file": "/x.ovpn", "auth_files": "/a"},
		"nordvpn":      {"access_token": "t", "countrys": "de"},
		"mullvad":      {"account_id": "1", "citty": "ber"},
		"pia":          {"username": "u", "password": "p", "port_forwardings": true},
		"protonvpn":    {"username": "u", "password": "p", "secure_cores": true},
	}

	assert.ElementsMatch(t, SchemaTypes(), keysOf(cases),
		"this table must cover every backend type with a schema")

	for backendType, cfgMap := range cases {
		t.Run(backendType, func(t *testing.T) {
			err := ValidateConfigKeys(config.BackendConfig{
				Name: "test", Type: backendType, Enabled: true, Config: cfgMap,
			})
			require.Error(t, err, "type %s must reject its typo key", backendType)
		})
	}
}

// A typo nested inside the wireguard peer block is rejected too.
func TestBackendConfigKeys_NestedPeerTypoRejected(t *testing.T) {
	err := ValidateConfigKeys(config.BackendConfig{
		Name: "wg", Type: "wireguard", Enabled: true,
		Config: map[string]any{
			"private_key": "k",
			"address":     "10.0.0.2/24",
			"peer": map[string]any{
				"public_key":            "pk",
				"endpoint":              "vpn.example.com:51820",
				"persistent_keepalives": 25,
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persistent_keepalives")
}

// The documented full configuration for each type keeps validating.
func TestBackendConfigKeys_ValidConfigsAccepted(t *testing.T) {
	cases := map[string]map[string]any{
		"direct":       {"connect_timeout": "5s", "keep_alive": "30s", "local_addr": "1.2.3.4"},
		"http_proxy":   {"address": "x:1", "username": "u", "password": "p", "connect_timeout": "5s"},
		"socks5_proxy": {"address": "x:1", "username": "u", "password": "p", "connect_timeout": "5s"},
		"wireguard": {"private_key": "k", "address": "10.0.0.2/24", "dns": []string{"1.1.1.1"}, "mtu": 1420,
			"peer": map[string]any{"public_key": "pk", "endpoint": "e:51820", "preshared_key": "psk", "persistent_keepalive": 25, "allowed_ips": []string{"0.0.0.0/0"}}},
		"openvpn": {"config_file": "/x.ovpn", "config_content": "", "auth_file": "/a", "username": "u", "password": "p",
			"binary": "/usr/sbin/openvpn", "management_addr": "127.0.0.1", "management_port": 7505,
			"connect_timeout": "30s", "extra_args": []string{"--verb", "3"}, "leak_proof_routing": true},
		"nordvpn": {"country": "de", "city": "berlin", "protocol": "wireguard", "auto_select": true, "max_load": 70,
			"refresh_interval": "1h", "features": []string{"p2p"}, "access_token": "t", "username": "u", "password": "p",
			"ca_cert": "PEM", "tls_auth_key": "KEY", "leak_proof_routing": true},
		"mullvad": {"account_id": "1", "country": "de", "city": "ber", "protocol": "wireguard", "auto_select": true,
			"max_load": 70, "refresh_interval": "1h", "features": []string{"p2p"}, "ca_cert": "PEM", "tls_auth_key": "KEY", "leak_proof_routing": false},
		"pia": {"username": "u", "password": "p", "country": "de", "city": "ber", "protocol": "wireguard",
			"auto_select": true, "max_load": 70, "refresh_interval": "1h", "port_forwarding": true, "features": []string{"p2p"}, "leak_proof_routing": false},
		"protonvpn": {"auth_mode": "manual", "username": "u", "password": "p", "country": "de", "city": "ber", "tier": 2,
			"protocol": "wireguard", "auto_select": true, "max_load": 70, "refresh_interval": "1h", "secure_core": false,
			"features": []string{"p2p"}, "ca_cert": "PEM", "tls_auth_key": "KEY", "leak_proof_routing": false},
	}

	for backendType, cfgMap := range cases {
		t.Run(backendType, func(t *testing.T) {
			assert.NoError(t, ValidateConfigKeys(config.BackendConfig{
				Name: "test", Type: backendType, Enabled: true, Config: cfgMap,
			}))
		})
	}
}

// CreateAll must fail hard on a config error rather than skipping the backend:
// a typo demoting a backend silently is the fake success the audit flagged.
func TestCreateAll_UnknownKeyIsFatal(t *testing.T) {
	factory := NewFactory()
	_, err := factory.CreateAll([]config.BackendConfig{
		{Name: "ok", Type: "direct", Enabled: true},
		{Name: "typo", Type: "direct", Enabled: true, Config: map[string]any{"connect_timeot": "5s"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect_timeot")
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
