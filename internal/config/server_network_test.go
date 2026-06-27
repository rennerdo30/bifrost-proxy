package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNetworkConfig_AddressFamily(t *testing.T) {
	yes, no := true, false
	// Default (unset) must be dual-stack so IPv6/dual-stack hosts keep working.
	assert.Equal(t, "tcp", NetworkConfig{}.AddressFamily())
	assert.Equal(t, "tcp", NetworkConfig{IPv6: &yes}.AddressFamily())
	// Only an explicit ipv6:false restricts to IPv4.
	assert.Equal(t, "tcp4", NetworkConfig{IPv6: &no}.AddressFamily())
}

func TestServerConfig_ParsesNetworkBlock(t *testing.T) {
	yamlData := `
server:
  http:
    listen: ":7080"
network:
  ipv6: true
  prefer_ipv6: true
  keepalive: 45s
  dial_timeout: 10s
  max_connections: 500
`
	var cfg ServerConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	require.NotNil(t, cfg.Network.IPv6)
	assert.True(t, *cfg.Network.IPv6)
	assert.True(t, cfg.Network.PreferIPv6)
	assert.Equal(t, "45s", cfg.Network.KeepAlive.Duration().String())
	assert.Equal(t, "10s", cfg.Network.DialTimeout.Duration().String())
	assert.Equal(t, 500, cfg.Network.MaxConnections)
}

func TestServerConfig_ParsesTLSClientAuth(t *testing.T) {
	yamlData := `
server:
  http:
    listen: ":7080"
    tls:
      enabled: true
      cert_file: /tmp/cert.pem
      key_file: /tmp/key.pem
      client_auth: require
      client_ca_file: /tmp/ca.pem
`
	var cfg ServerConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	require.NotNil(t, cfg.Server.HTTP.TLS)
	assert.True(t, cfg.Server.HTTP.TLS.Enabled)
	assert.Equal(t, "require", cfg.Server.HTTP.TLS.ClientAuth)
	assert.Equal(t, "/tmp/ca.pem", cfg.Server.HTTP.TLS.ClientCAFile)
}

func TestServerConfig_ParsesRouteWeights(t *testing.T) {
	yamlData := `
routes:
  - domains: ["*"]
    backends: ["a", "b"]
    load_balance: weighted
    weights:
      a: 5
      b: 2
`
	var cfg ServerConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	require.Len(t, cfg.Routes, 1)
	assert.Equal(t, 5, cfg.Routes[0].Weights["a"])
	assert.Equal(t, 2, cfg.Routes[0].Weights["b"])
}

func TestServerConfig_ParsesHealthThresholds(t *testing.T) {
	yamlData := `
health_check:
  type: tcp
  target: example.com:443
  interval: 10s
  healthy_threshold: 3
  unhealthy_threshold: 2
`
	var cfg ServerConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	assert.Equal(t, 3, cfg.HealthCheck.HealthyThreshold)
	assert.Equal(t, 2, cfg.HealthCheck.UnhealthyThreshold)
}

func TestServerConfig_ParsesNegotiate(t *testing.T) {
	yamlData := `
auth:
  negotiate:
    enabled: true
    kerberos_provider: krb
    ntlm_provider: ntlm
    allow_ntlm: true
    prefer_kerberos: true
    realm: EXAMPLE.COM
`
	var cfg ServerConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	require.NotNil(t, cfg.Auth.Negotiate)
	assert.True(t, cfg.Auth.Negotiate.Enabled)
	assert.Equal(t, "krb", cfg.Auth.Negotiate.KerberosProvider)
	assert.Equal(t, "ntlm", cfg.Auth.Negotiate.NTLMProvider)
	assert.True(t, cfg.Auth.Negotiate.AllowNTLM)
	assert.Equal(t, "EXAMPLE.COM", cfg.Auth.Negotiate.Realm)
}
