package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validClientBase() ClientConfig {
	return ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Server: ServerConnection{Address: "proxy.example.com:7080"},
	}
}

// server.tls on the client was parsed and never read: enabling it yielded a
// PLAINTEXT upstream connection while the config promised encryption. It is
// refused until implemented.
func TestClientConfig_UpstreamTLSIsRefused(t *testing.T) {
	cfg := validClientBase()
	cfg.Server.TLS = &TLSConfig{Enabled: true}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext")

	// Present but disabled stays fine.
	cfg.Server.TLS = &TLSConfig{Enabled: false}
	assert.NoError(t, cfg.Validate())
}

// Client listener tls/max_connections were silently ignored (the struct is
// shared with the server, which honors both). Refused now.
func TestClientConfig_ListenerTLSAndMaxConnectionsRefused(t *testing.T) {
	cfg := validClientBase()
	cfg.Proxy.HTTP.TLS = &TLSConfig{Enabled: true}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.http.tls")

	cfg = validClientBase()
	cfg.Proxy.SOCKS5.Listen = "127.0.0.1:7381"
	cfg.Proxy.SOCKS5.MaxConnections = 10
	err = cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_connections")
}

// An unknown health check type used to silently become a bare TCP connect that
// reported green for a dead application layer.
func TestHealthCheckConfig_UnknownTypeRejected(t *testing.T) {
	for _, bad := range []string{"htpp", "grpc", "icmp"} {
		cfg := HealthCheckConfig{Type: bad}
		err := cfg.Validate()
		require.Error(t, err, "type %q must be rejected", bad)
		assert.Contains(t, err.Error(), bad)
	}
	for _, good := range []string{"", "tcp", "http", "ping"} {
		assert.NoError(t, (&HealthCheckConfig{Type: good}).Validate(), "type %q", good)
	}
}

// A route pattern the runtime matcher would drop — a duplicate within one
// route, or anything past its MaxPatterns limit — used to disappear without a
// word, sending those domains to the default backend. Rejected at validation
// now.
func TestServerConfig_InvalidRoutePatternRejected(t *testing.T) {
	cfg := ServerConfig{
		Server:   ServerSettings{HTTP: ListenerConfig{Listen: ":7080"}},
		Backends: []BackendConfig{{Name: "direct", Type: "direct", Enabled: true}},
		Routes: []RouteConfig{
			// The same pattern twice on ONE route: the runtime matcher keeps
			// only the first and used to drop the second silently.
			{Domains: []string{"a.example.com", "a.example.com"}, Backend: "direct"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unusable")

	// The same pattern on two different routes stays legal (priority
	// disambiguates at runtime, one matcher per route).
	cfg.Routes = []RouteConfig{
		{Domains: []string{"*.example.com"}, Backend: "direct", Priority: 10},
		{Domains: []string{"*.example.com"}, Backend: "direct", Priority: 1},
	}
	assert.NoError(t, cfg.Validate())
}
