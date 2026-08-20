package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestServerConfig_ParsesHealthCheckSchemeBlock covers the health check fields
// that the health checker already supported but that had no YAML representation,
// so HTTPS health checks were unreachable from configuration entirely.
func TestServerConfig_ParsesHealthCheckSchemeBlock(t *testing.T) {
	yamlData := `
server:
  http:
    listen: ":7080"
health_check:
  type: http
  target: backend.internal:8443
  path: /healthz
  scheme: https
  insecure_skip_verify: true
  interval: 15s
  timeout: 3s
  healthy_threshold: 2
  unhealthy_threshold: 3
`
	var cfg ServerConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	hc := cfg.HealthCheck
	assert.Equal(t, HealthCheckTypeHTTP, hc.Type)
	assert.Equal(t, "backend.internal:8443", hc.Target)
	assert.Equal(t, "/healthz", hc.Path)
	assert.Equal(t, HealthCheckSchemeHTTPS, hc.Scheme)
	assert.True(t, hc.InsecureSkipVerify)
	assert.Equal(t, 2, hc.HealthyThreshold)
	assert.Equal(t, 3, hc.UnhealthyThreshold)

	// And it must survive a round-trip back to YAML so the Web UI's save path
	// does not silently drop the values.
	out, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	var round ServerConfig
	require.NoError(t, yaml.Unmarshal(out, &round))
	assert.Equal(t, hc, round.HealthCheck)
}

// TestHealthCheckConfig_SchemeOmittedWhenUnset keeps the emitted YAML clean for
// the common TCP case: the new fields must not appear when unset.
func TestHealthCheckConfig_SchemeOmittedWhenUnset(t *testing.T) {
	hc := HealthCheckConfig{Type: "tcp", Target: "127.0.0.1:80"}
	out, err := yaml.Marshal(&hc)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "scheme")
	assert.NotContains(t, string(out), "insecure_skip_verify")
}

func TestHealthCheckConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     HealthCheckConfig
		wantErr string
	}{
		{
			name: "empty is valid",
			cfg:  HealthCheckConfig{},
		},
		{
			name: "tcp without scheme is valid",
			cfg:  HealthCheckConfig{Type: "tcp", Target: "127.0.0.1:80"},
		},
		{
			name: "http with http scheme is valid",
			cfg:  HealthCheckConfig{Type: HealthCheckTypeHTTP, Scheme: HealthCheckSchemeHTTP},
		},
		{
			name: "https scheme is valid",
			cfg:  HealthCheckConfig{Type: HealthCheckTypeHTTP, Scheme: HealthCheckSchemeHTTPS},
		},
		{
			name: "https with insecure_skip_verify is valid",
			cfg: HealthCheckConfig{
				Type: HealthCheckTypeHTTP, Scheme: HealthCheckSchemeHTTPS, InsecureSkipVerify: true,
			},
		},
		{
			name:    "unknown scheme rejected",
			cfg:     HealthCheckConfig{Type: HealthCheckTypeHTTP, Scheme: "ftp"},
			wantErr: `health_check scheme must be "http" or "https", got "ftp"`,
		},
		{
			name:    "scheme on a tcp check is rejected as inert",
			cfg:     HealthCheckConfig{Type: "tcp", Scheme: HealthCheckSchemeHTTPS},
			wantErr: `health_check scheme is only supported for type "http", got type "tcp"`,
		},
		{
			name:    "insecure_skip_verify on a ping check is rejected as inert",
			cfg:     HealthCheckConfig{Type: "ping", InsecureSkipVerify: true},
			wantErr: `health_check insecure_skip_verify is only supported for type "http", got type "ping"`,
		},
		{
			name:    "insecure_skip_verify without https is rejected",
			cfg:     HealthCheckConfig{Type: HealthCheckTypeHTTP, InsecureSkipVerify: true},
			wantErr: `health_check insecure_skip_verify requires scheme "https"`,
		},
		{
			// <= 0 is documented to mean "1", so a negative value must keep
			// loading rather than becoming a startup failure on upgrade.
			name: "non-positive thresholds are accepted as 'immediate'",
			cfg:  HealthCheckConfig{Type: "tcp", HealthyThreshold: -1, UnhealthyThreshold: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestServerConfig_ValidateHealthCheck asserts the health check block is
// validated through the normal ServerConfig.Validate path (which the Web UI save
// and the startup loader both use), for both the global and per-backend blocks.
func TestServerConfig_ValidateHealthCheck(t *testing.T) {
	base := func() ServerConfig {
		return ServerConfig{
			Server:   ServerSettings{HTTP: ListenerConfig{Listen: ":7080"}},
			Backends: []BackendConfig{{Name: "default", Type: "direct", Enabled: true}},
		}
	}

	t.Run("valid global https health check", func(t *testing.T) {
		cfg := base()
		cfg.HealthCheck = HealthCheckConfig{
			Type: HealthCheckTypeHTTP, Target: "a:8443",
			Scheme: HealthCheckSchemeHTTPS, InsecureSkipVerify: true,
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("invalid global scheme is rejected", func(t *testing.T) {
		cfg := base()
		cfg.HealthCheck = HealthCheckConfig{Type: HealthCheckTypeHTTP, Scheme: "gopher"}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "health_check scheme must be")
	})

	t.Run("invalid per-backend scheme is rejected and names the backend", func(t *testing.T) {
		cfg := base()
		cfg.Backends[0].HealthCheck = &HealthCheckConfig{
			Type: HealthCheckTypeHTTP, Scheme: "gopher",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "backend default")
		assert.Contains(t, err.Error(), "health_check scheme must be")
	})
}
