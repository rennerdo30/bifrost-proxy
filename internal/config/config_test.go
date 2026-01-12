package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	// Create temp config file
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	content := `
server:
  http:
    listen: ":8080"
backends:
  - name: direct
    type: direct
    enabled: true
routes:
  - domains: ["*"]
    backend: direct
`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	var cfg ServerConfig
	err = Load(configFile, &cfg)
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.Server.HTTP.Listen)
	assert.Len(t, cfg.Backends, 1)
	assert.Equal(t, "direct", cfg.Backends[0].Name)
}

func TestServerConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
	}{
		{
			name: "valid minimal config",
			config: ServerConfig{
				Server: ServerSettings{
					HTTP: ListenerConfig{Listen: ":8080"},
				},
				Backends: []BackendConfig{
					{Name: "direct", Type: "direct", Enabled: true},
				},
				Routes: []RouteConfig{
					{Domains: []string{"*"}, Backend: "direct"},
				},
			},
			wantErr: false,
		},
		{
			name: "no listeners",
			config: ServerConfig{
				Server: ServerSettings{},
				Backends: []BackendConfig{
					{Name: "direct", Type: "direct", Enabled: true},
				},
			},
			wantErr: true,
		},
		{
			name: "no backends",
			config: ServerConfig{
				Server: ServerSettings{
					HTTP: ListenerConfig{Listen: ":8080"},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate backend name",
			config: ServerConfig{
				Server: ServerSettings{
					HTTP: ListenerConfig{Listen: ":8080"},
				},
				Backends: []BackendConfig{
					{Name: "direct", Type: "direct", Enabled: true},
					{Name: "direct", Type: "direct", Enabled: true},
				},
			},
			wantErr: true,
		},
		{
			name: "route references unknown backend",
			config: ServerConfig{
				Server: ServerSettings{
					HTTP: ListenerConfig{Listen: ":8080"},
				},
				Backends: []BackendConfig{
					{Name: "direct", Type: "direct", Enabled: true},
				},
				Routes: []RouteConfig{
					{Domains: []string{"*"}, Backend: "unknown"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClientConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ClientConfig{
				Proxy: ClientProxySettings{
					HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
				},
				Server: ServerConnection{
					Address: "proxy.example.com:8080",
				},
				Routes: []ClientRouteConfig{
					{Domains: []string{"*"}, Action: "server"},
				},
			},
			wantErr: false,
		},
		{
			name: "no proxy listeners",
			config: ClientConfig{
				Server: ServerConnection{
					Address: "proxy.example.com:8080",
				},
			},
			wantErr: true,
		},
		{
			name: "no server address",
			config: ClientConfig{
				Proxy: ClientProxySettings{
					HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid route action",
			config: ClientConfig{
				Proxy: ClientProxySettings{
					HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
				},
				Server: ServerConnection{
					Address: "proxy.example.com:8080",
				},
				Routes: []ClientRouteConfig{
					{Domains: []string{"*"}, Action: "invalid"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnvironmentVariableExpansion(t *testing.T) {
	os.Setenv("TEST_PORT", "9999")
	defer os.Unsetenv("TEST_PORT")

	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	content := `
server:
  http:
    listen: ":${TEST_PORT}"
backends:
  - name: direct
    type: direct
    enabled: true
`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	var cfg ServerConfig
	err = Load(configFile, &cfg)
	require.NoError(t, err)

	assert.Equal(t, ":9999", cfg.Server.HTTP.Listen)
}
