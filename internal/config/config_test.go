package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

func TestLoad(t *testing.T) {
	// Create temp config file
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	content := `
server:
  http:
    listen: ":7080"
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

	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen)
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
					HTTP: ListenerConfig{Listen: ":7080"},
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
					HTTP: ListenerConfig{Listen: ":7080"},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate backend name",
			config: ServerConfig{
				Server: ServerSettings{
					HTTP: ListenerConfig{Listen: ":7080"},
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
					HTTP: ListenerConfig{Listen: ":7080"},
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
					HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
				},
				Server: ServerConnection{
					Address: "proxy.example.com:7080",
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
					Address: "proxy.example.com:7080",
				},
			},
			wantErr: true,
		},
		{
			name: "no server address (direct-only mode)",
			config: ClientConfig{
				Proxy: ClientProxySettings{
					HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
				},
			},
			wantErr: false, // Server address is optional - client can work in direct-only mode
		},
		{
			name: "invalid server address format",
			config: ClientConfig{
				Proxy: ClientProxySettings{
					HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
				},
				Server: ServerConnection{
					Address: "invalid-no-port",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid route action",
			config: ClientConfig{
				Proxy: ClientProxySettings{
					HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
				},
				Server: ServerConnection{
					Address: "proxy.example.com:7080",
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

func TestLoad_FileNotFound(t *testing.T) {
	var cfg ServerConfig
	err := Load("/nonexistent/path/config.yaml", &cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "invalid.yaml")

	// Invalid YAML content
	content := `
server:
  http:
    listen: [invalid yaml
`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	var cfg ServerConfig
	err = Load(configFile, &cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "saved.yaml")

	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "direct", Type: "direct", Enabled: true},
		},
	}

	err := Save(configFile, &cfg)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(configFile)
	require.NoError(t, err)

	// Load it back and verify
	var loaded ServerConfig
	err = Load(configFile, &loaded)
	require.NoError(t, err)
	assert.Equal(t, ":7080", loaded.Server.HTTP.Listen)
}

func TestSave_NestedDirectory(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "nested", "deep", "config.yaml")

	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
	}

	err := Save(configFile, &cfg)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(configFile)
	require.NoError(t, err)
}

func TestSave_InvalidPath(t *testing.T) {
	// Try to save to a path where we can't create directories
	err := Save("/dev/null/impossible/config.yaml", &ServerConfig{})
	assert.Error(t, err)
}

func TestValidateConfig_WithValidator(t *testing.T) {
	cfg := &ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "direct", Type: "direct", Enabled: true},
		},
	}

	err := ValidateConfig(cfg)
	assert.NoError(t, err)
}

func TestValidateConfig_InvalidConfig(t *testing.T) {
	cfg := &ServerConfig{} // Empty config - no listeners

	err := ValidateConfig(cfg)
	assert.Error(t, err)
}

func TestValidateConfig_NonValidator(t *testing.T) {
	// Test with a type that doesn't implement Validator
	type SimpleStruct struct {
		Name string
	}

	cfg := &SimpleStruct{Name: "test"}
	err := ValidateConfig(cfg)
	assert.NoError(t, err) // Should return nil for non-validators
}

func TestLoadAndValidate_Valid(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "valid.yaml")

	content := `
server:
  http:
    listen: ":7080"
backends:
  - name: direct
    type: direct
    enabled: true
`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	var cfg ServerConfig
	err = LoadAndValidate(configFile, &cfg)
	require.NoError(t, err)
	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen)
}

func TestLoadAndValidate_LoadError(t *testing.T) {
	var cfg ServerConfig
	err := LoadAndValidate("/nonexistent/config.yaml", &cfg)
	assert.Error(t, err)
}

func TestLoadAndValidate_ValidationError(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "invalid.yaml")

	// Valid YAML but invalid config (no backends)
	content := `
server:
  http:
    listen: ":7080"
`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	var cfg ServerConfig
	err = LoadAndValidate(configFile, &cfg)
	assert.Error(t, err)
}

func TestBackup(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	// Create original file
	content := "server:\n  http:\n    listen: ':7080'\n"
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	// Create backup
	backupPath, err := Backup(configFile)
	require.NoError(t, err)
	assert.Contains(t, backupPath, "config.yaml.backup.")

	// Verify backup was created
	_, err = os.Stat(backupPath)
	require.NoError(t, err)

	// Verify backup content matches
	backupContent, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	assert.Equal(t, content, string(backupContent))
}

func TestBackup_FileNotFound(t *testing.T) {
	_, err := Backup("/nonexistent/config.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config")
}

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen)
	assert.Equal(t, ":7180", cfg.Server.SOCKS5.Listen)
	assert.Empty(t, cfg.Auth.Mode)
	assert.False(t, cfg.RateLimit.Enabled)
	assert.True(t, cfg.AccessLog.Enabled)
	assert.Equal(t, "json", cfg.AccessLog.Format)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, ":7090", cfg.Metrics.Listen)
	assert.True(t, cfg.API.Enabled)
}

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()

	assert.Equal(t, "127.0.0.1:7380", cfg.Proxy.HTTP.Listen)
	assert.Equal(t, "127.0.0.1:7381", cfg.Proxy.SOCKS5.Listen)
	assert.Equal(t, "http", cfg.Server.Protocol)
	assert.Equal(t, 3, cfg.Server.RetryCount)
	assert.True(t, cfg.Debug.Enabled)
	assert.Equal(t, 1000, cfg.Debug.MaxEntries)
	assert.True(t, cfg.WebUI.Enabled)
	assert.True(t, cfg.API.Enabled)
	assert.True(t, cfg.Tray.Enabled)
}

// Duration type tests

func TestDuration_UnmarshalYAML(t *testing.T) {
	content := `timeout: 30s`

	type TestStruct struct {
		Timeout Duration `yaml:"timeout"`
	}

	var cfg TestStruct
	err := os.WriteFile(filepath.Join(t.TempDir(), "test.yaml"), []byte(content), 0644)
	require.NoError(t, err)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "duration.yaml")
	err = os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	err = Load(configFile, &cfg)
	require.NoError(t, err)
	assert.Equal(t, Duration(30*time.Second), cfg.Timeout)
}

func TestDuration_Duration(t *testing.T) {
	d := Duration(5 * time.Minute)
	assert.Equal(t, 5*time.Minute, d.Duration())
}

func TestDuration_MarshalJSON(t *testing.T) {
	d := Duration(1 * time.Hour)
	data, err := d.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `"1h0m0s"`, string(data))
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Duration
		wantErr bool
	}{
		{"valid duration", `"5m"`, Duration(5 * time.Minute), false},
		{"empty string", `""`, Duration(0), false},
		{"invalid duration", `"invalid"`, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, d)
			}
		})
	}
}

func TestDuration_MarshalYAML(t *testing.T) {
	d := Duration(2 * time.Hour)
	result, err := d.MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, "2h0m0s", result)
}

// Additional validation tests

func TestServerConfigValidation_BackendWithoutName(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Type: "direct", Enabled: true}, // Missing name
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend name is required")
}

func TestServerConfigValidation_BackendWithoutType(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "test", Enabled: true}, // Missing type
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend type is required")
}

func TestServerConfigValidation_RouteWithoutDomains(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "direct", Type: "direct", Enabled: true},
		},
		Routes: []RouteConfig{
			{Backend: "direct"}, // Missing domains
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route must have at least one domain")
}

func TestServerConfigValidation_RouteWithoutBackend(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "direct", Type: "direct", Enabled: true},
		},
		Routes: []RouteConfig{
			{Domains: []string{"*"}}, // Missing backend
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route must specify a backend")
}

func TestServerConfigValidation_RouteWithMultipleBackends(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "backend1", Type: "direct", Enabled: true},
			{Name: "backend2", Type: "direct", Enabled: true},
		},
		Routes: []RouteConfig{
			{Domains: []string{"*"}, Backends: []string{"backend1", "backend2"}},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestServerConfigValidation_RouteWithUnknownMultipleBackend(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
		Backends: []BackendConfig{
			{Name: "backend1", Type: "direct", Enabled: true},
		},
		Routes: []RouteConfig{
			{Domains: []string{"*"}, Backends: []string{"backend1", "unknown"}},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown backend")
}

func TestServerConfigValidation_SOCKS5OnlyListener(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			SOCKS5: ListenerConfig{Listen: ":7180"},
		},
		Backends: []BackendConfig{
			{Name: "direct", Type: "direct", Enabled: true},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestClientConfigValidation_NegativeMaxEntries(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Server: ServerConnection{
			Address: "proxy.example.com:7080",
		},
		Debug: DebugConfig{
			MaxEntries: -1,
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max_entries must be non-negative")
}

func TestClientConfigValidation_RouteWithoutAction(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Server: ServerConnection{
			Address: "proxy.example.com:7080",
		},
		Routes: []ClientRouteConfig{
			{Domains: []string{"*"}}, // Missing action
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route action is required")
}

func TestClientConfigValidation_SOCKS5OnlyProxy(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			SOCKS5: ListenerConfig{Listen: "127.0.0.1:7381"},
		},
		Server: ServerConnection{
			Address: "proxy.example.com:7080",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

// Struct tests for coverage

func TestBackendConfig_Fields(t *testing.T) {
	cfg := BackendConfig{
		Name:     "test-backend",
		Type:     "wireguard",
		Enabled:  true,
		Priority: 10,
		Weight:   100,
		Config: map[string]any{
			"interface": "wg0",
		},
		HealthCheck: &HealthCheckConfig{
			Type:     "tcp",
			Interval: Duration(30 * time.Second),
		},
	}

	assert.Equal(t, "test-backend", cfg.Name)
	assert.Equal(t, "wireguard", cfg.Type)
	assert.Equal(t, 10, cfg.Priority)
	assert.Equal(t, 100, cfg.Weight)
	assert.NotNil(t, cfg.HealthCheck)
}

func TestRouteConfig_Fields(t *testing.T) {
	cfg := RouteConfig{
		Name:        "default-route",
		Domains:     []string{"*.example.com", "api.test.com"},
		Backend:     "main",
		Priority:    100,
		Backends:    []string{"backend1", "backend2"},
		LoadBalance: "round_robin",
	}

	assert.Equal(t, "default-route", cfg.Name)
	assert.Len(t, cfg.Domains, 2)
	assert.Equal(t, "round_robin", cfg.LoadBalance)
}

func TestAuthConfig_Fields(t *testing.T) {
	cfg := AuthConfig{
		Mode: "native",
		Native: &NativeAuth{
			Users: []NativeUser{{Username: "admin", PasswordHash: "$2a$10$..."}},
		},
		Providers: []AuthProvider{
			{Name: "primary", Type: "native", Enabled: true, Priority: 10},
		},
	}

	assert.Equal(t, "native", cfg.Mode)
	assert.Len(t, cfg.Native.Users, 1)
	assert.Len(t, cfg.Providers, 1)
}

func TestRateLimitConfig_Fields(t *testing.T) {
	cfg := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100.0,
		BurstSize:         10,
		PerIP:             true,
		PerUser:           false,
		Bandwidth: &BandwidthConfig{
			Enabled:  true,
			Upload:   "10Mbps",
			Download: "100Mbps",
		},
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 100.0, cfg.RequestsPerSecond)
	assert.NotNil(t, cfg.Bandwidth)
	assert.Equal(t, "100Mbps", cfg.Bandwidth.Download)
}

func TestTLSConfig_Fields(t *testing.T) {
	cfg := TLSConfig{
		Enabled:  true,
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "/path/to/cert.pem", cfg.CertFile)
}

func TestHealthCheckConfig_Fields(t *testing.T) {
	cfg := HealthCheckConfig{
		Type:     "http",
		Interval: Duration(30 * time.Second),
		Timeout:  Duration(5 * time.Second),
		Target:   "https://example.com",
		Path:     "/health",
	}

	assert.Equal(t, "http", cfg.Type)
	assert.Equal(t, "/health", cfg.Path)
}

func TestServerConnection_Fields(t *testing.T) {
	cfg := ServerConnection{
		Address:    "proxy.example.com:7080",
		Protocol:   "http",
		Username:   "user",
		Password:   "pass",
		Timeout:    Duration(30 * time.Second),
		RetryCount: 3,
		RetryDelay: Duration(1 * time.Second),
	}

	assert.Equal(t, "proxy.example.com:7080", cfg.Address)
	assert.Equal(t, "http", cfg.Protocol)
	assert.Equal(t, 3, cfg.RetryCount)
}

func TestClientConfigValidation_ServerAddressMissingPort(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Server: ServerConnection{
			Address: "192.168.1.1", // Missing port
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "host:port format")
}

func TestClientConfigValidation_ServerAddressWithPort(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Server: ServerConnection{
			Address: "192.168.1.1:7080", // With port - should pass
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestClientConfigValidation_RouteWithEmptyDomains(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Routes: []ClientRouteConfig{
			{Domains: []string{}, Action: "server"}, // Empty domains
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route must have at least one domain pattern")
}

func TestClientConfigValidation_DirectAction(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Routes: []ClientRouteConfig{
			{Domains: []string{"*.local"}, Action: "direct"},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestClientConfigValidation_VPNEnabled_Valid(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		VPN: vpn.Config{
			Enabled: true,
			TUN: vpn.TUNConfig{
				Name:    "test0",
				Address: "10.255.0.1/24",
				MTU:     1400,
			},
			SplitTunnel: vpn.SplitTunnelConfig{
				Mode: "exclude",
			},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestClientConfigValidation_VPNEnabled_Invalid(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		VPN: vpn.Config{
			Enabled: true,
			TUN: vpn.TUNConfig{
				Name:    "test0",
				Address: "invalid-address", // Invalid address format
				MTU:     1400,
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid VPN config")
}

func TestClientConfigValidation_MeshEnabled_Valid(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Mesh: mesh.Config{
			Enabled:     true,
			NetworkID:   "test-network",
			NetworkCIDR: "10.100.0.0/16",
			Device: mesh.DeviceConfig{
				Type: "tap",
				Name: "mesh0",
				MTU:  1400,
			},
			Discovery: mesh.DiscoveryConfig{
				Server: "discovery.example.com:7080",
			},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestClientConfigValidation_MeshEnabled_Invalid(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Mesh: mesh.Config{
			Enabled:     true,
			NetworkID:   "", // Missing required network_id
			NetworkCIDR: "10.100.0.0/16",
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mesh config")
}

func TestDuration_UnmarshalYAML_Invalid(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "duration_invalid.yaml")

	// Invalid duration string
	content := `timeout: invalid-duration`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	type TestStruct struct {
		Timeout Duration `yaml:"timeout"`
	}

	var cfg TestStruct
	err = Load(configFile, &cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestDuration_UnmarshalYAML_DecodeError(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "duration_decode_error.yaml")

	// YAML value that can't be decoded to string (complex object)
	content := `timeout:
  nested: value
  another: key`
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	type TestStruct struct {
		Timeout Duration `yaml:"timeout"`
	}

	var cfg TestStruct
	err = Load(configFile, &cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestDuration_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var d Duration
	// Invalid JSON - not a string
	err := d.UnmarshalJSON([]byte(`123`))
	assert.Error(t, err)
}

// Test Backup when write fails (use a directory path as the backup destination)
func TestBackup_WriteError(t *testing.T) {
	// On Unix, we can try to write to a read-only directory
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	subDir := filepath.Join(dir, "readonly")

	// Create the config file first
	content := "test: value\n"
	err := os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	// Create a read-only directory to force write failure
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	// Create a file with the backup name pattern inside readonly dir
	// to trigger write failure when backup tries to create the file
	readonlyConfig := filepath.Join(subDir, "config.yaml")
	err = os.WriteFile(readonlyConfig, []byte(content), 0644)
	require.NoError(t, err)

	// Make the directory read-only
	err = os.Chmod(subDir, 0555)
	require.NoError(t, err)
	defer os.Chmod(subDir, 0755) // Restore permissions for cleanup

	// Attempt to backup - this should fail on write
	_, err = Backup(readonlyConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write backup")
}

// Test Save to a path with no write permission
func TestSave_WriteError(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "readonly")

	err := os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	// Make the directory read-only
	err = os.Chmod(subDir, 0555)
	require.NoError(t, err)
	defer os.Chmod(subDir, 0755) // Restore permissions for cleanup

	configFile := filepath.Join(subDir, "config.yaml")
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":7080"},
		},
	}

	err = Save(configFile, &cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write config file")
}

// Additional auth config tests
func TestAuthConfig_LDAPFields(t *testing.T) {
	cfg := AuthConfig{
		Mode: "ldap",
		LDAP: &LDAPAuth{
			URL:                "ldap://ldap.example.com:389",
			BaseDN:             "dc=example,dc=com",
			BindDN:             "cn=admin,dc=example,dc=com",
			BindPassword:       "secret",
			UserFilter:         "(uid={{.Username}})",
			GroupFilter:        "(member={{.DN}})",
			RequireGroup:       "cn=vpnusers,ou=groups,dc=example,dc=com",
			TLS:                true,
			InsecureSkipVerify: false,
		},
	}

	assert.Equal(t, "ldap", cfg.Mode)
	assert.NotNil(t, cfg.LDAP)
	assert.Equal(t, "ldap://ldap.example.com:389", cfg.LDAP.URL)
	assert.True(t, cfg.LDAP.TLS)
}

func TestAuthConfig_OAuthFields(t *testing.T) {
	cfg := AuthConfig{
		Mode: "oauth",
		OAuth: &OAuthAuth{
			Provider:     "google",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			IssuerURL:    "https://accounts.google.com",
			RedirectURL:  "https://app.example.com/oauth/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	}

	assert.Equal(t, "oauth", cfg.Mode)
	assert.NotNil(t, cfg.OAuth)
	assert.Equal(t, "google", cfg.OAuth.Provider)
	assert.Len(t, cfg.OAuth.Scopes, 3)
}

func TestAuthConfig_SystemFields(t *testing.T) {
	cfg := AuthConfig{
		Mode: "system",
		System: &SystemAuth{
			Service:       "bifrost",
			AllowedUsers:  []string{"admin", "user1"},
			AllowedGroups: []string{"vpnusers", "admins"},
		},
	}

	assert.Equal(t, "system", cfg.Mode)
	assert.NotNil(t, cfg.System)
	assert.Equal(t, "bifrost", cfg.System.Service)
	assert.Len(t, cfg.System.AllowedUsers, 2)
	assert.Len(t, cfg.System.AllowedGroups, 2)
}

func TestAuthProvider_Fields(t *testing.T) {
	provider := AuthProvider{
		Name:     "primary-ldap",
		Type:     "ldap",
		Enabled:  true,
		Priority: 10,
		Config: map[string]any{
			"url":     "ldap://ldap.example.com:389",
			"base_dn": "dc=example,dc=com",
		},
	}

	assert.Equal(t, "primary-ldap", provider.Name)
	assert.Equal(t, "ldap", provider.Type)
	assert.True(t, provider.Enabled)
	assert.Equal(t, 10, provider.Priority)
	assert.NotNil(t, provider.Config)
}

func TestListenerConfig_Fields(t *testing.T) {
	cfg := ListenerConfig{
		Listen:         ":8443",
		ReadTimeout:    Duration(60 * time.Second),
		WriteTimeout:   Duration(60 * time.Second),
		IdleTimeout:    Duration(120 * time.Second),
		MaxConnections: 1000,
		TLS: &TLSConfig{
			Enabled:  true,
			CertFile: "/etc/ssl/cert.pem",
			KeyFile:  "/etc/ssl/key.pem",
		},
	}

	assert.Equal(t, ":8443", cfg.Listen)
	assert.Equal(t, Duration(60*time.Second), cfg.ReadTimeout)
	assert.Equal(t, 1000, cfg.MaxConnections)
	assert.NotNil(t, cfg.TLS)
	assert.True(t, cfg.TLS.Enabled)
}

func TestAccessLogConfig_Fields(t *testing.T) {
	cfg := AccessLogConfig{
		Enabled: true,
		Format:  "apache",
		Output:  "/var/log/bifrost/access.log",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "apache", cfg.Format)
	assert.Equal(t, "/var/log/bifrost/access.log", cfg.Output)
}

func TestMetricsConfig_Fields(t *testing.T) {
	cfg := MetricsConfig{
		Enabled:            true,
		Listen:             ":7090",
		Path:               "/metrics",
		CollectionInterval: Duration(60 * time.Second),
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, ":7090", cfg.Listen)
	assert.Equal(t, "/metrics", cfg.Path)
	assert.Equal(t, Duration(60*time.Second), cfg.CollectionInterval)
}

func TestWebUIConfig_Fields(t *testing.T) {
	cfg := WebUIConfig{
		Enabled:  true,
		Listen:   ":7081",
		BasePath: "/admin",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, ":7081", cfg.Listen)
	assert.Equal(t, "/admin", cfg.BasePath)
}

func TestAPIConfig_Fields(t *testing.T) {
	cfg := APIConfig{
		Enabled:             true,
		Listen:              ":7082",
		Token:               "secret-token",
		EnableRequestLog:    true,
		RequestLogSize:      5000,
		WebSocketMaxClients: 50,
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, ":7082", cfg.Listen)
	assert.Equal(t, "secret-token", cfg.Token)
	assert.True(t, cfg.EnableRequestLog)
	assert.Equal(t, 5000, cfg.RequestLogSize)
	assert.Equal(t, 50, cfg.WebSocketMaxClients)
}

func TestAutoUpdateConfig_Fields(t *testing.T) {
	cfg := AutoUpdateConfig{
		Enabled:       true,
		CheckInterval: Duration(12 * time.Hour),
		Channel:       "prerelease",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, Duration(12*time.Hour), cfg.CheckInterval)
	assert.Equal(t, "prerelease", cfg.Channel)
}

func TestDebugConfig_Fields(t *testing.T) {
	cfg := DebugConfig{
		Enabled:       true,
		MaxEntries:    500,
		CaptureBody:   true,
		MaxBodySize:   128 * 1024,
		FilterDomains: []string{"*.example.com", "api.test.com"},
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 500, cfg.MaxEntries)
	assert.True(t, cfg.CaptureBody)
	assert.Equal(t, 128*1024, cfg.MaxBodySize)
	assert.Len(t, cfg.FilterDomains, 2)
}

func TestTrayConfig_Fields(t *testing.T) {
	cfg := TrayConfig{
		Enabled:           true,
		StartMinimized:    true,
		ShowQuickGUI:      false,
		AutoConnect:       true,
		ShowNotifications: false,
		WindowX:           100,
		WindowY:           200,
	}

	assert.True(t, cfg.Enabled)
	assert.True(t, cfg.StartMinimized)
	assert.False(t, cfg.ShowQuickGUI)
	assert.True(t, cfg.AutoConnect)
	assert.False(t, cfg.ShowNotifications)
	assert.Equal(t, 100, cfg.WindowX)
	assert.Equal(t, 200, cfg.WindowY)
}

func TestClientRouteConfig_Fields(t *testing.T) {
	cfg := ClientRouteConfig{
		Name:     "internal-route",
		Domains:  []string{"*.internal.example.com"},
		Action:   "direct",
		Priority: 50,
	}

	assert.Equal(t, "internal-route", cfg.Name)
	assert.Len(t, cfg.Domains, 1)
	assert.Equal(t, "direct", cfg.Action)
	assert.Equal(t, 50, cfg.Priority)
}

func TestNativeUser_Fields(t *testing.T) {
	user := NativeUser{
		Username:     "testuser",
		PasswordHash: "$2a$12$...",
	}

	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "$2a$12$...", user.PasswordHash)
}

func TestBandwidthConfig_Fields(t *testing.T) {
	cfg := BandwidthConfig{
		Enabled:  true,
		Upload:   "50Mbps",
		Download: "200Mbps",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "50Mbps", cfg.Upload)
	assert.Equal(t, "200Mbps", cfg.Download)
}

// NamedServer and multi-server tests

func TestNamedServer_Fields(t *testing.T) {
	server := NamedServer{
		Name:      "Primary Server",
		Address:   "proxy.example.com:8080",
		Protocol:  "http",
		Username:  "user",
		Password:  "pass",
		IsDefault: true,
	}

	assert.Equal(t, "Primary Server", server.Name)
	assert.Equal(t, "proxy.example.com:8080", server.Address)
	assert.Equal(t, "http", server.Protocol)
	assert.Equal(t, "user", server.Username)
	assert.Equal(t, "pass", server.Password)
	assert.True(t, server.IsDefault)
}

func TestClientConfigValidation_ValidServers(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:      "Primary",
				Address:   "us.example.com:8080",
				Protocol:  "http",
				IsDefault: true,
			},
			{
				Name:     "Europe",
				Address:  "eu.example.com:8080",
				Protocol: "socks5",
			},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestClientConfigValidation_ServerMissingName(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:    "", // Missing name
				Address: "us.example.com:8080",
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server name is required")
}

func TestClientConfigValidation_ServerMissingAddress(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:    "Primary",
				Address: "", // Missing address
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address is required")
}

func TestClientConfigValidation_ServerInvalidAddressFormat(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:    "Primary",
				Address: "invalid-no-port", // Invalid format
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "host:port format")
}

func TestClientConfigValidation_ServerDuplicateName(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:    "Primary",
				Address: "us.example.com:8080",
			},
			{
				Name:    "Primary", // Duplicate name
				Address: "eu.example.com:8080",
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate server name")
}

func TestClientConfigValidation_ServerInvalidProtocol(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:     "Primary",
				Address:  "us.example.com:8080",
				Protocol: "invalid", // Invalid protocol
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protocol must be 'http' or 'socks5'")
}

func TestClientConfigValidation_ServerEmptyProtocolValid(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:7380"},
		},
		Servers: []NamedServer{
			{
				Name:     "Primary",
				Address:  "us.example.com:8080",
				Protocol: "", // Empty is valid (defaults to http)
			},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}
