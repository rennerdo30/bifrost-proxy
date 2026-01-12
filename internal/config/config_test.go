package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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
			HTTP: ListenerConfig{Listen: ":8080"},
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
	assert.Equal(t, ":8080", loaded.Server.HTTP.Listen)
}

func TestSave_NestedDirectory(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "nested", "deep", "config.yaml")

	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":8080"},
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
    listen: ":8080"
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
	assert.Equal(t, ":8080", cfg.Server.HTTP.Listen)
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
    listen: ":8080"
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
	content := "server:\n  http:\n    listen: ':8080'\n"
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

	assert.Equal(t, ":8080", cfg.Server.HTTP.Listen)
	assert.Equal(t, ":1080", cfg.Server.SOCKS5.Listen)
	assert.Equal(t, "none", cfg.Auth.Mode)
	assert.False(t, cfg.RateLimit.Enabled)
	assert.True(t, cfg.AccessLog.Enabled)
	assert.Equal(t, "json", cfg.AccessLog.Format)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, ":9090", cfg.Metrics.Listen)
	assert.True(t, cfg.API.Enabled)
}

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()

	assert.Equal(t, "127.0.0.1:3128", cfg.Proxy.HTTP.Listen)
	assert.Equal(t, "127.0.0.1:1081", cfg.Proxy.SOCKS5.Listen)
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
			HTTP: ListenerConfig{Listen: ":8080"},
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
			SOCKS5: ListenerConfig{Listen: ":1080"},
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
			HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
		},
		Server: ServerConnection{
			Address: "proxy.example.com:8080",
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
			HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
		},
		Server: ServerConnection{
			Address: "proxy.example.com:8080",
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
			SOCKS5: ListenerConfig{Listen: "127.0.0.1:1081"},
		},
		Server: ServerConnection{
			Address: "proxy.example.com:8080",
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
		Address:    "proxy.example.com:8080",
		Protocol:   "http",
		Username:   "user",
		Password:   "pass",
		Timeout:    Duration(30 * time.Second),
		RetryCount: 3,
		RetryDelay: Duration(1 * time.Second),
	}

	assert.Equal(t, "proxy.example.com:8080", cfg.Address)
	assert.Equal(t, "http", cfg.Protocol)
	assert.Equal(t, 3, cfg.RetryCount)
}

func TestClientConfigValidation_ServerAddressMissingPort(t *testing.T) {
	cfg := ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
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
			HTTP: ListenerConfig{Listen: "127.0.0.1:3128"},
		},
		Server: ServerConnection{
			Address: "192.168.1.1:8080", // With port - should pass
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}
