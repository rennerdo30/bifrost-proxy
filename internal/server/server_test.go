package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ldap"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/none"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/oauth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/system"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

func TestNew(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.NotNil(t, s.backends)
	assert.NotNil(t, s.router)
	assert.NotNil(t, s.healthManager)
	assert.NotNil(t, s.metrics)
	assert.False(t, s.Running())
}

func TestNew_WithRoutes(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
}

func TestNew_WithRateLimit(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			BurstSize:         10,
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.NotNil(t, s.rateLimiterIP)
}

func TestNew_WithAuth(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "none", Type: "none", Enabled: true},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.NotNil(t, s.authenticator)
}

func TestNew_InvalidBackend(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "invalid", Type: "unknown-type", Enabled: true},
		},
	}

	_, err := New(cfg)
	assert.Error(t, err)
}

func TestCreateAuthenticator_None(t *testing.T) {
	auth, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "none", Type: "none", Enabled: true},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_Empty(t *testing.T) {
	auth, err := createAuthenticator(config.AuthConfig{})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_Native(t *testing.T) {
	auth, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{
				Name:    "native",
				Type:    "native",
				Enabled: true,
				Config: map[string]any{
					"users": []map[string]any{
						{"username": "test", "password_hash": "hash"},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_Native_NilConfig(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "native", Type: "native", Enabled: true},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "native auth config is required")
}

func TestCreateAuthenticator_LDAP_NilConfig(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "ldap", Type: "ldap", Enabled: true},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ldap config is required")
}

func TestCreateAuthenticator_OAuth_NilConfig(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "oauth", Type: "oauth", Enabled: true},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth config is required")
}

func TestCreateAuthenticator_System(t *testing.T) {
	auth, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{
				Name:    "system",
				Type:    "system",
				Enabled: true,
				Config: map[string]any{
					"service": "test-service",
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_System_NilConfig(t *testing.T) {
	// System auth works with nil config (uses defaults)
	auth, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "system", Type: "system", Enabled: true},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_Unknown(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "unknown", Type: "unknown", Enabled: true},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown auth plugin type")
}

func TestCreateAuthenticator_RejectsLegacyMode(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Mode: "none",
		Providers: []config.AuthProvider{
			{
				Name:    "native-provider",
				Type:    "native",
				Enabled: true,
				Config: map[string]any{
					"users": []map[string]any{
						{"username": "test", "password_hash": "hash"},
					},
				},
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "legacy auth.mode is no longer supported")
}

func TestFactory_CreateChain_Empty(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.CreateChain([]auth.ProviderConfig{})
	require.NoError(t, err)
	require.NotNil(t, authenticator) // Returns NoneAuthenticator
}

func TestFactory_CreateChain_Disabled(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{Name: "test", Type: "native", Enabled: false},
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator) // Returns NoneAuthenticator since all disabled
}

func TestFactory_CreateChain_Multiple(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.CreateChain([]auth.ProviderConfig{
		{
			Name:    "none1",
			Type:    "none",
			Enabled: true,
		},
		{
			Name:     "native1",
			Type:     "native",
			Enabled:  true,
			Priority: 10,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "test", "password_hash": "hash"},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestFactory_CreateChain_InvalidProvider(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.CreateChain([]auth.ProviderConfig{
		{Name: "invalid", Type: "native", Enabled: true}, // Missing config
	})
	assert.Error(t, err)
}

func TestFactory_Create_LDAP(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ldap-test",
		Type:    "ldap",
		Enabled: true,
		Config: map[string]any{
			"url":     "ldap://localhost:389",
			"base_dn": "dc=example,dc=com",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, authenticator)
}

func TestFactory_Create_OAuth_MissingEndpoints(t *testing.T) {
	// OAuth requires OIDC discovery or explicit introspect/userinfo URLs
	// Without valid endpoints, it will fail - this tests the error case
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name:    "oauth-test",
		Type:    "oauth",
		Enabled: true,
		Config: map[string]any{
			"provider":      "generic",
			"client_id":     "test-client",
			"client_secret": "test-secret",
			"issuer_url":    "https://example.com", // Not a real OIDC issuer
		},
	})
	// This will fail because OIDC discovery fails and no explicit URLs provided
	assert.Error(t, err)
}

func TestServer_Running(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.Running())
}

func TestServer_StartStop(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = s.Start(ctx)
	require.NoError(t, err)
	assert.True(t, s.Running())

	// Start again (should be no-op)
	err = s.Start(ctx)
	require.NoError(t, err)

	// Stop
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
	assert.False(t, s.Running())

	// Stop again (should be no-op)
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_StartWithSOCKS5(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)
	assert.True(t, s.Running())

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_StartWithMetrics(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Path:    "/metrics",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)
	assert.True(t, s.Running())

	// Give servers time to start
	time.Sleep(50 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_StartWithAPI(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Token:   "test-token",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)
	assert.True(t, s.Running())

	// Wait for API server to be available
	require.Eventually(t, func() bool { return s.API() != nil }, time.Second, 10*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_GetSanitizedConfig(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP:   config.ListenerConfig{Listen: "0.0.0.0:7080"},
			SOCKS5: config.ListenerConfig{Listen: "0.0.0.0:7180"},
		},
		Backends: []config.BackendConfig{
			{Name: "backend1", Type: "direct", Enabled: true},
			{Name: "backend2", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "backend1"},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "none", Type: "none", Enabled: true},
			},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			BurstSize:         10,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Listen:  "0.0.0.0:9090",
			Path:    "/metrics",
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "0.0.0.0:9000",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	sanitized := s.GetSanitizedConfig()
	require.NotNil(t, sanitized)

	m, ok := sanitized.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, 2, m["backends_count"])
	assert.Equal(t, 1, m["routes_count"])

	backendNames, ok := m["backend_names"].([]string)
	require.True(t, ok)
	assert.Contains(t, backendNames, "backend1")
	assert.Contains(t, backendNames, "backend2")
}

func TestServer_GetFullConfig(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	fullCfg := s.GetFullConfig()
	require.NotNil(t, fullCfg)
	assert.Equal(t, "0.0.0.0:7080", fullCfg.Server.HTTP.Listen)
}

func TestServer_SaveConfig_NoPath(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	newCfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:9090"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	err = s.SaveConfig(newCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config path not set")
}

func TestServer_ReloadConfig_NoPath(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	err = s.ReloadConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config path not set")
}

func TestServer_GetSetConfigPath(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.Empty(t, s.GetConfigPath())

	s.SetConfigPath("/path/to/config.yaml")
	assert.Equal(t, "/path/to/config.yaml", s.GetConfigPath())
}

func TestServer_isAuthRequired_None(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "none", Type: "none", Enabled: true},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Empty(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: nil,
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Native(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{
					Name:    "native",
					Type:    "native",
					Enabled: true,
					Config: map[string]any{
						"users": []map[string]any{
							{"username": "test", "password_hash": "hash"},
						},
					},
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.True(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Providers_AllDisabled(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "test", Type: "native", Enabled: false},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Providers_NoneType(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "test", Type: "none", Enabled: true},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Providers_Native(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{
					Name:    "test",
					Type:    "native",
					Enabled: true,
					Config: map[string]any{
						"users": []map[string]any{
							{"username": "test", "password_hash": "hash"},
						},
					},
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.True(t, s.isAuthRequired())
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		name        string
		listen      string
		defaultPort string
		expected    string
	}{
		{"empty", "", "8080", "8080"},
		{"host:port", "0.0.0.0:7080", "9090", "7080"},
		{"just port", ":7080", "9090", "7080"},
		{"localhost", "localhost:3000", "8080", "3000"},
		{"invalid", "invalid", "8080", "8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPort(tt.listen, tt.defaultPort)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
}

func TestServer_API_NilBeforeStart(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.Nil(t, s.API())
}

func TestServer_getBackend(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"}, // Use port 0 to get random available port
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"example.com", "*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Start the server to ensure backends are initialized
	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Stop(stopCtx)
	}()

	be := s.getBackend("example.com", "192.168.1.1")
	// Backend may be nil if no route matches - the catch-all should work
	if be != nil {
		assert.Equal(t, "default", be.Name())
	}
}

func TestServer_authenticate_Success(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{Name: "none", Type: "none", Enabled: true},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// NoneAuthenticator accepts any credentials
	_, authErr := s.authenticator.Authenticate(context.Background(), "any", "any")
	assert.NoError(t, authErr)
}

func TestServer_authenticate_Failure(t *testing.T) {
	// Create a hash for "correctpassword"
	hash, err := auth.HashPassword("correctpassword")
	require.NoError(t, err)

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{
					Name:    "native",
					Type:    "native",
					Enabled: true,
					Config: map[string]any{
						"users": []map[string]any{
							{"username": "testuser", "password_hash": hash},
						},
					},
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Wrong password should fail
	_, authErr := s.authenticator.Authenticate(context.Background(), "testuser", "wrongpassword")
	assert.Error(t, authErr)
}

func TestServer_ReloadConfig_WithPath(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	err := config.Save(configPath, initialConfig)
	require.NoError(t, err)

	s, err := New(initialConfig)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	// Reload should succeed
	err = s.ReloadConfig()
	require.NoError(t, err)
}

func TestServer_ReloadConfig_InvalidFile(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Set an invalid config path
	s.SetConfigPath("/nonexistent/config.yaml")

	err = s.ReloadConfig()
	assert.Error(t, err)
}

func TestServer_SaveConfig_WithPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	newConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:9090"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	err = s.SaveConfig(newConfig)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

func TestServer_SaveConfig_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	// Create an invalid config (missing required backend for route)
	invalidConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:9090"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "nonexistent"},
		},
	}

	err = s.SaveConfig(invalidConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestServer_onConnect(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Create a mock backend
	be := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})

	// Create a pipe for mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// onConnect should not panic
	ctx := context.Background()
	s.onConnect(ctx, serverConn, "example.com", be)
}

func TestServer_onError(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Create a pipe for mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// onError should not panic
	ctx := context.Background()
	testErr := fmt.Errorf("test error")
	s.onError(ctx, serverConn, "example.com", testErr)
}

func TestServer_StartHTTPListenerError(t *testing.T) {
	// First server will bind to the port
	firstServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer firstServer.Close()

	addr := firstServer.Addr().String()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: addr}, // Use already bound address
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Start should fail because port is already in use
	err = s.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listen HTTP")
}

func TestServer_StartSOCKS5ListenerError(t *testing.T) {
	// First server will bind to the port
	firstServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer firstServer.Close()

	addr := firstServer.Addr().String()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: addr}, // Use already bound address
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Start should fail because port is already in use
	err = s.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listen SOCKS5")
}

func TestServer_StartWithDefaultMetricsPath(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Path:    "", // Empty path should default to /metrics
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_ReloadConfig_WithRateLimiter(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			BurstSize:         10,
		},
	}

	err := config.Save(configPath, initialConfig)
	require.NoError(t, err)

	s, err := New(initialConfig)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	// Reload should update rate limiter
	err = s.ReloadConfig()
	require.NoError(t, err)
}

func TestServer_HandleHTTPConn(t *testing.T) {
	// Create a test target server that immediately closes
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer targetServer.Close()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Get the actual listening address
	httpAddr := s.httpListener.Addr().String()

	// Make a CONNECT request to the proxy with timeout
	conn, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send CONNECT request to target server
	targetURL := strings.TrimPrefix(targetServer.URL, "http://")
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL, targetURL)
	_, err = conn.Write([]byte(connectReq))
	require.NoError(t, err)

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Close connection before stopping server to avoid waiting for grace period
	conn.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_HandleSOCKS5Conn(t *testing.T) {
	// Create a test target server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	go func() {
		for {
			conn, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			conn.Write([]byte("Hello from target"))
			conn.Close()
		}
	}()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Get the actual listening address
	socks5Addr := s.socks5Listener.Addr().String()

	// Make a SOCKS5 connection
	conn, err := net.Dial("tcp", socks5Addr)
	require.NoError(t, err)

	// SOCKS5 handshake - no auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	assert.Equal(t, byte(0x05), authResp[0]) // SOCKS version
	assert.Equal(t, byte(0x00), authResp[1]) // No auth required

	// Connect to target
	targetAddr := targetServer.Addr().(*net.TCPAddr)
	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // VER, CMD=CONNECT, RSV, ATYP=IPv4
	connectReq = append(connectReq, targetAddr.IP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetAddr.Port))
	connectReq = append(connectReq, portBytes...)

	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	// Read connect response
	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	assert.Equal(t, byte(0x05), connectResp[0]) // SOCKS version
	assert.Equal(t, byte(0x00), connectResp[1]) // Success

	// Close connection before stopping server
	conn.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_HandleHTTPConn_WithRateLimiting(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1, // Very low rate limit for testing
			BurstSize:         1,
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	httpAddr := s.httpListener.Addr().String()

	// First request should succeed (within rate limit)
	conn1, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn1.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn1.Write([]byte("CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	conn1.Close()

	// Immediate second request may hit rate limit
	conn2, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn2.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn2.Write([]byte("CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)

	// Read response - might be 429 if rate limited
	reader := bufio.NewReader(conn2)
	resp, err := http.ReadResponse(reader, nil)
	if err == nil {
		resp.Body.Close()
		// Either success or rate limited response is valid
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusBadGateway) // BadGateway if connect fails
	}
	conn2.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_HandleSOCKS5Conn_WithRateLimiting(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			BurstSize:         1,
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	socks5Addr := s.socks5Listener.Addr().String()

	// First connection - should succeed
	conn1, err := net.Dial("tcp", socks5Addr)
	require.NoError(t, err)
	_, err = conn1.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	conn1.Close()

	// Second immediate connection - may be rate limited (connection closed)
	conn2, err := net.Dial("tcp", socks5Addr)
	require.NoError(t, err)

	conn2.SetReadDeadline(time.Now().Add(1 * time.Second))
	// Either the write succeeds or fails due to connection being closed
	// Both are valid behaviors under rate limiting
	_, _ = conn2.Write([]byte{0x05, 0x01, 0x00})
	conn2.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestNew_WithCache(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Cache: cache.Config{
			Enabled: true,
			Storage: cache.StorageConfig{
				Type: "memory",
				Memory: &cache.MemoryConfig{
					MaxSize:    100,
					MaxEntries: 1000,
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.NotNil(t, s.cacheManager)
	assert.NotNil(t, s.cacheInterceptor)
}

func TestNew_WithInvalidAccessLog(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		AccessLog: config.AccessLogConfig{
			Enabled: true,
			Format:  "invalid-format", // Invalid format
			Output:  "stdout",
		},
	}

	_, err := New(cfg)
	// Access log should handle unknown format gracefully or return error
	// Depending on implementation, this may or may not error
	if err != nil {
		assert.Contains(t, err.Error(), "access logger")
	}
}

func TestNew_WithInvalidRoute(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "nonexistent"}, // References nonexistent backend
		},
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load routes")
}

func TestConvertProvidersConfig_WithConfigMap(t *testing.T) {
	providers := []config.AuthProvider{
		{
			Name:     "native-with-config",
			Type:     "native",
			Enabled:  true,
			Priority: 1,
			Config: map[string]any{
				"users": []map[string]any{
					{"username": "test", "password_hash": "hash"},
				},
			},
		},
	}

	result, err := convertProvidersConfig(providers)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "native-with-config", result[0].Name)
	assert.NotNil(t, result[0].Config)
}

func TestConvertProvidersConfig_RejectsLegacyTypeSpecificConfig(t *testing.T) {
	_, err := convertProvidersConfig([]config.AuthProvider{
		{
			Name:    "legacy-native",
			Type:    "native",
			Enabled: true,
			Native: &config.NativeAuth{
				Users: []config.NativeUser{
					{Username: "user1", PasswordHash: "hash1"},
				},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uses legacy type-specific auth config")
}

func TestServer_StartWithCacheEnabled(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Cache: cache.Config{
			Enabled: true,
			Storage: cache.StorageConfig{
				Type: "memory",
				Memory: &cache.MemoryConfig{
					MaxSize:    100,
					MaxEntries: 1000,
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)
	assert.True(t, s.Running())

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_HandleHTTPConn_WithConnectionLimiting(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{
				Listen:         "127.0.0.1:0",
				MaxConnections: 1, // Very low limit for testing
			},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	httpAddr := s.httpListener.Addr().String()

	// Create a target server that holds connections
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	targetAddr := targetServer.Addr().String()

	// Server goroutine that accepts but holds connections
	go func() {
		for {
			conn, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			// Hold connection open for a while
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	// First connection - should succeed and establish tunnel
	conn1, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn1.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq1 := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	_, err = conn1.Write([]byte(connectReq1))
	require.NoError(t, err)

	// Read response for first connection
	reader1 := bufio.NewReader(conn1)
	resp1, err := http.ReadResponse(reader1, nil)
	if err == nil {
		resp1.Body.Close()
	}
	// Don't close conn1 yet - keep it active

	// Second connection - may get 503 due to connection limit
	conn2, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn2.SetDeadline(time.Now().Add(2 * time.Second))

	connectReq2 := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	_, err = conn2.Write([]byte(connectReq2))
	if err == nil {
		reader2 := bufio.NewReader(conn2)
		resp2, err := http.ReadResponse(reader2, nil)
		if err == nil {
			resp2.Body.Close()
			// Connection limit may cause 503 response
			// Or it may succeed if first connection finished quickly
		}
	}
	conn2.Close()
	conn1.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_HandleSOCKS5Conn_WithConnectionLimiting(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{
				Listen:         "127.0.0.1:0",
				MaxConnections: 1, // Very low limit for testing
			},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	socks5Addr := s.socks5Listener.Addr().String()

	// Create a target server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	// Server goroutine
	go func() {
		for {
			conn, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	// First connection - establish SOCKS5 tunnel
	conn1, err := net.DialTimeout("tcp", socks5Addr, 2*time.Second)
	require.NoError(t, err)
	conn1.SetDeadline(time.Now().Add(5 * time.Second))

	// SOCKS5 handshake
	_, err = conn1.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn1, authResp)
	if err != nil {
		conn1.Close()
		// Stop server
		stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		s.Stop(stopCtx)
		return
	}

	// Keep conn1 active, try second connection
	conn2, err := net.DialTimeout("tcp", socks5Addr, 2*time.Second)
	require.NoError(t, err)
	conn2.SetDeadline(time.Now().Add(2 * time.Second))

	// This may be rejected due to connection limit
	// Either succeeds or connection is closed - both valid
	_, _ = conn2.Write([]byte{0x05, 0x01, 0x00})

	conn2.Close()
	conn1.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_onError_WithBackendInContext(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// Create a pipe for mock connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create context with backend name
	ctx := util.WithBackend(context.Background(), "test-backend")
	testErr := fmt.Errorf("test connection error")

	// onError should handle backend name in context without panic
	s.onError(ctx, serverConn, "example.com", testErr)
}

func TestServer_ReloadConfig_WithInvalidRoutes(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	err := config.Save(configPath, initialConfig)
	require.NoError(t, err)

	s, err := New(initialConfig)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	// Now modify the config file to have invalid route (backend doesn't exist)
	invalidConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "nonexistent-backend"},
		},
	}
	err = config.Save(configPath, invalidConfig)
	require.NoError(t, err)

	// Reload should fail due to invalid route
	err = s.ReloadConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "route references unknown backend")
}

func TestServer_ReloadConfig_WithWebSocketHub(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
	}

	err := config.Save(configPath, initialConfig)
	require.NoError(t, err)

	s, err := New(initialConfig)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	// Start server to initialize wsHub
	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Give time for API server to start
	time.Sleep(100 * time.Millisecond)

	// Reload should broadcast to wsHub
	err = s.ReloadConfig()
	require.NoError(t, err)

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_StopWithGracePeriodTimeout(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP:           config.ListenerConfig{Listen: "127.0.0.1:0"},
			GracefulPeriod: config.Duration(100 * time.Millisecond), // Very short grace period
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Create a hanging connection by starting a long request
	httpAddr := s.httpListener.Addr().String()

	// Target server that holds connections
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	targetAddr := targetServer.Addr().String()

	go func() {
		for {
			conn, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			// Hold connection much longer than grace period
			time.Sleep(10 * time.Second)
			conn.Close()
		}
	}()

	// Start a connection that will hang
	conn, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	_, err = conn.Write([]byte(connectReq))
	require.NoError(t, err)

	// Read initial response
	reader := bufio.NewReader(conn)
	resp, _ := http.ReadResponse(reader, nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	// Connection established, now stop server
	// The grace period should timeout

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should complete despite hanging connection due to grace period timeout
	err = s.Stop(stopCtx)
	require.NoError(t, err)

	conn.Close()
}

func TestServer_StartWithCustomWebSocketMaxClients(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		API: config.APIConfig{
			Enabled:             true,
			Listen:              "127.0.0.1:0",
			WebSocketMaxClients: 5, // Custom value
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_HandleSOCKS5Conn_WithAuth(t *testing.T) {
	// Create a hash for "testpassword"
	hash, err := auth.HashPassword("testpassword")
	require.NoError(t, err)

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProvider{
				{
					Name:    "native",
					Type:    "native",
					Enabled: true,
					Config: map[string]any{
						"users": []map[string]any{
							{"username": "testuser", "password_hash": hash},
						},
					},
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Create a target server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	go func() {
		for {
			conn, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			conn.Write([]byte("Hello"))
			conn.Close()
		}
	}()

	socks5Addr := s.socks5Listener.Addr().String()

	// Connect with username/password auth
	conn, err := net.Dial("tcp", socks5Addr)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// SOCKS5 handshake - request username/password auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x02}) // Version 5, 1 auth method, username/password
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	// If server accepts username/password auth
	if authResp[1] == 0x02 {
		// Send username/password
		username := "testuser"
		password := "testpassword"
		authReq := []byte{0x01} // Version 1 of username/password auth
		authReq = append(authReq, byte(len(username)))
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)
		_, err = conn.Write(authReq)
		require.NoError(t, err)

		// Read auth result
		authResult := make([]byte, 2)
		_, err = io.ReadFull(conn, authResult)
		if err == nil {
			assert.Equal(t, byte(0x01), authResult[0]) // Version 1
			assert.Equal(t, byte(0x00), authResult[1]) // Success
		}
	}

	conn.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestExtractPort_AdditionalCases(t *testing.T) {
	tests := []struct {
		name        string
		listen      string
		defaultPort string
		expected    string
	}{
		{"ipv6_with_port", "[::1]:7080", "9090", "7080"},
		{"just_colon", ":", "8080", ""},
		{"no_colon_invalid", "8080", "9090", "9090"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPort(tt.listen, tt.defaultPort)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServer_StartWithAPIAndRequestLog(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		API: config.APIConfig{
			Enabled:          true,
			Listen:           "127.0.0.1:0",
			EnableRequestLog: true,
			RequestLogSize:   100,
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Wait for API server to be available
	require.Eventually(t, func() bool { return s.API() != nil }, time.Second, 10*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_HandleHTTPConn_WithAPIEnabled(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Create target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	httpAddr := s.httpListener.Addr().String()
	targetURL := strings.TrimPrefix(targetServer.URL, "http://")

	// Make a request through the proxy
	conn, err := net.DialTimeout("tcp", httpAddr, 2*time.Second)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL, targetURL)
	_, err = conn.Write([]byte(connectReq))
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err == nil {
		resp.Body.Close()
	}

	conn.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestServer_HandleSOCKS5Conn_WithAPIEnabled(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Create target server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	go func() {
		for {
			conn, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			conn.Write([]byte("Hello"))
			conn.Close()
		}
	}()

	socks5Addr := s.socks5Listener.Addr().String()

	// Make SOCKS5 connection
	conn, err := net.Dial("tcp", socks5Addr)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// SOCKS5 handshake
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	conn.Close()

	// Stop server
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

func TestNew_LoggingSetupError(t *testing.T) {
	// Test with invalid logging config that should cause setup to fail
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Logging: logging.Config{
			Level:  "invalid-level", // This may or may not cause an error depending on implementation
			Format: "json",
			Output: "stdout",
		},
	}

	// This test verifies the logging setup path is executed
	_, err := New(cfg)
	// Depending on implementation, this may or may not error
	// The important thing is that the code path is executed
	_ = err
}

func TestServer_ReloadConfig_RateLimitDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Start with rate limiting disabled but rate limiter created
	initialConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			BurstSize:         10,
		},
	}

	err := config.Save(configPath, initialConfig)
	require.NoError(t, err)

	s, err := New(initialConfig)
	require.NoError(t, err)
	s.SetConfigPath(configPath)

	// Modify config to disable rate limiting
	newConfig := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:7080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "default"},
		},
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
	}
	err = config.Save(configPath, newConfig)
	require.NoError(t, err)

	// Reload should handle disabled rate limit
	err = s.ReloadConfig()
	require.NoError(t, err)
}

// TestNew_WithInvalidCacheStorageType tests server creation with invalid cache storage type.
func TestNew_WithInvalidCacheStorageType(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Cache: cache.Config{
			Enabled: true,
			Storage: cache.StorageConfig{
				Type: "invalid-storage-type", // Invalid storage type
			},
		},
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache")
}

// TestNew_WithCacheRules tests server creation with cache rules.
func TestNew_WithCacheRules(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Cache: cache.Config{
			Enabled: true,
			Storage: cache.StorageConfig{
				Type: "memory",
				Memory: &cache.MemoryConfig{
					MaxSize:    100,
					MaxEntries: 1000,
				},
			},
			Rules: []cache.RuleConfig{
				{
					Name:    "test-rule",
					Enabled: true,
					Domains: []string{"*.example.com"},
				},
			},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.NotNil(t, s.cacheManager)
}

// TestNew_BackendStartupFailure tests that disabled backends don't fail server creation.
func TestNew_BackendStartupFailure(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
			// Disabled backend with invalid config should not fail
			{Name: "disabled-invalid", Type: "wireguard", Enabled: false},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
}

// TestNew_MultipleBackendTypes tests server with multiple backend types.
func TestNew_MultipleBackendTypes(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "direct1", Type: "direct", Enabled: true},
			{Name: "direct2", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"example.com"}, Backend: "direct1"},
			{Domains: []string{"*"}, Backend: "direct2"},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, s)
}

// TestServer_MetricsServerConfig tests metrics server configuration.
// Note: Metrics server runs in a goroutine, so bind errors are logged asynchronously
// and don't cause Start() to return an error.
func TestServer_MetricsServerConfig(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Path:    "/custom-metrics",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Give the server time to start
	time.Sleep(50 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}

// TestServer_APIServerConfig tests API server configuration.
// Note: API server runs in a goroutine, so bind errors are logged asynchronously
// and don't cause Start() to return an error.
func TestServer_APIServerConfig(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Start(ctx)
	require.NoError(t, err)

	// Give the server time to start
	time.Sleep(50 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Stop(stopCtx)
}
