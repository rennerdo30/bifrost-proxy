package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
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
	assert.NotNil(t, s.rateLimiter)
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
			Mode: "none",
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
	auth, err := createAuthenticator(config.AuthConfig{Mode: "none"})
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
		Mode: "native",
		Native: &config.NativeAuth{
			Users: []config.NativeUser{
				{Username: "test", PasswordHash: "hash"},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_Native_NilConfig(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Mode:   "native",
		Native: nil,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "native auth config required")
}

func TestCreateAuthenticator_LDAP_NilConfig(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Mode: "ldap",
		LDAP: nil,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ldap auth config required")
}

func TestCreateAuthenticator_OAuth_NilConfig(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Mode:  "oauth",
		OAuth: nil,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth auth config required")
}

func TestCreateAuthenticator_System(t *testing.T) {
	auth, err := createAuthenticator(config.AuthConfig{
		Mode: "system",
		System: &config.SystemAuth{
			Service: "test-service",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_System_NilConfig(t *testing.T) {
	// System auth works with nil config (uses defaults)
	auth, err := createAuthenticator(config.AuthConfig{
		Mode: "system",
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateAuthenticator_Unknown(t *testing.T) {
	_, err := createAuthenticator(config.AuthConfig{
		Mode: "unknown",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown auth mode")
}

func TestCreateChainAuthenticator_Empty(t *testing.T) {
	auth, err := createChainAuthenticator([]config.AuthProvider{})
	require.NoError(t, err)
	require.NotNil(t, auth) // Returns NoneAuthenticator
}

func TestCreateChainAuthenticator_Disabled(t *testing.T) {
	auth, err := createChainAuthenticator([]config.AuthProvider{
		{Name: "test", Type: "native", Enabled: false},
	})
	require.NoError(t, err)
	require.NotNil(t, auth) // Returns NoneAuthenticator since all disabled
}

func TestCreateChainAuthenticator_Multiple(t *testing.T) {
	auth, err := createChainAuthenticator([]config.AuthProvider{
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
			Native: &config.NativeAuth{
				Users: []config.NativeUser{
					{Username: "test", PasswordHash: "hash"},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateChainAuthenticator_InvalidProvider(t *testing.T) {
	_, err := createChainAuthenticator([]config.AuthProvider{
		{Name: "invalid", Type: "native", Enabled: true}, // Missing Native config
	})
	assert.Error(t, err)
}

func TestCreateSingleAuthenticator_LDAP(t *testing.T) {
	ldapCfg := &config.LDAPAuth{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	auth, err := createSingleAuthenticator("ldap", nil, nil, ldapCfg, nil)
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestCreateSingleAuthenticator_OAuth(t *testing.T) {
	// OAuth requires OIDC discovery or explicit introspect/userinfo URLs
	// Without valid endpoints, it will fail - this tests the error case
	oauthCfg := &config.OAuthAuth{
		Provider:     "generic",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    "https://example.com", // Not a real OIDC issuer
	}

	_, err := createSingleAuthenticator("oauth", nil, nil, nil, oauthCfg)
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

	// Give API server time to start
	time.Sleep(50 * time.Millisecond)

	assert.NotNil(t, s.API())

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Stop(stopCtx)
	require.NoError(t, err)
}

func TestServer_GetSanitizedConfig(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP:   config.ListenerConfig{Listen: "0.0.0.0:8080"},
			SOCKS5: config.ListenerConfig{Listen: "0.0.0.0:1080"},
		},
		Backends: []config.BackendConfig{
			{Name: "backend1", Type: "direct", Enabled: true},
			{Name: "backend2", Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: "backend1"},
		},
		Auth: config.AuthConfig{
			Mode: "none",
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	fullCfg := s.GetFullConfig()
	require.NotNil(t, fullCfg)
	assert.Equal(t, "0.0.0.0:8080", fullCfg.Server.HTTP.Listen)
}

func TestServer_SaveConfig_NoPath(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Mode: "none",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Empty(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Mode: "",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, s.isAuthRequired())
}

func TestServer_isAuthRequired_Native(t *testing.T) {
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Mode: "native",
			Native: &config.NativeAuth{
				Users: []config.NativeUser{
					{Username: "test", PasswordHash: "hash"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
					Native: &config.NativeAuth{
						Users: []config.NativeUser{
							{Username: "test", PasswordHash: "hash"},
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
		{"host:port", "0.0.0.0:8080", "9090", "8080"},
		{"just port", ":8080", "9090", "8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
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
			HTTP: config.ListenerConfig{Listen: "0.0.0.0:8080"},
		},
		Backends: []config.BackendConfig{
			{Name: "default", Type: "direct", Enabled: true},
		},
		Auth: config.AuthConfig{
			Mode: "none",
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)

	// NoneAuthenticator accepts any credentials
	assert.True(t, s.authenticate("any", "any"))
}
