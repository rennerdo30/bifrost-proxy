package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestNewPACGenerator(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	require.NotNil(t, gen)
	assert.Equal(t, "localhost", gen.proxyHost)
	assert.Equal(t, "8080", gen.proxyPort)
	assert.Equal(t, "1080", gen.socks5Port)
}

func TestPACGenerator_Generate_NoRoutes(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	assert.Contains(t, pac, "FindProxyForURL")
	assert.Contains(t, pac, "return \"DIRECT\"")
}

func TestPACGenerator_Generate_WithRoutes(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"*.google.com", "google.com"},
					Backend: "default",
				},
				{
					Domains: []string{"example.com"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	assert.Contains(t, pac, "FindProxyForURL")
	assert.Contains(t, pac, "*.google.com")
	assert.Contains(t, pac, "example.com")
	assert.Contains(t, pac, "PROXY localhost:7080")
	assert.Contains(t, pac, "SOCKS5 localhost:7180")
}

func TestPACGenerator_Generate_CatchAll(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"*.google.com"},
					Backend: "default",
				},
				{
					Domains: []string{"*"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	assert.Contains(t, pac, "FindProxyForURL")
	// Catch-all should result in proxy being default
	assert.Contains(t, pac, "PROXY localhost:7080")
}

func TestPACGenerator_Generate_EmptyHost(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{}
	}

	// Empty proxy host - should use request host
	gen := NewPACGenerator(getConfig, "", "8080", "1080")
	pac := gen.Generate("192.168.1.1:9000")

	assert.Contains(t, pac, "FindProxyForURL")
}

func TestPACGenerator_Generate_HostWithPort(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"*"},
					Backend: "default",
				},
			},
		}
	}

	// Empty proxy host - should extract host from request without port
	gen := NewPACGenerator(getConfig, "", "8080", "1080")
	pac := gen.Generate("192.168.1.1:9000")

	assert.Contains(t, pac, "PROXY 192.168.1.1:7080")
}

func TestPACGenerator_HandlePAC(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"example.com"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")

	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	req.Host = "localhost:9000"
	w := httptest.NewRecorder()

	gen.HandlePAC(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/x-ns-proxy-autoconfig", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "proxy.pac")
	assert.Contains(t, w.Body.String(), "FindProxyForURL")
}

func TestPACGenerator_Generate_EmptyDomains(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	assert.Contains(t, pac, "FindProxyForURL")
	assert.Contains(t, pac, "return \"DIRECT\"")
}

func TestPACGenerator_Generate_OnlyCatchAll(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"*"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	assert.Contains(t, pac, "FindProxyForURL")
	// Should use proxy as default
	assert.Contains(t, pac, "PROXY localhost:7080")
	assert.NotContains(t, pac, "return \"DIRECT\"")
}

func TestPACGenerator_Generate_MixedCatchAllAndSpecific(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"*.example.com"},
					Backend: "default",
				},
				{
					// Route with catch-all - specific domains in same route won't be included
					Domains: []string{"*"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	assert.Contains(t, pac, "*.example.com")
	// With catch-all, default should return proxy
	assert.Contains(t, pac, "PROXY localhost:7080")
}

func TestEscapeJS(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`with"quote`, `with\"quote`},
		{`with'quote`, `with\'quote`},
		{`with\backslash`, `with\\backslash`},
		{`mixed"'\\`, `mixed\"\'\\\\`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeJS(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPACGenerator_Generate_SpecialCharactersInDomain(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{`test"domain.com`, `test'domain.com`},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	// Should escape special characters
	assert.Contains(t, pac, `test\"domain.com`)
	assert.Contains(t, pac, `test\'domain.com`)
}

func TestPACGenerator_Generate_RouteNumbering(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"first.com"},
					Backend: "default",
				},
				{
					Domains: []string{"second.com"},
					Backend: "default",
				},
				{
					Domains: []string{"third.com"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	// Check route comments are numbered
	assert.Contains(t, pac, "Route 1:")
	assert.Contains(t, pac, "Route 2:")
	assert.Contains(t, pac, "Route 3:")
}

func TestPACGenerator_Generate_WildcardHelper(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	// Should include the wildcardMatch helper function
	assert.Contains(t, pac, "function wildcardMatch")
	assert.Contains(t, pac, "pattern.startsWith")
	assert.Contains(t, pac, "shExpMatch")
}

func TestPACGenerator_Generate_IPv6Host(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"*"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "", "8080", "1080")
	// IPv6 address with port
	pac := gen.Generate("[::1]:9000")

	assert.Contains(t, pac, "FindProxyForURL")
}

func TestPACGenerator_Generate_MultipleDomainsPerRoute(t *testing.T) {
	getConfig := func() *config.ServerConfig {
		return &config.ServerConfig{
			Routes: []config.RouteConfig{
				{
					Domains: []string{"a.com", "b.com", "c.com"},
					Backend: "default",
				},
			},
		}
	}

	gen := NewPACGenerator(getConfig, "localhost", "8080", "1080")
	pac := gen.Generate("localhost:9000")

	// All domains should be joined with ||
	assert.Contains(t, pac, "a.com")
	assert.Contains(t, pac, "b.com")
	assert.Contains(t, pac, "c.com")
	// Should use || for OR conditions
	lines := strings.Split(pac, "\n")
	foundCondition := false
	for _, line := range lines {
		if strings.Contains(line, "if (") && strings.Contains(line, "||") {
			foundCondition = true
			break
		}
	}
	assert.True(t, foundCondition, "Should have || in condition")
}
