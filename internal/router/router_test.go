package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

func TestServerRouter(t *testing.T) {
	// Create backend manager
	mgr := backend.NewManager()
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "direct"})
	require.NoError(t, mgr.Add(directBackend))

	// Create router
	r := NewServerRouter(mgr)

	// Add routes
	routes := []config.RouteConfig{
		{Domains: []string{"*.internal.com"}, Backend: "direct", Priority: 100},
		{Domains: []string{"*"}, Backend: "direct", Priority: 1},
	}
	require.NoError(t, r.LoadRoutes(routes))

	// Test matching
	tests := []struct {
		domain  string
		matched bool
	}{
		{"api.internal.com", true},
		{"internal.com", true}, // Matches * catch-all (*.internal.com only matches subdomains)
		{"example.com", true},  // Matches *
	}

	for _, tt := range tests {
		result := r.Match(tt.domain)
		assert.Equal(t, tt.matched, result.Matched, "domain: %s", tt.domain)
	}
}

func TestClientRouter(t *testing.T) {
	r := NewClientRouter()

	routes := []config.ClientRouteConfig{
		{Domains: []string{"localhost", "127.0.0.1"}, Action: "direct", Priority: 100},
		{Domains: []string{"*.example.com"}, Action: "direct", Priority: 50},
		{Domains: []string{"*"}, Action: "server", Priority: 1},
	}
	require.NoError(t, r.LoadRoutes(routes))

	tests := []struct {
		domain string
		action ClientAction
	}{
		{"localhost", ActionDirect},
		{"127.0.0.1", ActionDirect},
		{"api.example.com", ActionDirect},
		{"google.com", ActionServer},
		{"internal.company.com", ActionServer},
	}

	for _, tt := range tests {
		action := r.Match(tt.domain)
		assert.Equal(t, tt.action, action, "domain: %s", tt.domain)
	}
}

func TestRoutePriority(t *testing.T) {
	r := &Router{
		loadBalancers: make(map[string]LoadBalancer),
	}

	// Add routes in non-priority order
	r.AddRoute(&Route{
		Name:     "low",
		Matcher:  matcher.New([]string{"*"}),
		Backend:  "low",
		Priority: 1,
	})
	r.AddRoute(&Route{
		Name:     "high",
		Matcher:  matcher.New([]string{"*.example.com"}),
		Backend:  "high",
		Priority: 100,
	})
	r.AddRoute(&Route{
		Name:     "medium",
		Matcher:  matcher.New([]string{"api.example.com"}),
		Backend:  "medium",
		Priority: 50,
	})

	// Routes should be sorted by priority
	routes := r.Routes()
	assert.Equal(t, "high", routes[0].Name)
	assert.Equal(t, "medium", routes[1].Name)
	assert.Equal(t, "low", routes[2].Name)
}
