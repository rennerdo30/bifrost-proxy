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

func TestRouter_RemoveRoute(t *testing.T) {
	r := &Router{
		loadBalancers: make(map[string]LoadBalancer),
	}

	r.AddRoute(&Route{
		Name:    "test1",
		Matcher: matcher.New([]string{"*.example.com"}),
	})
	r.AddRoute(&Route{
		Name:    "test2",
		Matcher: matcher.New([]string{"*.test.com"}),
	})

	assert.Len(t, r.Routes(), 2)

	r.RemoveRoute("test1")
	assert.Len(t, r.Routes(), 1)
	assert.Equal(t, "test2", r.Routes()[0].Name)
}

func TestRouter_RemoveRoute_NotFound(t *testing.T) {
	r := &Router{
		loadBalancers: make(map[string]LoadBalancer),
	}

	r.AddRoute(&Route{
		Name:    "test",
		Matcher: matcher.New([]string{"*.example.com"}),
	})

	// Should not panic
	r.RemoveRoute("nonexistent")
	assert.Len(t, r.Routes(), 1)
}

func TestRouter_Clear(t *testing.T) {
	r := &Router{
		loadBalancers: make(map[string]LoadBalancer),
	}

	r.AddRoute(&Route{Name: "test1", Matcher: matcher.New([]string{"*"})})
	r.AddRoute(&Route{Name: "test2", Matcher: matcher.New([]string{"*"})})

	assert.Len(t, r.Routes(), 2)

	r.Clear()
	assert.Empty(t, r.Routes())
}

func TestRouter_Match_NoMatch(t *testing.T) {
	mgr := backend.NewManager()
	r := New(mgr)

	result := r.Match("example.com")
	assert.False(t, result.Matched)
}

func TestRouter_SelectBackend_Single(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	b.Start(nil)
	mgr.Add(b)

	r := New(mgr)

	result := RouteResult{
		Matched: true,
		Backend: b,
	}

	selected := r.SelectBackend(result, "192.168.1.1")
	assert.Equal(t, b, selected)
}

func TestRouter_SelectBackend_Multiple(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)
	mgr.Add(b1)
	mgr.Add(b2)

	r := New(mgr)
	r.AddRoute(&Route{
		Name:        "multi",
		Matcher:     matcher.New([]string{"*"}),
		Backends:    []string{"b1", "b2"},
		LoadBalance: "round_robin",
	})

	result := RouteResult{
		Matched:  true,
		Route:    r.routes[0],
		Backends: []backend.Backend{b1, b2},
	}

	// Should select a backend
	selected := r.SelectBackend(result, "192.168.1.1")
	assert.NotNil(t, selected)
}

func TestRouter_SelectBackend_NoHealthy(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	// Not started, so unhealthy
	mgr.Add(b)

	r := New(mgr)

	result := RouteResult{
		Matched: true,
		Backend: b,
	}

	selected := r.SelectBackend(result, "192.168.1.1")
	assert.Nil(t, selected)
}

func TestNewLoadBalancer_RoundRobin(t *testing.T) {
	lb := NewLoadBalancer("round_robin")
	_, ok := lb.(*RoundRobinBalancer)
	assert.True(t, ok)
}

func TestNewLoadBalancer_Empty(t *testing.T) {
	lb := NewLoadBalancer("")
	_, ok := lb.(*RoundRobinBalancer)
	assert.True(t, ok)
}

func TestNewLoadBalancer_LeastConn(t *testing.T) {
	lb := NewLoadBalancer("least_conn")
	_, ok := lb.(*LeastConnBalancer)
	assert.True(t, ok)
}

func TestNewLoadBalancer_IPHash(t *testing.T) {
	lb := NewLoadBalancer("ip_hash")
	_, ok := lb.(*IPHashBalancer)
	assert.True(t, ok)
}

func TestNewLoadBalancer_Unknown(t *testing.T) {
	lb := NewLoadBalancer("unknown")
	// Defaults to round_robin
	_, ok := lb.(*RoundRobinBalancer)
	assert.True(t, ok)
}

func TestRoundRobinBalancer_Select(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)

	lb := &RoundRobinBalancer{}
	backends := []backend.Backend{b1, b2}

	// Should cycle through backends
	selected1 := lb.Select(backends, "")
	selected2 := lb.Select(backends, "")

	// Both should be selected at some point
	assert.NotNil(t, selected1)
	assert.NotNil(t, selected2)
}

func TestRoundRobinBalancer_Select_Empty(t *testing.T) {
	lb := &RoundRobinBalancer{}
	selected := lb.Select(nil, "")
	assert.Nil(t, selected)
}

func TestRoundRobinBalancer_Select_NoHealthy(t *testing.T) {
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	// Not started, unhealthy

	lb := &RoundRobinBalancer{}
	selected := lb.Select([]backend.Backend{b}, "")
	assert.Nil(t, selected)
}

func TestLeastConnBalancer_Select(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)

	lb := &LeastConnBalancer{}
	backends := []backend.Backend{b1, b2}

	selected := lb.Select(backends, "")
	assert.NotNil(t, selected)
}

func TestLeastConnBalancer_Select_Empty(t *testing.T) {
	lb := &LeastConnBalancer{}
	selected := lb.Select(nil, "")
	assert.Nil(t, selected)
}

func TestIPHashBalancer_Select(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)

	lb := &IPHashBalancer{}
	backends := []backend.Backend{b1, b2}

	// Same IP should return same backend (session persistence)
	selected1 := lb.Select(backends, "192.168.1.1")
	selected2 := lb.Select(backends, "192.168.1.1")
	assert.Equal(t, selected1.Name(), selected2.Name())

	// Different IP may return different backend
	selected3 := lb.Select(backends, "10.0.0.1")
	assert.NotNil(t, selected3)
}

func TestIPHashBalancer_Select_Empty(t *testing.T) {
	lb := &IPHashBalancer{}
	selected := lb.Select(nil, "192.168.1.1")
	assert.Nil(t, selected)
}

func TestWeightedBalancer_New(t *testing.T) {
	weights := map[string]int{"b1": 3, "b2": 1}
	lb := NewWeightedBalancer(weights)
	assert.NotNil(t, lb)
	assert.Equal(t, weights, lb.weights)
}

func TestWeightedBalancer_Select(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)

	weights := map[string]int{"b1": 3, "b2": 1}
	lb := NewWeightedBalancer(weights)

	// Select multiple times - b1 should be selected more often
	b1Count := 0
	for i := 0; i < 100; i++ {
		selected := lb.Select([]backend.Backend{b1, b2}, "")
		if selected.Name() == "b1" {
			b1Count++
		}
	}

	// b1 has weight 3, b2 has weight 1, so b1 should be ~75%
	assert.Greater(t, b1Count, 50)
}

func TestWeightedBalancer_Select_Empty(t *testing.T) {
	lb := NewWeightedBalancer(nil)
	selected := lb.Select(nil, "")
	assert.Nil(t, selected)
}

func TestWeightedBalancer_Select_NoHealthy(t *testing.T) {
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	// Not started, unhealthy

	lb := NewWeightedBalancer(nil)
	selected := lb.Select([]backend.Backend{b}, "")
	assert.Nil(t, selected)
}

func TestClientRouter_Routes(t *testing.T) {
	r := NewClientRouter()

	routes := []config.ClientRouteConfig{
		{Domains: []string{"localhost"}, Action: "direct"},
		{Domains: []string{"*"}, Action: "server"},
	}
	r.LoadRoutes(routes)

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 2)
}

func TestServerRouter_GetBackendForDomain(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "direct"})
	b.Start(nil)
	mgr.Add(b)

	r := NewServerRouter(mgr)
	routes := []config.RouteConfig{
		{Domains: []string{"*.example.com"}, Backend: "direct"},
	}
	r.LoadRoutes(routes)

	result := r.GetBackendForDomain("api.example.com", "192.168.1.1")
	assert.NotNil(t, result)
	assert.Equal(t, "direct", result.Name())
}

func TestServerRouter_GetBackendForDomain_NoMatch(t *testing.T) {
	mgr := backend.NewManager()
	r := NewServerRouter(mgr)

	result := r.GetBackendForDomain("example.com", "192.168.1.1")
	assert.Nil(t, result)
}

func TestRoute_Struct(t *testing.T) {
	m := matcher.New([]string{"*.example.com"})
	r := &Route{
		Name:        "test-route",
		Matcher:     m,
		Backend:     "backend1",
		Backends:    []string{"backend1", "backend2"},
		LoadBalance: "round_robin",
		Priority:    100,
	}

	assert.Equal(t, "test-route", r.Name)
	assert.Equal(t, "backend1", r.Backend)
	assert.Len(t, r.Backends, 2)
	assert.Equal(t, "round_robin", r.LoadBalance)
	assert.Equal(t, 100, r.Priority)
}

func TestRouteResult_Struct(t *testing.T) {
	r := RouteResult{
		Matched: true,
	}
	assert.True(t, r.Matched)
}
