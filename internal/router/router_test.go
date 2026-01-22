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

// Additional tests for 100% coverage

func TestClientRouter_Match_EmptyRoutes(t *testing.T) {
	r := NewClientRouter()
	// No routes loaded, should return default (server)
	action := r.Match("example.com")
	assert.Equal(t, ActionServer, action)
}

func TestClientRouter_Match_NoMatchingRoute(t *testing.T) {
	r := NewClientRouter()
	// Load routes that won't match
	routes := []config.ClientRouteConfig{
		{Domains: []string{"specific.example.com"}, Action: "direct", Priority: 10},
	}
	r.LoadRoutes(routes)

	// This domain doesn't match the specific pattern
	action := r.Match("other.domain.com")
	// Default to server when no match
	assert.Equal(t, ActionServer, action)
}

func TestClientRouter_sortRoutes_SingleElement(t *testing.T) {
	r := NewClientRouter()
	routes := []config.ClientRouteConfig{
		{Domains: []string{"single.com"}, Action: "direct", Priority: 10},
	}
	r.LoadRoutes(routes)

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 1)
	assert.Equal(t, "single.com", allRoutes[0].Name)
}

func TestClientRouter_sortRoutes_AlreadySorted(t *testing.T) {
	r := NewClientRouter()
	// Routes already in descending priority order
	routes := []config.ClientRouteConfig{
		{Domains: []string{"high.com"}, Action: "direct", Priority: 100},
		{Domains: []string{"medium.com"}, Action: "direct", Priority: 50},
		{Domains: []string{"low.com"}, Action: "server", Priority: 10},
	}
	r.LoadRoutes(routes)

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 3)
	assert.Equal(t, 100, allRoutes[0].Priority)
	assert.Equal(t, 50, allRoutes[1].Priority)
	assert.Equal(t, 10, allRoutes[2].Priority)
}

func TestClientRouter_sortRoutes_ReverseSorted(t *testing.T) {
	r := NewClientRouter()
	// Routes in ascending priority order (needs full sort)
	routes := []config.ClientRouteConfig{
		{Domains: []string{"low.com"}, Action: "server", Priority: 10},
		{Domains: []string{"medium.com"}, Action: "direct", Priority: 50},
		{Domains: []string{"high.com"}, Action: "direct", Priority: 100},
	}
	r.LoadRoutes(routes)

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 3)
	assert.Equal(t, 100, allRoutes[0].Priority)
	assert.Equal(t, 50, allRoutes[1].Priority)
	assert.Equal(t, 10, allRoutes[2].Priority)
}

func TestClientRouter_sortRoutes_Empty(t *testing.T) {
	r := NewClientRouter()
	// Load empty routes
	r.LoadRoutes(nil)
	assert.Empty(t, r.Routes())
}

func TestLeastConnBalancer_Select_NoHealthy(t *testing.T) {
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	// Not started, unhealthy

	lb := &LeastConnBalancer{}
	selected := lb.Select([]backend.Backend{b}, "")
	assert.Nil(t, selected)
}

func TestLeastConnBalancer_Select_SingleBackend(t *testing.T) {
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "single"})
	b.Start(nil)

	lb := &LeastConnBalancer{}
	selected := lb.Select([]backend.Backend{b}, "")
	assert.NotNil(t, selected)
	assert.Equal(t, "single", selected.Name())
}

func TestIPHashBalancer_Select_NoHealthy(t *testing.T) {
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	// Not started, unhealthy

	lb := &IPHashBalancer{}
	selected := lb.Select([]backend.Backend{b}, "192.168.1.1")
	assert.Nil(t, selected)
}

func TestRouter_Match_WithMultipleBackends(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)
	mgr.Add(b1)
	mgr.Add(b2)

	r := New(mgr)
	r.AddRoute(&Route{
		Name:     "multi-backend",
		Matcher:  matcher.New([]string{"*.example.com"}),
		Backends: []string{"b1", "b2"},
	})

	result := r.Match("api.example.com")
	assert.True(t, result.Matched)
	assert.Len(t, result.Backends, 2)
}

func TestRouter_Match_BackendNotFound(t *testing.T) {
	mgr := backend.NewManager()
	// Don't add backend to manager

	r := New(mgr)
	r.AddRoute(&Route{
		Name:    "missing-backend",
		Matcher: matcher.New([]string{"*.example.com"}),
		Backend: "nonexistent",
	})

	result := r.Match("api.example.com")
	assert.True(t, result.Matched)
	assert.Nil(t, result.Backend) // Backend not found
}

func TestRouter_Match_MultipleBackendsPartiallyHealthy(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil) // Only start b1
	// b2 not started (unhealthy)
	mgr.Add(b1)
	mgr.Add(b2)

	r := New(mgr)
	r.AddRoute(&Route{
		Name:     "partial-health",
		Matcher:  matcher.New([]string{"*.example.com"}),
		Backends: []string{"b1", "b2"},
	})

	result := r.Match("api.example.com")
	assert.True(t, result.Matched)
	// Only healthy backends are included
	assert.Len(t, result.Backends, 1)
	assert.Equal(t, "b1", result.Backends[0].Name())
}

func TestRouter_Match_MultipleBackendsNotFound(t *testing.T) {
	mgr := backend.NewManager()
	// Don't add any backends

	r := New(mgr)
	r.AddRoute(&Route{
		Name:     "missing-backends",
		Matcher:  matcher.New([]string{"*.example.com"}),
		Backends: []string{"nonexistent1", "nonexistent2"},
	})

	result := r.Match("api.example.com")
	assert.True(t, result.Matched)
	assert.Empty(t, result.Backends) // No backends found
}

func TestRouter_SelectBackend_MultipleNoLoadBalancer(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)
	mgr.Add(b1)
	mgr.Add(b2)

	r := New(mgr)
	// Don't add a route with load balancer, just create a result directly

	result := RouteResult{
		Matched:  true,
		Route:    &Route{Name: "no-lb-route"},
		Backends: []backend.Backend{b1, b2},
	}

	// No load balancer for this route, should fallback to first healthy
	selected := r.SelectBackend(result, "192.168.1.1")
	assert.NotNil(t, selected)
}

func TestRouter_SelectBackend_EmptyBackends(t *testing.T) {
	mgr := backend.NewManager()
	r := New(mgr)

	result := RouteResult{
		Matched:  true,
		Route:    &Route{Name: "empty"},
		Backends: []backend.Backend{},
	}

	selected := r.SelectBackend(result, "192.168.1.1")
	assert.Nil(t, selected)
}

func TestRouter_SelectBackend_AllUnhealthyMultiple(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	// Don't start - both unhealthy
	mgr.Add(b1)
	mgr.Add(b2)

	r := New(mgr)

	result := RouteResult{
		Matched:  true,
		Route:    &Route{Name: "all-unhealthy"},
		Backends: []backend.Backend{b1, b2},
	}

	selected := r.SelectBackend(result, "192.168.1.1")
	assert.Nil(t, selected)
}

func TestServerRouter_LoadRoutes_NameFromBackends(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "backend1"})
	mgr.Add(b)

	r := NewServerRouter(mgr)
	routes := []config.RouteConfig{
		{
			Domains:  []string{"*.example.com"},
			Backends: []string{"backend1"}, // No Name, no Backend, but has Backends
		},
	}
	require.NoError(t, r.LoadRoutes(routes))

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 1)
	// Name should default to first backend name
	assert.Equal(t, "backend1", allRoutes[0].Name)
}

func TestServerRouter_LoadRoutes_EmptyRouteName(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "mybackend"})
	mgr.Add(b)

	r := NewServerRouter(mgr)
	routes := []config.RouteConfig{
		{
			Domains: []string{"*.example.com"},
			Backend: "mybackend",
			// Name is empty, should default to backend name
		},
	}
	require.NoError(t, r.LoadRoutes(routes))

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 1)
	assert.Equal(t, "mybackend", allRoutes[0].Name)
}

func TestServerRouter_LoadRoutes_WithExplicitPriority(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "direct"})
	mgr.Add(b)

	r := NewServerRouter(mgr)
	routes := []config.RouteConfig{
		{
			Name:     "high-priority",
			Domains:  []string{"*.example.com"},
			Backend:  "direct",
			Priority: 100,
		},
		{
			Name:     "low-priority",
			Domains:  []string{"*"},
			Backend:  "direct",
			Priority: 10,
		},
	}
	require.NoError(t, r.LoadRoutes(routes))

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 2)
	// Should be sorted by priority (high first)
	assert.Equal(t, "high-priority", allRoutes[0].Name)
	assert.Equal(t, 100, allRoutes[0].Priority)
}

func TestServerRouter_LoadRoutes_DefaultPriority(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "direct"})
	mgr.Add(b)

	r := NewServerRouter(mgr)
	routes := []config.RouteConfig{
		{
			Name:    "first",
			Domains: []string{"*.first.com"},
			Backend: "direct",
			// Priority = 0 (default)
		},
		{
			Name:    "second",
			Domains: []string{"*.second.com"},
			Backend: "direct",
			// Priority = 0 (default)
		},
	}
	require.NoError(t, r.LoadRoutes(routes))

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 2)
	// First route should have priority 2 (len=2, index=0 -> 2-0=2)
	// Second route should have priority 1 (len=2, index=1 -> 2-1=1)
	assert.Equal(t, 2, allRoutes[0].Priority)
	assert.Equal(t, 1, allRoutes[1].Priority)
}

func TestClientRouter_LoadRoutes_DefaultPriority(t *testing.T) {
	r := NewClientRouter()
	routes := []config.ClientRouteConfig{
		{
			Domains: []string{"first.com"},
			Action:  "direct",
			// Priority = 0 (default)
		},
		{
			Domains: []string{"second.com"},
			Action:  "server",
			// Priority = 0 (default)
		},
	}
	require.NoError(t, r.LoadRoutes(routes))

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 2)
	// First route should have priority 2 (len=2, index=0 -> 2-0=2)
	assert.Equal(t, 2, allRoutes[0].Priority)
	assert.Equal(t, 1, allRoutes[1].Priority)
}

func TestClientRouter_LoadRoutes_DefaultName(t *testing.T) {
	r := NewClientRouter()
	routes := []config.ClientRouteConfig{
		{
			Domains: []string{"example.com", "test.com"},
			Action:  "direct",
			// Name is empty, should default to first domain
		},
	}
	require.NoError(t, r.LoadRoutes(routes))

	allRoutes := r.Routes()
	assert.Len(t, allRoutes, 1)
	assert.Equal(t, "example.com", allRoutes[0].Name)
}

func TestClientRouter_LoadRoutes_EmptyDomains(t *testing.T) {
	r := NewClientRouter()
	routes := []config.ClientRouteConfig{
		{
			Name:    "empty-domains",
			Domains: []string{},
			Action:  "direct",
		},
	}
	err := r.LoadRoutes(routes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must have at least one domain")

	allRoutes := r.Routes()
	assert.Empty(t, allRoutes)
}

func TestRouter_AddRoute_WithLoadBalancer(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	mgr.Add(b1)
	mgr.Add(b2)

	r := New(mgr)
	r.AddRoute(&Route{
		Name:        "lb-route",
		Matcher:     matcher.New([]string{"*"}),
		Backends:    []string{"b1", "b2"},
		LoadBalance: "ip_hash",
	})

	// Verify load balancer was created
	r.mu.RLock()
	lb, exists := r.loadBalancers["lb-route"]
	r.mu.RUnlock()

	assert.True(t, exists)
	assert.NotNil(t, lb)
}

func TestRouter_RemoveRoute_WithLoadBalancer(t *testing.T) {
	mgr := backend.NewManager()
	r := New(mgr)

	r.AddRoute(&Route{
		Name:        "lb-route",
		Matcher:     matcher.New([]string{"*"}),
		Backends:    []string{"b1", "b2"},
		LoadBalance: "round_robin",
	})

	// Verify load balancer exists
	r.mu.RLock()
	_, exists := r.loadBalancers["lb-route"]
	r.mu.RUnlock()
	assert.True(t, exists)

	// Remove route
	r.RemoveRoute("lb-route")

	// Verify load balancer was removed
	r.mu.RLock()
	_, exists = r.loadBalancers["lb-route"]
	r.mu.RUnlock()
	assert.False(t, exists)
}

func TestWeightedBalancer_Select_DefaultWeight(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)

	// Weight only for b1, b2 should get default weight of 1
	weights := map[string]int{"b1": 2}
	lb := NewWeightedBalancer(weights)

	// Select multiple times
	selections := make(map[string]int)
	for i := 0; i < 30; i++ {
		selected := lb.Select([]backend.Backend{b1, b2}, "")
		if selected != nil {
			selections[selected.Name()]++
		}
	}

	// Both should be selected
	assert.Greater(t, selections["b1"], 0)
	assert.Greater(t, selections["b2"], 0)
	// b1 should be selected roughly twice as often
	assert.Greater(t, selections["b1"], selections["b2"])
}

func TestClientAction_Constants(t *testing.T) {
	assert.Equal(t, ClientAction("server"), ActionServer)
	assert.Equal(t, ClientAction("direct"), ActionDirect)
}

func TestClientRoute_Struct(t *testing.T) {
	m := matcher.New([]string{"*.example.com"})
	route := &ClientRoute{
		Name:     "test-client-route",
		Matcher:  m,
		Action:   ActionDirect,
		Priority: 50,
	}

	assert.Equal(t, "test-client-route", route.Name)
	assert.Equal(t, ActionDirect, route.Action)
	assert.Equal(t, 50, route.Priority)
	assert.NotNil(t, route.Matcher)
}

func TestServerRouter_GetBackendForDomain_WithMultipleBackends(t *testing.T) {
	mgr := backend.NewManager()
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)
	mgr.Add(b1)
	mgr.Add(b2)

	r := NewServerRouter(mgr)
	routes := []config.RouteConfig{
		{
			Name:        "multi",
			Domains:     []string{"*.example.com"},
			Backends:    []string{"b1", "b2"},
			LoadBalance: "round_robin",
		},
	}
	r.LoadRoutes(routes)

	result := r.GetBackendForDomain("api.example.com", "192.168.1.1")
	assert.NotNil(t, result)
}

func TestRouter_Concurrency(t *testing.T) {
	mgr := backend.NewManager()
	b := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	b.Start(nil)
	mgr.Add(b)

	r := New(mgr)
	r.AddRoute(&Route{
		Name:    "test",
		Matcher: matcher.New([]string{"*"}),
		Backend: "test",
	})

	// Concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				r.Match("example.com")
				r.Routes()
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestLeastConnBalancer_SelectsLowestConnections(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b1.Start(nil)
	b2.Start(nil)

	lb := &LeastConnBalancer{}
	backends := []backend.Backend{b1, b2}

	// Both have 0 connections initially, first iteration
	selected := lb.Select(backends, "")
	assert.NotNil(t, selected)
}

func TestIPHashBalancer_Consistency(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b3 := backend.NewDirectBackend(backend.DirectConfig{Name: "b3"})
	b1.Start(nil)
	b2.Start(nil)
	b3.Start(nil)

	lb := &IPHashBalancer{}
	backends := []backend.Backend{b1, b2, b3}

	// Same IP should always select same backend
	clientIP := "10.20.30.40"
	selected1 := lb.Select(backends, clientIP)
	selected2 := lb.Select(backends, clientIP)
	selected3 := lb.Select(backends, clientIP)

	assert.Equal(t, selected1.Name(), selected2.Name())
	assert.Equal(t, selected2.Name(), selected3.Name())
}

func TestRoundRobinBalancer_Cycling(t *testing.T) {
	b1 := backend.NewDirectBackend(backend.DirectConfig{Name: "b1"})
	b2 := backend.NewDirectBackend(backend.DirectConfig{Name: "b2"})
	b3 := backend.NewDirectBackend(backend.DirectConfig{Name: "b3"})
	b1.Start(nil)
	b2.Start(nil)
	b3.Start(nil)

	lb := &RoundRobinBalancer{}
	backends := []backend.Backend{b1, b2, b3}

	// Select 6 times - should cycle through all backends twice
	selections := make([]string, 6)
	for i := 0; i < 6; i++ {
		selected := lb.Select(backends, "")
		selections[i] = selected.Name()
	}

	// All three backends should be selected at least once
	counts := make(map[string]int)
	for _, name := range selections {
		counts[name]++
	}
	assert.Equal(t, 2, counts["b1"])
	assert.Equal(t, 2, counts["b2"])
	assert.Equal(t, 2, counts["b3"])
}
