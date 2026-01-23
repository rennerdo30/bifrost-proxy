// Package router provides domain-based routing for Bifrost.
package router

import (
	"sort"
	"sync"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

// Route represents a routing rule.
type Route struct {
	Name        string
	Matcher     *matcher.Matcher
	Backend     string              // Single backend name
	Backends    []string            // Multiple backend names for load balancing
	LoadBalance string              // round_robin, least_conn, ip_hash, weighted
	Priority    int
}

// RouteResult contains the result of a route match.
type RouteResult struct {
	Matched  bool
	Route    *Route
	Backend  backend.Backend
	Backends []backend.Backend
}

// Router provides domain-based routing.
type Router struct {
	routes         []*Route
	backendManager *backend.Manager
	loadBalancers  map[string]LoadBalancer
	mu             sync.RWMutex
}

// New creates a new Router.
func New(backendManager *backend.Manager) *Router {
	return &Router{
		backendManager: backendManager,
		loadBalancers:  make(map[string]LoadBalancer),
	}
}

// AddRoute adds a routing rule.
func (r *Router) AddRoute(route *Route) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = append(r.routes, route)
	r.sortRoutes()

	// Create load balancer for multi-backend routes
	if len(route.Backends) > 1 {
		r.loadBalancers[route.Name] = NewLoadBalancer(route.LoadBalance)
	}
}

// RemoveRoute removes a routing rule by name.
func (r *Router) RemoveRoute(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, route := range r.routes {
		if route.Name == name {
			r.routes = append(r.routes[:i], r.routes[i+1:]...)
			delete(r.loadBalancers, name)
			break
		}
	}
}

// Match finds the best matching route for a domain.
func (r *Router) Match(domain string) RouteResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if route == nil || route.Matcher == nil {
			continue
		}
		if route.Matcher.Match(domain) {
			result := RouteResult{
				Matched: true,
				Route:   route,
			}

			// Get backend(s)
			if r.backendManager != nil {
				if route.Backend != "" {
					if b, err := r.backendManager.Get(route.Backend); err == nil {
						result.Backend = b
					}
				}

				if len(route.Backends) > 0 {
					for _, name := range route.Backends {
						if b, err := r.backendManager.Get(name); err == nil && b.IsHealthy() {
							result.Backends = append(result.Backends, b)
						}
					}
				}
			}

			return result
		}
	}

	return RouteResult{Matched: false}
}

// SelectBackend selects a backend from a route result using load balancing.
func (r *Router) SelectBackend(result RouteResult, clientIP string) backend.Backend {
	// Single backend
	if result.Backend != nil && result.Backend.IsHealthy() {
		return result.Backend
	}

	// Multiple backends - use load balancer
	if len(result.Backends) > 0 && result.Route != nil {
		r.mu.RLock()
		lb, exists := r.loadBalancers[result.Route.Name]
		r.mu.RUnlock()

		if exists {
			return lb.Select(result.Backends, clientIP)
		}

		// Fallback to first healthy backend
		for _, b := range result.Backends {
			if b.IsHealthy() {
				return b
			}
		}
	}

	return nil
}

// sortRoutes sorts routes by priority (higher priority first).
func (r *Router) sortRoutes() {
	sort.Slice(r.routes, func(i, j int) bool {
		return r.routes[i].Priority > r.routes[j].Priority
	})
}

// Routes returns all routes.
func (r *Router) Routes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*Route, len(r.routes))
	copy(routes, r.routes)
	return routes
}

// Clear removes all routes.
func (r *Router) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = nil
	r.loadBalancers = make(map[string]LoadBalancer)
}

// LoadBalancer selects a backend from a list.
type LoadBalancer interface {
	Select(backends []backend.Backend, clientIP string) backend.Backend
}

// NewLoadBalancer creates a load balancer of the given type.
func NewLoadBalancer(lbType string) LoadBalancer {
	switch lbType {
	case "round_robin", "":
		return &RoundRobinBalancer{}
	case "least_conn":
		return &LeastConnBalancer{}
	case "ip_hash":
		return &IPHashBalancer{}
	default:
		return &RoundRobinBalancer{}
	}
}
