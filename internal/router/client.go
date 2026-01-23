package router

import (
	"fmt"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

// ClientAction represents the action to take for a matched route.
type ClientAction string

const (
	// ActionServer routes traffic through the Bifrost server.
	ActionServer ClientAction = "server"
	// ActionDirect connects directly to the target.
	ActionDirect ClientAction = "direct"
)

// ClientRoute represents a client-side routing rule.
type ClientRoute struct {
	Name     string
	Matcher  *matcher.Matcher
	Action   ClientAction
	Priority int
}

// ClientRouter handles routing for the Bifrost client.
type ClientRouter struct {
	routes []*ClientRoute
}

// NewClientRouter creates a new client router.
func NewClientRouter() *ClientRouter {
	return &ClientRouter{}
}

// LoadRoutes loads routes from configuration.
func (r *ClientRouter) LoadRoutes(routes []config.ClientRouteConfig) error {
	if r == nil {
		return nil
	}
	r.routes = nil

	for i, routeCfg := range routes {
		route := &ClientRoute{
			Name:     routeCfg.Name,
			Matcher:  matcher.New(routeCfg.Domains),
			Action:   ClientAction(routeCfg.Action),
			Priority: routeCfg.Priority,
		}

		if len(routeCfg.Domains) == 0 {
			return fmt.Errorf("route %d must have at least one domain", i)
		}

		// Use domains as default name
		if route.Name == "" && len(routeCfg.Domains) > 0 {
			route.Name = routeCfg.Domains[0]
		}

		// Default priority based on order if not specified
		if route.Priority == 0 {
			route.Priority = len(routes) - i
		}

		r.routes = append(r.routes, route)
	}

	// Sort by priority
	r.sortRoutes()

	return nil
}

// Match finds the action for a given domain.
func (r *ClientRouter) Match(domain string) ClientAction {
	if r == nil {
		return ActionServer
	}
	for _, route := range r.routes {
		if route == nil || route.Matcher == nil {
			continue
		}
		if route.Matcher.Match(domain) {
			return route.Action
		}
	}

	// Default to server if no match
	return ActionServer
}

// Routes returns all routes.
func (r *ClientRouter) Routes() []*ClientRoute {
	if r == nil {
		return nil
	}
	routes := make([]*ClientRoute, len(r.routes))
	copy(routes, r.routes)
	return routes
}

// sortRoutes sorts routes by priority (higher first).
func (r *ClientRouter) sortRoutes() {
	// Simple insertion sort - routes list is typically small
	for i := 1; i < len(r.routes); i++ {
		key := r.routes[i]
		j := i - 1
		for j >= 0 && r.routes[j].Priority < key.Priority {
			r.routes[j+1] = r.routes[j]
			j--
		}
		r.routes[j+1] = key
	}
}
