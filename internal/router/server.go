package router

import (
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

// ServerRouter handles routing for the Bifrost server.
type ServerRouter struct {
	*Router
}

// NewServerRouter creates a new server router.
func NewServerRouter(backendManager *backend.Manager) *ServerRouter {
	return &ServerRouter{
		Router: New(backendManager),
	}
}

// LoadRoutes loads routes from configuration.
func (r *ServerRouter) LoadRoutes(routes []config.RouteConfig) error {
	if r == nil || r.Router == nil {
		return nil
	}
	r.Clear()

	for i, routeCfg := range routes {
		// Validate backends exist
		if r.backendManager != nil {
			if routeCfg.Backend != "" {
				if _, err := r.backendManager.Get(routeCfg.Backend); err != nil {
					return err
				}
			}
			for _, name := range routeCfg.Backends {
				if _, err := r.backendManager.Get(name); err != nil {
					return err
				}
			}
		}

		route := &Route{
			Name:        routeCfg.Name,
			Matcher:     matcher.New(routeCfg.Domains),
			Backend:     routeCfg.Backend,
			Backends:    routeCfg.Backends,
			LoadBalance: routeCfg.LoadBalance,
			Priority:    routeCfg.Priority,
		}

		// Use index as default name if not provided
		if route.Name == "" {
			route.Name = routeCfg.Backend
			if route.Name == "" && len(routeCfg.Backends) > 0 {
				route.Name = routeCfg.Backends[0]
			}
		}

		// Default priority based on order if not specified
		if route.Priority == 0 {
			route.Priority = len(routes) - i
		}

		r.AddRoute(route)
	}

	return nil
}

// GetBackendForDomain returns the appropriate backend for a domain.
func (r *ServerRouter) GetBackendForDomain(domain, clientIP string) backend.Backend {
	if r == nil || r.Router == nil {
		return nil
	}
	result := r.Match(domain)
	if !result.Matched {
		return nil
	}
	return r.SelectBackend(result, clientIP)
}
