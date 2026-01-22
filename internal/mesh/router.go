package mesh

import (
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// RouteType represents the type of route.
type RouteType int

const (
	// RouteTypeDirect is a direct route to a peer.
	RouteTypeDirect RouteType = iota

	// RouteTypeNextHop is a route through another peer.
	RouteTypeNextHop

	// RouteTypeRelay is a route through a relay.
	RouteTypeRelay
)

// String returns a human-readable string for the route type.
func (t RouteType) String() string {
	switch t {
	case RouteTypeDirect:
		return "direct"
	case RouteTypeNextHop:
		return "next_hop"
	case RouteTypeRelay:
		return "relay"
	default:
		return "unknown"
	}
}

// Route represents a route to a peer.
type Route struct {
	// DestPeerID is the destination peer ID.
	DestPeerID string

	// DestIP is the destination virtual IP.
	DestIP netip.Addr

	// NextHop is the next hop peer ID (empty for direct routes).
	NextHop string

	// Type is the route type.
	Type RouteType

	// Metric is the route cost (lower is better).
	Metric int

	// Latency is the measured latency.
	Latency time.Duration

	// HopCount is the number of hops.
	HopCount int

	// LastUpdated is when the route was last updated.
	LastUpdated time.Time

	// Active indicates if the route is currently active.
	Active bool
}

// MeshRouter manages the mesh routing table.
type MeshRouter struct {
	localPeerID string
	localIP     netip.Addr

	routes       map[string][]*Route // DestPeerID -> routes
	routesByIP   map[netip.Addr]*Route
	directPeers  map[string]bool

	pathCostFunc PathCostFunc
	maxHops      int
	routeTimeout time.Duration

	onRouteChanged func(route *Route)

	mu sync.RWMutex
}

// PathCostFunc calculates the cost of a path.
type PathCostFunc func(latency time.Duration, hopCount int) int

// RouterConfig contains router configuration.
type RouterConfig struct {
	// LocalPeerID is the local peer ID.
	LocalPeerID string

	// LocalIP is the local virtual IP.
	LocalIP netip.Addr

	// MaxHops is the maximum number of hops.
	MaxHops int

	// RouteTimeout is the route expiry timeout.
	RouteTimeout time.Duration

	// PathCostFunc calculates path costs.
	PathCostFunc PathCostFunc
}

// DefaultRouterConfig returns a default router configuration.
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		MaxHops:      8,
		RouteTimeout: 5 * time.Minute,
		PathCostFunc: DefaultPathCostFunc,
	}
}

// DefaultPathCostFunc is the default path cost function.
func DefaultPathCostFunc(latency time.Duration, hopCount int) int {
	// Cost = latency_ms + (hopCount * 100)
	return int(latency.Milliseconds()) + (hopCount * 100)
}

// NewMeshRouter creates a new mesh router.
func NewMeshRouter(config RouterConfig) *MeshRouter {
	if config.PathCostFunc == nil {
		config.PathCostFunc = DefaultPathCostFunc
	}

	return &MeshRouter{
		localPeerID:  config.LocalPeerID,
		localIP:      config.LocalIP,
		routes:       make(map[string][]*Route),
		routesByIP:   make(map[netip.Addr]*Route),
		directPeers:  make(map[string]bool),
		pathCostFunc: config.PathCostFunc,
		maxHops:      config.MaxHops,
		routeTimeout: config.RouteTimeout,
	}
}

// AddDirectRoute adds a direct route to a peer.
func (r *MeshRouter) AddDirectRoute(peerID string, peerIP netip.Addr, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	route := &Route{
		DestPeerID:  peerID,
		DestIP:      peerIP,
		NextHop:     "",
		Type:        RouteTypeDirect,
		Metric:      r.pathCostFunc(latency, 1),
		Latency:     latency,
		HopCount:    1,
		LastUpdated: time.Now(),
		Active:      true,
	}

	r.addRoute(route)
	r.directPeers[peerID] = true

	slog.Debug("added direct route",
		"dest", peerID,
		"ip", peerIP.String(),
		"latency", latency,
	)

	if r.onRouteChanged != nil {
		r.onRouteChanged(route)
	}
}

// RemoveDirectRoute removes a direct route to a peer.
func (r *MeshRouter) RemoveDirectRoute(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.directPeers, peerID)
	r.removeRoutesTo(peerID)

	slog.Debug("removed direct route", "dest", peerID)
}

// AddRoute adds or updates a route.
func (r *MeshRouter) AddRoute(route *Route) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate route
	if route.HopCount > r.maxHops {
		return
	}

	// Don't add routes to ourselves
	if route.DestPeerID == r.localPeerID {
		return
	}

	// Update timestamps
	route.LastUpdated = time.Now()

	r.addRoute(route)

	if r.onRouteChanged != nil {
		r.onRouteChanged(route)
	}
}

// addRoute adds a route (must hold lock).
func (r *MeshRouter) addRoute(route *Route) {
	routes := r.routes[route.DestPeerID]

	// Check if we already have this route
	for i, existing := range routes {
		if existing.NextHop == route.NextHop {
			// Update existing route
			routes[i] = route
			r.updateBestRoute(route.DestPeerID)
			return
		}
	}

	// Add new route
	r.routes[route.DestPeerID] = append(routes, route)
	r.updateBestRoute(route.DestPeerID)
}

// removeRoutesTo removes all routes to a peer.
func (r *MeshRouter) removeRoutesTo(peerID string) {
	// Remove direct routes
	routes := r.routes[peerID]
	for _, route := range routes {
		if route.DestIP.IsValid() {
			delete(r.routesByIP, route.DestIP)
		}
	}
	delete(r.routes, peerID)

	// Remove routes via this peer
	for destPeerID, routes := range r.routes {
		filtered := make([]*Route, 0, len(routes))
		for _, route := range routes {
			if route.NextHop != peerID {
				filtered = append(filtered, route)
			}
		}
		if len(filtered) > 0 {
			r.routes[destPeerID] = filtered
			r.updateBestRoute(destPeerID)
		} else {
			for _, route := range r.routes[destPeerID] {
				if route.DestIP.IsValid() {
					delete(r.routesByIP, route.DestIP)
				}
			}
			delete(r.routes, destPeerID)
		}
	}
}

// updateBestRoute updates the best route for a destination.
func (r *MeshRouter) updateBestRoute(peerID string) {
	routes := r.routes[peerID]
	if len(routes) == 0 {
		return
	}

	// Sort by metric
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Metric < routes[j].Metric
	})

	best := routes[0]

	// Update IP lookup
	if best.DestIP.IsValid() {
		r.routesByIP[best.DestIP] = best
	}
}

// GetRoute returns the best route to a peer.
func (r *MeshRouter) GetRoute(peerID string) *Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := r.routes[peerID]
	if len(routes) == 0 {
		return nil
	}

	// Return the best (lowest metric) route
	return routes[0]
}

// GetRouteByIP returns the route for a virtual IP.
func (r *MeshRouter) GetRouteByIP(ip netip.Addr) *Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.routesByIP[ip]
}

// GetNextHop returns the next hop peer ID for a destination.
func (r *MeshRouter) GetNextHop(destPeerID string) string {
	route := r.GetRoute(destPeerID)
	if route == nil {
		return ""
	}

	if route.Type == RouteTypeDirect {
		return destPeerID
	}

	return route.NextHop
}

// GetNextHopByIP returns the next hop peer ID for a virtual IP.
func (r *MeshRouter) GetNextHopByIP(ip netip.Addr) string {
	route := r.GetRouteByIP(ip)
	if route == nil {
		return ""
	}

	if route.Type == RouteTypeDirect {
		return route.DestPeerID
	}

	return route.NextHop
}

// GetAllRoutes returns all routes.
func (r *MeshRouter) GetAllRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*Route, 0)
	for _, peerRoutes := range r.routes {
		routes = append(routes, peerRoutes...)
	}

	return routes
}

// GetBestRoutes returns the best route to each destination.
func (r *MeshRouter) GetBestRoutes() []*Route {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*Route, 0, len(r.routes))
	for _, peerRoutes := range r.routes {
		if len(peerRoutes) > 0 {
			routes = append(routes, peerRoutes[0])
		}
	}

	return routes
}

// GetDirectPeers returns all directly connected peers.
func (r *MeshRouter) GetDirectPeers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]string, 0, len(r.directPeers))
	for peerID := range r.directPeers {
		peers = append(peers, peerID)
	}

	return peers
}

// IsDirect returns whether there's a direct route to a peer.
func (r *MeshRouter) IsDirect(peerID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.directPeers[peerID]
}

// UpdateLatency updates the latency for a direct route.
func (r *MeshRouter) UpdateLatency(peerID string, latency time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	routes := r.routes[peerID]
	for _, route := range routes {
		if route.Type == RouteTypeDirect {
			route.Latency = latency
			route.Metric = r.pathCostFunc(latency, route.HopCount)
			route.LastUpdated = time.Now()
		}
	}

	r.updateBestRoute(peerID)
}

// ExpireRoutes removes stale routes.
func (r *MeshRouter) ExpireRoutes() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	expired := make([]string, 0)

	for peerID, routes := range r.routes {
		active := make([]*Route, 0, len(routes))
		for _, route := range routes {
			// Don't expire direct routes
			if route.Type == RouteTypeDirect && r.directPeers[peerID] {
				active = append(active, route)
				continue
			}

			if now.Sub(route.LastUpdated) > r.routeTimeout {
				slog.Debug("route expired",
					"dest", peerID,
					"via", route.NextHop,
				)
			} else {
				active = append(active, route)
			}
		}

		if len(active) > 0 {
			r.routes[peerID] = active
			r.updateBestRoute(peerID)
		} else {
			expired = append(expired, peerID)
		}
	}

	for _, peerID := range expired {
		for _, route := range r.routes[peerID] {
			if route.DestIP.IsValid() {
				delete(r.routesByIP, route.DestIP)
			}
		}
		delete(r.routes, peerID)
	}
}

// OnRouteChanged sets the route change callback.
func (r *MeshRouter) OnRouteChanged(callback func(*Route)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRouteChanged = callback
}

// RouteTableStats contains routing table statistics.
type RouteTableStats struct {
	TotalRoutes   int
	DirectRoutes  int
	NextHopRoutes int
	RelayRoutes   int
	Destinations  int
}

// GetStats returns routing table statistics.
func (r *MeshRouter) GetStats() RouteTableStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RouteTableStats{
		Destinations: len(r.routes),
	}

	for _, routes := range r.routes {
		stats.TotalRoutes += len(routes)
		for _, route := range routes {
			switch route.Type {
			case RouteTypeDirect:
				stats.DirectRoutes++
			case RouteTypeNextHop:
				stats.NextHopRoutes++
			case RouteTypeRelay:
				stats.RelayRoutes++
			}
		}
	}

	return stats
}

// ForwardingEntry represents an entry in the forwarding table.
type ForwardingEntry struct {
	DestIP    netip.Prefix
	NextHopIP netip.Addr
	Interface string
	Metric    int
}

// GetForwardingTable returns the forwarding table.
func (r *MeshRouter) GetForwardingTable() []ForwardingEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := make([]ForwardingEntry, 0, len(r.routesByIP))

	for destIP, route := range r.routesByIP {
		// Create host route
		prefix := netip.PrefixFrom(destIP, destIP.BitLen())

		var nextHopIP netip.Addr
		if route.Type == RouteTypeDirect {
			nextHopIP = route.DestIP
		} else {
			// Lookup next hop's IP
			nextHopRoute := r.routes[route.NextHop]
			if len(nextHopRoute) > 0 {
				nextHopIP = nextHopRoute[0].DestIP
			}
		}

		entries = append(entries, ForwardingEntry{
			DestIP:    prefix,
			NextHopIP: nextHopIP,
			Metric:    route.Metric,
		})
	}

	return entries
}
