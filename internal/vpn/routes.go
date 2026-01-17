package vpn

import (
	"context"
)

// RouteManager manages system routing tables for the VPN.
type RouteManager interface {
	// Setup configures routes for the VPN.
	Setup(ctx context.Context, tunName string, cfg Config) error

	// Cleanup removes VPN routes and restores original configuration.
	Cleanup(ctx context.Context) error

	// AddBypassRoute adds a route that bypasses the VPN.
	AddBypassRoute(destination string) error

	// RemoveBypassRoute removes a bypass route.
	RemoveBypassRoute(destination string) error
}

// NewRouteManager creates a platform-specific route manager.
func NewRouteManager() RouteManager {
	return newPlatformRouteManager()
}

// RouteEntry represents a routing table entry.
type RouteEntry struct {
	Destination string // CIDR notation
	Gateway     string // Next hop
	Interface   string // Interface name
	Metric      int    // Route metric
}

// SavedRoute stores original route information for restoration.
type SavedRoute struct {
	Entry    RouteEntry
	WasAdded bool // True if this route was added by VPN
}
