package vpn

import (
	"context"
	"fmt"
	"net/netip"
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

// normalizeCIDR parses a CIDR or bare IP and returns it in canonical CIDR
// notation (bare IPs become /32 or /128). It is shared by the platform route
// managers when installing include-mode routes.
func normalizeCIDR(destination string) (string, error) {
	if prefix, err := netip.ParsePrefix(destination); err == nil {
		return prefix.Masked().String(), nil
	}

	addr, err := netip.ParseAddr(destination)
	if err != nil {
		return "", fmt.Errorf("invalid IP or CIDR: %s", destination)
	}
	if addr.Is4() {
		return addr.String() + "/32", nil
	}
	return addr.String() + "/128", nil
}
