package vpn

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
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

// routeAlreadyExists reports whether a route-add command failed only because
// the desired route is already present. That outcome IS the desired state, so
// callers treat it as success instead of a setup failure — but every other
// failure is a real one and must not be papered over.
func routeAlreadyExists(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "file exists") || // macOS/BSD route(8), Linux EEXIST
		strings.Contains(lower, "already exists") || // Windows route/netsh
		strings.Contains(lower, "object already exists") // Windows netsh variant
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
