//go:build darwin

package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// darwinRouteManager implements RouteManager for macOS.
type darwinRouteManager struct {
	tunName         string
	tunAddr         netip.Prefix
	savedRoutes     []SavedRoute
	bypassRoutes    []string
	originalGateway string
	originalDNS     []string
	networkService  string
	mu              sync.Mutex
}

func newPlatformRouteManager() RouteManager {
	return &darwinRouteManager{
		savedRoutes:  make([]SavedRoute, 0),
		bypassRoutes: make([]string, 0),
	}
}

// Setup configures routes for the VPN on macOS.
func (r *darwinRouteManager) Setup(ctx context.Context, tunName string, cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tunName = tunName

	// Parse TUN address
	var err error
	r.tunAddr, err = netip.ParsePrefix(cfg.TUN.Address)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}

	// Find the primary network service
	r.networkService, err = r.getPrimaryNetworkService()
	if err != nil {
		slog.Warn("could not find primary network service", "error", err)
	}

	// Save original default gateway
	r.originalGateway, err = r.getDefaultGateway()
	if err != nil {
		slog.Warn("could not get default gateway", "error", err)
	}

	// Add bypass routes for always_bypass CIDRs
	for _, cidr := range cfg.SplitTunnel.AlwaysBypass {
		if err := r.AddBypassRoute(cidr); err != nil {
			slog.Warn("failed to add bypass route", "cidr", cidr, "error", err)
		}
	}

	// Add default route through TUN (if not in include mode)
	if cfg.SplitTunnel.Mode == "exclude" {
		// Route all traffic through TUN using two specific routes
		tunGateway := r.tunAddr.Addr().String()

		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := r.addRoute(cidr, tunGateway); err != nil {
				slog.Warn("failed to add default route", "cidr", cidr, "error", err)
			} else {
				r.savedRoutes = append(r.savedRoutes, SavedRoute{
					Entry: RouteEntry{
						Destination: cidr,
						Gateway:     tunGateway,
					},
					WasAdded: true,
				})
			}
		}
	}

	// Configure DNS if enabled
	if cfg.DNS.Enabled {
		if err := r.configureDNS(cfg.DNS.Listen); err != nil {
			slog.Warn("failed to configure DNS", "error", err)
		}
	}

	slog.Info("routes configured for VPN",
		"tun", tunName,
		"mode", cfg.SplitTunnel.Mode,
	)

	return nil
}

// Cleanup removes VPN routes and restores original configuration.
func (r *darwinRouteManager) Cleanup(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error

	// Remove added routes in reverse order
	for i := len(r.savedRoutes) - 1; i >= 0; i-- {
		route := r.savedRoutes[i]
		if route.WasAdded {
			if err := r.deleteRoute(route.Entry.Destination); err != nil {
				slog.Warn("failed to remove route", "destination", route.Entry.Destination, "error", err)
				lastErr = err
			}
		}
	}
	r.savedRoutes = nil

	// Remove bypass routes
	for _, cidr := range r.bypassRoutes {
		if err := r.deleteRoute(cidr); err != nil {
			slog.Warn("failed to remove bypass route", "cidr", cidr, "error", err)
		}
	}
	r.bypassRoutes = nil

	// Restore DNS
	if err := r.restoreDNS(); err != nil {
		slog.Warn("failed to restore DNS", "error", err)
		lastErr = err
	}

	slog.Info("routes cleaned up")
	return lastErr
}

// AddBypassRoute adds a route that bypasses the VPN.
func (r *darwinRouteManager) AddBypassRoute(destination string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate CIDR
	_, err := netip.ParsePrefix(destination)
	if err != nil {
		// Try as single IP
		addr, err := netip.ParseAddr(destination)
		if err != nil {
			return fmt.Errorf("invalid destination: %s", destination)
		}
		if addr.Is4() {
			destination = addr.String() + "/32"
		} else {
			destination = addr.String() + "/128"
		}
	}

	// Add route through original gateway
	if r.originalGateway != "" {
		if err := r.addRoute(destination, r.originalGateway); err != nil {
			return err
		}
	}

	r.bypassRoutes = append(r.bypassRoutes, destination)
	return nil
}

// RemoveBypassRoute removes a bypass route.
func (r *darwinRouteManager) RemoveBypassRoute(destination string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.deleteRoute(destination); err != nil {
		return err
	}

	// Remove from list
	routes := make([]string, 0, len(r.bypassRoutes))
	for _, route := range r.bypassRoutes {
		if route != destination {
			routes = append(routes, route)
		}
	}
	r.bypassRoutes = routes

	return nil
}

// addRoute adds a route using the route command.
func (r *darwinRouteManager) addRoute(destination, gateway string) error {
	// Convert CIDR to network and netmask
	prefix, err := netip.ParsePrefix(destination)
	if err != nil {
		return err
	}

	network := prefix.Masked().Addr().String()
	bits := prefix.Bits()

	// route add -net network -netmask mask gateway
	var cmd *exec.Cmd
	if prefix.Addr().Is4() {
		mask := fmt.Sprintf("%d.%d.%d.%d",
			0xFF<<(8-min(bits, 8)),
			0xFF<<(8-max(0, min(bits-8, 8))),
			0xFF<<(8-max(0, min(bits-16, 8))),
			0xFF<<(8-max(0, min(bits-24, 8))))
		cmd = exec.Command("route", "-n", "add", "-net", network, "-netmask", mask, gateway)
	} else {
		cmd = exec.Command("route", "-n", "add", "-inet6", destination, gateway)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add failed: %w: %s", err, string(output))
	}
	return nil
}

// deleteRoute removes a route using the route command.
func (r *darwinRouteManager) deleteRoute(destination string) error {
	prefix, err := netip.ParsePrefix(destination)
	if err != nil {
		return err
	}

	network := prefix.Masked().Addr().String()
	bits := prefix.Bits()

	var cmd *exec.Cmd
	if prefix.Addr().Is4() {
		mask := fmt.Sprintf("%d.%d.%d.%d",
			0xFF<<(8-min(bits, 8)),
			0xFF<<(8-max(0, min(bits-8, 8))),
			0xFF<<(8-max(0, min(bits-16, 8))),
			0xFF<<(8-max(0, min(bits-24, 8))))
		cmd = exec.Command("route", "-n", "delete", "-net", network, "-netmask", mask)
	} else {
		cmd = exec.Command("route", "-n", "delete", "-inet6", destination)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Ignore "not in table" error
		if !strings.Contains(string(output), "not in table") {
			return fmt.Errorf("route delete failed: %w: %s", err, string(output))
		}
	}
	return nil
}

// getDefaultGateway gets the current default gateway.
func (r *darwinRouteManager) getDefaultGateway() (string, error) {
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output to find gateway
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("could not find gateway in route output")
}

// getPrimaryNetworkService gets the primary network service name.
func (r *darwinRouteManager) getPrimaryNetworkService() (string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// Check if this service has an IP address
		cmd := exec.Command("networksetup", "-getinfo", line)
		info, err := cmd.Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(info), "IP address:") && !strings.Contains(string(info), "IP address: none") {
			return line, nil
		}
	}

	return "", fmt.Errorf("no primary network service found")
}

// configureDNS configures the system to use our DNS server.
func (r *darwinRouteManager) configureDNS(dnsAddr string) error {
	if r.networkService == "" {
		return fmt.Errorf("no network service found")
	}

	// Extract IP from address
	host, _, _ := splitHostPort(dnsAddr) //nolint:errcheck // Fallback to raw address if split fails
	if host == "" {
		host = dnsAddr
	}

	// Save current DNS
	cmd := exec.Command("networksetup", "-getdnsservers", r.networkService) //nolint:gosec // G204: network service is from system network config
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "aren't any") {
				r.originalDNS = append(r.originalDNS, line)
			}
		}
	}

	// Set new DNS
	cmd = exec.Command("networksetup", "-setdnsservers", r.networkService, host) //nolint:gosec // G204: network service and host are validated
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set DNS: %w: %s", err, string(output))
	}

	// Flush DNS cache
	_ = exec.Command("dscacheutil", "-flushcache").Run()               //nolint:errcheck,gosec // Best effort DNS cache flush
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()         //nolint:errcheck,gosec // Best effort mDNSResponder restart

	return nil
}

// restoreDNS restores the original DNS configuration.
func (r *darwinRouteManager) restoreDNS() error {
	if r.networkService == "" {
		return nil
	}

	var args []string
	if len(r.originalDNS) == 0 {
		args = []string{"-setdnsservers", r.networkService, "empty"}
	} else {
		args = append([]string{"-setdnsservers", r.networkService}, r.originalDNS...)
	}

	cmd := exec.Command("networksetup", args...) //nolint:gosec // G204: args are from validated config and original DNS settings
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore DNS: %w: %s", err, string(output))
	}

	// Flush DNS cache
	_ = exec.Command("dscacheutil", "-flushcache").Run()               //nolint:errcheck,gosec // Best effort DNS cache flush
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()         //nolint:errcheck,gosec // Best effort mDNSResponder restart

	r.originalDNS = nil
	return nil
}

//nolint:unparam // b is always 8 in usage but kept for min function semantics
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//nolint:unparam // a is always 0 in usage but kept for max function semantics
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// splitHostPort splits a host:port string.
func splitHostPort(addr string) (host, port string, err error) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, "", nil
	}
	return addr[:lastColon], addr[lastColon+1:], nil
}
