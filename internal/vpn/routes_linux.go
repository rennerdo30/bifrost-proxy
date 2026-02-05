//go:build linux

package vpn

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// linuxRouteManager implements RouteManager for Linux.
type linuxRouteManager struct {
	tunName         string
	tunAddr         netip.Prefix
	savedRoutes     []SavedRoute
	savedDNS        []string
	bypassRoutes    []string
	originalGateway string
	mu              sync.Mutex
}

func newPlatformRouteManager() RouteManager {
	return &linuxRouteManager{
		savedRoutes:  make([]SavedRoute, 0),
		bypassRoutes: make([]string, 0),
	}
}

// Setup configures routes for the VPN on Linux.
func (r *linuxRouteManager) Setup(ctx context.Context, tunName string, cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tunName = tunName

	// Parse TUN address
	var err error
	r.tunAddr, err = netip.ParsePrefix(cfg.TUN.Address)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}

	// Save original default gateway
	r.originalGateway, err = r.getDefaultGateway()
	if err != nil {
		slog.Warn("could not get default gateway", "error", err)
	}

	// Add route for TUN subnet
	tunNet := r.tunAddr.Masked()
	if err := r.addRoute(tunNet.String(), "", tunName); err != nil {
		return fmt.Errorf("failed to add TUN route: %w", err)
	}
	r.savedRoutes = append(r.savedRoutes, SavedRoute{
		Entry: RouteEntry{
			Destination: tunNet.String(),
			Interface:   tunName,
		},
		WasAdded: true,
	})

	// Add bypass routes for always_bypass CIDRs
	for _, cidr := range cfg.SplitTunnel.AlwaysBypass {
		if err := r.AddBypassRoute(cidr); err != nil {
			slog.Warn("failed to add bypass route", "cidr", cidr, "error", err)
		}
	}

	// Add default route through TUN (if not in include mode)
	if cfg.SplitTunnel.Mode == "exclude" {
		// Route all traffic through TUN
		// Add two specific routes to cover all IPv4 (0.0.0.0/1 and 128.0.0.0/1)
		// This avoids replacing the default route directly
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := r.addRoute(cidr, "", tunName); err != nil {
				slog.Warn("failed to add default route", "cidr", cidr, "error", err)
			} else {
				r.savedRoutes = append(r.savedRoutes, SavedRoute{
					Entry: RouteEntry{
						Destination: cidr,
						Interface:   tunName,
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
func (r *linuxRouteManager) Cleanup(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error

	// Remove added routes in reverse order
	for i := len(r.savedRoutes) - 1; i >= 0; i-- {
		route := r.savedRoutes[i]
		if route.WasAdded {
			if err := r.deleteRoute(route.Entry.Destination, route.Entry.Interface); err != nil {
				slog.Warn("failed to remove route", "destination", route.Entry.Destination, "error", err)
				lastErr = err
			}
		}
	}
	r.savedRoutes = nil

	// Remove bypass routes
	for _, cidr := range r.bypassRoutes {
		if err := r.deleteRoute(cidr, ""); err != nil {
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
func (r *linuxRouteManager) AddBypassRoute(destination string) error {
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
		if err := r.addRoute(destination, r.originalGateway, ""); err != nil {
			return err
		}
	}

	r.bypassRoutes = append(r.bypassRoutes, destination)
	return nil
}

// RemoveBypassRoute removes a bypass route.
func (r *linuxRouteManager) RemoveBypassRoute(destination string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.deleteRoute(destination, ""); err != nil {
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

// addRoute adds a route using ip route.
func (r *linuxRouteManager) addRoute(destination, gateway, iface string) error {
	args := []string{"route", "add", destination}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	if iface != "" {
		args = append(args, "dev", iface)
	}

	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route add failed: %w: %s", err, string(output))
	}
	return nil
}

// deleteRoute removes a route using ip route.
func (r *linuxRouteManager) deleteRoute(destination, iface string) error {
	args := []string{"route", "del", destination}
	if iface != "" {
		args = append(args, "dev", iface)
	}

	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Ignore "No such process" error (route already removed)
		if !strings.Contains(string(output), "No such process") {
			return fmt.Errorf("ip route del failed: %w: %s", err, string(output))
		}
	}
	return nil
}

// getDefaultGateway gets the current default gateway.
func (r *linuxRouteManager) getDefaultGateway() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output: default via 192.168.1.1 dev eth0 ...
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not parse default gateway")
}

// configureDNS configures the system to use our DNS server.
func (r *linuxRouteManager) configureDNS(dnsAddr string) error {
	// Extract IP from address
	host, _, err := splitHostPort(dnsAddr)
	if err != nil {
		host = dnsAddr
	}

	// Save current resolv.conf
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "nameserver") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					r.savedDNS = append(r.savedDNS, fields[1])
				}
			}
		}
	}

	// Try to use resolvectl if available (systemd-resolved)
	if _, err := exec.LookPath("resolvectl"); err == nil {
		cmd := exec.Command("resolvectl", "dns", r.tunName, host) //nolint:gosec // G204: tunName and host are validated
		if err := cmd.Run(); err != nil {
			slog.Debug("resolvectl failed, trying resolv.conf", "error", err)
		} else {
			// Set as default DNS
			cmd = exec.Command("resolvectl", "default-route", r.tunName, "true") //nolint:gosec // G204: tunName is validated
			_ = cmd.Run()                                                        //nolint:errcheck // Best effort
			return nil
		}
	}

	// Fall back to modifying resolv.conf directly
	// Create new resolv.conf with our DNS server first
	newContent := fmt.Sprintf("# Modified by Bifrost VPN\nnameserver %s\n", host)
	for _, ns := range r.savedDNS {
		newContent += fmt.Sprintf("nameserver %s\n", ns)
	}

	return os.WriteFile("/etc/resolv.conf", []byte(newContent), 0644) //nolint:gosec // G306: resolv.conf must be world-readable
}

// restoreDNS restores the original DNS configuration.
func (r *linuxRouteManager) restoreDNS() error {
	if len(r.savedDNS) == 0 {
		return nil
	}

	// Try resolvectl first
	if _, err := exec.LookPath("resolvectl"); err == nil {
		_ = exec.Command("resolvectl", "revert", r.tunName).Run() //nolint:gosec,errcheck // G204: tunName is validated; best effort
	}

	// Restore resolv.conf
	content := "# Restored by Bifrost VPN\n"
	for _, ns := range r.savedDNS {
		content += fmt.Sprintf("nameserver %s\n", ns)
	}

	r.savedDNS = nil
	return os.WriteFile("/etc/resolv.conf", []byte(content), 0644) //nolint:gosec // G306: resolv.conf must be world-readable
}

// splitHostPort splits a host:port string.
func splitHostPort(addr string) (host, port string, err error) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, "", nil
	}
	return addr[:lastColon], addr[lastColon+1:], nil
}
