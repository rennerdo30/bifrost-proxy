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

	// From here on every failure is FATAL and rolls back what was added: a
	// route that could not be installed means traffic the operator asked to
	// tunnel (or bypass) flows somewhere else, while the caller — the desktop
	// VPN toggle above all — would report the VPN as on. A route that already
	// exists is fine (see routeAlreadyExists); anything else is not.
	//
	// The bypass routes go through addBypassRouteLocked: the exported
	// AddBypassRoute takes r.mu, which Setup already holds, so calling it here
	// self-deadlocked on the DEFAULT config (three always_bypass entries).
	for _, cidr := range cfg.SplitTunnel.AlwaysBypass {
		if err := r.addBypassRouteLocked(cidr); err != nil {
			r.rollbackLocked()
			return fmt.Errorf("add bypass route %s: %w", cidr, err)
		}
	}

	if cfg.SplitTunnel.Mode == "exclude" {
		// Exclude mode: route all traffic through TUN.
		// Add two specific routes to cover all IPv4 (0.0.0.0/1 and 128.0.0.0/1)
		// This avoids replacing the default route directly. These ARE the
		// tunnel — without either of them traffic leaks over the physical
		// interface.
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := r.addRoute(cidr, "", tunName); err != nil {
				r.rollbackLocked()
				return fmt.Errorf("add VPN default route %s: %w", cidr, err)
			}
			r.savedRoutes = append(r.savedRoutes, SavedRoute{
				Entry: RouteEntry{
					Destination: cidr,
					Interface:   tunName,
				},
				WasAdded: true,
			})
		}
	} else {
		// Include mode: only the configured IPs/CIDRs are routed into the TUN;
		// everything else keeps using the existing default route. App/domain
		// rules are resolved to IPs dynamically by the DNS server and
		// split-tunnel engine, so only static IP rules get system routes here.
		for _, cidr := range cfg.SplitTunnel.IPs {
			dest, err := normalizeCIDR(cidr)
			if err != nil {
				r.rollbackLocked()
				return fmt.Errorf("invalid include IP/CIDR %s: %w", cidr, err)
			}
			if err := r.addRoute(dest, "", tunName); err != nil {
				r.rollbackLocked()
				return fmt.Errorf("add include route %s: %w", dest, err)
			}
			r.savedRoutes = append(r.savedRoutes, SavedRoute{
				Entry: RouteEntry{
					Destination: dest,
					Interface:   tunName,
				},
				WasAdded: true,
			})
		}
	}

	// Configure DNS if enabled. In exclude (full-tunnel) mode a failure here
	// would leave system DNS queries going to the old resolver off-tunnel
	// while the UI claims the VPN is on, so it is fatal like the routes.
	if cfg.DNS.Enabled {
		if err := r.configureDNS(cfg.DNS.Listen); err != nil {
			r.rollbackLocked()
			return fmt.Errorf("configure DNS: %w", err)
		}
	}

	slog.Info("routes configured for VPN",
		"tun", tunName,
		"mode", cfg.SplitTunnel.Mode,
	)

	return nil
}

// rollbackLocked undoes everything a partially completed Setup installed, so a
// failed Setup leaves the system as it found it. Callers must hold r.mu.
func (r *linuxRouteManager) rollbackLocked() {
	for i := len(r.savedRoutes) - 1; i >= 0; i-- {
		route := r.savedRoutes[i]
		if !route.WasAdded {
			continue
		}
		if err := r.deleteRoute(route.Entry.Destination, route.Entry.Interface); err != nil {
			slog.Warn("rollback: failed to remove route", "destination", route.Entry.Destination, "error", err)
		}
	}
	r.savedRoutes = r.savedRoutes[:0]

	for _, cidr := range r.bypassRoutes {
		if err := r.deleteRoute(cidr, ""); err != nil {
			slog.Warn("rollback: failed to remove bypass route", "cidr", cidr, "error", err)
		}
	}
	r.bypassRoutes = r.bypassRoutes[:0]

	if err := r.restoreDNS(); err != nil {
		slog.Warn("rollback: failed to restore DNS", "error", err)
	}
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
	return r.addBypassRouteLocked(destination)
}

// addBypassRouteLocked is AddBypassRoute without the lock, for Setup, which
// already holds r.mu.
func (r *linuxRouteManager) addBypassRouteLocked(destination string) error {
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

	cmd := exec.Command("ip", args...) //nolint:gosec // G204: VPN route management requires system commands
	output, err := cmd.CombinedOutput()
	if err != nil {
		// The desired route already being present is the desired state, not a
		// failure — distinguish it so Setup does not roll a working
		// configuration back over it.
		if routeAlreadyExists(string(output)) {
			slog.Debug("route already exists", "destination", destination)
			return nil
		}
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

	cmd := exec.Command("ip", args...) //nolint:gosec // G204: VPN route management requires system commands
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
	cmd := exec.Command("ip", "route", "show", "default") //nolint:gosec // G204: VPN route management requires system commands
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
	host, _ := splitHostPort(dnsAddr)

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
			// Make the tunnel authoritative for DNS. This is the step that
			// stops queries going to the pre-existing resolver, so it is not
			// best-effort: if it fails, DNS still resolves - via the original
			// servers - and the VPN looks healthy while leaking every lookup.
			// Fall through to the resolv.conf path rather than returning nil.
			cmd = exec.Command("resolvectl", "default-route", r.tunName, "true") //nolint:gosec // G204: tunName is validated
			if err := cmd.Run(); err != nil {
				slog.Warn("resolvectl could not make the tunnel the default DNS route; falling back to resolv.conf to avoid leaking queries",
					"interface", r.tunName, "error", err)
			} else {
				return nil
			}
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

// splitHostPort splits "host:port", returning the whole string as the host when
// there is no colon. It cannot fail, so it returns no error - the error return
// it used to have was never non-nil, which made every call site look like it
// was handling a failure that could not happen.
func splitHostPort(addr string) (host, port string) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, ""
	}
	return addr[:lastColon], addr[lastColon+1:]
}
