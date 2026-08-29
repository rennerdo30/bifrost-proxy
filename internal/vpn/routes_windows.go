//go:build windows

package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// windowsRouteManager implements RouteManager for Windows.
type windowsRouteManager struct {
	tunName         string
	tunAddr         netip.Prefix
	ifIndex         int
	savedRoutes     []SavedRoute
	bypassRoutes    []string
	originalGateway string
	originalDNS     []string
	mu              sync.Mutex
}

func newPlatformRouteManager() RouteManager {
	return &windowsRouteManager{
		savedRoutes:  make([]SavedRoute, 0),
		bypassRoutes: make([]string, 0),
	}
}

// Setup configures routes for the VPN on Windows.
func (r *windowsRouteManager) Setup(ctx context.Context, tunName string, cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tunName = tunName

	// Parse TUN address
	var err error
	r.tunAddr, err = netip.ParsePrefix(cfg.TUN.Address)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}

	// Get interface index
	iface, err := net.InterfaceByName(tunName)
	if err != nil {
		// Try finding by address
		iface, err = r.findInterfaceByAddr(r.tunAddr.Addr())
		if err != nil {
			return fmt.Errorf("could not find interface: %w", err)
		}
	}
	r.ifIndex = iface.Index

	// Save original default gateway
	r.originalGateway, err = r.getDefaultGateway()
	if err != nil {
		slog.Warn("could not get default gateway", "error", err)
	}

	// From here on every failure is FATAL and rolls back what was added: a
	// route that could not be installed means traffic the operator asked to
	// tunnel (or bypass) flows somewhere else, while the caller — the desktop
	// VPN toggle above all — would report the VPN as on. Warning and returning
	// nil here was exactly the fake success the audit flagged. A route that
	// already exists is fine (see routeAlreadyExists); anything else is not.
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

	tunGateway := r.tunAddr.Addr().String()

	if cfg.SplitTunnel.Mode == "exclude" {
		// Exclude mode: route all traffic through TUN using two specific routes.
		// These ARE the tunnel — without either of them traffic leaks over the
		// physical interface.
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := r.addRoute(cidr, tunGateway, r.ifIndex); err != nil {
				r.rollbackLocked()
				return fmt.Errorf("add VPN default route %s: %w", cidr, err)
			}
			r.savedRoutes = append(r.savedRoutes, SavedRoute{
				Entry: RouteEntry{
					Destination: cidr,
					Gateway:     tunGateway,
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
			if err := r.addRoute(dest, tunGateway, r.ifIndex); err != nil {
				r.rollbackLocked()
				return fmt.Errorf("add include route %s: %w", dest, err)
			}
			r.savedRoutes = append(r.savedRoutes, SavedRoute{
				Entry: RouteEntry{
					Destination: dest,
					Gateway:     tunGateway,
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
		"ifIndex", r.ifIndex,
	)

	return nil
}

// rollbackLocked undoes everything a partially completed Setup installed, so a
// failed Setup leaves the system as it found it. Callers must hold r.mu.
func (r *windowsRouteManager) rollbackLocked() {
	for i := len(r.savedRoutes) - 1; i >= 0; i-- {
		route := r.savedRoutes[i]
		if !route.WasAdded {
			continue
		}
		if err := r.deleteRoute(route.Entry.Destination); err != nil {
			slog.Warn("rollback: failed to remove route", "destination", route.Entry.Destination, "error", err)
		}
	}
	r.savedRoutes = r.savedRoutes[:0]

	for _, cidr := range r.bypassRoutes {
		if err := r.deleteRoute(cidr); err != nil {
			slog.Warn("rollback: failed to remove bypass route", "cidr", cidr, "error", err)
		}
	}
	r.bypassRoutes = r.bypassRoutes[:0]

	if err := r.restoreDNS(); err != nil {
		slog.Warn("rollback: failed to restore DNS", "error", err)
	}
}

// Cleanup removes VPN routes and restores original configuration.
func (r *windowsRouteManager) Cleanup(ctx context.Context) error {
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
func (r *windowsRouteManager) AddBypassRoute(destination string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addBypassRouteLocked(destination)
}

// addBypassRouteLocked is AddBypassRoute without the lock, for Setup, which
// already holds r.mu.
func (r *windowsRouteManager) addBypassRouteLocked(destination string) error {
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

	// Add route through original gateway (if index 0 means use default)
	if r.originalGateway != "" {
		if err := r.addRoute(destination, r.originalGateway, 0); err != nil {
			return err
		}
	}

	r.bypassRoutes = append(r.bypassRoutes, destination)
	return nil
}

// RemoveBypassRoute removes a bypass route.
func (r *windowsRouteManager) RemoveBypassRoute(destination string) error {
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
func (r *windowsRouteManager) addRoute(destination, gateway string, ifIndex int) error {
	prefix, err := netip.ParsePrefix(destination)
	if err != nil {
		return err
	}

	network := prefix.Masked().Addr().String()
	mask := prefixLengthToMask(prefix.Bits())

	args := []string{"add", network, "mask", mask, gateway}
	if ifIndex > 0 {
		args = append(args, "if", fmt.Sprintf("%d", ifIndex))
	}

	cmd := exec.Command("route", args...) //nolint:gosec // G204: VPN route management requires system commands
	output, err := cmd.CombinedOutput()
	if err != nil {
		// The desired route already being present is the desired state, not a
		// failure — distinguish it so Setup does not roll a working
		// configuration back over it.
		if routeAlreadyExists(string(output)) {
			slog.Debug("route already exists", "destination", destination)
			return nil
		}
		return fmt.Errorf("route add failed: %w: %s", err, string(output))
	}
	return nil
}

// deleteRoute removes a route using the route command.
func (r *windowsRouteManager) deleteRoute(destination string) error {
	prefix, err := netip.ParsePrefix(destination)
	if err != nil {
		return err
	}

	network := prefix.Masked().Addr().String()
	mask := prefixLengthToMask(prefix.Bits())

	cmd := exec.Command("route", "delete", network, "mask", mask) //nolint:gosec // G204: VPN route management requires system commands
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Ignore "not found" errors
		if !strings.Contains(string(output), "not found") && !strings.Contains(string(output), "Element not found") {
			return fmt.Errorf("route delete failed: %w: %s", err, string(output))
		}
	}
	return nil
}

// prefixLengthToMask converts a prefix length to a dotted decimal mask.
func prefixLengthToMask(bits int) string {
	mask := uint32(0xFFFFFFFF) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xFF,
		(mask>>16)&0xFF,
		(mask>>8)&0xFF,
		mask&0xFF)
}

// getDefaultGateway gets the current default gateway.
func (r *windowsRouteManager) getDefaultGateway() (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0") //nolint:gosec // G204: VPN route management requires system commands
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output to find gateway
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			// Route table format: Network, Netmask, Gateway, Interface, Metric
			if len(fields) >= 4 {
				gateway := fields[2]
				// Validate it looks like an IP
				if _, err := netip.ParseAddr(gateway); err == nil {
					return gateway, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find default gateway")
}

// findInterfaceByAddr finds an interface by its IP address.
func (r *windowsRouteManager) findInterfaceByAddr(addr netip.Addr) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ifAddr, ok := netip.AddrFromSlice(ipnet.IP); ok {
					if ifAddr == addr {
						return &iface, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("interface not found for address %s", addr)
}

// configureDNS configures the system to use our DNS server.
func (r *windowsRouteManager) configureDNS(dnsAddr string) error {
	// Extract IP from address
	host, _ := splitHostPort(dnsAddr)
	if host == "" {
		host = dnsAddr
	}

	// Save current DNS
	cmd := exec.Command("netsh", "interface", "ip", "show", "dns", r.tunName) //nolint:gosec // G204: VPN route management requires system commands
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "DNS Server") || strings.Contains(line, "Statically Configured") {
				fields := strings.Fields(line)
				for _, field := range fields {
					if addr, err := netip.ParseAddr(field); err == nil {
						r.originalDNS = append(r.originalDNS, addr.String())
					}
				}
			}
		}
	}

	// Set new DNS using netsh
	cmd = exec.Command("netsh", "interface", "ip", "set", "dns", //nolint:gosec // G204: VPN route management requires system commands
		fmt.Sprintf("name=%s", r.tunName),
		"source=static",
		fmt.Sprintf("addr=%s", host),
		"register=primary")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set DNS: %w: %s", err, string(output))
	}

	// Flush DNS cache
	exec.Command("ipconfig", "/flushdns").Run() //nolint:gosec,errcheck // G204: VPN route management requires system commands; best effort

	return nil
}

// restoreDNS restores the original DNS configuration.
func (r *windowsRouteManager) restoreDNS() error {
	// Reset DNS to DHCP
	cmd := exec.Command("netsh", "interface", "ip", "set", "dns", //nolint:gosec // G204: VPN route management requires system commands
		fmt.Sprintf("name=%s", r.tunName),
		"source=dhcp")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore DNS: %w: %s", err, string(output))
	}

	// Flush DNS cache
	exec.Command("ipconfig", "/flushdns").Run() //nolint:gosec,errcheck // G204: VPN route management requires system commands; best effort

	r.originalDNS = nil
	return nil
}

// splitHostPort splits a host:port string.
// splitHostPort splits "host:port", returning the whole string as the host when
// there is no colon. It cannot fail, so it returns no error - the discarded
// error return it used to have made every call site look like it was ignoring
// a failure.
func splitHostPort(addr string) (host, port string) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, ""
	}
	return addr[:lastColon], addr[lastColon+1:]
}
