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

	// Add bypass routes for always_bypass CIDRs
	for _, cidr := range cfg.SplitTunnel.AlwaysBypass {
		if err := r.AddBypassRoute(cidr); err != nil {
			slog.Warn("failed to add bypass route", "cidr", cidr, "error", err)
		}
	}

	// Add default route through TUN (if not in include mode)
	if cfg.SplitTunnel.Mode == "exclude" {
		tunGateway := r.tunAddr.Addr().String()

		// Route all traffic through TUN using two specific routes
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := r.addRoute(cidr, tunGateway, r.ifIndex); err != nil {
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
		"ifIndex", r.ifIndex,
	)

	return nil
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
	host, _, _ := splitHostPort(dnsAddr)
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
func splitHostPort(addr string) (host, port string, err error) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, "", nil
	}
	return addr[:lastColon], addr[lastColon+1:], nil
}
