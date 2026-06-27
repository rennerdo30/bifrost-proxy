//go:build linux

package backend

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// platformLeakProofRouter returns the Linux policy-routing implementation.
func platformLeakProofRouter(name string) leakProofRouter {
	return &linuxLeakProofRouter{name: name}
}

// linuxLeakProofRouter implements leak-proof egress on Linux using policy
// routing. It creates a dedicated routing table whose default route is the tun
// device that owns localAddr, then adds an `ip rule` matching packets sourced
// from localAddr into that table. This guarantees that connections bound to the
// tunnel source address are routed via the tunnel, never the default interface.
//
// REQUIRES ROOT (CAP_NET_ADMIN). RUNTIME-UNVALIDATED in this build environment.
type linuxLeakProofRouter struct {
	name string

	mu        sync.Mutex
	installed bool
	tableID   int
	localAddr string
	tunDev    string
}

// runIP executes an `ip` subcommand. It is a field so tests can substitute a
// fake without invoking the real binary or requiring root.
var runIP = func(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", args...) //nolint:gosec // G204: args are constructed from validated, numeric/IP values
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// tableIDForName derives a stable routing table id in the range [10000,11000)
// from the backend name, keeping it out of the way of common system tables.
func tableIDForName(name string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return 10000 + int(h.Sum32()%1000)
}

// findTunDevice returns the interface name that owns the given local address.
func findTunDevice(localAddr string) (string, error) {
	target := net.ParseIP(localAddr)
	if target == nil {
		return "", fmt.Errorf("invalid local address %q", localAddr)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, aErr := iface.Addrs()
		if aErr != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(target) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface found for local address %s", localAddr)
}

func (r *linuxLeakProofRouter) Install(ctx context.Context, localAddr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.installed {
		return nil
	}
	if localAddr == "" {
		return fmt.Errorf("leak-proof routing requires a tunnel local address")
	}

	tunDev, err := findTunDevice(localAddr)
	if err != nil {
		return fmt.Errorf("locate tunnel device: %w", err)
	}

	tableID := tableIDForName(r.name)
	table := strconv.Itoa(tableID)

	// Default route in the dedicated table via the tun device.
	if _, err := runIP(ctx, "route", "replace", "default", "dev", tunDev, "table", table); err != nil {
		return fmt.Errorf("install default route: %w", err)
	}

	// Rule: packets sourced from the tunnel IP use the dedicated table.
	if _, err := runIP(ctx, "rule", "add", "from", localAddr, "table", table); err != nil {
		// Roll back the route we just added so we don't leave partial state.
		_, _ = runIP(ctx, "route", "flush", "table", table) //nolint:errcheck // best-effort rollback
		return fmt.Errorf("install policy rule: %w", err)
	}

	r.installed = true
	r.tableID = tableID
	r.localAddr = localAddr
	r.tunDev = tunDev
	return nil
}

func (r *linuxLeakProofRouter) Remove(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.installed {
		return nil
	}

	table := strconv.Itoa(r.tableID)
	var firstErr error
	if _, err := runIP(ctx, "rule", "del", "from", r.localAddr, "table", table); err != nil && firstErr == nil {
		firstErr = err
	}
	if _, err := runIP(ctx, "route", "flush", "table", table); err != nil && firstErr == nil {
		firstErr = err
	}

	r.installed = false
	return firstErr
}
