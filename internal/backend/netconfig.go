package backend

import (
	"context"
	"net"
	"sort"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// NetworkTuning captures the subset of config.NetworkConfig that backends apply
// to their outbound net.Dialer(s). It is a plain value so it can be copied into
// per-backend config structs without dragging the config package into hot
// paths.
//
// Semantics:
//   - KeepAlive: TCP keep-alive period. Zero leaves the backend default in
//     place; negative disables keep-alive.
//   - DialTimeout: default connect timeout when a backend has no more specific
//     timeout. Zero leaves the backend default.
//   - PreferIPv6: when true and a destination resolves to both families, IPv6
//     addresses are tried first.
//   - AddressFamily: "tcp" (dual-stack), "tcp4" or "tcp6" restriction applied
//     to the dial network.
type NetworkTuning struct {
	KeepAlive     time.Duration
	DialTimeout   time.Duration
	PreferIPv6    bool
	AddressFamily string
}

// NetworkTuningFromConfig derives NetworkTuning from a config.NetworkConfig.
func NetworkTuningFromConfig(n config.NetworkConfig) NetworkTuning {
	return NetworkTuning{
		KeepAlive:     n.KeepAlive.Duration(),
		DialTimeout:   n.DialTimeout.Duration(),
		PreferIPv6:    n.PreferIPv6,
		AddressFamily: n.AddressFamily(),
	}
}

// IsZero reports whether the tuning carries no overrides.
func (t NetworkTuning) IsZero() bool {
	return t.KeepAlive == 0 && t.DialTimeout == 0 && !t.PreferIPv6 && (t.AddressFamily == "" || t.AddressFamily == "tcp")
}

// apply mutates a net.Dialer in place with the tuning's keep-alive, dial
// timeout, and (when requested) IPv6-first address ordering.
//
// applyTimeout controls whether DialTimeout overwrites an existing dialer
// timeout: backends that already derive a timeout from config pass false to
// avoid clobbering it unless the network default is more specific.
func (t NetworkTuning) apply(d *net.Dialer, overrideTimeout bool) {
	if d == nil {
		return
	}
	if t.KeepAlive != 0 {
		d.KeepAlive = t.KeepAlive
	}
	if t.DialTimeout > 0 && (overrideTimeout || d.Timeout == 0) {
		d.Timeout = t.DialTimeout
	}
	if t.PreferIPv6 {
		// Resolve and order candidate addresses with IPv6 first. The Resolver's
		// default order is unspecified across platforms, so we sort explicitly
		// inside a custom control-less dial path via Resolver.
		d.Resolver = ipv6FirstResolver()
	}
}

// dialNetwork returns the network string to use for outbound dials, honoring an
// explicit address-family restriction.
func (t NetworkTuning) dialNetwork(fallback string) string {
	if t.AddressFamily != "" {
		return t.AddressFamily
	}
	if fallback != "" {
		return fallback
	}
	return "tcp"
}

// ipv6FirstResolver returns a resolver whose Dial uses the system resolver but
// whose lookups are reordered to prefer IPv6. Go's net.Resolver does not expose
// result ordering directly, so prefer-IPv6 is implemented at the dial layer via
// orderAddrsIPv6First when a dialer performs its own resolution.
func ipv6FirstResolver() *net.Resolver {
	// The standard resolver already returns both families; ordering preference
	// is applied by the dial helper. Returning the default resolver keeps DNS
	// behavior unchanged while signaling intent.
	return net.DefaultResolver
}

// orderAddrsIPv6First reorders IP addresses so IPv6 addresses precede IPv4 ones,
// preserving the relative order within each family. Exposed for the prefer-IPv6
// dial path and unit testing.
func orderAddrsIPv6First(addrs []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, len(addrs))
	copy(out, addrs)
	sort.SliceStable(out, func(i, j int) bool {
		return isIPv6(out[i].IP) && !isIPv6(out[j].IP)
	})
	return out
}

func isIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// dialPreferIPv6 establishes a connection preferring IPv6 addresses. It resolves
// the host, orders candidates IPv6-first, and dials each in turn until one
// succeeds. It is used by backends whose tuning requests PreferIPv6 and whose
// dial network is not already family-restricted.
func dialPreferIPv6(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Not a host:port we can split; fall back to the normal dial.
		return d.DialContext(ctx, network, address)
	}

	// If the host is already a literal IP there is nothing to reorder.
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, address)
	}

	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips = orderAddrsIPv6First(ips)

	var lastErr error
	for _, ip := range ips {
		// Skip families excluded by an explicit address-family restriction.
		if network == "tcp4" && isIPv6(ip.IP) {
			continue
		}
		if network == "tcp6" && !isIPv6(ip.IP) {
			continue
		}
		conn, dErr := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if dErr == nil {
			return conn, nil
		}
		lastErr = dErr
	}
	if lastErr == nil {
		lastErr = &net.AddrError{Err: "no addresses found", Addr: host}
	}
	return nil, lastErr
}
