package proxy

import (
	"net"
	"sync"
	"time"
)

// localIPTTL is how long the set of this host's own addresses is cached before
// being re-read. Interface addresses change rarely, and the lookup only
// happens for a target that already matched one of our listener ports, so a
// short TTL costs nothing on the hot path.
const localIPTTL = 30 * time.Second

// isWildcardListenHost reports whether a listen host binds every local
// address, in which case any local IP on that port is one of our listeners.
func isWildcardListenHost(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	default:
		return false
	}
}

// SelfGuard rejects proxy targets that point back at one of this proxy's own
// listeners.
//
// Without this check a request whose target is the proxy's own listen address
// is self-amplifying: the selected backend dials the listener, the listener
// accepts and re-proxies the very same target, and every hop burns two sockets
// plus a pair of copy goroutines. Nothing in the data path breaks the cycle --
// an opaque tunnel clears its deadlines (see enterTunnel), so the sockets sit
// ESTABLISHED indefinitely -- so the process climbs until it exhausts memory
// and file descriptors.
type SelfGuard struct {
	// wildcardPorts are ports bound on every local address.
	wildcardPorts map[string]struct{}
	// boundAddrs holds explicit ip:port listeners.
	boundAddrs map[string]struct{}
	// watchedPorts is wildcardPorts plus every port in boundAddrs. A target
	// whose port is absent here can never be one of ours, which keeps the
	// common case free of any address lookup.
	watchedPorts map[string]struct{}

	// localIPs returns this host's own addresses. Overridden in tests.
	localIPs func() ([]net.IP, error)
	// lookupIP resolves a hostname target. Overridden in tests.
	lookupIP func(host string) ([]net.IP, error)

	mu       sync.Mutex
	cached   []net.IP
	cachedAt time.Time
}

// NewSelfGuard builds a guard for the given listener addresses ("host:port",
// as they appear in the server config). Addresses that do not parse are
// ignored: a listener the server could not bind cannot be looped into. A guard
// with no usable addresses never reports a loop.
func NewSelfGuard(listenAddrs ...string) *SelfGuard {
	g := &SelfGuard{
		wildcardPorts: make(map[string]struct{}),
		boundAddrs:    make(map[string]struct{}),
		watchedPorts:  make(map[string]struct{}),
		localIPs:      interfaceIPs,
		lookupIP:      net.LookupIP,
	}

	for _, addr := range listenAddrs {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port == "" {
			continue
		}
		if isWildcardListenHost(host) {
			g.wildcardPorts[port] = struct{}{}
		} else if ip := net.ParseIP(host); ip != nil {
			g.boundAddrs[net.JoinHostPort(ip.String(), port)] = struct{}{}
		} else {
			// A hostname listener: treat it as wildcard on that port rather
			// than resolving at startup, so we fail closed on the loop.
			g.wildcardPorts[port] = struct{}{}
		}
		g.watchedPorts[port] = struct{}{}
	}

	return g
}

// interfaceIPs returns every address assigned to a local interface.
func interfaceIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
			ips = append(ips, ipnet.IP)
		}
	}
	return ips, nil
}

// IsSelf reports whether target ("host:port") resolves to one of our own
// listeners. A target without a port, or one that cannot be parsed, is never
// treated as a loop: the proxy data paths always carry an explicit port by the
// time they dial.
func (g *SelfGuard) IsSelf(target string) bool {
	if g == nil || len(g.watchedPorts) == 0 {
		return false
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	if _, watched := g.watchedPorts[port]; !watched {
		return false
	}

	for _, ip := range g.targetIPs(host) {
		if _, ok := g.wildcardPorts[port]; ok && g.isLocalIP(ip) {
			return true
		}
		if _, ok := g.boundAddrs[net.JoinHostPort(ip.String(), port)]; ok {
			return true
		}
	}
	return false
}

// targetIPs resolves a target host to IPs, accepting an IP literal as-is.
func (g *SelfGuard) targetIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := g.lookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

// isLocalIP reports whether ip belongs to this host. Loopback and the
// unspecified address always do.
func (g *SelfGuard) isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	for _, local := range g.currentLocalIPs() {
		if local.Equal(ip) {
			return true
		}
	}
	return false
}

// currentLocalIPs returns the cached local addresses, refreshing on TTL.
func (g *SelfGuard) currentLocalIPs() []net.IP {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.cached != nil && time.Since(g.cachedAt) < localIPTTL {
		return g.cached
	}
	ips, err := g.localIPs()
	if err != nil {
		// Keep any previous snapshot rather than losing loop protection.
		return g.cached
	}
	g.cached, g.cachedAt = ips, time.Now()
	return g.cached
}
