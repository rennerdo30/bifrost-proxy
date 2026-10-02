package proxy

import (
	"errors"
	"net"
	"testing"
)

// withStubs pins the guard's address lookups so tests never touch the host's
// real interfaces or DNS.
func withStubs(g *SelfGuard, local []string, dns map[string][]string) *SelfGuard {
	g.localIPs = func() ([]net.IP, error) {
		ips := make([]net.IP, 0, len(local))
		for _, s := range local {
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			}
		}
		return ips, nil
	}
	g.lookupIP = func(host string) ([]net.IP, error) {
		names, ok := dns[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		ips := make([]net.IP, 0, len(names))
		for _, s := range names {
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			}
		}
		return ips, nil
	}
	return g
}

// TestSelfGuardDetectsOwnListener reproduces the Proxmox incident: a request
// whose target is the proxy's own wildcard listener must be refused, because
// dialing it makes the proxy re-proxy the same target forever.
func TestSelfGuardDetectsOwnListener(t *testing.T) {
	g := withStubs(NewSelfGuard("0.0.0.0:7080", "0.0.0.0:7180"), []string{"192.168.100.107"}, nil)

	if !g.IsSelf("192.168.100.107:7080") {
		t.Fatal("own wildcard listener address must be reported as a loop")
	}
	if !g.IsSelf("127.0.0.1:7080") {
		t.Fatal("loopback on a wildcard listener port must be reported as a loop")
	}
	if !g.IsSelf("192.168.100.107:7180") {
		t.Fatal("second wildcard listener port must be reported as a loop")
	}
}

func TestSelfGuardAllowsNormalTargets(t *testing.T) {
	g := withStubs(NewSelfGuard("0.0.0.0:7080"), []string{"192.168.100.107"}, map[string][]string{
		"example.com": {"93.184.216.34"},
	})

	cases := []string{
		"example.com:443",      // unrelated port
		"example.com:7080",     // our port, but not our address
		"93.184.216.34:7080",   // remote host on our port
		"192.168.100.107:443",  // our address, not our port
		"192.168.100.108:7080", // neighbour on our port
	}
	for _, target := range cases {
		if g.IsSelf(target) {
			t.Errorf("target %q must not be treated as a loop", target)
		}
	}
}

// TestSelfGuardResolvesHostnameToSelf covers a DNS name that points back at
// this host, which loops just as an IP literal does.
func TestSelfGuardResolvesHostnameToSelf(t *testing.T) {
	g := withStubs(NewSelfGuard("0.0.0.0:7080"), []string{"192.168.100.107"}, map[string][]string{
		"proxy.internal": {"192.168.100.107"},
	})

	if !g.IsSelf("proxy.internal:7080") {
		t.Fatal("hostname resolving to our own address must be reported as a loop")
	}
}

// TestSelfGuardExplicitBindOnlyMatchesThatAddress checks that a listener bound
// to one address does not blanket-block its port on every local address.
func TestSelfGuardExplicitBindOnlyMatchesThatAddress(t *testing.T) {
	g := withStubs(NewSelfGuard("127.0.0.1:7090"), []string{"192.168.100.107"}, nil)

	if !g.IsSelf("127.0.0.1:7090") {
		t.Fatal("the explicitly bound address must be reported as a loop")
	}
	if g.IsSelf("192.168.100.107:7090") {
		t.Fatal("a different local address on that port is not that listener")
	}
}

func TestSelfGuardIgnoresMalformedAndEmpty(t *testing.T) {
	g := withStubs(NewSelfGuard("0.0.0.0:7080"), []string{"192.168.100.107"}, nil)

	for _, target := range []string{"", "no-port", "192.168.100.107", "::::"} {
		if g.IsSelf(target) {
			t.Errorf("malformed target %q must not be treated as a loop", target)
		}
	}

	if NewSelfGuard().IsSelf("192.168.100.107:7080") {
		t.Error("a guard with no listeners must never report a loop")
	}
	var nilGuard *SelfGuard
	if nilGuard.IsSelf("192.168.100.107:7080") {
		t.Error("a nil guard must be inert")
	}
}

func TestSelfGuardSkipsBadListenAddrs(t *testing.T) {
	g := withStubs(NewSelfGuard("not-an-addr", "0.0.0.0:7080"), []string{"192.168.100.107"}, nil)

	if !g.IsSelf("192.168.100.107:7080") {
		t.Fatal("a valid listener alongside an unparsable one must still guard")
	}
}

// TestSelfGuardHostnameListenerFailsClosed documents that a listener given as
// a hostname guards its whole port rather than being resolved at startup.
func TestSelfGuardHostnameListenerFailsClosed(t *testing.T) {
	g := withStubs(NewSelfGuard("proxy.internal:7080"), []string{"192.168.100.107"}, nil)

	if !g.IsSelf("192.168.100.107:7080") {
		t.Fatal("a hostname listener must guard its port on local addresses")
	}
}
