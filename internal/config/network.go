package config

// NetworkConfig contains network-level tuning for outbound (backend) dials and
// inbound listeners. Fields are optional; zero values fall back to Go/OS
// defaults.
//
// Only the straightforward, self-contained fields are applied today:
//   - IPv6 / PreferIPv6 control address-family selection for outbound dials.
//   - KeepAlive sets the TCP keep-alive period on outbound dials.
//   - MaxConnections is a process-wide ceiling on concurrent proxied
//     connections (0 = unlimited).
//
// DialTimeout is surfaced for completeness but listener-specific timeouts
// continue to be taken from the per-listener config.
type NetworkConfig struct {
	// IPv6 controls the outbound-dial address family. It is a pointer so that
	// "unset" (the default) is distinguishable from an explicit value:
	//   - unset (nil) or true -> dual-stack ("tcp", either family). This is the
	//     historical default; leaving it unset must NOT restrict address family.
	//   - explicit false      -> IPv4 only ("tcp4").
	IPv6 *bool `yaml:"ipv6" json:"ipv6"`

	// PreferIPv6 prefers IPv6 over IPv4 when a destination resolves to both.
	PreferIPv6 bool `yaml:"prefer_ipv6" json:"prefer_ipv6"`

	// KeepAlive is the TCP keep-alive period applied to outbound dials.
	// Zero leaves the Go default in place; negative disables keep-alive.
	KeepAlive Duration `yaml:"keepalive" json:"keepalive"`

	// DialTimeout is the default timeout for establishing outbound connections
	// when a more specific timeout is not configured.
	DialTimeout Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// MaxConnections is a process-wide ceiling on the number of concurrent
	// proxied connections across all listeners (0 = unlimited).
	MaxConnections int `yaml:"max_connections" json:"max_connections"`
}

// AddressFamily returns the network string ("tcp" or "tcp4") to use for
// outbound dials. The default (IPv6 unset) is dual-stack "tcp" so IPv6-only
// and dual-stack destinations keep working; only an explicit ipv6:false
// restricts dials to IPv4.
func (n NetworkConfig) AddressFamily() string {
	if n.IPv6 != nil && !*n.IPv6 {
		return "tcp4"
	}
	return "tcp"
}
