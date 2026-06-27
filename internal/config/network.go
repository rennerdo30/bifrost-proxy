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
	// IPv6 enables use of IPv6 addresses for outbound connections. When false,
	// dials are restricted to IPv4 ("tcp4").
	IPv6 bool `yaml:"ipv6" json:"ipv6"`

	// PreferIPv6 prefers IPv6 over IPv4 when a destination resolves to both.
	// Only meaningful when IPv6 is true.
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

// AddressFamily returns the network string ("tcp", "tcp4") to use for outbound
// dials based on the IPv6 toggle. "tcp" lets the resolver use either family;
// "tcp4" forces IPv4 only.
func (n NetworkConfig) AddressFamily() string {
	if n.IPv6 {
		return "tcp"
	}
	return "tcp4"
}
