package vpn

import (
	"fmt"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/duration"
)

// VPN configuration defaults.
const (
	// DefaultTUNAddress is the default TUN interface address with prefix.
	DefaultTUNAddress = "10.255.0.1/24"
	// DefaultTUNMTU is the default TUN interface MTU.
	DefaultTUNMTU = 1400
	// DefaultDNSListen is the default listen address for the built-in DNS server.
	DefaultDNSListen = "10.255.0.1:53"
	// DefaultDNSCacheTTL is the default DNS response cache lifetime.
	DefaultDNSCacheTTL = 5 * time.Minute
	// DefaultSplitTunnelMode is the default split tunnel mode.
	DefaultSplitTunnelMode = ModeExclude
	// DefaultInterceptMode is the default DNS intercept mode.
	DefaultInterceptMode = InterceptModeAll
)

// DefaultDNSUpstream lists the upstream resolvers used when none are configured.
func DefaultDNSUpstream() []string {
	return []string{"8.8.8.8", "1.1.1.1"}
}

// DNS intercept modes.
const (
	// InterceptModeAll intercepts every DNS query.
	InterceptModeAll = "all"
	// InterceptModeTunnelOnly intercepts only queries for tunneled destinations.
	InterceptModeTunnelOnly = "tunnel_only"
)

// Config contains all VPN configuration.
type Config struct {
	// Enabled controls whether VPN mode is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TUN contains TUN device configuration.
	TUN TUNConfig `yaml:"tun" json:"tun"`

	// SplitTunnel contains split tunneling configuration.
	SplitTunnel SplitTunnelConfig `yaml:"split_tunnel" json:"split_tunnel"`

	// DNS contains DNS server configuration.
	DNS DNSConfig `yaml:"dns" json:"dns"`
}

// DNSConfig contains DNS server configuration.
type DNSConfig struct {
	// Enabled controls whether the built-in DNS server is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Listen is the address to listen on (e.g., "10.255.0.1:53").
	Listen string `yaml:"listen" json:"listen"`

	// Upstream lists upstream DNS servers to forward queries to.
	Upstream []string `yaml:"upstream" json:"upstream"`

	// CacheTTL is the duration to cache DNS responses.
	CacheTTL duration.Duration `yaml:"cache_ttl" json:"cache_ttl"`

	// InterceptMode controls which DNS queries are intercepted.
	// "all": Intercept all DNS queries
	// "tunnel_only": Only intercept queries for tunneled destinations
	InterceptMode string `yaml:"intercept_mode" json:"intercept_mode"`
}

// Validate validates the DNS configuration.
func (c *DNSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Listen == "" {
		c.Listen = DefaultDNSListen
	}

	if len(c.Upstream) == 0 {
		c.Upstream = DefaultDNSUpstream()
	}

	if c.CacheTTL == 0 {
		c.CacheTTL = duration.Duration(DefaultDNSCacheTTL)
	}

	if c.InterceptMode == "" {
		c.InterceptMode = DefaultInterceptMode
	}

	if c.InterceptMode != InterceptModeAll && c.InterceptMode != InterceptModeTunnelOnly {
		return &ConfigError{
			Field:   "dns.intercept_mode",
			Message: "must be 'all' or 'tunnel_only'",
		}
	}

	return nil
}

// Validate validates the VPN configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // No validation needed if disabled
	}

	if err := c.TUN.Validate(); err != nil {
		return fmt.Errorf("invalid TUN config: %w", err)
	}

	if err := c.SplitTunnel.Validate(); err != nil {
		return fmt.Errorf("invalid split tunnel config: %w", err)
	}

	if err := c.DNS.Validate(); err != nil {
		return fmt.Errorf("invalid DNS config: %w", err)
	}

	return nil
}

// DefaultConfig returns the default VPN configuration.
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		TUN: TUNConfig{
			Name:    defaultTUNName(),
			Address: DefaultTUNAddress,
			MTU:     DefaultTUNMTU,
		},
		SplitTunnel: SplitTunnelConfig{
			Mode: DefaultSplitTunnelMode,
			Apps: []AppRule{},
			Domains: []string{
				"*.local",
			},
			IPs: []string{},
			AlwaysBypass: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
		DNS: DNSConfig{
			Enabled:       true,
			Listen:        DefaultDNSListen,
			Upstream:      DefaultDNSUpstream(),
			CacheTTL:      duration.Duration(DefaultDNSCacheTTL),
			InterceptMode: DefaultInterceptMode,
		},
	}
}
