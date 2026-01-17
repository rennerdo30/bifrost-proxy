package vpn

import (
	"fmt"
	"time"
)

// Config contains all VPN configuration.
type Config struct {
	// Enabled controls whether VPN mode is active.
	Enabled bool `yaml:"enabled"`

	// TUN contains TUN device configuration.
	TUN TUNConfig `yaml:"tun"`

	// SplitTunnel contains split tunneling configuration.
	SplitTunnel SplitTunnelConfig `yaml:"split_tunnel"`

	// DNS contains DNS server configuration.
	DNS DNSConfig `yaml:"dns"`
}

// DNSConfig contains DNS server configuration.
type DNSConfig struct {
	// Enabled controls whether the built-in DNS server is active.
	Enabled bool `yaml:"enabled"`

	// Listen is the address to listen on (e.g., "10.255.0.1:53").
	Listen string `yaml:"listen"`

	// Upstream lists upstream DNS servers to forward queries to.
	Upstream []string `yaml:"upstream"`

	// CacheTTL is the duration to cache DNS responses.
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// InterceptMode controls which DNS queries are intercepted.
	// "all": Intercept all DNS queries
	// "tunnel_only": Only intercept queries for tunneled destinations
	InterceptMode string `yaml:"intercept_mode"`
}

// Validate validates the DNS configuration.
func (c *DNSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Listen == "" {
		c.Listen = "10.255.0.1:53"
	}

	if len(c.Upstream) == 0 {
		c.Upstream = []string{"8.8.8.8", "1.1.1.1"}
	}

	if c.CacheTTL == 0 {
		c.CacheTTL = 5 * time.Minute
	}

	if c.InterceptMode == "" {
		c.InterceptMode = "all"
	}

	if c.InterceptMode != "all" && c.InterceptMode != "tunnel_only" {
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
			Address: "10.255.0.1/24",
			MTU:     1400,
		},
		SplitTunnel: SplitTunnelConfig{
			Mode: "exclude",
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
			Listen:        "10.255.0.1:53",
			Upstream:      []string{"8.8.8.8", "1.1.1.1"},
			CacheTTL:      5 * time.Minute,
			InterceptMode: "all",
		},
	}
}

// ExampleConfig returns an example configuration with documentation.
func ExampleConfig() string {
	return `# VPN Configuration
vpn:
  # Enable VPN mode (requires root/admin privileges)
  enabled: true

  # TUN device settings
  tun:
    # Interface name (Linux: "bifrost0", macOS: "utun", Windows: "Bifrost")
    name: bifrost0
    # IP address and subnet for the TUN interface
    address: 10.255.0.1/24
    # MTU size (default: 1400)
    mtu: 1400

  # Split tunneling configuration
  split_tunnel:
    # Mode: "exclude" (listed items bypass VPN) or "include" (only listed items use VPN)
    mode: exclude

    # Applications to exclude/include (by process name)
    apps:
      - name: slack
      - name: zoom
      - name: teams

    # Domain patterns to exclude/include
    domains:
      - "*.local"
      - "*.internal.company.com"
      - "*.office365.com"

    # IP addresses or CIDR ranges to exclude/include
    ips:
      - "10.0.0.0/8"        # Private networks
      - "172.16.0.0/12"
      - "192.168.0.0/16"

    # Destinations that always bypass VPN (checked first)
    always_bypass:
      - "127.0.0.0/8"       # Loopback
      - "169.254.0.0/16"    # Link-local

  # DNS server configuration
  dns:
    # Enable built-in DNS server
    enabled: true
    # Listen address (should match TUN address)
    listen: "10.255.0.1:53"
    # Upstream DNS servers
    upstream:
      - "8.8.8.8"
      - "1.1.1.1"
    # Cache duration for DNS responses
    cache_ttl: 5m
    # Intercept mode: "all" or "tunnel_only"
    intercept_mode: all
`
}
