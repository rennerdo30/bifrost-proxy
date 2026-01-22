package config

import (
	"fmt"
	"net"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// ClientConfig is the main configuration for the Bifrost client.
type ClientConfig struct {
	Proxy       ClientProxySettings `yaml:"proxy" json:"proxy"`
	Server      ServerConnection    `yaml:"server" json:"server"`
	Routes      []ClientRouteConfig `yaml:"routes" json:"routes"`
	Debug       DebugConfig         `yaml:"debug" json:"debug"`
	Logging     logging.Config      `yaml:"logging" json:"logging"`
	WebUI       WebUIConfig         `yaml:"web_ui" json:"web_ui"`
	API         APIConfig           `yaml:"api" json:"api"`
	Tray        TrayConfig          `yaml:"tray" json:"tray"`
	AutoUpdate  AutoUpdateConfig    `yaml:"auto_update" json:"auto_update"`
	SystemProxy SystemProxyConfig   `yaml:"system_proxy" json:"system_proxy"`
	VPN         vpn.Config          `yaml:"vpn" json:"vpn"`
	Mesh        mesh.Config         `yaml:"mesh" json:"mesh"`
}

// SystemProxyConfig contains settings for OS-level proxy configuration.
type SystemProxyConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// ClientProxySettings contains client proxy listener settings.
type ClientProxySettings struct {
	HTTP   ListenerConfig `yaml:"http" json:"http"`
	SOCKS5 ListenerConfig `yaml:"socks5" json:"socks5"`
}

// ServerConnection contains settings for connecting to the Bifrost server.
type ServerConnection struct {
	Address     string             `yaml:"address" json:"address"`
	Protocol    string             `yaml:"protocol" json:"protocol"` // http, socks5
	TLS         *TLSConfig         `yaml:"tls,omitempty" json:"tls,omitempty"`
	Username    string             `yaml:"username,omitempty" json:"username,omitempty"`
	Password    string             `yaml:"password,omitempty" json:"password,omitempty"`
	Timeout     Duration           `yaml:"timeout" json:"timeout"`
	RetryCount  int                `yaml:"retry_count" json:"retry_count"`
	RetryDelay  Duration           `yaml:"retry_delay" json:"retry_delay"`
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty" json:"health_check,omitempty"`
}

// ClientRouteConfig describes a client routing rule.
type ClientRouteConfig struct {
	Name     string   `yaml:"name,omitempty" json:"name,omitempty"`
	Domains  []string `yaml:"domains" json:"domains"`
	Action   string   `yaml:"action" json:"action"` // server, direct
	Priority int      `yaml:"priority" json:"priority"`
}

// DebugConfig contains traffic debugging settings.
type DebugConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	MaxEntries    int      `yaml:"max_entries" json:"max_entries"`
	CaptureBody   bool     `yaml:"capture_body" json:"capture_body"`
	MaxBodySize   int      `yaml:"max_body_size" json:"max_body_size"`
	FilterDomains []string `yaml:"filter_domains,omitempty" json:"filter_domains,omitempty"`
}

// TrayConfig contains system tray settings.
type TrayConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled"`
	StartMinimized    bool `yaml:"start_minimized" json:"start_minimized"`
	ShowQuickGUI      bool `yaml:"show_quick_gui" json:"show_quick_gui"`
	AutoConnect       bool `yaml:"auto_connect" json:"auto_connect"`
	ShowNotifications bool `yaml:"show_notifications" json:"show_notifications"`
	WindowX           int  `yaml:"window_x" json:"window_x"`
	WindowY           int  `yaml:"window_y" json:"window_y"`
}

// DefaultClientConfig returns a client configuration with sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{
				Listen:       "127.0.0.1:7380",
				ReadTimeout:  Duration(30 * time.Second),
				WriteTimeout: Duration(30 * time.Second),
				IdleTimeout:  Duration(60 * time.Second),
			},
			SOCKS5: ListenerConfig{
				Listen: "127.0.0.1:7381",
			},
		},
		Server: ServerConnection{
			Protocol:   "http",
			Timeout:    Duration(30 * time.Second),
			RetryCount: 3,
			RetryDelay: Duration(1 * time.Second),
		},
		Debug: DebugConfig{
			Enabled:     true,
			MaxEntries:  1000,
			CaptureBody: false,
			MaxBodySize: 64 * 1024, // 64KB
		},
		Logging: logging.DefaultConfig(),
		WebUI: WebUIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:7382",
		},
		API: APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:7383",
		},
		Tray: TrayConfig{
			Enabled:           true,
			StartMinimized:    false,
			ShowQuickGUI:      true,
			AutoConnect:       false,
			ShowNotifications: true,
			WindowX:           -1,
			WindowY:           -1,
		},
		AutoUpdate: AutoUpdateConfig{
			Enabled:       false,
			CheckInterval: Duration(24 * time.Hour),
			Channel:       "stable",
		},
		SystemProxy: SystemProxyConfig{
			Enabled: false,
		},
		VPN:  vpn.DefaultConfig(),
		Mesh: mesh.DefaultConfig(),
	}
}

// Validate validates the client configuration.
func (c *ClientConfig) Validate() error {
	if c.Proxy.HTTP.Listen == "" && c.Proxy.SOCKS5.Listen == "" {
		return fmt.Errorf("at least one proxy listener (HTTP or SOCKS5) must be configured")
	}

	// Server address is optional - client can work in direct-only mode
	// Validate server address has host:port format if provided
	if c.Server.Address != "" {
		if _, _, err := net.SplitHostPort(c.Server.Address); err != nil {
			return fmt.Errorf("server address must be in host:port format (e.g., '192.168.1.1:8080'): %w", err)
		}
	}

	for _, r := range c.Routes {
		if len(r.Domains) == 0 {
			return fmt.Errorf("route must have at least one domain pattern")
		}
		if r.Action == "" {
			return fmt.Errorf("route action is required")
		}
		if r.Action != "server" && r.Action != "direct" {
			return fmt.Errorf("route action must be 'server' or 'direct', got: %s", r.Action)
		}
	}

	if c.Debug.MaxEntries < 0 {
		return fmt.Errorf("debug max_entries must be non-negative")
	}

	// Validate VPN config if enabled
	if c.VPN.Enabled {
		if err := c.VPN.Validate(); err != nil {
			return fmt.Errorf("invalid VPN config: %w", err)
		}
	}

	// Validate mesh config if enabled
	if c.Mesh.Enabled {
		if err := c.Mesh.Validate(); err != nil {
			return fmt.Errorf("invalid mesh config: %w", err)
		}
	}

	return nil
}
