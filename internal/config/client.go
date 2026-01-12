package config

import (
	"fmt"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
)

// ClientConfig is the main configuration for the Bifrost client.
type ClientConfig struct {
	Proxy   ClientProxySettings `yaml:"proxy"`
	Server  ServerConnection    `yaml:"server"`
	Routes  []ClientRouteConfig `yaml:"routes"`
	Debug   DebugConfig         `yaml:"debug"`
	Logging logging.Config      `yaml:"logging"`
	WebUI   WebUIConfig         `yaml:"web_ui"`
	API     APIConfig           `yaml:"api"`
	Tray    TrayConfig          `yaml:"tray"`
}

// ClientProxySettings contains client proxy listener settings.
type ClientProxySettings struct {
	HTTP   ListenerConfig `yaml:"http"`
	SOCKS5 ListenerConfig `yaml:"socks5"`
}

// ServerConnection contains settings for connecting to the Bifrost server.
type ServerConnection struct {
	Address     string    `yaml:"address"`
	Protocol    string    `yaml:"protocol"` // http, socks5
	TLS         *TLSConfig `yaml:"tls,omitempty"`
	Username    string    `yaml:"username,omitempty"`
	Password    string    `yaml:"password,omitempty"`
	Timeout     Duration  `yaml:"timeout"`
	RetryCount  int       `yaml:"retry_count"`
	RetryDelay  Duration  `yaml:"retry_delay"`
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty"`
}

// ClientRouteConfig describes a client routing rule.
type ClientRouteConfig struct {
	Name     string   `yaml:"name,omitempty"`
	Domains  []string `yaml:"domains"`
	Action   string   `yaml:"action"` // server, direct
	Priority int      `yaml:"priority"`
}

// DebugConfig contains traffic debugging settings.
type DebugConfig struct {
	Enabled      bool     `yaml:"enabled"`
	MaxEntries   int      `yaml:"max_entries"`
	CaptureBody  bool     `yaml:"capture_body"`
	MaxBodySize  int      `yaml:"max_body_size"`
	FilterDomains []string `yaml:"filter_domains,omitempty"`
}

// TrayConfig contains system tray settings.
type TrayConfig struct {
	Enabled bool `yaml:"enabled"`
	StartMinimized bool `yaml:"start_minimized"`
}

// DefaultClientConfig returns a client configuration with sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Proxy: ClientProxySettings{
			HTTP: ListenerConfig{
				Listen:       "127.0.0.1:3128",
				ReadTimeout:  Duration(30 * time.Second),
				WriteTimeout: Duration(30 * time.Second),
				IdleTimeout:  Duration(60 * time.Second),
			},
			SOCKS5: ListenerConfig{
				Listen: "127.0.0.1:1081",
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
			Listen:  "127.0.0.1:3129",
		},
		API: APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:3130",
		},
		Tray: TrayConfig{
			Enabled: true,
			StartMinimized: false,
		},
	}
}

// Validate validates the client configuration.
func (c *ClientConfig) Validate() error {
	if c.Proxy.HTTP.Listen == "" && c.Proxy.SOCKS5.Listen == "" {
		return fmt.Errorf("at least one proxy listener (HTTP or SOCKS5) must be configured")
	}

	if c.Server.Address == "" {
		return fmt.Errorf("server address is required")
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

	return nil
}
