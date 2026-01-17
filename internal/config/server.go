package config

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"gopkg.in/yaml.v3"
)

// ServerConfig is the main configuration for the Bifrost server.
type ServerConfig struct {
	Server      ServerSettings    `yaml:"server" json:"server"`
	Backends    []BackendConfig   `yaml:"backends" json:"backends"`
	Routes      []RouteConfig     `yaml:"routes" json:"routes"`
	Auth        AuthConfig        `yaml:"auth" json:"auth"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit" json:"rate_limit"`
	AccessLog   AccessLogConfig   `yaml:"access_log" json:"access_log"`
	Metrics     MetricsConfig     `yaml:"metrics" json:"metrics"`
	Logging     logging.Config    `yaml:"logging" json:"logging"`
	WebUI       WebUIConfig       `yaml:"web_ui" json:"web_ui"`
	API         APIConfig         `yaml:"api" json:"api"`
	HealthCheck HealthCheckConfig `yaml:"health_check" json:"health_check"`
	AutoUpdate  AutoUpdateConfig  `yaml:"auto_update" json:"auto_update"`
	Cache       cache.Config      `yaml:"cache" json:"cache"`
}

// ServerSettings contains server-specific settings.
type ServerSettings struct {
	HTTP           ListenerConfig `yaml:"http" json:"http"`
	SOCKS5         ListenerConfig `yaml:"socks5" json:"socks5"`
	GracefulPeriod Duration       `yaml:"graceful_period" json:"graceful_period"`
}

// ListenerConfig contains settings for a network listener.
type ListenerConfig struct {
	Listen         string     `yaml:"listen" json:"listen"`
	TLS            *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
	ReadTimeout    Duration   `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout   Duration   `yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout    Duration   `yaml:"idle_timeout" json:"idle_timeout"`
	MaxConnections int        `yaml:"max_connections" json:"max_connections"` // 0 = unlimited
}

// TLSConfig contains TLS settings.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

// BackendConfig describes a backend configuration.
type BackendConfig struct {
	Name        string             `yaml:"name" json:"name"`
	Type        string             `yaml:"type" json:"type"` // direct, wireguard, openvpn, http_proxy, socks5_proxy
	Enabled     bool               `yaml:"enabled" json:"enabled"`
	Priority    int                `yaml:"priority" json:"priority"`
	Weight      int                `yaml:"weight" json:"weight"`
	Config      map[string]any     `yaml:"config,omitempty" json:"config,omitempty"`
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty" json:"health_check,omitempty"`
}

// RouteConfig describes a routing rule.
type RouteConfig struct {
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Domains     []string `yaml:"domains" json:"domains"`
	Backend     string   `yaml:"backend" json:"backend"`
	Priority    int      `yaml:"priority" json:"priority"`
	Backends    []string `yaml:"backends,omitempty" json:"backends,omitempty"`       // For load balancing
	LoadBalance string   `yaml:"load_balance,omitempty" json:"load_balance,omitempty"` // round_robin, least_conn, ip_hash, weighted
}

// AuthConfig contains authentication settings.
// Supports multiple providers that are tried in priority order.
type AuthConfig struct {
	// Mode is for backwards compatibility with single-mode configs.
	// If set, it takes precedence over Providers.
	Mode   string      `yaml:"mode,omitempty" json:"mode,omitempty"` // none, native, system, ldap, oauth (legacy)
	Native *NativeAuth `yaml:"native,omitempty" json:"native,omitempty"`
	System *SystemAuth `yaml:"system,omitempty" json:"system,omitempty"`
	LDAP   *LDAPAuth   `yaml:"ldap,omitempty" json:"ldap,omitempty"`
	OAuth  *OAuthAuth  `yaml:"oauth,omitempty" json:"oauth,omitempty"`
	// Providers allows multiple authentication backends.
	// Each provider is tried in priority order (lowest first).
	Providers []AuthProvider `yaml:"providers,omitempty" json:"providers,omitempty"`
}

// AuthProvider represents a single authentication provider.
type AuthProvider struct {
	Name     string      `yaml:"name" json:"name"`                     // Unique name for this provider
	Type     string      `yaml:"type" json:"type"`                     // native, system, ldap, oauth
	Enabled  bool        `yaml:"enabled" json:"enabled"`               // Whether this provider is active
	Priority int         `yaml:"priority" json:"priority"`             // Lower priority is tried first
	Native   *NativeAuth `yaml:"native,omitempty" json:"native,omitempty"`
	System   *SystemAuth `yaml:"system,omitempty" json:"system,omitempty"`
	LDAP     *LDAPAuth   `yaml:"ldap,omitempty" json:"ldap,omitempty"`
	OAuth    *OAuthAuth  `yaml:"oauth,omitempty" json:"oauth,omitempty"`
}

// NativeAuth contains native authentication settings.
type NativeAuth struct {
	Users []NativeUser `yaml:"users" json:"users"`
}

// NativeUser represents a native user credential.
type NativeUser struct {
	Username     string `yaml:"username" json:"username"`
	PasswordHash string `yaml:"password_hash" json:"password_hash"` // bcrypt hash
}

// LDAPAuth contains LDAP authentication settings.
type LDAPAuth struct {
	URL                string `yaml:"url" json:"url"`
	BaseDN             string `yaml:"base_dn" json:"base_dn"`
	BindDN             string `yaml:"bind_dn" json:"bind_dn"`
	BindPassword       string `yaml:"bind_password" json:"bind_password"`
	UserFilter         string `yaml:"user_filter" json:"user_filter"`
	GroupFilter        string `yaml:"group_filter,omitempty" json:"group_filter,omitempty"`
	RequireGroup       string `yaml:"require_group,omitempty" json:"require_group,omitempty"`
	TLS                bool   `yaml:"tls" json:"tls"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// OAuthAuth contains OAuth/OIDC authentication settings.
type OAuthAuth struct {
	Provider     string   `yaml:"provider" json:"provider"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	IssuerURL    string   `yaml:"issuer_url" json:"issuer_url"`
	RedirectURL  string   `yaml:"redirect_url" json:"redirect_url"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
}

// SystemAuth contains system/PAM authentication settings.
type SystemAuth struct {
	Service       string   `yaml:"service,omitempty" json:"service,omitempty"`               // PAM service name (default: "login")
	AllowedUsers  []string `yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`   // List of allowed usernames
	AllowedGroups []string `yaml:"allowed_groups,omitempty" json:"allowed_groups,omitempty"` // List of allowed groups
}

// RateLimitConfig contains rate limiting settings.
type RateLimitConfig struct {
	Enabled           bool             `yaml:"enabled" json:"enabled"`
	RequestsPerSecond float64          `yaml:"requests_per_second" json:"requests_per_second"`
	BurstSize         int              `yaml:"burst_size" json:"burst_size"`
	PerIP             bool             `yaml:"per_ip" json:"per_ip"`
	PerUser           bool             `yaml:"per_user" json:"per_user"`
	Bandwidth         *BandwidthConfig `yaml:"bandwidth,omitempty" json:"bandwidth,omitempty"`
}

// BandwidthConfig contains bandwidth throttling settings.
type BandwidthConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Upload   string `yaml:"upload" json:"upload"`     // e.g., "10Mbps"
	Download string `yaml:"download" json:"download"` // e.g., "100Mbps"
}

// AccessLogConfig contains access logging settings.
type AccessLogConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Format  string `yaml:"format" json:"format"` // json, apache
	Output  string `yaml:"output" json:"output"` // stdout, stderr, or file path
}

// MetricsConfig contains Prometheus metrics settings.
type MetricsConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	Listen             string   `yaml:"listen" json:"listen"`
	Path               string   `yaml:"path" json:"path"`
	CollectionInterval Duration `yaml:"collection_interval" json:"collection_interval"` // Default: 15s, for low-power devices use 60s-300s
}

// WebUIConfig contains Web UI settings.
type WebUIConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Listen   string `yaml:"listen" json:"listen"`
	BasePath string `yaml:"base_path" json:"base_path"`
}

// APIConfig contains REST API settings.
type APIConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled"`
	Listen              string `yaml:"listen" json:"listen"`
	Token               string `yaml:"token" json:"token,omitempty"`
	EnableRequestLog    bool   `yaml:"enable_request_log" json:"enable_request_log"`       // Enable request logging for Web UI
	RequestLogSize      int    `yaml:"request_log_size" json:"request_log_size"`           // Max number of requests to keep (default 1000)
	WebSocketMaxClients int    `yaml:"websocket_max_clients" json:"websocket_max_clients"` // Default: 100, for low-power devices use 5-10
}

// HealthCheckConfig contains health check settings.
type HealthCheckConfig struct {
	Type     string   `yaml:"type" json:"type"` // tcp, http, ping
	Interval Duration `yaml:"interval" json:"interval"`
	Timeout  Duration `yaml:"timeout" json:"timeout"`
	Target   string   `yaml:"target,omitempty" json:"target,omitempty"`
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"` // For HTTP health checks
}

// AutoUpdateConfig contains auto-update settings.
type AutoUpdateConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	CheckInterval Duration `yaml:"check_interval" json:"check_interval"`
	Channel       string   `yaml:"channel" json:"channel"` // stable, prerelease
}

// Duration is a time.Duration that can be unmarshaled from YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// DefaultServerConfig returns a server configuration with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{
				Listen:       ":8080",
				ReadTimeout:  Duration(30 * time.Second),
				WriteTimeout: Duration(30 * time.Second),
				IdleTimeout:  Duration(60 * time.Second),
			},
			SOCKS5: ListenerConfig{
				Listen: ":1080",
			},
			GracefulPeriod: Duration(30 * time.Second),
		},
		Auth: AuthConfig{
			Mode: "none",
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
		},
		AccessLog: AccessLogConfig{
			Enabled: true,
			Format:  "json",
			Output:  "stdout",
		},
		Metrics: MetricsConfig{
			Enabled:            true,
			Listen:             ":9090",
			Path:               "/metrics",
			CollectionInterval: Duration(15 * time.Second),
		},
		API: APIConfig{
			Enabled: true,
			Listen:  ":8082",
		},
		Logging: logging.DefaultConfig(),
		AutoUpdate: AutoUpdateConfig{
			Enabled:       false,
			CheckInterval: Duration(24 * time.Hour),
			Channel:       "stable",
		},
		Cache: cache.DefaultConfig(),
	}
}

// Validate validates the server configuration.
func (c *ServerConfig) Validate() error {
	if c.Server.HTTP.Listen == "" && c.Server.SOCKS5.Listen == "" {
		return fmt.Errorf("at least one listener (HTTP or SOCKS5) must be configured")
	}

	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend must be configured")
	}

	backendNames := make(map[string]bool)
	for _, b := range c.Backends {
		if b.Name == "" {
			return fmt.Errorf("backend name is required")
		}
		if backendNames[b.Name] {
			return fmt.Errorf("duplicate backend name: %s", b.Name)
		}
		backendNames[b.Name] = true

		if b.Type == "" {
			return fmt.Errorf("backend type is required for backend: %s", b.Name)
		}
	}

	for _, r := range c.Routes {
		if len(r.Domains) == 0 {
			return fmt.Errorf("route must have at least one domain pattern")
		}
		if r.Backend == "" && len(r.Backends) == 0 {
			return fmt.Errorf("route must specify a backend or backends")
		}
		if r.Backend != "" && !backendNames[r.Backend] {
			return fmt.Errorf("route references unknown backend: %s", r.Backend)
		}
		for _, b := range r.Backends {
			if !backendNames[b] {
				return fmt.Errorf("route references unknown backend: %s", b)
			}
		}
	}

	return nil
}
