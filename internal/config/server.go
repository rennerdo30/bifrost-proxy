package config

import (
	"fmt"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"gopkg.in/yaml.v3"
)

// ServerConfig is the main configuration for the Bifrost server.
type ServerConfig struct {
	Server     ServerSettings     `yaml:"server"`
	Backends   []BackendConfig    `yaml:"backends"`
	Routes     []RouteConfig      `yaml:"routes"`
	Auth       AuthConfig         `yaml:"auth"`
	RateLimit  RateLimitConfig    `yaml:"rate_limit"`
	AccessLog  AccessLogConfig    `yaml:"access_log"`
	Metrics    MetricsConfig      `yaml:"metrics"`
	Logging    logging.Config     `yaml:"logging"`
	WebUI      WebUIConfig        `yaml:"web_ui"`
	API        APIConfig          `yaml:"api"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`
}

// ServerSettings contains server-specific settings.
type ServerSettings struct {
	HTTP           ListenerConfig `yaml:"http"`
	SOCKS5         ListenerConfig `yaml:"socks5"`
	GracefulPeriod Duration       `yaml:"graceful_period"`
}

// ListenerConfig contains settings for a network listener.
type ListenerConfig struct {
	Listen       string   `yaml:"listen"`
	TLS          *TLSConfig `yaml:"tls,omitempty"`
	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	IdleTimeout  Duration `yaml:"idle_timeout"`
}

// TLSConfig contains TLS settings.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// BackendConfig describes a backend configuration.
type BackendConfig struct {
	Name      string            `yaml:"name"`
	Type      string            `yaml:"type"` // direct, wireguard, openvpn, http_proxy, socks5_proxy
	Enabled   bool              `yaml:"enabled"`
	Priority  int               `yaml:"priority"`
	Weight    int               `yaml:"weight"`
	Config    map[string]any    `yaml:"config,omitempty"`
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty"`
}

// RouteConfig describes a routing rule.
type RouteConfig struct {
	Name      string   `yaml:"name,omitempty"`
	Domains   []string `yaml:"domains"`
	Backend   string   `yaml:"backend"`
	Priority  int      `yaml:"priority"`
	Backends  []string `yaml:"backends,omitempty"` // For load balancing
	LoadBalance string `yaml:"load_balance,omitempty"` // round_robin, least_conn, ip_hash, weighted
}

// AuthConfig contains authentication settings.
type AuthConfig struct {
	Mode   string      `yaml:"mode"` // none, native, system, ldap, oauth
	Native *NativeAuth `yaml:"native,omitempty"`
	System *SystemAuth `yaml:"system,omitempty"`
	LDAP   *LDAPAuth   `yaml:"ldap,omitempty"`
	OAuth  *OAuthAuth  `yaml:"oauth,omitempty"`
}

// NativeAuth contains native authentication settings.
type NativeAuth struct {
	Users []NativeUser `yaml:"users"`
}

// NativeUser represents a native user credential.
type NativeUser struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"` // bcrypt hash
}

// LDAPAuth contains LDAP authentication settings.
type LDAPAuth struct {
	URL            string `yaml:"url"`
	BaseDN         string `yaml:"base_dn"`
	BindDN         string `yaml:"bind_dn"`
	BindPassword   string `yaml:"bind_password"`
	UserFilter     string `yaml:"user_filter"`
	GroupFilter    string `yaml:"group_filter,omitempty"`
	RequireGroup   string `yaml:"require_group,omitempty"`
	TLS            bool   `yaml:"tls"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// OAuthAuth contains OAuth/OIDC authentication settings.
type OAuthAuth struct {
	Provider     string   `yaml:"provider"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	IssuerURL    string   `yaml:"issuer_url"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
}

// SystemAuth contains system/PAM authentication settings.
type SystemAuth struct {
	Service       string   `yaml:"service,omitempty"`        // PAM service name (default: "login")
	AllowedUsers  []string `yaml:"allowed_users,omitempty"`  // List of allowed usernames
	AllowedGroups []string `yaml:"allowed_groups,omitempty"` // List of allowed groups
}

// RateLimitConfig contains rate limiting settings.
type RateLimitConfig struct {
	Enabled      bool     `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	BurstSize    int      `yaml:"burst_size"`
	PerIP        bool     `yaml:"per_ip"`
	PerUser      bool     `yaml:"per_user"`
	Bandwidth    *BandwidthConfig `yaml:"bandwidth,omitempty"`
}

// BandwidthConfig contains bandwidth throttling settings.
type BandwidthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Upload   string `yaml:"upload"`   // e.g., "10Mbps"
	Download string `yaml:"download"` // e.g., "100Mbps"
}

// AccessLogConfig contains access logging settings.
type AccessLogConfig struct {
	Enabled bool   `yaml:"enabled"`
	Format  string `yaml:"format"` // json, apache
	Output  string `yaml:"output"` // stdout, stderr, or file path
}

// MetricsConfig contains Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

// WebUIConfig contains Web UI settings.
type WebUIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	BasePath string `yaml:"base_path"`
}

// APIConfig contains REST API settings.
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Token   string `yaml:"token"`
}

// HealthCheckConfig contains health check settings.
type HealthCheckConfig struct {
	Type     string   `yaml:"type"` // tcp, http, ping
	Interval Duration `yaml:"interval"`
	Timeout  Duration `yaml:"timeout"`
	Target   string   `yaml:"target,omitempty"`
	Path     string   `yaml:"path,omitempty"` // For HTTP health checks
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
			Enabled: true,
			Listen:  ":9090",
			Path:    "/metrics",
		},
		API: APIConfig{
			Enabled: true,
			Listen:  ":8082",
		},
		Logging: logging.DefaultConfig(),
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
