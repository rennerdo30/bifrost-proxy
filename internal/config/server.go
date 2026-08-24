package config

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
)

// ServerConfig is the main configuration for the Bifrost server.
type ServerConfig struct {
	Server        ServerSettings      `yaml:"server" json:"server"`
	Backends      []BackendConfig     `yaml:"backends" json:"backends"`
	Routes        []RouteConfig       `yaml:"routes" json:"routes"`
	Auth          AuthConfig          `yaml:"auth" json:"auth"`
	RateLimit     RateLimitConfig     `yaml:"rate_limit" json:"rate_limit"`
	AccessControl AccessControlConfig `yaml:"access_control" json:"access_control"`
	AccessLog     AccessLogConfig     `yaml:"access_log" json:"access_log"`
	Metrics       MetricsConfig       `yaml:"metrics" json:"metrics"`
	Logging       logging.Config      `yaml:"logging" json:"logging"`
	WebUI         WebUIConfig         `yaml:"web_ui" json:"web_ui"`
	API           APIConfig           `yaml:"api" json:"api"`
	HealthCheck   HealthCheckConfig   `yaml:"health_check" json:"health_check"`
	AutoUpdate    AutoUpdateConfig    `yaml:"auto_update" json:"auto_update"`
	Cache         cache.Config        `yaml:"cache" json:"cache"`
	Network       NetworkConfig       `yaml:"network" json:"network"`
	Session       SessionConfig       `yaml:"session" json:"session"`
	MITM          MITMConfig          `yaml:"mitm" json:"mitm"`
	Mesh          MeshConfig          `yaml:"mesh" json:"mesh"`
}

// MeshConfig configures the server's mesh coordinator API — the REST/WebSocket
// surface under /api/v1/mesh that clients use to discover each other.
type MeshConfig struct {
	// Enabled mounts the coordinator routes. Defaults to true so that existing
	// deployments (where the coordinator was unconditionally mounted) keep
	// working; set it to false to remove the endpoints entirely.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// StatePath is the file the coordinator persists its networks and peers to,
	// so they survive a restart. When empty the coordinator keeps state in
	// memory only and every network/peer registration is lost on restart.
	StatePath string `yaml:"state_path,omitempty" json:"state_path,omitempty"`
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

	// ClientAuth controls whether and how the listener requests/verifies client
	// certificates for mutual TLS (mTLS). Recognized values:
	//   ""                 - no client certificate requested (default)
	//   "request"          - request but do not verify (tls.RequestClientCert)
	//   "require_any"      - require a cert, do not verify chain
	//                        (tls.RequireAnyClientCert)
	//   "verify_if_given"  - verify chain only if a cert is presented
	//                        (tls.VerifyClientCertIfGiven)
	//   "require"          - require AND verify chain
	//                        (tls.RequireAndVerifyClientCert)
	// When verification is requested the client CA pool is sourced from
	// ClientCAFile, or (if empty) from the configured mTLS auth provider.
	ClientAuth string `yaml:"client_auth,omitempty" json:"client_auth,omitempty"`

	// ClientCAFile is the PEM file of CA certificates used to verify client
	// certificates. If empty, the mTLS auth provider's CA pool is used.
	ClientCAFile string `yaml:"client_ca_file,omitempty" json:"client_ca_file,omitempty"`
}

// BackendConfig describes a backend configuration.
type BackendConfig struct {
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"` // direct, wireguard, openvpn, http_proxy, socks5_proxy
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Priority int    `yaml:"priority" json:"priority"`
	// Weight is the default relative weight for this backend in "weighted"
	// load-balancing routes. It seeds RouteConfig.Weights for any weighted
	// route that lists this backend without an explicit per-route weight
	// (see ServerConfig.seedRouteWeights). Values <= 0 are treated as unset
	// (the balancer then defaults the backend to a weight of 1). Explicit
	// per-route weights override this.
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
	Backends    []string `yaml:"backends,omitempty" json:"backends,omitempty"`         // For load balancing
	LoadBalance string   `yaml:"load_balance,omitempty" json:"load_balance,omitempty"` // round_robin, least_conn, ip_hash, weighted

	// Weights maps a backend name (from Backends) to its relative weight for the
	// "weighted" load-balancing strategy. Backends without an entry default to a
	// weight of 1. Ignored for other strategies.
	Weights map[string]int `yaml:"weights,omitempty" json:"weights,omitempty"`
}

// AuthConfig contains authentication settings.
// Supports multiple providers that are tried in priority order.
type AuthConfig struct {
	// Mode is deprecated and intentionally unsupported.
	// Use Providers with explicit plugin types and config maps.
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
	// Legacy type-specific fields are parsed only to surface
	// migration errors; they are intentionally unsupported.
	Native *NativeAuth `yaml:"native,omitempty" json:"native,omitempty"`
	System *SystemAuth `yaml:"system,omitempty" json:"system,omitempty"`
	LDAP   *LDAPAuth   `yaml:"ldap,omitempty" json:"ldap,omitempty"`
	OAuth  *OAuthAuth  `yaml:"oauth,omitempty" json:"oauth,omitempty"`

	// Providers allows multiple authentication backends.
	// Each provider is tried in priority order (lowest first).
	Providers []AuthProvider `yaml:"providers,omitempty" json:"providers,omitempty"`

	// BruteForce enables failed-login rate limiting with exponential lockout
	// around the whole provider chain. The implementation existed, fully
	// tested, with no config key and no caller — a security control the
	// project believed it shipped and did not (TODO.md had marked it FIXED).
	BruteForce *BruteForceConfig `yaml:"brute_force,omitempty" json:"brute_force,omitempty"`

	// Negotiate enables HTTP Negotiate (SPNEGO/Kerberos with optional NTLM
	// fallback) authentication on the HTTP proxy listener. This is middleware,
	// not a chain provider: it drives the multi-step challenge/response
	// handshake required by Windows domain clients and delegates credential
	// validation to the referenced kerberos/ntlm auth providers.
	Negotiate *NegotiateConfig `yaml:"negotiate,omitempty" json:"negotiate,omitempty"`
}

// BruteForceConfig configures failed-login lockout for auth.brute_force.
// Zero values take the protector's defaults (5 attempts, 1m initial lockout
// with exponential backoff to 1h, 15m counting window).
type BruteForceConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	MaxAttempts int      `yaml:"max_attempts,omitempty" json:"max_attempts,omitempty"`
	LockoutTime Duration `yaml:"lockout_time,omitempty" json:"lockout_time,omitempty"`
	MaxLockout  Duration `yaml:"max_lockout,omitempty" json:"max_lockout,omitempty"`
	WindowSize  Duration `yaml:"window_size,omitempty" json:"window_size,omitempty"`
}

// NegotiateConfig configures HTTP Negotiate (SPNEGO/Kerberos/NTLM) middleware
// for the HTTP proxy listener.
type NegotiateConfig struct {
	// Enabled turns on Negotiate authentication on the HTTP proxy listener.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// KerberosProvider is the name of an auth provider (type "kerberos") whose
	// authenticator validates SPNEGO/Kerberos tokens. Required when enabled.
	KerberosProvider string `yaml:"kerberos_provider,omitempty" json:"kerberos_provider,omitempty"`
	// NTLMProvider is the name of an auth provider (type "ntlm") whose
	// authenticator validates NTLM tokens. Optional; required only when
	// AllowNTLM is true.
	NTLMProvider string `yaml:"ntlm_provider,omitempty" json:"ntlm_provider,omitempty"`
	// PreferKerberos tries Kerberos before NTLM (default true).
	PreferKerberos bool `yaml:"prefer_kerberos,omitempty" json:"prefer_kerberos,omitempty"`
	// AllowNTLM enables NTLM fallback when Kerberos is unavailable/fails.
	AllowNTLM bool `yaml:"allow_ntlm,omitempty" json:"allow_ntlm,omitempty"`
	// Realm is the realm advertised in the authentication challenge.
	Realm string `yaml:"realm,omitempty" json:"realm,omitempty"`
}

// AuthProvider represents a single authentication provider.
// Use Config for plugin-specific settings.
// Legacy type-specific fields are deprecated and unsupported.
type AuthProvider struct {
	Name     string         `yaml:"name" json:"name"`                         // Unique name for this provider
	Type     string         `yaml:"type" json:"type"`                         // plugin type (e.g., native, ldap, oauth, apikey, jwt, none)
	Enabled  bool           `yaml:"enabled" json:"enabled"`                   // Whether this provider is active
	Priority int            `yaml:"priority" json:"priority"`                 // Lower priority is tried first
	Config   map[string]any `yaml:"config,omitempty" json:"config,omitempty"` // Plugin-specific configuration (new format)

	// Legacy type-specific config is parsed only to surface
	// migration errors; it is intentionally unsupported.
	Native *NativeAuth `yaml:"native,omitempty" json:"native,omitempty"`
	System *SystemAuth `yaml:"system,omitempty" json:"system,omitempty"`
	LDAP   *LDAPAuth   `yaml:"ldap,omitempty" json:"ldap,omitempty"`
	OAuth  *OAuthAuth  `yaml:"oauth,omitempty" json:"oauth,omitempty"`
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

// AccessControlConfig contains IP whitelist/blacklist settings.
type AccessControlConfig struct {
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
	Blacklist []string `yaml:"blacklist" json:"blacklist"`
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

	// AllowedOrigins extends the set of browser origins permitted to open a
	// WebSocket to /api/v1/ws. The request's own Host is ALWAYS allowed, so the
	// dashboard served by this server needs no configuration here; entries are
	// only needed when a reverse proxy rewrites Host so that the browser's
	// Origin no longer matches it (Home Assistant Ingress, Traefik, nginx).
	//
	// Each entry is a host pattern ("bifrost.example.com", "*.example.com",
	// "homeassistant.local:8123") or a scheme-qualified origin
	// ("https://bifrost.example.com"), matched case-insensitively with shell-style
	// wildcards. A bare "*" (AllowedOriginsWildcard) disables origin checking
	// entirely and is logged as a warning at startup — it lets any web page the
	// operator's browser visits open a socket and read the live traffic stream,
	// so prefer naming the real origins.
	//
	// WebSockets are exempt from the same-origin policy and CORS, which is why
	// this check exists at all: without it any page could connect to a Bifrost
	// reachable from the victim's browser.
	AllowedOrigins []string `yaml:"allowed_origins,omitempty" json:"allowed_origins,omitempty"`
}

// AllowedOriginsWildcard is the explicit opt-out value for APIConfig.AllowedOrigins
// that disables WebSocket origin verification.
const AllowedOriginsWildcard = "*"

// originSchemeSeparator separates an optional scheme from the host in an
// allowed_origins entry.
const originSchemeSeparator = "://"

// validateAllowedOrigin reports whether one APIConfig.AllowedOrigins entry can
// ever match a browser Origin. The matcher compares the pattern against either
// "host[:port]" or "scheme://host[:port]" — never against a path — so an entry
// carrying a path (or an invalid glob) is a silent dead entry and is rejected.
func validateAllowedOrigin(origin string) error {
	if strings.TrimSpace(origin) != origin {
		return fmt.Errorf("must not contain leading or trailing whitespace (got %q)", origin)
	}
	if origin == "" {
		return fmt.Errorf("must not be empty; remove the entry or use %q to disable origin checking", AllowedOriginsWildcard)
	}

	// The explicit opt-out. It is routed through a separate code path that logs a
	// warning at startup, which is the whole point of spelling it "*".
	if origin == AllowedOriginsWildcard {
		return nil
	}

	hostPattern := origin
	if scheme, rest, found := strings.Cut(origin, originSchemeSeparator); found {
		if scheme == "" {
			return fmt.Errorf("missing scheme before %q in %q", originSchemeSeparator, origin)
		}
		hostPattern = rest
	}
	if hostPattern == "" {
		return fmt.Errorf("missing host in %q", origin)
	}
	if strings.Contains(hostPattern, "/") {
		return fmt.Errorf("must be a host or scheme://host without a path (got %q)", origin)
	}

	// Reject patterns that match every host without being the explicit "*".
	// "**", "?*", "*:*", "https://*" and friends all match anything, but would
	// take the ordinary allowlist path — disabling the origin check with no
	// startup warning at all. Turning the check off must stay loud and singular,
	// so there is exactly one spelling for it.
	if !strings.ContainsFunc(hostPattern, isHostIdentifyingRune) {
		return fmt.Errorf("pattern %q identifies no host and would match every origin; "+
			"use %q on its own to disable origin checking (which is logged at startup), "+
			"or name the actual origins", origin, AllowedOriginsWildcard)
	}

	// path.Match is the matcher used at handshake time; ask it to vet the glob.
	if _, err := path.Match(origin, ""); err != nil {
		return fmt.Errorf("invalid wildcard pattern %q: %w", origin, err)
	}
	return nil
}

// isHostIdentifyingRune reports whether r contributes to naming a specific host,
// as opposed to being a wildcard or a separator. Every real hostname contains at
// least one such rune, so a pattern with none of them cannot be selective.
func isHostIdentifyingRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// HealthCheckConfig contains health check settings.
type HealthCheckConfig struct {
	Type     string   `yaml:"type" json:"type"` // tcp, http, ping
	Interval Duration `yaml:"interval" json:"interval"`
	Timeout  Duration `yaml:"timeout" json:"timeout"`
	Target   string   `yaml:"target,omitempty" json:"target,omitempty"`
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"` // For HTTP health checks

	// Scheme selects the URL scheme for HTTP health checks: "http" or "https".
	// Empty means HealthCheckSchemeHTTP.
	Scheme string `yaml:"scheme,omitempty" json:"scheme,omitempty"`
	// InsecureSkipVerify disables TLS certificate verification for HTTPS health
	// checks. Only meaningful when Scheme is "https"; use it for backends that
	// present a self-signed certificate.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`

	// HealthyThreshold is the number of consecutive successful checks required
	// before a backend is marked healthy (de-bouncing). <= 0 means 1.
	HealthyThreshold int `yaml:"healthy_threshold,omitempty" json:"healthy_threshold,omitempty"`
	// UnhealthyThreshold is the number of consecutive failed checks required
	// before a backend is marked unhealthy (de-bouncing). <= 0 means 1.
	UnhealthyThreshold int `yaml:"unhealthy_threshold,omitempty" json:"unhealthy_threshold,omitempty"`
}

// Health check URL schemes for HTTP-type health checks.
const (
	HealthCheckSchemeHTTP  = "http"
	HealthCheckSchemeHTTPS = "https"
)

// HealthCheckTypeHTTP is the health check type that probes an HTTP(S) URL and
// is therefore the only type for which Scheme and InsecureSkipVerify apply.
const HealthCheckTypeHTTP = "http"

// Validate checks a health check block for internally inconsistent settings.
// It is intentionally lenient about empty values (they fall back to defaults)
// and only rejects values the health checker cannot act on, so that an operator
// gets an error at save/load time rather than a silently ignored setting.
func (c *HealthCheckConfig) Validate() error {
	switch c.Scheme {
	case "", HealthCheckSchemeHTTP, HealthCheckSchemeHTTPS:
	default:
		return fmt.Errorf("health_check scheme must be %q or %q, got %q",
			HealthCheckSchemeHTTP, HealthCheckSchemeHTTPS, c.Scheme)
	}

	// scheme/insecure_skip_verify are only consumed by the HTTP checker. Accept
	// them when the type is unset (the global block may only be supplying
	// defaults), but reject a combination that can never take effect.
	if c.Type != "" && c.Type != HealthCheckTypeHTTP {
		if c.Scheme != "" {
			return fmt.Errorf("health_check scheme is only supported for type %q, got type %q",
				HealthCheckTypeHTTP, c.Type)
		}
		if c.InsecureSkipVerify {
			return fmt.Errorf("health_check insecure_skip_verify is only supported for type %q, got type %q",
				HealthCheckTypeHTTP, c.Type)
		}
	}

	if c.InsecureSkipVerify && c.Scheme != HealthCheckSchemeHTTPS {
		return fmt.Errorf("health_check insecure_skip_verify requires scheme %q", HealthCheckSchemeHTTPS)
	}

	// HealthyThreshold/UnhealthyThreshold are deliberately not validated here:
	// any value <= 0 is documented to mean "1" (transition immediately), so
	// rejecting a negative value would both contradict that contract and break
	// configs that load fine today.

	return nil
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
				Listen:       ":7080",
				ReadTimeout:  Duration(30 * time.Second),
				WriteTimeout: Duration(30 * time.Second),
				IdleTimeout:  Duration(60 * time.Second),
			},
			SOCKS5: ListenerConfig{
				Listen: ":7180",
			},
			GracefulPeriod: Duration(30 * time.Second),
		},
		Auth: AuthConfig{},
		RateLimit: RateLimitConfig{
			Enabled: false,
		},
		AccessControl: AccessControlConfig{},
		AccessLog: AccessLogConfig{
			Enabled: true,
			Format:  "json",
			Output:  "stdout",
		},
		Metrics: MetricsConfig{
			Enabled:            true,
			Listen:             ":7090",
			Path:               "/metrics",
			CollectionInterval: Duration(15 * time.Second),
		},
		API: APIConfig{
			Enabled: true,
			Listen:  ":7082",
		},
		Logging: logging.DefaultConfig(),
		AutoUpdate: AutoUpdateConfig{
			Enabled:       false,
			CheckInterval: Duration(24 * time.Hour),
			Channel:       "stable",
		},
		Cache: cache.DefaultConfig(),
		Mesh: MeshConfig{
			// Preserves the historical behavior of always mounting the
			// coordinator; persistence stays opt-in via state_path.
			Enabled: true,
		},
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

		if b.HealthCheck != nil {
			if err := b.HealthCheck.Validate(); err != nil {
				return fmt.Errorf("backend %s: %w", b.Name, err)
			}
		}
	}

	if err := c.HealthCheck.Validate(); err != nil {
		return err
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

	c.seedRouteWeights()

	if c.API.RequestLogSize < 0 {
		return fmt.Errorf("api request_log_size must be non-negative")
	}
	// Upper sanity bound: request_log_size sizes a ring buffer allocated up
	// front. The value is operator config, not request data, but cap it to keep
	// worst-case memory predictable and to reject obvious misconfiguration.
	if c.API.RequestLogSize > MaxRingBufferEntries {
		return fmt.Errorf("api request_log_size must not exceed %d", MaxRingBufferEntries)
	}

	// Reject unusable allowed_origins entries here rather than letting them fail
	// silently at handshake time: an entry with a path or a bad glob would never
	// match any origin, so the operator would see WebSocket rejections with no
	// hint that their allowlist is the cause.
	for i, origin := range c.API.AllowedOrigins {
		if err := validateAllowedOrigin(origin); err != nil {
			return fmt.Errorf("api allowed_origins[%d]: %w", i, err)
		}
		// "*" disables the check wholesale, so a list like
		// ["https://a.example", "*"] reads as a narrow grant while actually
		// granting everything. Require the opt-out to stand alone, so it cannot
		// hide among entries that suggest the opposite.
		if origin == AllowedOriginsWildcard && len(c.API.AllowedOrigins) > 1 {
			return fmt.Errorf("api allowed_origins[%d]: %q disables origin checking entirely and "+
				"must be the only entry; remove the other %d entr%s or drop the wildcard",
				i, AllowedOriginsWildcard, len(c.API.AllowedOrigins)-1,
				map[bool]string{true: "y", false: "ies"}[len(c.API.AllowedOrigins) == 2])
		}
	}

	if err := c.Auth.Validate(); err != nil {
		return err
	}

	if err := c.Session.Validate(); err != nil {
		return err
	}

	if err := c.MITM.Validate(); err != nil {
		return err
	}

	return nil
}

// seedRouteWeights propagates per-backend BackendConfig.Weight values into the
// "weighted" load-balancing routes that do not already specify an explicit
// weight for a backend. Without this, BackendConfig.Weight would be a silent
// no-op: the weighted balancer only consults RouteConfig.Weights. A backend
// weight <= 0 is treated as unset (the balancer defaults missing entries to 1).
// Explicit per-route weights always win over the backend-level default.
func (c *ServerConfig) seedRouteWeights() {
	backendWeights := make(map[string]int, len(c.Backends))
	for _, b := range c.Backends {
		if b.Weight > 0 {
			backendWeights[b.Name] = b.Weight
		}
	}
	if len(backendWeights) == 0 {
		return
	}

	for i := range c.Routes {
		r := &c.Routes[i]
		if r.LoadBalance != "weighted" || len(r.Backends) == 0 {
			continue
		}
		for _, name := range r.Backends {
			w, ok := backendWeights[name]
			if !ok {
				continue
			}
			if _, set := r.Weights[name]; set {
				continue // explicit per-route weight wins
			}
			if r.Weights == nil {
				r.Weights = make(map[string]int)
			}
			r.Weights[name] = w
		}
	}
}

// Validate rejects the legacy auth configuration shapes (auth.mode and
// type-specific blocks like auth.native/auth.providers[].native) at load/save
// time so the Web UI can surface a clear error before a save bricks the server.
// The runtime authenticator factory enforces the same rules; this surfaces them
// earlier and via the standard config validation path.
func (c *AuthConfig) Validate() error {
	if c.Mode != "" {
		return fmt.Errorf("legacy auth.mode is no longer supported; migrate to auth.providers with explicit plugin types")
	}
	if c.Native != nil || c.System != nil || c.LDAP != nil || c.OAuth != nil {
		return fmt.Errorf("legacy top-level auth provider config (auth.native/system/ldap/oauth) is no longer supported; migrate to auth.providers[].config")
	}
	for i, p := range c.Providers {
		if p.Native != nil || p.System != nil || p.LDAP != nil || p.OAuth != nil {
			return fmt.Errorf("provider %q at index %d uses legacy type-specific auth config; migrate to providers[%d].config", p.Name, i, i)
		}
	}
	return nil
}
