package backend

import (
	"fmt"
	"sort"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// The prototypes below enumerate, per backend type, exactly the keys the
// factory reads out of backends[].config. yaml.v3's KnownFields cannot look
// into a map[string]any field, so before this check a typo such as
// connect_timeot loaded without complaint and the setting silently kept its
// default. Every field the factory stops or starts reading must be mirrored
// here — the schema IS the documentation of what the type accepts.
//
// The values are irrelevant (validation only checks keys and shape), so
// scalar fields are typed loosely where the factory tolerates it.

type directKeys struct {
	ConnectTimeout string `yaml:"connect_timeout"`
	KeepAlive      string `yaml:"keep_alive"`
	LocalAddr      string `yaml:"local_addr"`
}

type httpProxyKeys struct {
	Address        string `yaml:"address"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	ConnectTimeout string `yaml:"connect_timeout"`
}

type socks5ProxyKeys struct {
	Address        string `yaml:"address"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	ConnectTimeout string `yaml:"connect_timeout"`
}

type wireguardPeerKeys struct {
	PublicKey           string   `yaml:"public_key"`
	Endpoint            string   `yaml:"endpoint"`
	PresharedKey        string   `yaml:"preshared_key"`
	PersistentKeepalive int      `yaml:"persistent_keepalive"`
	AllowedIPs          []string `yaml:"allowed_ips"`
}

type wireguardKeys struct {
	PrivateKey string            `yaml:"private_key"`
	Address    string            `yaml:"address"`
	DNS        []string          `yaml:"dns"`
	MTU        int               `yaml:"mtu"`
	Peer       wireguardPeerKeys `yaml:"peer"`
}

type openvpnKeys struct {
	ConfigFile       string   `yaml:"config_file"`
	ConfigContent    string   `yaml:"config_content"`
	AuthFile         string   `yaml:"auth_file"`
	Username         string   `yaml:"username"`
	Password         string   `yaml:"password"`
	Binary           string   `yaml:"binary"`
	ManagementAddr   string   `yaml:"management_addr"`
	ManagementPort   int      `yaml:"management_port"`
	ConnectTimeout   string   `yaml:"connect_timeout"`
	ExtraArgs        []string `yaml:"extra_args"`
	LeakProofRouting bool     `yaml:"leak_proof_routing"`
}

type nordvpnKeys struct {
	Country          string   `yaml:"country"`
	City             string   `yaml:"city"`
	Protocol         string   `yaml:"protocol"`
	AutoSelect       bool     `yaml:"auto_select"`
	MaxLoad          int      `yaml:"max_load"`
	RefreshInterval  string   `yaml:"refresh_interval"`
	Features         []string `yaml:"features"`
	AccessToken      string   `yaml:"access_token"`
	Username         string   `yaml:"username"`
	Password         string   `yaml:"password"`
	CACert           string   `yaml:"ca_cert"`
	TLSAuthKey       string   `yaml:"tls_auth_key"`
	LeakProofRouting bool     `yaml:"leak_proof_routing"`
}

type mullvadKeys struct {
	AccountID        string   `yaml:"account_id"`
	Country          string   `yaml:"country"`
	City             string   `yaml:"city"`
	Protocol         string   `yaml:"protocol"`
	AutoSelect       bool     `yaml:"auto_select"`
	MaxLoad          int      `yaml:"max_load"`
	RefreshInterval  string   `yaml:"refresh_interval"`
	Features         []string `yaml:"features"`
	CACert           string   `yaml:"ca_cert"`
	TLSAuthKey       string   `yaml:"tls_auth_key"`
	LeakProofRouting bool     `yaml:"leak_proof_routing"`
}

type piaKeys struct {
	Username         string   `yaml:"username"`
	Password         string   `yaml:"password"`
	Country          string   `yaml:"country"`
	City             string   `yaml:"city"`
	Protocol         string   `yaml:"protocol"`
	AutoSelect       bool     `yaml:"auto_select"`
	MaxLoad          int      `yaml:"max_load"`
	RefreshInterval  string   `yaml:"refresh_interval"`
	PortForwarding   bool     `yaml:"port_forwarding"`
	Features         []string `yaml:"features"`
	LeakProofRouting bool     `yaml:"leak_proof_routing"`
}

type protonvpnKeys struct {
	AuthMode         string   `yaml:"auth_mode"`
	Username         string   `yaml:"username"`
	Password         string   `yaml:"password"`
	Country          string   `yaml:"country"`
	City             string   `yaml:"city"`
	Tier             int      `yaml:"tier"`
	Protocol         string   `yaml:"protocol"`
	AutoSelect       bool     `yaml:"auto_select"`
	MaxLoad          int      `yaml:"max_load"`
	RefreshInterval  string   `yaml:"refresh_interval"`
	SecureCore       bool     `yaml:"secure_core"`
	Features         []string `yaml:"features"`
	CACert           string   `yaml:"ca_cert"`
	TLSAuthKey       string   `yaml:"tls_auth_key"`
	LeakProofRouting bool     `yaml:"leak_proof_routing"`
}

// configPrototypes maps every backend type the factory knows to a fresh
// prototype for strict key validation.
var configPrototypes = map[string]func() any{
	"direct":       func() any { return &directKeys{} },
	"http_proxy":   func() any { return &httpProxyKeys{} },
	"socks5_proxy": func() any { return &socks5ProxyKeys{} },
	"wireguard":    func() any { return &wireguardKeys{} },
	"openvpn":      func() any { return &openvpnKeys{} },
	"nordvpn":      func() any { return &nordvpnKeys{} },
	"mullvad":      func() any { return &mullvadKeys{} },
	"pia":          func() any { return &piaKeys{} },
	"protonvpn":    func() any { return &protonvpnKeys{} },
}

// SchemaTypes returns every backend type with a key schema, sorted, so tests
// can prove the registry and the factory switch stay in lockstep.
func SchemaTypes() []string {
	types := make([]string, 0, len(configPrototypes))
	for t := range configPrototypes {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// ValidateConfigKeys rejects unknown keys in a backend's dynamic config block.
// It runs inside Factory.Create so every construction path — startup, reload,
// and the dashboard's save — gets the same strictness typed sections have.
func ValidateConfigKeys(cfg config.BackendConfig) error {
	prototype, ok := configPrototypes[cfg.Type]
	if !ok {
		return fmt.Errorf("%w: %s", ErrInvalidBackendType, cfg.Type)
	}
	section := fmt.Sprintf("backend %q (type %s) config", cfg.Name, cfg.Type)
	return config.ValidateKnownKeys(section, cfg.Config, prototype())
}

// ValidateConfigs applies ValidateConfigKeys to every enabled backend, for
// validate-only paths (the `validate` command, the dashboard's validate and
// save endpoints) that must reject exactly what startup would reject.
func ValidateConfigs(cfgs []config.BackendConfig) error {
	for _, cfg := range cfgs {
		if !cfg.Enabled {
			continue
		}
		if err := ValidateConfigKeys(cfg); err != nil {
			return err
		}
	}
	return nil
}
