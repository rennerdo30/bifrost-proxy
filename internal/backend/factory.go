package backend

import (
	"fmt"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// Factory creates backends from configuration.
type Factory struct{}

// NewFactory creates a new backend factory.
func NewFactory() *Factory {
	return &Factory{}
}

// Create creates a backend from configuration.
func (f *Factory) Create(cfg config.BackendConfig) (Backend, error) {
	switch cfg.Type {
	case "direct":
		return f.createDirect(cfg)
	case "http_proxy":
		return f.createHTTPProxy(cfg)
	case "socks5_proxy":
		return f.createSOCKS5Proxy(cfg)
	case "wireguard":
		return f.createWireGuard(cfg)
	case "openvpn":
		return f.createOpenVPN(cfg)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidBackendType, cfg.Type)
	}
}

func (f *Factory) createDirect(cfg config.BackendConfig) (Backend, error) {
	directCfg := DirectConfig{
		Name: cfg.Name,
	}

	if v, ok := cfg.Config["connect_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			directCfg.ConnectTimeout = d
		}
	}

	if v, ok := cfg.Config["keep_alive"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			directCfg.KeepAlive = d
		}
	}

	if v, ok := cfg.Config["local_addr"].(string); ok {
		directCfg.LocalAddr = v
	}

	return NewDirectBackend(directCfg), nil
}

func (f *Factory) createHTTPProxy(cfg config.BackendConfig) (Backend, error) {
	httpCfg := HTTPProxyConfig{
		Name: cfg.Name,
	}

	if v, ok := cfg.Config["address"].(string); ok {
		httpCfg.Address = v
	} else {
		return nil, fmt.Errorf("http_proxy backend requires 'address' config")
	}

	if v, ok := cfg.Config["username"].(string); ok {
		httpCfg.Username = v
	}

	if v, ok := cfg.Config["password"].(string); ok {
		httpCfg.Password = v
	}

	if v, ok := cfg.Config["connect_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			httpCfg.ConnectTimeout = d
		}
	}

	return NewHTTPProxyBackend(httpCfg), nil
}

func (f *Factory) createSOCKS5Proxy(cfg config.BackendConfig) (Backend, error) {
	socksCfg := SOCKS5ProxyConfig{
		Name: cfg.Name,
	}

	if v, ok := cfg.Config["address"].(string); ok {
		socksCfg.Address = v
	} else {
		return nil, fmt.Errorf("socks5_proxy backend requires 'address' config")
	}

	if v, ok := cfg.Config["username"].(string); ok {
		socksCfg.Username = v
	}

	if v, ok := cfg.Config["password"].(string); ok {
		socksCfg.Password = v
	}

	if v, ok := cfg.Config["connect_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			socksCfg.ConnectTimeout = d
		}
	}

	return NewSOCKS5ProxyBackend(socksCfg), nil
}

func (f *Factory) createWireGuard(cfg config.BackendConfig) (Backend, error) {
	wgCfg := WireGuardConfig{
		Name: cfg.Name,
	}

	if v, ok := cfg.Config["private_key"].(string); ok {
		wgCfg.PrivateKey = v
	} else {
		return nil, fmt.Errorf("wireguard backend requires 'private_key' config")
	}

	if v, ok := cfg.Config["address"].(string); ok {
		wgCfg.Address = v
	} else {
		return nil, fmt.Errorf("wireguard backend requires 'address' config")
	}

	if v, ok := cfg.Config["dns"].([]any); ok {
		for _, d := range v {
			if s, ok := d.(string); ok {
				wgCfg.DNS = append(wgCfg.DNS, s)
			}
		}
	}

	if v, ok := cfg.Config["mtu"].(int); ok {
		wgCfg.MTU = v
	}

	// Parse peer config
	if peerCfg, ok := cfg.Config["peer"].(map[string]any); ok {
		if v, ok := peerCfg["public_key"].(string); ok {
			wgCfg.Peer.PublicKey = v
		}
		if v, ok := peerCfg["endpoint"].(string); ok {
			wgCfg.Peer.Endpoint = v
		}
		if v, ok := peerCfg["preshared_key"].(string); ok {
			wgCfg.Peer.PresharedKey = v
		}
		if v, ok := peerCfg["persistent_keepalive"].(int); ok {
			wgCfg.Peer.PersistentKeepalive = v
		}
		if v, ok := peerCfg["allowed_ips"].([]any); ok {
			for _, ip := range v {
				if s, ok := ip.(string); ok {
					wgCfg.Peer.AllowedIPs = append(wgCfg.Peer.AllowedIPs, s)
				}
			}
		}
	}

	return NewWireGuardBackend(wgCfg), nil
}

func (f *Factory) createOpenVPN(cfg config.BackendConfig) (Backend, error) {
	ovpnCfg := OpenVPNConfig{
		Name: cfg.Name,
	}

	if v, ok := cfg.Config["config_file"].(string); ok {
		ovpnCfg.ConfigFile = v
	} else {
		return nil, fmt.Errorf("openvpn backend requires 'config_file' config")
	}

	if v, ok := cfg.Config["auth_file"].(string); ok {
		ovpnCfg.AuthFile = v
	}

	if v, ok := cfg.Config["binary"].(string); ok {
		ovpnCfg.Binary = v
	}

	if v, ok := cfg.Config["management_addr"].(string); ok {
		ovpnCfg.ManagementAddr = v
	}

	if v, ok := cfg.Config["management_port"].(int); ok {
		ovpnCfg.ManagementPort = v
	}

	if v, ok := cfg.Config["connect_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			ovpnCfg.ConnectTimeout = d
		}
	}

	if v, ok := cfg.Config["extra_args"].([]any); ok {
		for _, arg := range v {
			if s, ok := arg.(string); ok {
				ovpnCfg.ExtraArgs = append(ovpnCfg.ExtraArgs, s)
			}
		}
	}

	return NewOpenVPNBackend(ovpnCfg), nil
}

// CreateAll creates all backends from configuration.
func (f *Factory) CreateAll(configs []config.BackendConfig) (*Manager, error) {
	manager := NewManager()

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}

		backend, err := f.Create(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create backend %s: %w", cfg.Name, err)
		}

		if err := manager.Add(backend); err != nil {
			return nil, fmt.Errorf("failed to add backend %s: %w", cfg.Name, err)
		}
	}

	return manager, nil
}
