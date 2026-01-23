package backend

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/mullvad"
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
	case "nordvpn":
		return f.createNordVPN(cfg)
	case "mullvad":
		return f.createMullvad(cfg)
	case "pia":
		return f.createPIA(cfg)
	case "protonvpn":
		return f.createProtonVPN(cfg)
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

	// Config can be provided via file path OR inline content
	if v, ok := cfg.Config["config_file"].(string); ok && v != "" {
		ovpnCfg.ConfigFile = v
	}
	if v, ok := cfg.Config["config_content"].(string); ok && v != "" {
		ovpnCfg.ConfigContent = v
	}

	// Require either config_file or config_content
	if ovpnCfg.ConfigFile == "" && ovpnCfg.ConfigContent == "" {
		return nil, fmt.Errorf("openvpn backend requires 'config_file' or 'config_content' config")
	}

	// Auth can be provided via file path OR inline credentials
	if v, ok := cfg.Config["auth_file"].(string); ok {
		ovpnCfg.AuthFile = v
	}
	if v, ok := cfg.Config["username"].(string); ok {
		ovpnCfg.Username = v
	}
	if v, ok := cfg.Config["password"].(string); ok {
		ovpnCfg.Password = v
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

func (f *Factory) createNordVPN(cfg config.BackendConfig) (Backend, error) {
	nordCfg := NordVPNConfig{
		Name: cfg.Name,
	}

	if v, ok := cfg.Config["country"].(string); ok {
		nordCfg.Country = v
	}

	if v, ok := cfg.Config["city"].(string); ok {
		nordCfg.City = v
	}

	if v, ok := cfg.Config["protocol"].(string); ok {
		nordCfg.Protocol = v
	}

	if v, ok := cfg.Config["auto_select"].(bool); ok {
		nordCfg.AutoSelect = v
	}

	if v, ok := cfg.Config["max_load"].(int); ok {
		nordCfg.MaxLoad = v
	}

	if v, ok := cfg.Config["refresh_interval"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			nordCfg.RefreshInterval = d
		}
	}

	if v, ok := cfg.Config["features"].([]any); ok {
		for _, f := range v {
			if s, ok := f.(string); ok {
				nordCfg.Features = append(nordCfg.Features, s)
			}
		}
	}

	// Authentication
	if v, ok := cfg.Config["access_token"].(string); ok {
		nordCfg.AccessToken = v
	}
	if v, ok := cfg.Config["username"].(string); ok {
		nordCfg.Username = v
	}
	if v, ok := cfg.Config["password"].(string); ok {
		nordCfg.Password = v
	}

	// Validate credentials based on protocol
	protocol := nordCfg.Protocol
	if protocol == "" {
		protocol = "wireguard"
	}
	if protocol == "wireguard" || protocol == "nordlynx" {
		if nordCfg.AccessToken == "" {
			return nil, fmt.Errorf("nordvpn wireguard backend requires 'access_token' (private key) config")
		}
	} else if protocol == "openvpn" {
		if nordCfg.Username == "" || nordCfg.Password == "" {
			return nil, fmt.Errorf("nordvpn openvpn backend requires 'username' and 'password' config")
		}
	}

	return NewNordVPNBackend(nordCfg), nil
}

func (f *Factory) createMullvad(cfg config.BackendConfig) (Backend, error) {
	mullvadCfg := MullvadConfig{
		Name: cfg.Name,
	}

	// Account ID is required
	if v, ok := cfg.Config["account_id"].(string); ok {
		mullvadCfg.AccountID = v
	} else {
		return nil, fmt.Errorf("mullvad backend requires 'account_id' config")
	}

	if v, ok := cfg.Config["country"].(string); ok {
		mullvadCfg.Country = v
	}

	if v, ok := cfg.Config["city"].(string); ok {
		mullvadCfg.City = v
	}

	if v, ok := cfg.Config["protocol"].(string); ok {
		mullvadCfg.Protocol = v
	}

	if v, ok := cfg.Config["auto_select"].(bool); ok {
		mullvadCfg.AutoSelect = v
	}

	if v, ok := cfg.Config["max_load"].(int); ok {
		mullvadCfg.MaxLoad = v
	}

	if v, ok := cfg.Config["refresh_interval"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			mullvadCfg.RefreshInterval = d
		}
	}

	if v, ok := cfg.Config["features"].([]any); ok {
		for _, f := range v {
			if s, ok := f.(string); ok {
				mullvadCfg.Features = append(mullvadCfg.Features, s)
			}
		}
	}

	// Create Mullvad client with account ID
	client, err := mullvad.NewClient(mullvadCfg.AccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to create mullvad client: %w", err)
	}

	return NewMullvadBackend(mullvadCfg, client), nil
}

func (f *Factory) createPIA(cfg config.BackendConfig) (Backend, error) {
	piaCfg := PIAConfig{
		Name: cfg.Name,
	}

	// Credentials are required
	if v, ok := cfg.Config["username"].(string); ok {
		piaCfg.Username = v
	} else {
		return nil, fmt.Errorf("pia backend requires 'username' config")
	}

	if v, ok := cfg.Config["password"].(string); ok {
		piaCfg.Password = v
	} else {
		return nil, fmt.Errorf("pia backend requires 'password' config")
	}

	if v, ok := cfg.Config["country"].(string); ok {
		piaCfg.Country = v
	}

	if v, ok := cfg.Config["city"].(string); ok {
		piaCfg.City = v
	}

	if v, ok := cfg.Config["protocol"].(string); ok {
		piaCfg.Protocol = v
	}

	if v, ok := cfg.Config["auto_select"].(bool); ok {
		piaCfg.AutoSelect = v
	}

	if v, ok := cfg.Config["max_load"].(int); ok {
		piaCfg.MaxLoad = v
	}

	if v, ok := cfg.Config["refresh_interval"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			piaCfg.RefreshInterval = d
		}
	}

	if v, ok := cfg.Config["port_forwarding"].(bool); ok {
		piaCfg.PortForwarding = v
	}

	if v, ok := cfg.Config["features"].([]any); ok {
		for _, f := range v {
			if s, ok := f.(string); ok {
				piaCfg.Features = append(piaCfg.Features, s)
			}
		}
	}

	return NewPIABackend(piaCfg), nil
}

func (f *Factory) createProtonVPN(cfg config.BackendConfig) (Backend, error) {
	protonCfg := ProtonVPNConfig{
		Name: cfg.Name,
	}

	// Credentials are required (OpenVPN credentials from Proton account)
	if v, ok := cfg.Config["username"].(string); ok {
		protonCfg.Username = v
	} else {
		return nil, fmt.Errorf("protonvpn backend requires 'username' config (OpenVPN credentials)")
	}

	if v, ok := cfg.Config["password"].(string); ok {
		protonCfg.Password = v
	} else {
		return nil, fmt.Errorf("protonvpn backend requires 'password' config (OpenVPN credentials)")
	}

	if v, ok := cfg.Config["country"].(string); ok {
		protonCfg.Country = v
	}

	if v, ok := cfg.Config["city"].(string); ok {
		protonCfg.City = v
	}

	// Tier: 0=free, 1=basic, 2=plus
	if v, ok := cfg.Config["tier"].(int); ok {
		protonCfg.Tier = v
	}

	if v, ok := cfg.Config["protocol"].(string); ok {
		protonCfg.Protocol = v
	}

	if v, ok := cfg.Config["auto_select"].(bool); ok {
		protonCfg.AutoSelect = v
	}

	if v, ok := cfg.Config["max_load"].(int); ok {
		protonCfg.MaxLoad = v
	}

	if v, ok := cfg.Config["refresh_interval"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			protonCfg.RefreshInterval = d
		}
	}

	if v, ok := cfg.Config["secure_core"].(bool); ok {
		protonCfg.SecureCore = v
	}

	if v, ok := cfg.Config["features"].([]any); ok {
		for _, f := range v {
			if s, ok := f.(string); ok {
				protonCfg.Features = append(protonCfg.Features, s)
			}
		}
	}

	return NewProtonVPNBackend(protonCfg), nil
}

// CreateAll creates all backends from configuration.
// Backends that fail to create are logged and skipped rather than causing a total failure.
// Returns an error only if no backends could be created at all.
func (f *Factory) CreateAll(configs []config.BackendConfig) (*Manager, error) {
	manager := NewManager()
	var successCount int
	var enabledCount int

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		enabledCount++

		backend, err := f.Create(cfg)
		if err != nil {
			slog.Error("failed to create backend, skipping",
				"backend", cfg.Name,
				"type", cfg.Type,
				"error", err,
			)
			continue
		}

		if err := manager.Add(backend); err != nil {
			slog.Error("failed to add backend to manager, skipping",
				"backend", cfg.Name,
				"type", cfg.Type,
				"error", err,
			)
			continue
		}

		successCount++
		slog.Info("backend created successfully",
			"backend", cfg.Name,
			"type", cfg.Type,
		)
	}

	if enabledCount > 0 && successCount == 0 {
		return nil, fmt.Errorf("all %d enabled backends failed to initialize", enabledCount)
	}

	if enabledCount > 0 && successCount < enabledCount {
		slog.Warn("some backends failed to initialize",
			"successful", successCount,
			"failed", enabledCount-successCount,
			"total_enabled", enabledCount,
		)
	}

	return manager, nil
}
