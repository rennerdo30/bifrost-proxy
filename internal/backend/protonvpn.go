package backend

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/protonvpn"
)

// ProtonVPNBackend provides connections through ProtonVPN.
type ProtonVPNBackend struct {
	name            string
	config          ProtonVPNConfig
	client          *protonvpn.Client
	delegate        Backend // OpenVPN backend (WireGuard requires API auth)
	selectedServer  *vpnprovider.Server
	startTime       time.Time
	healthy         atomic.Bool
	stats           protonvpnStats
	mu              sync.RWMutex
	running         bool
	stopChan        chan struct{}
	refreshTicker   *time.Ticker
	logger          *slog.Logger
}

type protonvpnStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// ProtonVPNConfig holds configuration for a ProtonVPN backend.
type ProtonVPNConfig struct {
	Name            string        `yaml:"name"`
	Username        string        `yaml:"username"`                    // Required: ProtonVPN OpenVPN username
	Password        string        `yaml:"password"`                    // Required: ProtonVPN OpenVPN password
	Country         string        `yaml:"country,omitempty"`           // ISO country code (e.g., "US", "DE")
	City            string        `yaml:"city,omitempty"`              // City name
	Tier            int           `yaml:"tier,omitempty"`              // Subscription tier: 0=free, 1=basic, 2=plus (default: 2)
	Protocol        string        `yaml:"protocol,omitempty"`          // Currently only "openvpn" is supported
	AutoSelect      bool          `yaml:"auto_select,omitempty"`       // Automatically select best server
	MaxLoad         int           `yaml:"max_load,omitempty"`          // Max server load percentage (0-100)
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"`  // How often to check for better servers
	Features        []string      `yaml:"features,omitempty"`          // Required features (e.g., "p2p", "streaming", "secure_core")
	SecureCore      bool          `yaml:"secure_core,omitempty"`       // Use Secure Core servers (multi-hop)
}

// NewProtonVPNBackend creates a new ProtonVPN backend.
func NewProtonVPNBackend(cfg ProtonVPNConfig) *ProtonVPNBackend {
	// ProtonVPN WireGuard requires API authentication which is complex,
	// so we default to OpenVPN
	if cfg.Protocol == "" {
		cfg.Protocol = "openvpn"
	}
	if cfg.Tier == 0 {
		cfg.Tier = protonvpn.TierPlus // Default to Plus tier
	}
	if cfg.MaxLoad == 0 {
		cfg.MaxLoad = 80
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute
	}

	// Create client with manual credentials
	client := protonvpn.NewClient(
		protonvpn.WithManualCredentials(cfg.Username, cfg.Password, cfg.Tier),
	)

	return &ProtonVPNBackend{
		name:     cfg.Name,
		config:   cfg,
		client:   client,
		stopChan: make(chan struct{}),
		logger:   slog.Default(),
	}
}

// Name returns the backend name.
func (b *ProtonVPNBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *ProtonVPNBackend) Type() string {
	return "protonvpn"
}

// Dial creates a connection through ProtonVPN.
func (b *ProtonVPNBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.RLock()
	if !b.running || b.delegate == nil {
		b.mu.RUnlock()
		return nil, NewBackendError(b.name, "dial", ErrBackendNotStarted)
	}
	delegate := b.delegate
	b.mu.RUnlock()

	conn, err := delegate.Dial(ctx, network, address)
	if err != nil {
		b.recordError(err)
		return nil, err
	}

	b.stats.activeConns.Add(1)
	b.stats.totalConns.Add(1)

	// Wrap connection to track stats
	tracked := &TrackedConn{
		Conn: conn,
		OnClose: func(bytesRead, bytesWritten int64) {
			b.stats.activeConns.Add(-1)
			b.stats.bytesRecv.Add(bytesRead)
			b.stats.bytesSent.Add(bytesWritten)
		},
	}

	return tracked, nil
}

// DialTimeout creates a connection with a specific timeout.
func (b *ProtonVPNBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the ProtonVPN connection.
func (b *ProtonVPNBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	b.logger.Info("starting ProtonVPN backend",
		"name", b.name,
		"protocol", b.config.Protocol,
		"country", b.config.Country,
		"tier", b.getTierName(),
		"secure_core", b.config.SecureCore,
	)

	// WireGuard is not supported without API authentication
	if b.config.Protocol == "wireguard" {
		return NewBackendError(b.name, "start", fmt.Errorf("WireGuard requires ProtonVPN API authentication; use OpenVPN with manual credentials instead"))
	}

	// Select a server
	server, err := b.selectServer(ctx)
	if err != nil {
		return NewBackendError(b.name, "select server", err)
	}
	b.selectedServer = server

	b.logger.Info("selected ProtonVPN server",
		"server", server.Name,
		"hostname", server.Hostname,
		"country", server.CountryCode,
		"city", server.City,
		"load", server.Load,
	)

	// Create credentials
	creds := vpnprovider.Credentials{
		Username: b.config.Username,
		Password: b.config.Password,
	}

	// Create the delegate backend (OpenVPN only for now)
	if err := b.createDelegate(ctx, server, creds); err != nil {
		return NewBackendError(b.name, "create delegate", err)
	}

	// Start the delegate
	if err := b.delegate.Start(ctx); err != nil {
		return NewBackendError(b.name, "start delegate", err)
	}

	b.running = true
	b.startTime = time.Now()
	b.healthy.Store(true)

	// Start server refresh goroutine if auto_select is enabled
	if b.config.AutoSelect && b.config.RefreshInterval > 0 {
		b.refreshTicker = time.NewTicker(b.config.RefreshInterval)
		go b.serverRefreshLoop()
	}

	return nil
}

func (b *ProtonVPNBackend) selectServer(ctx context.Context) (*vpnprovider.Server, error) {
	criteria := vpnprovider.ServerCriteria{
		Country:  b.config.Country,
		City:     b.config.City,
		Protocol: b.config.Protocol,
		MaxLoad:  b.config.MaxLoad,
		Features: b.config.Features,
		Fastest:  b.config.AutoSelect,
	}

	// Add tier feature for filtering
	switch b.config.Tier {
	case protonvpn.TierFree:
		criteria.Features = append(criteria.Features, "free")
	case protonvpn.TierBasic:
		criteria.Features = append(criteria.Features, "basic")
	case protonvpn.TierPlus:
		criteria.Features = append(criteria.Features, "plus")
	}

	// Add secure core feature if requested
	if b.config.SecureCore {
		criteria.Features = append(criteria.Features, "secure_core")
	}

	return b.client.SelectServer(ctx, criteria)
}

func (b *ProtonVPNBackend) createDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) error {
	switch b.config.Protocol {
	case "openvpn":
		ovpnConfig, err := b.client.GenerateOpenVPNConfig(ctx, server, creds)
		if err != nil {
			return fmt.Errorf("generate OpenVPN config: %w", err)
		}

		cfg := OpenVPNConfig{
			Name:          b.name + "-ovpn",
			ConfigContent: ovpnConfig.ConfigContent,
			Username:      ovpnConfig.Username,
			Password:      ovpnConfig.Password,
		}
		b.delegate = NewOpenVPNBackend(cfg)

	case "wireguard":
		// WireGuard is not supported without API authentication
		return fmt.Errorf("WireGuard requires ProtonVPN API authentication; use OpenVPN instead")

	default:
		return fmt.Errorf("unsupported protocol: %s", b.config.Protocol)
	}

	return nil
}

func (b *ProtonVPNBackend) serverRefreshLoop() {
	for {
		select {
		case <-b.stopChan:
			return
		case <-b.refreshTicker.C:
			b.checkAndRefreshServer()
		}
	}
}

func (b *ProtonVPNBackend) checkAndRefreshServer() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newServer, err := b.selectServer(ctx)
	if err != nil {
		b.logger.Warn("failed to check for better server",
			"error", err,
		)
		return
	}

	b.mu.RLock()
	currentServer := b.selectedServer
	b.mu.RUnlock()

	// Only log if there's a significantly better server available
	if currentServer != nil && newServer.Load < currentServer.Load-15 {
		b.logger.Info("better server available",
			"current_server", currentServer.Name,
			"current_load", currentServer.Load,
			"new_server", newServer.Name,
			"new_load", newServer.Load,
		)
	}
}

// Stop shuts down the ProtonVPN connection.
func (b *ProtonVPNBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil
	}

	close(b.stopChan)

	if b.refreshTicker != nil {
		b.refreshTicker.Stop()
	}

	if b.delegate != nil {
		if err := b.delegate.Stop(ctx); err != nil {
			b.logger.Warn("failed to stop delegate backend",
				"error", err,
			)
		}
	}

	b.running = false
	b.healthy.Store(false)
	b.stopChan = make(chan struct{})

	return nil
}

// IsHealthy returns the health status.
func (b *ProtonVPNBackend) IsHealthy() bool {
	if !b.healthy.Load() {
		return false
	}

	b.mu.RLock()
	delegate := b.delegate
	b.mu.RUnlock()

	if delegate != nil {
		return delegate.IsHealthy()
	}

	return false
}

// Stats returns backend statistics.
func (b *ProtonVPNBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "protonvpn",
		Healthy:           b.IsHealthy(),
		ActiveConnections: b.stats.activeConns.Load(),
		TotalConnections:  b.stats.totalConns.Load(),
		BytesSent:         b.stats.bytesSent.Load(),
		BytesReceived:     b.stats.bytesRecv.Load(),
		Errors:            b.stats.errors.Load(),
		LastError:         lastErr,
		LastErrorTime:     lastErrTime,
		Uptime:            time.Since(b.startTime),
	}
}

func (b *ProtonVPNBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}

// SelectedServer returns the currently selected server, if any.
func (b *ProtonVPNBackend) SelectedServer() *vpnprovider.Server {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.selectedServer
}

func (b *ProtonVPNBackend) getTierName() string {
	switch b.config.Tier {
	case protonvpn.TierFree:
		return "free"
	case protonvpn.TierBasic:
		return "basic"
	case protonvpn.TierPlus:
		return "plus"
	default:
		return fmt.Sprintf("tier_%d", b.config.Tier)
	}
}

// GetAvailableCountries returns the list of available countries.
func (b *ProtonVPNBackend) GetAvailableCountries(ctx context.Context) ([]vpnprovider.Country, error) {
	return b.client.GetAvailableCountries(ctx)
}
