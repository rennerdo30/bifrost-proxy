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
	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/nordvpn"
)

// NordVPNBackend provides connections through NordVPN.
type NordVPNBackend struct {
	name            string
	config          NordVPNConfig
	client          *nordvpn.Client
	delegate        Backend // Either WireGuard or OpenVPN backend
	selectedServer  *vpnprovider.Server
	startTime       time.Time
	healthy         atomic.Bool
	stats           nordvpnStats
	mu              sync.RWMutex
	running         bool
	stopChan        chan struct{}
	refreshTicker   *time.Ticker
	logger          *slog.Logger
}

type nordvpnStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// NordVPNConfig holds configuration for a NordVPN backend.
type NordVPNConfig struct {
	Name            string        `yaml:"name"`
	Country         string        `yaml:"country,omitempty"`           // ISO country code (e.g., "US", "DE")
	City            string        `yaml:"city,omitempty"`              // City name
	Protocol        string        `yaml:"protocol,omitempty"`          // "wireguard" or "openvpn" (default: wireguard)
	AutoSelect      bool          `yaml:"auto_select,omitempty"`       // Automatically select best server
	MaxLoad         int           `yaml:"max_load,omitempty"`          // Max server load percentage (0-100)
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"`  // How often to check for better servers
	Features        []string      `yaml:"features,omitempty"`          // Required features (e.g., "p2p", "streaming")

	// Authentication - for WireGuard, use access_token (private key)
	// For OpenVPN, use username and password
	AccessToken string `yaml:"access_token,omitempty"` // WireGuard private key
	Username    string `yaml:"username,omitempty"`     // OpenVPN username
	Password    string `yaml:"password,omitempty"`     // OpenVPN password
}

// NewNordVPNBackend creates a new NordVPN backend.
func NewNordVPNBackend(cfg NordVPNConfig) *NordVPNBackend {
	if cfg.Protocol == "" {
		cfg.Protocol = "wireguard"
	}
	if cfg.MaxLoad == 0 {
		cfg.MaxLoad = 70
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute
	}

	return &NordVPNBackend{
		name:     cfg.Name,
		config:   cfg,
		client:   nordvpn.NewClient(),
		stopChan: make(chan struct{}),
		logger:   slog.Default(),
	}
}

// Name returns the backend name.
func (b *NordVPNBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *NordVPNBackend) Type() string {
	return "nordvpn"
}

// Dial creates a connection through NordVPN.
func (b *NordVPNBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
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
func (b *NordVPNBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the NordVPN connection.
func (b *NordVPNBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	b.logger.Info("starting NordVPN backend",
		"name", b.name,
		"protocol", b.config.Protocol,
		"country", b.config.Country,
	)

	// Select a server
	server, err := b.selectServer(ctx)
	if err != nil {
		return NewBackendError(b.name, "select server", err)
	}
	b.selectedServer = server

	b.logger.Info("selected NordVPN server",
		"server", server.Hostname,
		"country", server.CountryCode,
		"city", server.City,
		"load", server.Load,
	)

	// Create credentials
	creds := vpnprovider.Credentials{
		AccessToken: b.config.AccessToken,
		Username:    b.config.Username,
		Password:    b.config.Password,
	}

	// Create the delegate backend based on protocol
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

func (b *NordVPNBackend) selectServer(ctx context.Context) (*vpnprovider.Server, error) {
	criteria := vpnprovider.ServerCriteria{
		Country:  b.config.Country,
		City:     b.config.City,
		Protocol: b.config.Protocol,
		MaxLoad:  b.config.MaxLoad,
		Features: b.config.Features,
		Fastest:  b.config.AutoSelect,
	}

	return b.client.SelectServer(ctx, criteria)
}

func (b *NordVPNBackend) createDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) error {
	switch b.config.Protocol {
	case "wireguard", "nordlynx":
		wgConfig, err := b.client.GenerateWireGuardConfig(ctx, server, creds)
		if err != nil {
			return fmt.Errorf("generate WireGuard config: %w", err)
		}

		cfg := WireGuardConfig{
			Name:       b.name + "-wg",
			PrivateKey: wgConfig.PrivateKey,
			Address:    wgConfig.Address,
			DNS:        wgConfig.DNS,
			Peer: WireGuardPeer{
				PublicKey:           wgConfig.Peer.PublicKey,
				Endpoint:            wgConfig.Peer.Endpoint,
				AllowedIPs:          wgConfig.Peer.AllowedIPs,
				PersistentKeepalive: wgConfig.Peer.PersistentKeepalive,
				PresharedKey:        wgConfig.Peer.PresharedKey,
			},
		}
		b.delegate = NewWireGuardBackend(cfg)

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

	default:
		return fmt.Errorf("unsupported protocol: %s", b.config.Protocol)
	}

	return nil
}

func (b *NordVPNBackend) serverRefreshLoop() {
	for {
		select {
		case <-b.stopChan:
			return
		case <-b.refreshTicker.C:
			b.checkAndRefreshServer()
		}
	}
}

func (b *NordVPNBackend) checkAndRefreshServer() {
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

	// Only switch if the new server is significantly better (20% less load)
	if currentServer != nil && newServer.Load < currentServer.Load-20 {
		b.logger.Info("switching to better server",
			"old_server", currentServer.Hostname,
			"old_load", currentServer.Load,
			"new_server", newServer.Hostname,
			"new_load", newServer.Load,
		)
		// Note: Hot-swapping is complex, log for now
		// In a production implementation, you'd want to gracefully
		// drain connections and switch to the new server
	}
}

// Stop shuts down the NordVPN connection.
func (b *NordVPNBackend) Stop(ctx context.Context) error {
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
func (b *NordVPNBackend) IsHealthy() bool {
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
func (b *NordVPNBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	b.mu.RLock()
	server := b.selectedServer
	b.mu.RUnlock()

	stats := Stats{
		Name:              b.name,
		Type:              "nordvpn",
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

	// Add server info to stats if available
	if server != nil {
		b.logger.Debug("NordVPN backend stats",
			"server", server.Hostname,
			"load", server.Load,
		)
	}

	return stats
}

func (b *NordVPNBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}

// SelectedServer returns the currently selected server, if any.
func (b *NordVPNBackend) SelectedServer() *vpnprovider.Server {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.selectedServer
}
