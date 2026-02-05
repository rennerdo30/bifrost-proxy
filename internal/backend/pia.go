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
	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/pia"
)

// PIABackend provides connections through Private Internet Access VPN.
type PIABackend struct {
	name           string
	config         PIAConfig
	client         *pia.Client
	delegate       Backend // Either WireGuard or OpenVPN backend
	selectedServer *vpnprovider.Server
	startTime      time.Time
	healthy        atomic.Bool
	stats          piaStats
	mu             sync.RWMutex
	running        bool
	stopChan       chan struct{}
	refreshTicker  *time.Ticker
	logger         *slog.Logger
}

type piaStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// PIAConfig holds configuration for a PIA backend.
type PIAConfig struct {
	Name            string        `yaml:"name"`
	Username        string        `yaml:"username"`                   // Required: PIA username
	Password        string        `yaml:"password"`                   // Required: PIA password
	Country         string        `yaml:"country,omitempty"`          // ISO country code (e.g., "US", "DE")
	City            string        `yaml:"city,omitempty"`             // City/region name
	Protocol        string        `yaml:"protocol,omitempty"`         // "wireguard" or "openvpn" (default: wireguard)
	AutoSelect      bool          `yaml:"auto_select,omitempty"`      // Automatically select best server
	MaxLoad         int           `yaml:"max_load,omitempty"`         // Max server load percentage (0-100)
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"` // How often to check for better servers
	PortForwarding  bool          `yaml:"port_forwarding,omitempty"`  // Enable port forwarding (PIA feature)
	Features        []string      `yaml:"features,omitempty"`         // Required features
}

// NewPIABackend creates a new PIA backend.
func NewPIABackend(cfg PIAConfig) *PIABackend {
	if cfg.Protocol == "" {
		cfg.Protocol = "wireguard"
	}
	if cfg.MaxLoad == 0 {
		cfg.MaxLoad = 80
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute
	}

	return &PIABackend{
		name:     cfg.Name,
		config:   cfg,
		client:   pia.NewClient(cfg.Username, cfg.Password),
		stopChan: make(chan struct{}),
		logger:   slog.Default(),
	}
}

// Name returns the backend name.
func (b *PIABackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *PIABackend) Type() string {
	return "pia"
}

// Dial creates a connection through PIA.
func (b *PIABackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
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
func (b *PIABackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the PIA connection.
func (b *PIABackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	b.logger.Info("starting PIA backend",
		"name", b.name,
		"protocol", b.config.Protocol,
		"country", b.config.Country,
		"port_forwarding", b.config.PortForwarding,
	)

	// Authenticate first to validate credentials
	if _, err := b.client.Authenticate(ctx); err != nil {
		return NewBackendError(b.name, "authenticate", err)
	}

	// Select a server
	server, err := b.selectServer(ctx)
	if err != nil {
		return NewBackendError(b.name, "select server", err)
	}
	b.selectedServer = server

	b.logger.Info("selected PIA server",
		"server", server.Name,
		"country", server.CountryCode,
		"city", server.City,
	)

	// Create credentials
	creds := vpnprovider.Credentials{
		Username: b.config.Username,
		Password: b.config.Password,
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

func (b *PIABackend) selectServer(ctx context.Context) (*vpnprovider.Server, error) {
	criteria := vpnprovider.ServerCriteria{
		Country:  b.config.Country,
		City:     b.config.City,
		Protocol: b.config.Protocol,
		MaxLoad:  b.config.MaxLoad,
		Features: b.config.Features,
		Fastest:  b.config.AutoSelect,
	}

	// Add port_forwarding feature if requested
	if b.config.PortForwarding {
		criteria.Features = append(criteria.Features, "port_forwarding")
	}

	return b.client.SelectServer(ctx, criteria)
}

func (b *PIABackend) createDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) error {
	switch b.config.Protocol {
	case "wireguard":
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

func (b *PIABackend) serverRefreshLoop() {
	for {
		select {
		case <-b.stopChan:
			return
		case <-b.refreshTicker.C:
			b.checkAndRefreshServer()
		}
	}
}

func (b *PIABackend) checkAndRefreshServer() {
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

	// Log if a better server is available
	if currentServer != nil && newServer.Hostname != currentServer.Hostname {
		b.logger.Debug("alternative server available",
			"current_server", currentServer.Hostname,
			"alternative_server", newServer.Hostname,
		)
	}
}

// Stop shuts down the PIA connection.
func (b *PIABackend) Stop(ctx context.Context) error {
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

	// Invalidate the token
	b.client.InvalidateToken()

	b.running = false
	b.healthy.Store(false)
	b.stopChan = make(chan struct{})

	return nil
}

// IsHealthy returns the health status.
func (b *PIABackend) IsHealthy() bool {
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
func (b *PIABackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "pia",
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

func (b *PIABackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}

// SelectedServer returns the currently selected server, if any.
func (b *PIABackend) SelectedServer() *vpnprovider.Server {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.selectedServer
}
