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
	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/mullvad"
)

// MullvadBackend provides connections through Mullvad VPN.
type MullvadBackend struct {
	name           string
	config         MullvadConfig
	client         *mullvad.Client
	delegate       Backend // Either WireGuard or OpenVPN backend
	selectedServer *vpnprovider.Server
	startTime      time.Time
	healthy        atomic.Bool
	stats          mullvadStats
	mu             sync.RWMutex
	running        bool
	stopChan       chan struct{}
	refreshTicker  *time.Ticker
	logger         *slog.Logger
}

type mullvadStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// MullvadConfig holds configuration for a Mullvad backend.
type MullvadConfig struct {
	Name            string        `yaml:"name"`
	AccountID       string        `yaml:"account_id"`                 // Required: 16-digit Mullvad account number
	Country         string        `yaml:"country,omitempty"`          // ISO country code (e.g., "US", "DE")
	City            string        `yaml:"city,omitempty"`             // City name
	Protocol        string        `yaml:"protocol,omitempty"`         // "wireguard" or "openvpn" (default: wireguard)
	AutoSelect      bool          `yaml:"auto_select,omitempty"`      // Automatically select best server
	MaxLoad         int           `yaml:"max_load,omitempty"`         // Max server load percentage (0-100)
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"` // How often to check for better servers
	Features        []string      `yaml:"features,omitempty"`         // Required features

	// OpenVPN TLS material. CACert is the PEM-encoded CA certificate used to
	// verify the Mullvad OpenVPN server; it is REQUIRED for the OpenVPN protocol
	// (config generation fails closed without it). No CA is embedded in the
	// binary. TLSAuthKey is the optional OpenVPN tls-auth static key.
	CACert     string `yaml:"ca_cert,omitempty"`      // OpenVPN CA certificate (PEM)
	TLSAuthKey string `yaml:"tls_auth_key,omitempty"` // OpenVPN tls-auth static key

	// LeakProofRouting requests Linux policy-routing based egress isolation on
	// OpenVPN delegates so traffic cannot leak outside the tunnel. It requires
	// root, is Linux-only, and is OFF by default. WireGuard delegates use a
	// userspace netstack and are unaffected.
	LeakProofRouting bool `yaml:"leak_proof_routing,omitempty"`

	// Network carries process-wide outbound tuning (keep-alive, dial timeout,
	// prefer-IPv6) threaded onto OpenVPN delegates. WireGuard delegates dial
	// through a userspace netstack and ignore it.
	Network NetworkTuning `yaml:"-"`
}

// NewMullvadBackend creates a new Mullvad backend.
func NewMullvadBackend(cfg MullvadConfig, client *mullvad.Client) *MullvadBackend {
	if cfg.Protocol == "" {
		cfg.Protocol = "wireguard"
	}
	if cfg.MaxLoad == 0 {
		cfg.MaxLoad = 80
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute
	}

	return &MullvadBackend{
		name:     cfg.Name,
		config:   cfg,
		client:   client,
		stopChan: make(chan struct{}),
		logger:   slog.Default(),
	}
}

// Name returns the backend name.
func (b *MullvadBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *MullvadBackend) Type() string {
	return "mullvad"
}

// Dial creates a connection through Mullvad.
func (b *MullvadBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
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
func (b *MullvadBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the Mullvad connection.
func (b *MullvadBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	b.logger.Info("starting Mullvad backend",
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

	b.logger.Info("selected Mullvad server",
		"server", server.Hostname,
		"country", server.CountryCode,
		"city", server.City,
	)

	// Create credentials
	creds := vpnprovider.Credentials{
		AccountID:  b.config.AccountID,
		CACert:     b.config.CACert,
		TLSAuthKey: b.config.TLSAuthKey,
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

func (b *MullvadBackend) selectServer(ctx context.Context) (*vpnprovider.Server, error) {
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

func (b *MullvadBackend) createDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) error {
	delegate, err := b.buildDelegate(ctx, server, creds)
	if err != nil {
		return err
	}
	b.delegate = delegate
	return nil
}

// buildDelegate constructs (but does not start) a delegate backend.
func (b *MullvadBackend) buildDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (Backend, error) {
	switch b.config.Protocol {
	case "wireguard":
		wgConfig, err := b.client.GenerateWireGuardConfig(ctx, server, creds)
		if err != nil {
			return nil, fmt.Errorf("generate WireGuard config: %w", err)
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
		return NewWireGuardBackend(cfg), nil

	case "openvpn":
		ovpnConfig, err := b.client.GenerateOpenVPNConfig(ctx, server, creds)
		if err != nil {
			return nil, fmt.Errorf("generate OpenVPN config: %w", err)
		}

		cfg := OpenVPNConfig{
			Name:             b.name + "-ovpn",
			ConfigContent:    ovpnConfig.ConfigContent,
			Username:         ovpnConfig.Username,
			Password:         ovpnConfig.Password,
			LeakProofRouting: b.config.LeakProofRouting,
			Network:          b.config.Network,
		}
		return NewOpenVPNBackend(cfg), nil

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", b.config.Protocol)
	}
}

func (b *MullvadBackend) serverRefreshLoop() {
	for {
		select {
		case <-b.stopChan:
			return
		case <-b.refreshTicker.C:
			b.checkAndRefreshServer()
		}
	}
}

func (b *MullvadBackend) checkAndRefreshServer() {
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

	// Only switch if a different server is meaningfully less loaded (20% lower).
	if currentServer == nil || newServer.Hostname == currentServer.Hostname ||
		newServer.Load >= currentServer.Load-20 {
		return
	}

	b.logger.Info("switching to better server",
		"old_server", currentServer.Hostname,
		"old_load", currentServer.Load,
		"new_server", newServer.Hostname,
		"new_load", newServer.Load,
	)

	if err := b.swapDelegate(ctx, newServer); err != nil {
		b.logger.Warn("failed to switch to better server, keeping current",
			"new_server", newServer.Hostname,
			"error", err,
		)
		return
	}

	b.logger.Info("switched to better server", "server", newServer.Hostname)
}

// swapDelegate builds and starts a new delegate for the given server, then
// atomically replaces the running delegate and stops the old one. If building
// or starting the new delegate fails, the current delegate is left untouched.
func (b *MullvadBackend) swapDelegate(ctx context.Context, server *vpnprovider.Server) error {
	creds := vpnprovider.Credentials{
		AccountID:  b.config.AccountID,
		CACert:     b.config.CACert,
		TLSAuthKey: b.config.TLSAuthKey,
	}

	newDelegate, err := b.buildDelegate(ctx, server, creds)
	if err != nil {
		return fmt.Errorf("build delegate: %w", err)
	}

	if err := newDelegate.Start(ctx); err != nil {
		return fmt.Errorf("start delegate: %w", err)
	}

	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		_ = newDelegate.Stop(ctx) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("backend not running")
	}
	oldDelegate := b.delegate
	b.delegate = newDelegate
	b.selectedServer = server
	b.mu.Unlock()

	if oldDelegate != nil {
		if err := oldDelegate.Stop(ctx); err != nil {
			b.logger.Warn("failed to stop old delegate after swap", "error", err)
		}
	}

	return nil
}

// Stop shuts down the Mullvad connection.
func (b *MullvadBackend) Stop(ctx context.Context) error {
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
func (b *MullvadBackend) IsHealthy() bool {
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
func (b *MullvadBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "mullvad",
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

func (b *MullvadBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}

// SelectedServer returns the currently selected server, if any.
func (b *MullvadBackend) SelectedServer() *vpnprovider.Server {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.selectedServer
}

// GetAccountInfo returns the Mullvad account information.
func (b *MullvadBackend) GetAccountInfo(ctx context.Context) (*mullvad.AccountInfo, error) {
	return b.client.GetAccountInfo(ctx)
}
