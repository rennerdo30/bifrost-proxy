package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/pia"
)

// portForwardRunner drives the PIA port-forwarding lifecycle against a tunnel
// gateway. It is satisfied by *pia.PortForwarder; the indirection exists so the
// backend wiring can be unit-tested with a fake (no live PIA gateway).
type portForwardRunner interface {
	// Run acquires a forwarded port, delivers it once on portCh, then keeps it
	// alive until ctx is canceled. It blocks until ctx is done and returns the
	// terminal error.
	Run(ctx context.Context, params pia.PortForwardParams, portCh chan<- int) error
}

// portForwarderFactory builds a portForwardRunner for the given params. The
// default implementation returns a real *pia.PortForwarder; tests override it.
type portForwarderFactory func(params pia.PortForwardParams, logger *slog.Logger) portForwardRunner

// defaultPortForwarderFactory wires the production PIA port forwarder.
func defaultPortForwarderFactory(params pia.PortForwardParams, logger *slog.Logger) portForwardRunner {
	return pia.NewPortForwarder(params, logger)
}

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

	// Port forwarding lifecycle (only active when config.PortForwarding is set).
	newPortForwarder portForwarderFactory
	forwardedPort    atomic.Int64
	pfMu             sync.Mutex // guards pfCancel/pfDone
	pfCancel         context.CancelFunc
	pfDone           chan struct{}

	// gateway/gatewayHostname carry the in-tunnel port-forwarding parameters
	// surfaced by the most recently built WireGuard delegate. Guarded by mu.
	gateway         string
	gatewayHostname string
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
		name:             cfg.Name,
		config:           cfg,
		client:           pia.NewClient(cfg.Username, cfg.Password),
		stopChan:         make(chan struct{}),
		logger:           slog.Default(),
		newPortForwarder: defaultPortForwarderFactory,
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

	// Start port forwarding if enabled. Fail closed: if it cannot be set up
	// (missing gateway/token) we tear down the partially started backend and
	// return an error rather than silently claiming success.
	if b.config.PortForwarding {
		gw := gatewayInfo{ip: b.gateway, hostname: b.gatewayHostname}
		if err := b.startPortForwarding(gw); err != nil {
			b.logger.Error("PIA port forwarding could not be started", "error", err)
			if stopErr := b.delegate.Stop(ctx); stopErr != nil {
				b.logger.Warn("failed to stop delegate after port-forwarding failure", "error", stopErr)
			}
			b.client.InvalidateToken()
			b.running = false
			b.healthy.Store(false)
			return NewBackendError(b.name, "start port forwarding", err)
		}
	}

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

// gatewayInfo carries the in-tunnel port-forwarding parameters surfaced by a
// built delegate. Both fields are empty for protocols that do not expose them.
type gatewayInfo struct {
	ip       string
	hostname string
}

func (b *PIABackend) createDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) error {
	delegate, gw, err := b.buildDelegate(ctx, server, creds)
	if err != nil {
		return err
	}
	b.delegate = delegate
	b.gateway = gw.ip
	b.gatewayHostname = gw.hostname
	return nil
}

// buildDelegate constructs (but does not start) a delegate backend and returns
// the in-tunnel gateway parameters it surfaced (empty for OpenVPN).
func (b *PIABackend) buildDelegate(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (Backend, gatewayInfo, error) {
	switch b.config.Protocol {
	case "wireguard":
		wgConfig, err := b.client.GenerateWireGuardConfig(ctx, server, creds)
		if err != nil {
			return nil, gatewayInfo{}, fmt.Errorf("generate WireGuard config: %w", err)
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
		// Surface the in-tunnel gateway parameters so port forwarding can target
		// the gateway once the tunnel is up. Only WireGuard exposes these today.
		gw := gatewayInfo{ip: wgConfig.Gateway, hostname: wgConfig.GatewayHostname}
		return NewWireGuardBackend(cfg), gw, nil

	case "openvpn":
		ovpnConfig, err := b.client.GenerateOpenVPNConfig(ctx, server, creds)
		if err != nil {
			return nil, gatewayInfo{}, fmt.Errorf("generate OpenVPN config: %w", err)
		}

		cfg := OpenVPNConfig{
			Name:             b.name + "-ovpn",
			ConfigContent:    ovpnConfig.ConfigContent,
			Username:         ovpnConfig.Username,
			Password:         ovpnConfig.Password,
			LeakProofRouting: b.config.LeakProofRouting,
			Network:          b.config.Network,
		}
		// OpenVPN config generation does not surface the in-tunnel gateway, so
		// port forwarding cannot be driven for this protocol.
		return NewOpenVPNBackend(cfg), gatewayInfo{}, nil

	default:
		return nil, gatewayInfo{}, fmt.Errorf("unsupported protocol: %s", b.config.Protocol)
	}
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

	// Only switch if the new server is meaningfully less loaded (20% lower).
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
func (b *PIABackend) swapDelegate(ctx context.Context, server *vpnprovider.Server) error {
	creds := vpnprovider.Credentials{
		Username: b.config.Username,
		Password: b.config.Password,
	}

	newDelegate, gw, err := b.buildDelegate(ctx, server, creds)
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
	b.gateway = gw.ip
	b.gatewayHostname = gw.hostname
	b.mu.Unlock()

	if oldDelegate != nil {
		if err := oldDelegate.Stop(ctx); err != nil {
			b.logger.Warn("failed to stop old delegate after swap", "error", err)
		}
	}

	// The forwarded port is bound to the old gateway; rebind against the new
	// tunnel so port forwarding follows the server switch.
	if b.config.PortForwarding {
		b.stopPortForwarding()
		if err := b.startPortForwarding(gw); err != nil {
			b.logger.Error("failed to restart PIA port forwarding after server switch",
				"server", server.Hostname,
				"error", err,
			)
		}
	}

	return nil
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

	// Stop port forwarding (cancels the renewal loop and waits for it to exit).
	b.stopPortForwarding()
	b.forwardedPort.Store(0)

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

// ForwardedPort returns the port granted by PIA port forwarding, or 0 if port
// forwarding is disabled or a port has not yet been granted.
func (b *PIABackend) ForwardedPort() int {
	return int(b.forwardedPort.Load())
}

// startPortForwarding validates the tunnel gateway parameters, obtains a PIA
// token, and launches the port-forwarding lifecycle in a managed goroutine. It
// fails closed: a missing gateway or token returns an error (and does not start
// any goroutine) rather than silently claiming success. The Acquire/renew round
// trips themselves run asynchronously; the granted port is published via
// ForwardedPort once it is delivered.
//
// gw carries the gateway parameters from the active delegate. The caller is
// responsible for ensuring it reflects the current tunnel.
func (b *PIABackend) startPortForwarding(gw gatewayInfo) error {
	if gw.ip == "" || gw.hostname == "" {
		// Fail closed: without the in-tunnel gateway we cannot bind a port.
		return fmt.Errorf("%w (protocol %q does not surface a tunnel gateway)",
			pia.ErrPortForwardingNotAvailable, b.config.Protocol)
	}

	// Obtain a valid token up front so a credential/auth failure is surfaced
	// synchronously rather than buried in the background loop.
	token, err := b.client.Authenticate(context.Background())
	if err != nil {
		return fmt.Errorf("obtain token for port forwarding: %w", err)
	}

	params := pia.PortForwardParams{
		GatewayIP: gw.ip,
		Hostname:  gw.hostname,
		Token:     token.Value,
	}
	if err := params.Validate(); err != nil {
		return err
	}

	runner := b.newPortForwarder(params, b.logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	portCh := make(chan int, 1)

	b.pfMu.Lock()
	b.pfCancel = cancel
	b.pfDone = done
	b.pfMu.Unlock()

	go func() {
		defer close(done)
		if runErr := runner.Run(ctx, params, portCh); runErr != nil && !errors.Is(runErr, context.Canceled) {
			b.logger.Error("PIA port forwarding stopped", "name", b.name, "error", runErr)
			b.recordError(runErr)
		}
	}()

	// Publish the granted port asynchronously so Start does not block on the
	// live getSignature/bindPort round trip.
	go func() {
		select {
		case port := <-portCh:
			b.forwardedPort.Store(int64(port))
			b.logger.Info("PIA port forwarding active", "name", b.name, "port", port)
		case <-done:
			// Run exited before delivering a port (e.g. Acquire failed).
		}
	}()

	return nil
}

// stopPortForwarding cancels the running port-forwarding lifecycle (if any) and
// waits for the goroutine to exit. It is safe to call when port forwarding is
// not running.
func (b *PIABackend) stopPortForwarding() {
	b.pfMu.Lock()
	cancel := b.pfCancel
	done := b.pfDone
	b.pfCancel = nil
	b.pfDone = nil
	b.pfMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
