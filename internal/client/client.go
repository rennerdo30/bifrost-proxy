// Package client provides the Bifrost client implementation.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiclient "github.com/rennerdo30/bifrost-proxy/internal/api/client"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/debug"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/proxy"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
	"github.com/rennerdo30/bifrost-proxy/internal/sysproxy"
	"github.com/rennerdo30/bifrost-proxy/internal/tray"
	"github.com/rennerdo30/bifrost-proxy/internal/updater"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// clientSOCKS5DialTimeout is the timeout applied to upstream dials made on
// behalf of a local SOCKS5 client. The SOCKS5 listener has no per-listener
// timeout in the client config, unlike the HTTP listener.
const clientSOCKS5DialTimeout = 30 * time.Second

const (
	// apiReadHeaderTimeout bounds how long the local API/Web UI server waits
	// for a request's headers, mitigating Slowloris-style stalls.
	apiReadHeaderTimeout = 10 * time.Second

	// shutdownGracePeriod bounds how long Stop waits for in-flight connections
	// and background goroutines to finish before giving up.
	shutdownGracePeriod = 30 * time.Second

	// defaultHealthCheckInterval and defaultHealthCheckTimeout are used when
	// server.health_check omits (or zeroes) the corresponding field.
	defaultHealthCheckInterval = 30 * time.Second
	defaultHealthCheckTimeout  = 5 * time.Second

	// defaultUpdateCheckInterval is used when auto_update.check_interval is
	// unset or non-positive.
	defaultUpdateCheckInterval = 24 * time.Hour
)

// Client is the Bifrost client.
type Client struct {
	config          *config.ClientConfig
	configPath      string
	router          *router.ClientRouter
	serverConn      *ServerConnection
	debugger        *debug.Logger
	vpnManager      *vpn.Manager
	meshManager     apiclient.MeshManager
	sysProxyManager sysproxy.Manager
	tray            *tray.Tray
	updater         *updater.Updater

	httpListener   net.Listener
	socks5Listener net.Listener
	apiServer      *http.Server

	running bool
	mu      sync.RWMutex
	wg      sync.WaitGroup

	// done signals the background goroutines of the *current* run to exit. It
	// has a per-run lifetime: Start allocates a fresh channel and Stop closes
	// it, so a Start -> Stop -> Start -> Stop cycle no longer closes an already
	// closed channel. Goroutines must never read this field directly; Start
	// passes the channel it allocated to each goroutine so a subsequent Start
	// cannot race with, or silently resurrect, the previous run's loops.
	done chan struct{}

	// Traffic counters exposed through the local API's /status endpoint. They
	// are cumulative for bytes and instantaneous for connections, and are
	// updated from the proxy handlers' RecordMetrics hooks (bytes) and around
	// each ServeConn (connections).
	bytesSent     atomic.Int64
	bytesReceived atomic.Int64
	activeConns   atomic.Int64
}

// recordProxyTraffic accumulates the per-request byte counters reported by the
// HTTP and SOCKS5 proxy handlers. Negative values (unknown Content-Length) are
// ignored so the totals stay monotonic.
func (c *Client) recordProxyTraffic(sent, received int64) {
	if sent > 0 {
		c.bytesSent.Add(sent)
	}
	if received > 0 {
		c.bytesReceived.Add(received)
	}
}

// BytesSent returns the total number of bytes sent to proxy clients.
func (c *Client) BytesSent() int64 { return c.bytesSent.Load() }

// BytesReceived returns the total number of bytes received from proxy clients.
func (c *Client) BytesReceived() int64 { return c.bytesReceived.Load() }

// ActiveConnections returns the number of proxy connections currently being
// served across the HTTP and SOCKS5 listeners.
func (c *Client) ActiveConnections() int {
	n := c.activeConns.Load()
	if n < 0 {
		return 0
	}
	return int(n)
}

// serveProxyConn runs handler.ServeConn for one accepted connection while
// keeping the active-connection gauge accurate. The decrement is deferred so a
// panic in the handler cannot leak the gauge.
func (c *Client) serveProxyConn(ctx context.Context, conn net.Conn, serve func(context.Context, net.Conn)) {
	c.activeConns.Add(1)
	defer c.activeConns.Add(-1)
	serve(util.WithRequestID(ctx, generateRequestID()), conn)
}

// New creates a new Bifrost client.
func New(cfg *config.ClientConfig) (*Client, error) {
	// Initialize logging
	if err := logging.Setup(cfg.Logging); err != nil {
		return nil, fmt.Errorf("setup logging: %w", err)
	}

	// Create router
	r := router.NewClientRouter()
	if err := r.LoadRoutes(cfg.Routes); err != nil {
		return nil, fmt.Errorf("load routes: %w", err)
	}

	// Create server connection
	serverConn := NewServerConnection(ServerConnectionConfig{
		Address:    cfg.Server.Address,
		Protocol:   cfg.Server.Protocol,
		Username:   cfg.Server.Username,
		Password:   cfg.Server.Password,
		Timeout:    cfg.Server.Timeout.Duration(),
		RetryCount: cfg.Server.RetryCount,
		RetryDelay: cfg.Server.RetryDelay.Duration(),
	})

	// Create debugger
	var debugger *debug.Logger
	if cfg.Debug.Enabled {
		debugger = debug.NewLogger(debug.Config{
			MaxEntries:  cfg.Debug.MaxEntries,
			CaptureBody: cfg.Debug.CaptureBody,
			MaxBodySize: cfg.Debug.MaxBodySize,
		})
	}

	// Create VPN manager if enabled
	var vpnManager *vpn.Manager
	if cfg.VPN.Enabled {
		var err error
		vpnManager, err = vpn.New(cfg.VPN)
		if err != nil {
			return nil, fmt.Errorf("create VPN manager: %w", err)
		}
		// Configure VPN with server connector
		vpnManager.Configure(vpn.WithServerConnector(serverConn))
	}

	// Create mesh manager if enabled. The adapter bridges the mesh node's
	// netip.Addr LocalIP to the string the client API expects.
	meshManager, err := newMeshManager(cfg.Mesh)
	if err != nil {
		return nil, fmt.Errorf("create mesh manager: %w", err)
	}

	return &Client{
		config:          cfg,
		router:          r,
		serverConn:      serverConn,
		debugger:        debugger,
		vpnManager:      vpnManager,
		meshManager:     meshManager,
		sysProxyManager: sysproxy.New(),
		// Placeholder so the field is never nil before the first Start; Start
		// replaces it with this run's channel.
		done: make(chan struct{}),
	}, nil
}

// Start starts the client. A client that has been stopped can be started
// again: each run gets its own done channel, listeners and API server, so the
// Connect/Disconnect cycle exposed by the desktop app is safe to repeat.
// Calling Start on an already-running client is a no-op.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	// Allocate this run's shutdown channel. Without this, a restarted client
	// reused the channel Stop had already closed: every background loop
	// selecting on it exited immediately (Start still reported success) and the
	// next Stop panicked with "close of closed channel".
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()

	logging.Info("Starting Bifrost client")

	// Start system tray if enabled
	if c.config.Tray.Enabled {
		c.startTray(ctx)
	}

	// Start HTTP listener
	if c.config.Proxy.HTTP.Listen != "" {
		listener, err := net.Listen("tcp", c.config.Proxy.HTTP.Listen)
		if err != nil {
			return c.failStart(fmt.Errorf("listen HTTP: %w", err))
		}
		c.mu.Lock()
		c.httpListener = listener
		c.mu.Unlock()
		logging.Info("HTTP proxy listening", "address", c.config.Proxy.HTTP.Listen)

		c.wg.Add(1)
		go c.serveHTTP(ctx, listener, done)
	}

	// Start SOCKS5 listener
	if c.config.Proxy.SOCKS5.Listen != "" {
		listener, err := net.Listen("tcp", c.config.Proxy.SOCKS5.Listen)
		if err != nil {
			return c.failStart(fmt.Errorf("listen SOCKS5: %w", err))
		}
		c.mu.Lock()
		c.socks5Listener = listener
		c.mu.Unlock()
		logging.Info("SOCKS5 proxy listening", "address", c.config.Proxy.SOCKS5.Listen)

		c.wg.Add(1)
		go c.serveSOCKS5(ctx, listener, done)
	}

	// Start API/Web UI server
	if c.config.API.Enabled {
		api := apiclient.New(apiclient.Config{
			Router:   c.router,
			Debugger: c.debugger,
			ServerConnected: func() bool {
				return c.ServerConnected(context.Background())
			},
			Token: c.config.API.Token,
			VPNManager: func() apiclient.VPNManager {
				if c.vpnManager == nil {
					return nil
				}
				return c.vpnManager
			}(),
			MeshManager:     c.meshManager,
			ServerAddress:   c.config.Server.Address,
			HTTPProxyAddr:   c.config.Proxy.HTTP.Listen,
			SOCKS5ProxyAddr: c.config.Proxy.SOCKS5.Listen,
			ConfigGetter: func() interface{} {
				return c.config
			},
			ConfigUpdater:  c.updateConfig,
			ConfigReloader: c.reloadConfig,
			SettingsGetter: func() *apiclient.QuickSettings {
				return c.getQuickSettings()
			},
			SettingsUpdater: c.updateQuickSettings,
			// Traffic counters for /status. Without these the endpoint reported a
			// hardcoded-looking bytes_sent=0 / bytes_received=0 /
			// active_connections=0 forever.
			BytesSent:     c.BytesSent,
			BytesReceived: c.BytesReceived,
			ActiveConns:   c.ActiveConnections,
		})

		apiServer := &http.Server{
			Addr:              c.config.API.Listen,
			Handler:           api.HandlerWithUI(),
			ReadHeaderTimeout: apiReadHeaderTimeout, // Prevent Slowloris attacks
		}
		c.mu.Lock()
		c.apiServer = apiServer
		c.mu.Unlock()

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			logging.Info("API/Web UI server listening", "address", c.config.API.Listen)
			if err := apiServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				logging.Error("API server error", "error", err)
			}
		}()
	}

	// Start VPN if enabled
	if c.vpnManager != nil && c.vpnManager.Enabled() {
		if err := c.vpnManager.Start(ctx); err != nil {
			logging.Error("Failed to start VPN", "error", err)
			// VPN failure is not fatal for the client
		} else {
			logging.Info("VPN mode started")
		}
	}

	// Start mesh networking if enabled. Mesh requires a TUN/TAP device and a
	// reachable discovery server; failure is logged but not fatal so the proxy
	// remains usable. The API reflects the resulting status via meshManager.
	if c.meshManager != nil {
		if err := c.meshManager.Start(ctx); err != nil {
			logging.Error("Failed to start mesh networking", "error", err)
		} else {
			logging.Info("Mesh networking started")
		}
	}

	// Enable System Proxy if configured
	if c.config.SystemProxy.Enabled {
		// Prefer HTTP proxy for system settings
		proxyAddr := c.config.Proxy.HTTP.Listen
		if proxyAddr == "" {
			proxyAddr = c.config.Proxy.SOCKS5.Listen
		}

		if proxyAddr != "" {
			if err := c.sysProxyManager.SetProxy(proxyAddr); err != nil {
				if errors.Is(err, sysproxy.ErrNotSupported) {
					logging.Warn("System proxy configuration not supported on this platform; configure your OS/browser proxy manually", "address", proxyAddr)
				} else {
					logging.Error("Failed to set system proxy", "error", err)
				}
				if c.tray != nil {
					c.tray.SetStatus(tray.StatusWarning)
				}
			} else {
				logging.Info("System proxy enabled", "address", proxyAddr)
				if c.tray != nil {
					c.tray.SetStatus(tray.StatusConnected)
				}
			}
		} else {
			logging.Warn("System proxy enabled but no proxy listeners configured")
			if c.tray != nil {
				c.tray.SetStatus(tray.StatusWarning)
			}
		}
	}

	// Start the auto-update background checker if enabled. Failure to
	// initialize is logged but non-fatal so the proxy remains usable.
	if c.config.AutoUpdate.Enabled {
		c.startUpdater(ctx)
	}

	// Start the server health monitor if a health check is configured. This
	// gives the previously-inert server.health_check block a runtime effect:
	// it periodically probes server reachability and logs status transitions.
	c.startHealthMonitor(ctx, done)

	// Apply tray-driven startup behavior (auto-connect, start minimized).
	c.applyStartupBehavior()

	logging.Info("Bifrost client started")
	return nil
}

// failStart rolls back the partial startup performed before err occurred, so a
// Start that fails to bind a listener does not leave the client reporting
// Running() == true with an open done channel and a dead accept loop. It closes
// this run's done channel, shuts the already-bound listeners and waits for the
// goroutines they spawned, then returns err unchanged for convenient tail calls.
func (c *Client) failStart(err error) error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return err
	}
	c.running = false
	close(c.done)
	httpLn, socks5Ln := c.httpListener, c.socks5Listener
	c.httpListener, c.socks5Listener = nil, nil
	c.mu.Unlock()

	if httpLn != nil {
		_ = httpLn.Close() //nolint:errcheck // Best effort rollback
	}
	if socks5Ln != nil {
		_ = socks5Ln.Close() //nolint:errcheck // Best effort rollback
	}
	c.wg.Wait()

	logging.Error("Bifrost client failed to start; rolled back partial startup", "error", err)
	return err
}

// ServerConnected reports whether the configured Bifrost server is currently
// reachable, by performing a short TCP probe with the server connection's
// configured dial timeout. Callers should pass a context with their own deadline
// when they need a tighter bound (a UI status poll, for instance). This is the
// only honest source of "connected" state: the mere presence of a configured
// server address says nothing about reachability.
func (c *Client) ServerConnected(ctx context.Context) bool {
	return c.serverConn.IsConnected(ctx)
}

// startUpdater constructs the auto-updater from the client's AutoUpdate config
// and starts the periodic background checker. It is only called when
// AutoUpdate.Enabled is true. Any initialization error is logged and the client
// continues without automatic updates.
func (c *Client) startUpdater(ctx context.Context) {
	interval := c.config.AutoUpdate.CheckInterval.Duration()
	if interval <= 0 {
		interval = defaultUpdateCheckInterval
	}
	channel := c.config.AutoUpdate.Channel
	if channel == "" {
		channel = string(updater.ChannelStable)
	}

	u, err := updater.New(updater.Config{
		Enabled:       true,
		CheckInterval: interval,
		Channel:       updater.Channel(channel),
		GitHubOwner:   "rennerdo30",
		GitHubRepo:    "bifrost-proxy",
	}, updater.BinaryTypeClient, updateNotifier{c})
	if err != nil {
		logging.Error("Failed to initialize auto-updater", "error", err)
		return
	}

	c.mu.Lock()
	c.updater = u
	c.mu.Unlock()

	u.StartBackgroundChecker(ctx)
	logging.Info("Auto-update background checker started", "channel", channel, "check_interval", interval)
}

// startHealthMonitor launches a goroutine that periodically probes the
// configured Bifrost server for reachability. It consumes the previously-dead
// server.health_check config block. Transitions between reachable/unreachable
// are logged and, when a tray is present, reflected in the tray status.
//
// done belongs to the Start that launched this monitor; taking it as a parameter
// keeps a later Start (which allocates a fresh channel) from racing with, or
// resurrecting, this goroutine.
func (c *Client) startHealthMonitor(ctx context.Context, done <-chan struct{}) {
	hc := c.config.Server.HealthCheck
	if hc == nil {
		return
	}

	address := c.config.Server.Address
	if address == "" {
		logging.Warn("Server health check configured but no server address is set; health monitor disabled")
		return
	}

	interval := hc.Interval.Duration()
	if interval <= 0 {
		interval = defaultHealthCheckInterval
	}
	timeout := hc.Timeout.Duration()
	if timeout <= 0 {
		timeout = defaultHealthCheckTimeout
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// first forces an initial status log on the first tick.
		first := true
		lastHealthy := false

		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(ctx, timeout)
				healthy := c.ServerConnected(checkCtx)
				cancel()

				if !first && healthy == lastHealthy {
					continue
				}
				first = false
				lastHealthy = healthy

				// Log reachability transitions only. The tray status reflects the
				// user's connect/disconnect (system-proxy) state and must not be
				// overwritten here — a background probe forcing "Connected" would
				// mislead after the user has disconnected.
				if healthy {
					logging.Info("Server health check: reachable", "address", address)
				} else {
					logging.Warn("Server health check: unreachable", "address", address)
				}
			}
		}
	}()

	logging.Info("Server health monitor started", "address", address, "interval", interval)
}

// currentTray returns the tray under lock, or nil when no tray is running.
// updateNotifier surfaces an available update from the background checker via an
// info-level log and a desktop notification, so enabling auto-update has a
// visible effect instead of only writing debug logs.
type updateNotifier struct{ c *Client }

func (n updateNotifier) NotifyUpdateAvailable(info updater.UpdateInfo) {
	logging.Info("Update available",
		"new_version", info.NewVersion,
		"current_version", info.CurrentVersion,
		"url", info.ReleaseURL,
	)
	n.c.notify(fmt.Sprintf("Bifrost update available: %s (current %s)", info.NewVersion, info.CurrentVersion))
}

// applyStartupBehavior applies the persisted tray settings that affect launch:
//
//   - AutoConnect: enables the system proxy on startup (the desktop "connect"
//     action) so traffic is routed without the user clicking Connect. This is a
//     no-op when system proxy is already enabled.
//   - StartMinimized: when false, the Web UI dashboard is opened on launch so
//     the user is presented with a window. When true, nothing is opened and the
//     client runs in the background (reachable via the tray).
//
// These are desktop/tray settings, so they only take effect when the tray is
// enabled; in headless/server mode the client never spawns a browser. Both were
// previously persisted but never acted upon.
func (c *Client) applyStartupBehavior() {
	if !c.config.Tray.Enabled {
		return
	}

	if c.config.Tray.AutoConnect {
		logging.Info("Auto-connect enabled, connecting on startup")
		c.setSystemProxyEnabled(true)
	}

	if !c.config.Tray.StartMinimized {
		if url := c.uiURL(); url != "" {
			c.openUI()
		}
	}
}

// Stop stops the client. It is safe to call on a client that is not running
// (it is then a no-op) and safe to interleave with Start: the run's done channel
// is closed exactly once, under the same lock that guards c.running.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	close(c.done)
	// Detach this run's listeners and API server so a subsequent Start installs
	// fresh ones instead of having them torn down here a second time.
	httpLn, socks5Ln, apiServer := c.httpListener, c.socks5Listener, c.apiServer
	c.httpListener, c.socks5Listener, c.apiServer = nil, nil, nil
	c.mu.Unlock()

	logging.Info("Stopping Bifrost client")

	// Close listeners
	if httpLn != nil {
		_ = httpLn.Close() //nolint:errcheck // Best effort shutdown
	}
	if socks5Ln != nil {
		_ = socks5Ln.Close() //nolint:errcheck // Best effort shutdown
	}

	// Stop API server
	if apiServer != nil {
		_ = apiServer.Shutdown(ctx) //nolint:errcheck // Best effort shutdown
	}

	// Stop VPN
	if c.vpnManager != nil {
		if err := c.vpnManager.Stop(ctx); err != nil {
			logging.Error("Failed to stop VPN", "error", err)
		}
	}

	// Stop mesh networking
	if c.meshManager != nil {
		if err := c.meshManager.Stop(); err != nil {
			logging.Error("Failed to stop mesh networking", "error", err)
		}
	}

	// Stop the auto-update background checker
	c.mu.Lock()
	u := c.updater
	c.mu.Unlock()
	if u != nil {
		u.StopBackgroundChecker()
	}

	// Disable System Proxy if it was enabled
	if c.config.SystemProxy.Enabled {
		if err := c.sysProxyManager.ClearProxy(); err != nil {
			if errors.Is(err, sysproxy.ErrNotSupported) {
				// Nothing was set, so nothing to restore.
				logging.Debug("System proxy not supported on this platform; nothing to restore")
			} else {
				logging.Error("Failed to clear system proxy", "error", err)
			}
		} else {
			logging.Info("System proxy settings restored")
		}
	}

	// Stop system tray. Detached under the lock so a later Start (which calls
	// startTray under the same lock) creates a fresh tray instead of observing
	// a half-torn-down one.
	c.mu.Lock()
	t := c.tray
	c.tray = nil
	c.mu.Unlock()
	if t != nil {
		t.Quit()
	}

	// Wait for connections
	waited := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(shutdownGracePeriod):
		logging.Warn("Grace period exceeded", "grace_period", shutdownGracePeriod)
	}

	logging.Info("Bifrost client stopped")
	return nil
}

// serveHTTP handles HTTP proxy connections on the listener bound by the Start
// that launched it. The listener and done channel are parameters rather than
// fields so a restart cannot make this loop accept on a replaced listener or
// watch a replaced done channel.
func (c *Client) serveHTTP(ctx context.Context, listener net.Listener, done <-chan struct{}) {
	defer c.wg.Done()

	handler := proxy.NewHTTPHandler(proxy.HTTPHandlerConfig{
		GetBackend:  c.getBackend,
		DialTimeout: c.config.Proxy.HTTP.ReadTimeout.Duration(),
		OnConnect:   c.onConnect,
		OnError:     c.onError,
		RecordMetrics: func(_, _, _, _ string, _ time.Duration, sent, recv int64) {
			c.recordProxyTraffic(sent, recv)
		},
	})

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				logging.Error("HTTP accept error", "error", err)
				continue
			}
		}

		c.wg.Add(1)
		go func(conn net.Conn) {
			defer c.wg.Done()
			c.serveProxyConn(ctx, conn, handler.ServeConn)
		}(conn)
	}
}

// serveSOCKS5 handles SOCKS5 proxy connections on the listener bound by the
// Start that launched it. See serveHTTP for why both are parameters.
func (c *Client) serveSOCKS5(ctx context.Context, listener net.Listener, done <-chan struct{}) {
	defer c.wg.Done()

	handler := proxy.NewSOCKS5Handler(proxy.SOCKS5HandlerConfig{
		GetBackend:   c.getBackend,
		AuthRequired: false, // Client doesn't require auth
		DialTimeout:  clientSOCKS5DialTimeout,
		OnConnect:    c.onConnect,
		OnError:      c.onError,
		RecordMetrics: func(_, _, _, _ string, _ time.Duration, sent, recv int64) {
			c.recordProxyTraffic(sent, recv)
		},
	})

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				logging.Error("SOCKS5 accept error", "error", err)
				continue
			}
		}

		c.wg.Add(1)
		go func(conn net.Conn) {
			defer c.wg.Done()
			c.serveProxyConn(ctx, conn, handler.ServeConn)
		}(conn)
	}
}

// getBackend returns a backend based on routing rules.
func (c *Client) getBackend(domain, clientIP string) backend.Backend {
	action := c.router.Match(domain)

	return &ClientBackend{
		action:     action,
		serverConn: c.serverConn,
	}
}

// onConnect is called when a connection is established.
func (c *Client) onConnect(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
	if c.debugger != nil {
		c.debugger.LogConnect(ctx, host, conn.RemoteAddr().String())
	}
}

// onError is called when an error occurs.
func (c *Client) onError(ctx context.Context, conn net.Conn, host string, err error) {
	if c.debugger != nil {
		c.debugger.LogError(ctx, host, err)
	}
	logging.ErrorContext(ctx, "Connection error", "host", host, "error", err)
}

// Running returns whether the client is running.
func (c *Client) Running() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// GetDebugEntries returns debug entries.
func (c *Client) GetDebugEntries() []debug.Entry {
	if c.debugger == nil {
		return nil
	}
	return c.debugger.GetEntries()
}

// VPNManager returns the VPN manager if enabled, nil otherwise.
func (c *Client) VPNManager() *vpn.Manager {
	return c.vpnManager
}

func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// SetConfigPath sets the path to the config file for saving updates.
func (c *Client) SetConfigPath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configPath = path
}

// Config returns the current configuration.
func (c *Client) Config() *config.ClientConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

// updateConfig updates the configuration with the given changes.
func (c *Client) updateConfig(updates map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Handle route add/remove operations specially. These pseudo-keys are sent
	// by the routes CRUD handlers and must mutate c.config.Routes directly.
	// They are translated into a full "routes" replacement so they never reach
	// config.UpdateNode as literal keys (which would corrupt the YAML).
	routesChanged := false
	if raw, ok := updates["_add_route"]; ok {
		delete(updates, "_add_route")
		route, err := parseRouteUpdate(raw)
		if err != nil {
			return err
		}
		c.config.Routes = append(c.config.Routes, route)
		routesChanged = true
	}
	if raw, ok := updates["_remove_route"]; ok {
		delete(updates, "_remove_route")
		name, isStr := raw.(string)
		if !isStr || name == "" {
			return fmt.Errorf("_remove_route requires a non-empty route name")
		}
		filtered := c.config.Routes[:0]
		for _, r := range c.config.Routes {
			if r.Name == name {
				continue
			}
			filtered = append(filtered, r)
		}
		c.config.Routes = filtered
		routesChanged = true
	}

	if routesChanged {
		// Reload the router so the live routing table reflects the change.
		if err := c.router.LoadRoutes(c.config.Routes); err != nil {
			return fmt.Errorf("reload routes: %w", err)
		}
		// Translate the in-memory routes into a full "routes" replacement so it
		// is persisted correctly via the YAML node updater below.
		routeList := make([]interface{}, 0, len(c.config.Routes))
		for _, r := range c.config.Routes {
			domains := make([]interface{}, len(r.Domains))
			for i, d := range r.Domains {
				domains[i] = d
			}
			routeList = append(routeList, map[string]interface{}{
				"name":     r.Name,
				"domains":  domains,
				"action":   r.Action,
				"priority": r.Priority,
			})
		}
		updates["routes"] = routeList
	}

	// Apply updates to the config
	if server, ok := updates["server"].(map[string]interface{}); ok {
		if addr, ok := server["address"].(string); ok {
			c.config.Server.Address = addr
		}
		if proto, ok := server["protocol"].(string); ok {
			c.config.Server.Protocol = proto
		}
		if user, ok := server["username"].(string); ok {
			c.config.Server.Username = user
		}
		if pass, ok := server["password"].(string); ok {
			c.config.Server.Password = pass
		}
		if timeout, ok := server["timeout"].(string); ok {
			c.config.Server.Timeout = config.Duration(parseDuration(timeout))
		}
		if retryCount, ok := server["retry_count"].(float64); ok {
			c.config.Server.RetryCount = int(retryCount)
		}
		if retryDelay, ok := server["retry_delay"].(string); ok {
			c.config.Server.RetryDelay = config.Duration(parseDuration(retryDelay))
		}
		// Hot-apply the connection parameters so address/protocol/credential/
		// timeout/retry changes take effect on the next dial without a restart.
		c.applyServerConn()
	}

	if proxy, ok := updates["proxy"].(map[string]interface{}); ok {
		if httpCfg, ok := proxy["http"].(map[string]interface{}); ok {
			if listen, ok := httpCfg["listen"].(string); ok {
				c.config.Proxy.HTTP.Listen = listen
			}
			if rt, ok := httpCfg["read_timeout"].(string); ok {
				c.config.Proxy.HTTP.ReadTimeout = config.Duration(parseDuration(rt))
			}
		}
		if socks5Cfg, ok := proxy["socks5"].(map[string]interface{}); ok {
			if listen, ok := socks5Cfg["listen"].(string); ok {
				c.config.Proxy.SOCKS5.Listen = listen
			}
		}
	}

	if debug, ok := updates["debug"].(map[string]interface{}); ok {
		if enabled, ok := debug["enabled"].(bool); ok {
			c.config.Debug.Enabled = enabled
		}
		if maxEntries, ok := debug["max_entries"].(float64); ok {
			c.config.Debug.MaxEntries = int(maxEntries)
		}
		if captureBody, ok := debug["capture_body"].(bool); ok {
			c.config.Debug.CaptureBody = captureBody
		}
		if maxBodySize, ok := debug["max_body_size"].(float64); ok {
			c.config.Debug.MaxBodySize = int(maxBodySize)
		}
	}

	if logging, ok := updates["logging"].(map[string]interface{}); ok {
		if level, ok := logging["level"].(string); ok {
			c.config.Logging.Level = level
		}
		if format, ok := logging["format"].(string); ok {
			c.config.Logging.Format = format
		}
		if output, ok := logging["output"].(string); ok {
			c.config.Logging.Output = output
		}
	}

	if tray, ok := updates["tray"].(map[string]interface{}); ok {
		if enabled, ok := tray["enabled"].(bool); ok {
			c.config.Tray.Enabled = enabled
		}
		if startMin, ok := tray["start_minimized"].(bool); ok {
			c.config.Tray.StartMinimized = startMin
		}
		if showQuick, ok := tray["show_quick_gui"].(bool); ok {
			c.config.Tray.ShowQuickGUI = showQuick
		}
		if autoConn, ok := tray["auto_connect"].(bool); ok {
			c.config.Tray.AutoConnect = autoConn
		}
		if showNotif, ok := tray["show_notifications"].(bool); ok {
			c.config.Tray.ShowNotifications = showNotif
		}
	}

	if webUI, ok := updates["web_ui"].(map[string]interface{}); ok {
		if enabled, ok := webUI["enabled"].(bool); ok {
			c.config.WebUI.Enabled = enabled
		}
		if listen, ok := webUI["listen"].(string); ok {
			c.config.WebUI.Listen = listen
		}
	}

	if api, ok := updates["api"].(map[string]interface{}); ok {
		if enabled, ok := api["enabled"].(bool); ok {
			c.config.API.Enabled = enabled
		}
		if listen, ok := api["listen"].(string); ok {
			c.config.API.Listen = listen
		}
		if token, ok := api["token"].(string); ok {
			c.config.API.Token = token
		}
	}

	if autoUpdate, ok := updates["auto_update"].(map[string]interface{}); ok {
		if enabled, ok := autoUpdate["enabled"].(bool); ok {
			c.config.AutoUpdate.Enabled = enabled
		}
		if channel, ok := autoUpdate["channel"].(string); ok {
			c.config.AutoUpdate.Channel = channel
		}
	}

	if vpnCfg, ok := updates["vpn"].(map[string]interface{}); ok {
		if enabled, ok := vpnCfg["enabled"].(bool); ok {
			c.config.VPN.Enabled = enabled
		}
	}

	if sysProxy, ok := updates["system_proxy"].(map[string]interface{}); ok {
		if enabled, ok := sysProxy["enabled"].(bool); ok {
			oldEnabled := c.config.SystemProxy.Enabled
			c.config.SystemProxy.Enabled = enabled

			// Handle runtime toggle
			if enabled != oldEnabled {
				if enabled {
					// Enable
					proxyAddr := c.config.Proxy.HTTP.Listen
					if proxyAddr == "" {
						proxyAddr = c.config.Proxy.SOCKS5.Listen
					}
					if proxyAddr != "" {
						if err := c.sysProxyManager.SetProxy(proxyAddr); err != nil {
							if errors.Is(err, sysproxy.ErrNotSupported) {
								logging.Warn("System proxy configuration not supported on this platform; configure your OS/browser proxy manually", "address", proxyAddr)
							} else {
								logging.Error("Failed to enable system proxy", "error", err)
							}
						}
					}
				} else {
					// Disable
					if err := c.sysProxyManager.ClearProxy(); err != nil {
						if errors.Is(err, sysproxy.ErrNotSupported) {
							logging.Debug("System proxy not supported on this platform; nothing to restore")
						} else {
							logging.Error("Failed to disable system proxy", "error", err)
						}
					}
				}
			}
		}
	}

	if meshCfg, ok := updates["mesh"].(map[string]interface{}); ok {
		if enabled, ok := meshCfg["enabled"].(bool); ok {
			c.config.Mesh.Enabled = enabled
		}
		if networkID, ok := meshCfg["network_id"].(string); ok {
			c.config.Mesh.NetworkID = networkID
		}
		if networkCIDR, ok := meshCfg["network_cidr"].(string); ok {
			c.config.Mesh.NetworkCIDR = networkCIDR
		}
		if peerName, ok := meshCfg["peer_name"].(string); ok {
			c.config.Mesh.PeerName = peerName
		}
	}

	// Save to file if path is set
	if c.configPath != "" {
		node, err := config.LoadNode(c.configPath)
		if err != nil {
			logging.Warn("Failed to load config for update, preserving comments might fail", "error", err)
			// Fallback to struct-based save if load fails
			if err := config.Save(c.configPath, c.config); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
		} else {
			if err := config.UpdateNode(node, updates); err != nil {
				return fmt.Errorf("failed to update config node: %w", err)
			}
			if err := config.SaveNode(c.configPath, node); err != nil {
				return fmt.Errorf("failed to save config node: %w", err)
			}
		}
		logging.Info("Configuration saved", "path", c.configPath)
	}

	return nil
}

// applyServerConn pushes the current in-memory server settings into the live
// ServerConnection so they take effect on the next dial. Callers must hold
// c.mu (updateConfig and reloadConfig both do).
func (c *Client) applyServerConn() {
	c.serverConn.Reconfigure(ServerConnectionConfig{
		Address:    c.config.Server.Address,
		Protocol:   c.config.Server.Protocol,
		Username:   c.config.Server.Username,
		Password:   c.config.Server.Password,
		Timeout:    c.config.Server.Timeout.Duration(),
		RetryCount: c.config.Server.RetryCount,
		RetryDelay: c.config.Server.RetryDelay.Duration(),
	})
}

// reloadConfig reloads the client configuration from disk and hot-applies the
// settings that are safe to change on a running client. It backs the API's
// "Reload" action (previously unwired, which made that button always return
// HTTP 503).
//
// Hot-applied on reload: routing rules, logging, and the server connection
// parameters (address/protocol/credentials/timeouts). Settings that require
// recreating listeners, the API server, the tray, VPN, or mesh (see
// restartRequiredFields in the client API) are loaded into the in-memory config
// but only take full effect after a restart; the debug logger is likewise
// created once at startup and is not re-created here.
func (c *Client) reloadConfig() error {
	c.mu.RLock()
	path := c.configPath
	c.mu.RUnlock()

	if path == "" {
		return fmt.Errorf("no config file path set; cannot reload")
	}

	newCfg := config.DefaultClientConfig()
	if err := config.LoadAndValidate(path, &newCfg); err != nil {
		return fmt.Errorf("reload config: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Hot-apply routing rules.
	if err := c.router.LoadRoutes(newCfg.Routes); err != nil {
		return fmt.Errorf("reload routes: %w", err)
	}

	// Hot-apply logging configuration.
	if err := logging.Setup(newCfg.Logging); err != nil {
		return fmt.Errorf("reload logging: %w", err)
	}

	// Replace the in-memory config in place so the API getters observe the new
	// values, then push the server connection parameters into the live dialer.
	*c.config = newCfg
	c.applyServerConn()

	logging.Info("Configuration reloaded from disk", "path", path)
	return nil
}

func (c *Client) startTray(ctx context.Context) {
	c.mu.Lock()
	if c.tray != nil {
		c.mu.Unlock()
		return
	}

	t := tray.New(tray.Config{
		OnConnect: func() {
			c.setSystemProxyEnabled(true)
			c.notify("Connected")
		},
		OnDisconnect: func() {
			c.setSystemProxyEnabled(false)
			c.notify("Disconnected")
		},
		OnOpenUI: func() {
			c.openUI()
		},
		OnOpenQuick: func() {
			c.openUI()
		},
		OnQuit: func() {
			go func() {
				_ = c.Stop(context.Background()) //nolint:errcheck // Exiting anyway
				os.Exit(0)
			}()
		},
		ShowQuickGUI: c.config.Tray.ShowQuickGUI,
	})
	c.tray = t
	c.mu.Unlock()

	go t.Run(ctx)
}

// notify shows a desktop notification via the tray, but only when the user has
// enabled notifications in the tray settings. It is a no-op when notifications
// are disabled or the tray is unavailable.
func (c *Client) notify(message string) {
	c.mu.RLock()
	enabled := c.config.Tray.ShowNotifications
	t := c.tray
	c.mu.RUnlock()

	if !enabled || t == nil {
		return
	}
	if err := t.Notify(notifyTitle, message); err != nil {
		logging.Warn("Failed to send desktop notification", "error", err)
	}
}

// notifyTitle is the fixed title for desktop notifications.
const notifyTitle = "Bifrost"

func (c *Client) openUI() {
	url := c.uiURL()
	if url == "" {
		logging.Warn("Web UI is not enabled or listen address missing")
		return
	}
	if err := util.OpenURL(url); err != nil {
		logging.Error("Failed to open Web UI", "error", err, "url", url)
	}
}

func (c *Client) uiURL() string {
	if c.config.API.Enabled && c.config.API.Listen != "" {
		return normalizeListenAddress(c.config.API.Listen)
	}
	if c.config.WebUI.Enabled && c.config.WebUI.Listen != "" {
		return normalizeListenAddress(c.config.WebUI.Listen)
	}
	return ""
}

func normalizeListenAddress(listen string) string {
	if strings.HasPrefix(listen, "http://") || strings.HasPrefix(listen, "https://") {
		return listen
	}
	if strings.HasPrefix(listen, ":") {
		return "http://127.0.0.1" + listen
	}
	return "http://" + listen
}

func (c *Client) setSystemProxyEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.config.SystemProxy.Enabled == enabled {
		return
	}

	c.config.SystemProxy.Enabled = enabled

	if enabled {
		proxyAddr := c.config.Proxy.HTTP.Listen
		if proxyAddr == "" {
			proxyAddr = c.config.Proxy.SOCKS5.Listen
		}
		if proxyAddr != "" {
			if err := c.sysProxyManager.SetProxy(proxyAddr); err != nil {
				if errors.Is(err, sysproxy.ErrNotSupported) {
					logging.Warn("System proxy configuration not supported on this platform; configure your OS/browser proxy manually", "address", proxyAddr)
				} else {
					logging.Error("Failed to enable system proxy", "error", err)
				}
				if c.tray != nil {
					c.tray.SetStatus(tray.StatusWarning)
				}
				return
			}
			if c.tray != nil {
				c.tray.SetStatus(tray.StatusConnected)
			}
		} else {
			logging.Warn("System proxy enabled but no proxy listeners configured")
			if c.tray != nil {
				c.tray.SetStatus(tray.StatusWarning)
			}
		}
	} else {
		if err := c.sysProxyManager.ClearProxy(); err != nil {
			if errors.Is(err, sysproxy.ErrNotSupported) {
				logging.Debug("System proxy not supported on this platform; nothing to restore")
			} else {
				logging.Error("Failed to disable system proxy", "error", err)
				if c.tray != nil {
					c.tray.SetStatus(tray.StatusWarning)
				}
				return
			}
		}
		if c.tray != nil {
			c.tray.SetStatus(tray.StatusDisconnected)
		}
	}
}

// parseRouteUpdate converts a route map (as sent by the routes CRUD handler)
// into a config.ClientRouteConfig.
func parseRouteUpdate(raw interface{}) (config.ClientRouteConfig, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return config.ClientRouteConfig{}, fmt.Errorf("invalid route payload")
	}

	route := config.ClientRouteConfig{}
	if name, ok := m["name"].(string); ok {
		route.Name = name
	}
	if action, ok := m["action"].(string); ok {
		route.Action = action
	}
	if route.Action == "" {
		route.Action = "server"
	}
	switch p := m["priority"].(type) {
	case float64:
		route.Priority = int(p)
	case int:
		route.Priority = p
	}
	if domains, ok := m["domains"].([]interface{}); ok {
		for _, d := range domains {
			if s, ok := d.(string); ok {
				route.Domains = append(route.Domains, s)
			}
		}
	}
	if len(route.Domains) == 0 {
		return config.ClientRouteConfig{}, fmt.Errorf("route must have at least one domain pattern")
	}
	return route, nil
}

// parseDuration parses a duration string like "30s" or "5m".
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
