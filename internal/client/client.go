// Package client provides the Bifrost client implementation.
package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	apiclient "github.com/rennerdo30/bifrost-proxy/internal/api/client"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/debug"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/proxy"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// Client is the Bifrost client.
type Client struct {
	config         *config.ClientConfig
	router         *router.ClientRouter
	serverConn     *ServerConnection
	debugger       *debug.Logger
	vpnManager     *vpn.Manager

	httpListener   net.Listener
	socks5Listener net.Listener
	apiServer      *http.Server

	running bool
	mu      sync.RWMutex
	wg      sync.WaitGroup
	done    chan struct{}
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

	return &Client{
		config:     cfg,
		router:     r,
		serverConn: serverConn,
		debugger:   debugger,
		vpnManager: vpnManager,
		done:       make(chan struct{}),
	}, nil
}

// Start starts the client.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	logging.Info("Starting Bifrost client")

	// Start HTTP listener
	if c.config.Proxy.HTTP.Listen != "" {
		listener, err := net.Listen("tcp", c.config.Proxy.HTTP.Listen)
		if err != nil {
			return fmt.Errorf("listen HTTP: %w", err)
		}
		c.httpListener = listener
		logging.Info("HTTP proxy listening", "address", c.config.Proxy.HTTP.Listen)

		c.wg.Add(1)
		go c.serveHTTP(ctx)
	}

	// Start SOCKS5 listener
	if c.config.Proxy.SOCKS5.Listen != "" {
		listener, err := net.Listen("tcp", c.config.Proxy.SOCKS5.Listen)
		if err != nil {
			return fmt.Errorf("listen SOCKS5: %w", err)
		}
		c.socks5Listener = listener
		logging.Info("SOCKS5 proxy listening", "address", c.config.Proxy.SOCKS5.Listen)

		c.wg.Add(1)
		go c.serveSOCKS5(ctx)
	}

	// Start API/Web UI server
	if c.config.API.Enabled {
		api := apiclient.New(apiclient.Config{
			Router:   c.router,
			Debugger: c.debugger,
			ServerConnected: func() bool {
				return c.serverConn.IsConnected(context.Background())
			},
			Token:      c.config.API.Token,
			VPNManager: c.vpnManager,
		})

		c.apiServer = &http.Server{
			Addr:    c.config.API.Listen,
			Handler: api.HandlerWithUI(),
		}

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			logging.Info("API/Web UI server listening", "address", c.config.API.Listen)
			if err := c.apiServer.ListenAndServe(); err != http.ErrServerClosed {
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

	logging.Info("Bifrost client started")
	return nil
}

// Stop stops the client.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	close(c.done)
	c.mu.Unlock()

	logging.Info("Stopping Bifrost client")

	// Close listeners
	if c.httpListener != nil {
		c.httpListener.Close()
	}
	if c.socks5Listener != nil {
		c.socks5Listener.Close()
	}

	// Stop API server
	if c.apiServer != nil {
		c.apiServer.Shutdown(ctx)
	}

	// Stop VPN
	if c.vpnManager != nil {
		if err := c.vpnManager.Stop(ctx); err != nil {
			logging.Error("Failed to stop VPN", "error", err)
		}
	}

	// Wait for connections
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		logging.Warn("Grace period exceeded")
	}

	logging.Info("Bifrost client stopped")
	return nil
}

// serveHTTP handles HTTP proxy connections.
func (c *Client) serveHTTP(ctx context.Context) {
	defer c.wg.Done()

	handler := proxy.NewHTTPHandler(proxy.HTTPHandlerConfig{
		GetBackend:  c.getBackend,
		DialTimeout: c.config.Proxy.HTTP.ReadTimeout.Duration(),
		OnConnect:   c.onConnect,
		OnError:     c.onError,
	})

	for {
		conn, err := c.httpListener.Accept()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				logging.Error("HTTP accept error", "error", err)
				continue
			}
		}

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			ctx = util.WithRequestID(ctx, generateRequestID())
			handler.ServeConn(ctx, conn)
		}()
	}
}

// serveSOCKS5 handles SOCKS5 proxy connections.
func (c *Client) serveSOCKS5(ctx context.Context) {
	defer c.wg.Done()

	handler := proxy.NewSOCKS5Handler(proxy.SOCKS5HandlerConfig{
		GetBackend:   c.getBackend,
		AuthRequired: false, // Client doesn't require auth
		DialTimeout:  30 * time.Second,
		OnConnect:    c.onConnect,
		OnError:      c.onError,
	})

	for {
		conn, err := c.socks5Listener.Accept()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				logging.Error("SOCKS5 accept error", "error", err)
				continue
			}
		}

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			ctx = util.WithRequestID(ctx, generateRequestID())
			handler.ServeConn(ctx, conn)
		}()
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
