// Package server provides the Bifrost server implementation.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/accesscontrol"
	"github.com/rennerdo30/bifrost-proxy/internal/accesslog"
	apiserver "github.com/rennerdo30/bifrost-proxy/internal/api/server"
	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/negotiate"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/health"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/metrics"
	"github.com/rennerdo30/bifrost-proxy/internal/proxy"
	"github.com/rennerdo30/bifrost-proxy/internal/ratelimit"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// Server is the main Bifrost server.
type Server struct {
	config           *config.ServerConfig
	configPath       string // Path to config file for hot reload
	backends         *backend.Manager
	router           *router.ServerRouter
	authenticator    auth.Authenticator
	rateLimiterIP    *ratelimit.KeyedLimiter
	rateLimiterUser  *ratelimit.KeyedLimiter
	accessController *accesscontrol.Controller
	bandwidthConfig  *ratelimit.BandwidthConfig
	healthManager    *health.Manager
	metrics          *metrics.Metrics
	metricsCollector *metrics.Collector
	accessLogger     accesslog.Logger
	cacheManager     *cache.Manager
	cacheInterceptor *cache.Interceptor

	httpTLSConfig    *tls.Config
	negotiateHandler *negotiate.Handler
	mitmInterceptor  *proxy.MITMInterceptor

	httpListener   net.Listener
	socks5Listener net.Listener
	metricsServer  *http.Server
	apiServer      *http.Server
	wsHub          *apiserver.WebSocketHub
	api            *apiserver.API

	running bool
	mu      sync.RWMutex
	wg      sync.WaitGroup
	done    chan struct{}

	// Connection limiting for resource-constrained devices (OpenWrt)
	httpActiveConns   int32 // atomic counter for active HTTP connections
	socks5ActiveConns int32 // atomic counter for active SOCKS5 connections
	totalActiveConns  int32 // atomic counter for active connections across all listeners (network.max_connections)
}

// acquireGlobalConn enforces the process-wide network.max_connections ceiling.
// It returns false (without incrementing) when the limit would be exceeded. The
// caller must call releaseGlobalConn when the connection ends if this returns
// true. A limit of 0 means unlimited.
func (s *Server) acquireGlobalConn() bool {
	limit := s.config.Network.MaxConnections
	if limit <= 0 {
		return true
	}
	current := atomic.AddInt32(&s.totalActiveConns, 1)
	if current > int32(limit) { //nolint:gosec // G115: limit is a small config value
		atomic.AddInt32(&s.totalActiveConns, -1)
		return false
	}
	return true
}

// releaseGlobalConn decrements the process-wide active-connection counter.
func (s *Server) releaseGlobalConn() {
	if s.config.Network.MaxConnections <= 0 {
		return
	}
	atomic.AddInt32(&s.totalActiveConns, -1)
}

// New creates a new Bifrost server.
func New(cfg *config.ServerConfig) (*Server, error) {
	// Initialize logging
	if err := logging.Setup(cfg.Logging); err != nil {
		return nil, fmt.Errorf("setup logging: %w", err)
	}

	// Create backends, threading network tuning (keep-alive, dial timeout,
	// address family, prefer-IPv6) into every dialer-owning backend.
	factory := backend.NewFactoryWithNetwork(cfg.Network)
	backends, err := factory.CreateAll(cfg.Backends)
	if err != nil {
		return nil, fmt.Errorf("create backends: %w", err)
	}

	// Create router
	r := router.NewServerRouter(backends)
	if loadErr := r.LoadRoutes(cfg.Routes); loadErr != nil {
		return nil, fmt.Errorf("load routes: %w", loadErr)
	}

	// Create authenticator
	authenticator, err := createAuthenticator(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("create authenticator: %w", err)
	}

	// Create access controller
	var accessController *accesscontrol.Controller
	if len(cfg.AccessControl.Whitelist) > 0 || len(cfg.AccessControl.Blacklist) > 0 {
		accessController, err = accesscontrol.NewController(accesscontrol.Config{
			Whitelist: cfg.AccessControl.Whitelist,
			Blacklist: cfg.AccessControl.Blacklist,
		})
		if err != nil {
			return nil, fmt.Errorf("create access controller: %w", err)
		}
	}

	// Create rate limiters
	var rateLimiterIP *ratelimit.KeyedLimiter
	var rateLimiterUser *ratelimit.KeyedLimiter
	if cfg.RateLimit.Enabled {
		perIP := cfg.RateLimit.PerIP
		perUser := cfg.RateLimit.PerUser
		if !perIP && !perUser {
			// Preserve legacy behavior: default to per-IP limiting
			perIP = true
		}

		rlCfg := ratelimit.Config{
			RequestsPerSecond: cfg.RateLimit.RequestsPerSecond,
			BurstSize:         cfg.RateLimit.BurstSize,
		}

		if perIP {
			rateLimiterIP = ratelimit.NewKeyedLimiter(rlCfg)
		}
		if perUser {
			rateLimiterUser = ratelimit.NewKeyedLimiter(rlCfg)
		}
	}

	// Parse bandwidth throttling limits
	var bandwidthConfig *ratelimit.BandwidthConfig
	if cfg.RateLimit.Bandwidth != nil && cfg.RateLimit.Bandwidth.Enabled {
		upload, uploadErr := ratelimit.ParseBandwidth(cfg.RateLimit.Bandwidth.Upload)
		if uploadErr != nil {
			return nil, fmt.Errorf("parse upload bandwidth: %w", uploadErr)
		}
		download, downloadErr := ratelimit.ParseBandwidth(cfg.RateLimit.Bandwidth.Download)
		if downloadErr != nil {
			return nil, fmt.Errorf("parse download bandwidth: %w", downloadErr)
		}
		if upload > 0 || download > 0 {
			bandwidthConfig = &ratelimit.BandwidthConfig{
				Upload:   upload,
				Download: download,
			}
		}
	}

	// Create health manager
	healthManager := health.NewManager()

	// Create metrics
	m := metrics.New()
	// Use configurable collection interval (default 15s, for low-power devices use 60s-300s)
	collectionInterval := cfg.Metrics.CollectionInterval.Duration()
	collector := metrics.NewCollectorWithInterval(m, backends, collectionInterval)

	// Create access logger
	accessLogger, err := accesslog.New(accesslog.Config{
		Enabled: cfg.AccessLog.Enabled,
		Format:  cfg.AccessLog.Format,
		Output:  cfg.AccessLog.Output,
	})
	if err != nil {
		return nil, fmt.Errorf("create access logger: %w", err)
	}

	// Create cache manager if enabled
	var cacheManager *cache.Manager
	var cacheInterceptor *cache.Interceptor
	if cfg.Cache.Enabled {
		cacheManager, err = cache.NewManager(&cfg.Cache)
		if err != nil {
			return nil, fmt.Errorf("create cache manager: %w", err)
		}
		cacheInterceptor = cache.NewInterceptor(cacheManager)
	}

	srv := &Server{
		config:           cfg,
		backends:         backends,
		router:           r,
		authenticator:    authenticator,
		rateLimiterIP:    rateLimiterIP,
		rateLimiterUser:  rateLimiterUser,
		accessController: accessController,
		bandwidthConfig:  bandwidthConfig,
		healthManager:    healthManager,
		metrics:          m,
		metricsCollector: collector,
		accessLogger:     accessLogger,
		cacheManager:     cacheManager,
		cacheInterceptor: cacheInterceptor,
		done:             make(chan struct{}),
	}

	if hcErr := srv.setupHealthChecks(cfg); hcErr != nil {
		return nil, hcErr
	}

	if mErr := srv.setupMITM(); mErr != nil {
		return nil, mErr
	}

	// Build the HTTP proxy listener TLS config (server cert + optional mTLS
	// client-cert verification). The client CA pool falls back to the mTLS auth
	// provider's trust anchors when no explicit client_ca_file is set.
	mtlsPool, err := mtlsCAPoolFromAuth(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("build mTLS CA pool: %w", err)
	}
	httpTLS, err := buildListenerTLSConfig(cfg.Server.HTTP.TLS, mtlsPool)
	if err != nil {
		return nil, fmt.Errorf("build HTTP TLS config: %w", err)
	}
	srv.httpTLSConfig = httpTLS

	// Construct the Negotiate (SPNEGO/Kerberos + optional NTLM) middleware when
	// configured. This is middleware, not a chain provider.
	negHandler, err := buildNegotiateHandler(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("build negotiate handler: %w", err)
	}
	srv.negotiateHandler = negHandler

	return srv, nil
}

// setupMITM constructs the HTTPS interception cert minter from config when MITM
// is enabled, failing closed (returning an error at startup) if the CA material
// cannot be loaded. When MITM is disabled the interceptor stays nil and CONNECT
// tunnels remain opaque.
func (s *Server) setupMITM() error {
	if s == nil || !s.config.MITM.Enabled {
		return nil
	}
	certPEM, keyPEM, err := s.config.MITM.LoadCA()
	if err != nil {
		return fmt.Errorf("mitm: load CA: %w", err)
	}
	minter, err := proxy.NewCertMinter(proxy.MITMConfig{
		Enabled:        true,
		CACertPEM:      certPEM,
		CAKeyPEM:       keyPEM,
		LeafTTL:        s.config.MITM.LeafTTL.Duration(),
		MaxCachedCerts: s.config.MITM.MaxCachedCerts,
	})
	if err != nil {
		return fmt.Errorf("mitm: %w", err)
	}
	s.mitmInterceptor = &proxy.MITMInterceptor{Minter: minter}
	logging.Warn("HTTPS MITM interception is ENABLED — TLS to in-scope hosts will be decrypted")
	return nil
}

func (s *Server) setupHealthChecks(cfg *config.ServerConfig) error {
	if s == nil || s.healthManager == nil || s.backends == nil {
		return nil
	}

	for _, backendCfg := range cfg.Backends {
		if !backendCfg.Enabled {
			continue
		}

		hc := backendCfg.HealthCheck
		if hc == nil {
			// Use global defaults if provided
			if cfg.HealthCheck.Type != "" || cfg.HealthCheck.Target != "" || cfg.HealthCheck.Path != "" ||
				cfg.HealthCheck.Interval.Duration() != 0 || cfg.HealthCheck.Timeout.Duration() != 0 {
				hc = &cfg.HealthCheck
			}
		}

		if hc == nil {
			continue
		}

		if hc.Target == "" {
			logging.Warn("health check target missing; skipping",
				"backend", backendCfg.Name,
			)
			continue
		}

		checkCfg := health.Config{
			Type:     hc.Type,
			Target:   hc.Target,
			Interval: hc.Interval.Duration(),
			Timeout:  hc.Timeout.Duration(),
			Path:     hc.Path,
		}
		checker := health.New(checkCfg)

		be, err := s.backends.Get(backendCfg.Name)
		if err != nil {
			logging.Warn("health check backend not found; skipping",
				"backend", backendCfg.Name,
				"error", err,
			)
			continue
		}

		// Wrap backend to allow health overrides
		if _, ok := be.(backend.HealthOverride); !ok {
			wrapped := backend.WrapWithHealth(be)
			if err := s.backends.Remove(backendCfg.Name); err != nil {
				return fmt.Errorf("wrap backend health: remove %s: %w", backendCfg.Name, err)
			}
			if err := s.backends.Add(wrapped); err != nil {
				return fmt.Errorf("wrap backend health: add %s: %w", backendCfg.Name, err)
			}
			be = wrapped
		}

		backendForCheck := be
		// Honor de-bounce thresholds (defaults to 1/1 = immediate transitions).
		healthyThreshold := hc.HealthyThreshold
		unhealthyThreshold := hc.UnhealthyThreshold
		s.healthManager.RegisterWithThresholds(backendCfg.Name, checker, checkCfg.Interval, healthyThreshold, unhealthyThreshold, func(name string, result health.Result) {
			if ho, ok := backendForCheck.(backend.HealthOverride); ok {
				ho.SetHealth(result)
			}
		})
	}

	return nil
}

func createAuthenticator(cfg config.AuthConfig) (auth.Authenticator, error) {
	factory := auth.NewFactory()

	// Legacy mode-based auth is intentionally unsupported.
	if cfg.Mode != "" {
		return nil, fmt.Errorf("legacy auth.mode is no longer supported; migrate to auth.providers")
	}
	if hasLegacyAuthConfig(cfg) {
		return nil, fmt.Errorf("legacy top-level auth provider config is no longer supported; migrate to auth.providers")
	}

	// New multi-provider configuration.
	if len(cfg.Providers) > 0 {
		providers, err := convertProvidersConfig(cfg.Providers)
		if err != nil {
			return nil, err
		}
		return factory.CreateChain(providers)
	}

	// No auth config explicitly set; default to "none".
	return factory.Create(auth.ProviderConfig{
		Name:     "none",
		Type:     "none",
		Enabled:  true,
		Priority: 1,
	})
}

// ValidateAuthConfig validates authentication configuration against registered plugins.
func ValidateAuthConfig(cfg config.AuthConfig) error {
	_, err := createAuthenticator(cfg)
	return err
}

// convertProvidersConfig converts config.AuthProvider slice to auth.ProviderConfig slice.
func convertProvidersConfig(providers []config.AuthProvider) ([]auth.ProviderConfig, error) {
	result := make([]auth.ProviderConfig, 0, len(providers))

	for i, p := range providers {
		if hasLegacyProviderConfig(p) {
			return nil, fmt.Errorf("provider %q at index %d uses legacy type-specific auth config; migrate to providers[%d].config", p.Name, i, i)
		}
		providerCfg := auth.ProviderConfig{
			Name:     p.Name,
			Type:     p.Type,
			Enabled:  p.Enabled,
			Priority: p.Priority,
			Config:   p.Config,
		}

		result = append(result, providerCfg)
	}

	return result, nil
}

func hasLegacyProviderConfig(p config.AuthProvider) bool {
	return p.Native != nil || p.System != nil || p.LDAP != nil || p.OAuth != nil
}

func hasLegacyAuthConfig(cfg config.AuthConfig) bool {
	return cfg.Native != nil || cfg.System != nil || cfg.LDAP != nil || cfg.OAuth != nil
}

// Start starts the server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	logging.Info("Starting Bifrost server")

	// Start backends
	if err := s.backends.StartAll(ctx); err != nil {
		return fmt.Errorf("start backends: %w", err)
	}

	// Start cache manager
	if s.cacheManager != nil {
		if err := s.cacheManager.Start(ctx); err != nil {
			return fmt.Errorf("start cache manager: %w", err)
		}
		logging.Info("Cache manager started",
			"storage_type", s.config.Cache.Storage.Type,
			"presets", len(s.config.Cache.Presets),
			"rules", len(s.config.Cache.Rules),
		)
	}

	// Start health manager
	if err := s.healthManager.Start(ctx); err != nil {
		return fmt.Errorf("start health manager: %w", err)
	}

	// Start metrics collector
	s.metricsCollector.Start()

	// Initialize API if enabled (must be done before listeners start to avoid race conditions)
	if s.config.API.Enabled {
		// Extract ports from listen addresses
		httpPort := extractPort(s.config.Server.HTTP.Listen, "8080")
		socks5Port := extractPort(s.config.Server.SOCKS5.Listen, "1080")

		// Create API
		s.api = apiserver.New(apiserver.Config{
			Backends:         s.backends,
			HealthManager:    s.healthManager,
			CacheManager:     s.cacheManager,
			Token:            s.config.API.Token,
			GetConfig:        s.GetSanitizedConfig,
			GetFullConfig:    s.GetFullConfig,
			ReloadConfig:     s.ReloadConfig,
			SaveConfig:       s.SaveConfig,
			ConfigPath:       s.configPath,
			ProxyPort:        httpPort,
			SOCKS5Port:       socks5Port,
			EnableRequestLog: s.config.API.EnableRequestLog,
			RequestLogSize:   s.config.API.RequestLogSize,
		})

		// Create WebSocket hub with configurable max clients (default 100, for low-power devices use 5-10)
		wsMaxClients := s.config.API.WebSocketMaxClients
		if wsMaxClients <= 0 {
			wsMaxClients = apiserver.MaxWebSocketClients
		}
		s.wsHub = apiserver.NewWebSocketHubWithMaxClients(wsMaxClients)
		go s.wsHub.Run()

		// Periodically broadcast stats and backend health over the WebSocket so
		// the UI can stop polling once the WS is connected.
		s.wg.Add(1)
		go s.broadcastWSEvents()

		// Get the router and add WebSocket routes
		handler := s.api.RouterWithWebSocket(s.wsHub)

		s.apiServer = &http.Server{
			Addr:              s.config.API.Listen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		}
	}

	// Start HTTP proxy listener
	if s.config.Server.HTTP.Listen != "" {
		listener, err := net.Listen("tcp", s.config.Server.HTTP.Listen)
		if err != nil {
			return fmt.Errorf("listen HTTP: %w", err)
		}
		// Wrap with TLS when configured so the proxy can terminate TLS and, for
		// mTLS, verify client certificates. The handshake (and thus client cert
		// extraction in the proxy handler) happens on the wrapped connection.
		if s.httpTLSConfig != nil {
			listener = tls.NewListener(listener, s.httpTLSConfig)
			logging.Info("HTTP proxy TLS enabled",
				"client_auth", s.config.Server.HTTP.TLS.ClientAuth,
			)
		}
		s.httpListener = listener
		logging.Info("HTTP proxy listening", "address", s.config.Server.HTTP.Listen)

		s.wg.Add(1)
		go s.serveHTTP(ctx)
	}

	// Start SOCKS5 listener
	if s.config.Server.SOCKS5.Listen != "" {
		listener, err := net.Listen("tcp", s.config.Server.SOCKS5.Listen)
		if err != nil {
			return fmt.Errorf("listen SOCKS5: %w", err)
		}
		s.socks5Listener = listener
		logging.Info("SOCKS5 proxy listening", "address", s.config.Server.SOCKS5.Listen)

		s.wg.Add(1)
		go s.serveSOCKS5(ctx)
	}

	// Start metrics server
	if s.config.Metrics.Enabled {
		mux := http.NewServeMux()
		path := s.config.Metrics.Path
		if path == "" {
			path = "/metrics"
		}
		mux.Handle(path, s.metrics.Handler())

		s.metricsServer = &http.Server{
			Addr:              s.config.Metrics.Listen,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			logging.Info("Metrics server listening", "address", s.config.Metrics.Listen)
			if err := s.metricsServer.ListenAndServe(); err != http.ErrServerClosed {
				logging.Error("Metrics server error", "error", err)
			}
		}()
	}

	// Start API/Web UI server
	if s.config.API.Enabled {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			logging.Info("API/Web UI server listening", "address", s.config.API.Listen)
			if err := s.apiServer.ListenAndServe(); err != http.ErrServerClosed {
				logging.Error("API server error", "error", err)
			}
		}()
	}

	logging.Info("Bifrost server started")
	return nil
}

// Stop gracefully stops the server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.done)

	// Close listeners under lock to prevent race between checking running
	// flag and accepting new connections
	if s.httpListener != nil {
		if err := s.httpListener.Close(); err != nil {
			logging.Warn("Error closing HTTP listener", "error", err)
		}
	}
	if s.socks5Listener != nil {
		if err := s.socks5Listener.Close(); err != nil {
			logging.Warn("Error closing SOCKS5 listener", "error", err)
		}
	}
	s.mu.Unlock()

	logging.Info("Stopping Bifrost server")

	// Stop metrics server
	if s.metricsServer != nil {
		if err := s.metricsServer.Shutdown(ctx); err != nil {
			logging.Error("Error shutting down metrics server", "error", err)
		}
	}

	// Stop API server
	if s.apiServer != nil {
		if err := s.apiServer.Shutdown(ctx); err != nil {
			logging.Error("Error shutting down API server", "error", err)
		}
	}

	// Wait for connections with grace period
	gracePeriod := s.config.Server.GracefulPeriod.Duration()
	if gracePeriod == 0 {
		gracePeriod = 30 * time.Second
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(gracePeriod):
		logging.Warn("Grace period exceeded, forcing shutdown")
	}

	// Stop cache manager
	if s.cacheManager != nil {
		if err := s.cacheManager.Stop(ctx); err != nil {
			logging.Error("Error stopping cache manager", "error", err)
		}
	}

	// Stop health manager
	s.healthManager.Stop()

	// Stop metrics collector
	s.metricsCollector.Stop()

	// Stop backends
	if err := s.backends.StopAll(ctx); err != nil {
		logging.Error("Error stopping backends", "error", err)
	}

	// Close access logger
	s.accessLogger.Close()

	// Close rate limiters
	if s.rateLimiterIP != nil {
		s.rateLimiterIP.Close()
	}
	if s.rateLimiterUser != nil {
		s.rateLimiterUser.Close()
	}

	// Stop the Negotiate handler's challenge-cleanup goroutine to avoid a leak
	// across server restarts.
	if s.negotiateHandler != nil {
		if err := s.negotiateHandler.Close(); err != nil {
			logging.Warn("Error closing negotiate handler", "error", err)
		}
	}

	logging.Info("Bifrost server stopped")
	return nil
}

// GetSanitizedConfig returns the current config with secrets redacted.
func (s *Server) GetSanitizedConfig() interface{} {
	// Create a sanitized copy of the config
	sanitized := map[string]interface{}{
		"server": map[string]interface{}{
			"http": map[string]interface{}{
				"listen":        s.config.Server.HTTP.Listen,
				"read_timeout":  time.Duration(s.config.Server.HTTP.ReadTimeout).String(),
				"write_timeout": time.Duration(s.config.Server.HTTP.WriteTimeout).String(),
			},
			"socks5": map[string]interface{}{
				"listen": s.config.Server.SOCKS5.Listen,
			},
			"graceful_period": time.Duration(s.config.Server.GracefulPeriod).String(),
		},
		"auth": map[string]interface{}{
			"mode": s.config.Auth.Mode,
		},
		"rate_limit": map[string]interface{}{
			"enabled":             s.config.RateLimit.Enabled,
			"requests_per_second": s.config.RateLimit.RequestsPerSecond,
			"burst_size":          s.config.RateLimit.BurstSize,
			"per_ip":              s.config.RateLimit.PerIP,
			"per_user":            s.config.RateLimit.PerUser,
			"bandwidth": func() map[string]interface{} {
				if s.config.RateLimit.Bandwidth == nil {
					return map[string]interface{}{"enabled": false}
				}
				return map[string]interface{}{
					"enabled":  s.config.RateLimit.Bandwidth.Enabled,
					"upload":   s.config.RateLimit.Bandwidth.Upload,
					"download": s.config.RateLimit.Bandwidth.Download,
				}
			}(),
		},
		"access_control": map[string]interface{}{
			"whitelist": s.config.AccessControl.Whitelist,
			"blacklist": s.config.AccessControl.Blacklist,
		},
		"metrics": map[string]interface{}{
			"enabled": s.config.Metrics.Enabled,
			"listen":  s.config.Metrics.Listen,
			"path":    s.config.Metrics.Path,
		},
		"api": map[string]interface{}{
			"enabled": s.config.API.Enabled,
			"listen":  s.config.API.Listen,
		},
		"backends_count": len(s.config.Backends),
		"routes_count":   len(s.config.Routes),
	}

	// Add backend names (not full config)
	backendNames := make([]string, 0, len(s.config.Backends))
	for _, b := range s.config.Backends {
		backendNames = append(backendNames, b.Name)
	}
	sanitized["backend_names"] = backendNames

	return sanitized
}

// GetFullConfig returns the full configuration for editing.
func (s *Server) GetFullConfig() *config.ServerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return the config pointer - callers should not modify
	return s.config
}

// SaveConfig saves the configuration to file.
func (s *Server) SaveConfig(newConfig *config.ServerConfig) error {
	if s.configPath == "" {
		return fmt.Errorf("config path not set")
	}
	if err := newConfig.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return config.Save(s.configPath, newConfig)
}

// GetConfigPath returns the config file path.
func (s *Server) GetConfigPath() string {
	return s.configPath
}

// SetConfigPath sets the config file path for hot reload support.
func (s *Server) SetConfigPath(path string) {
	s.configPath = path
}

// ReloadConfig reloads the configuration from the config file.
// This implementation safely reloads routes and rate limits.
// Backend changes require a full restart.
func (s *Server) ReloadConfig() error {
	logging.Info("Reloading configuration")

	if s.configPath == "" {
		return fmt.Errorf("config path not set - cannot reload")
	}

	// Parse new config
	newCfg := config.DefaultServerConfig()
	if err := config.LoadAndValidate(s.configPath, &newCfg); err != nil {
		logging.Error("Failed to reload config", "error", err)
		return fmt.Errorf("parse config: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Track what was reloaded
	reloaded := []string{}

	// Reload routes (safe to do)
	if err := s.router.LoadRoutes(newCfg.Routes); err != nil {
		logging.Error("Failed to reload routes", "error", err)
		return fmt.Errorf("reload routes: %w", err)
	}
	reloaded = append(reloaded, "routes")
	logging.Info("Reloaded routes", "count", len(newCfg.Routes))

	// Update rate limiter settings if changed
	if newCfg.RateLimit.Enabled {
		perIP := newCfg.RateLimit.PerIP
		perUser := newCfg.RateLimit.PerUser
		if !perIP && !perUser {
			perIP = true
		}

		rlCfg := ratelimit.Config{
			RequestsPerSecond: newCfg.RateLimit.RequestsPerSecond,
			BurstSize:         newCfg.RateLimit.BurstSize,
		}

		if perIP {
			if s.rateLimiterIP == nil {
				s.rateLimiterIP = ratelimit.NewKeyedLimiter(rlCfg)
			} else {
				s.rateLimiterIP.UpdateConfig(rlCfg)
			}
		} else if s.rateLimiterIP != nil {
			s.rateLimiterIP.Close()
			s.rateLimiterIP = nil
		}

		if perUser {
			if s.rateLimiterUser == nil {
				s.rateLimiterUser = ratelimit.NewKeyedLimiter(rlCfg)
			} else {
				s.rateLimiterUser.UpdateConfig(rlCfg)
			}
		} else if s.rateLimiterUser != nil {
			s.rateLimiterUser.Close()
			s.rateLimiterUser = nil
		}

		reloaded = append(reloaded, "rate_limits")
		logging.Info("Reloaded rate limits",
			"requests_per_second", newCfg.RateLimit.RequestsPerSecond,
			"burst_size", newCfg.RateLimit.BurstSize,
			"per_ip", perIP,
			"per_user", perUser)
	} else {
		if s.rateLimiterIP != nil {
			s.rateLimiterIP.Close()
			s.rateLimiterIP = nil
		}
		if s.rateLimiterUser != nil {
			s.rateLimiterUser.Close()
			s.rateLimiterUser = nil
		}
	}

	// Update access control
	if len(newCfg.AccessControl.Whitelist) > 0 || len(newCfg.AccessControl.Blacklist) > 0 {
		ac, err := accesscontrol.NewController(accesscontrol.Config{
			Whitelist: newCfg.AccessControl.Whitelist,
			Blacklist: newCfg.AccessControl.Blacklist,
		})
		if err != nil {
			return fmt.Errorf("reload access control: %w", err)
		}
		s.accessController = ac
		reloaded = append(reloaded, "access_control")
	} else {
		s.accessController = nil
	}

	// Update bandwidth throttling configuration
	var bandwidthConfig *ratelimit.BandwidthConfig
	if newCfg.RateLimit.Bandwidth != nil && newCfg.RateLimit.Bandwidth.Enabled {
		upload, err := ratelimit.ParseBandwidth(newCfg.RateLimit.Bandwidth.Upload)
		if err != nil {
			return fmt.Errorf("reload upload bandwidth: %w", err)
		}
		download, err := ratelimit.ParseBandwidth(newCfg.RateLimit.Bandwidth.Download)
		if err != nil {
			return fmt.Errorf("reload download bandwidth: %w", err)
		}
		if upload > 0 || download > 0 {
			bandwidthConfig = &ratelimit.BandwidthConfig{
				Upload:   upload,
				Download: download,
			}
		}
	}
	s.bandwidthConfig = bandwidthConfig
	reloaded = append(reloaded, "bandwidth")

	// Reload cache rules/presets (rules are hot-reloadable; storage changes
	// still require a restart and are ignored by Manager.Reload).
	if s.cacheManager != nil {
		if err := s.cacheManager.Reload(&newCfg.Cache); err != nil {
			return fmt.Errorf("reload cache: %w", err)
		}
		s.config.Cache = newCfg.Cache
		reloaded = append(reloaded, "cache")
	}

	// Update config reference (for sanitized config endpoint)
	s.config.Routes = newCfg.Routes
	s.config.RateLimit = newCfg.RateLimit
	s.config.AccessControl = newCfg.AccessControl

	// Broadcast reload event via WebSocket
	if s.wsHub != nil {
		s.wsHub.Broadcast(apiserver.EventConfigReload, map[string]interface{}{
			"status":   "success",
			"reloaded": reloaded,
		})
	}

	logging.Info("Configuration reloaded successfully", "reloaded", reloaded)
	return nil
}

// wsBroadcastInterval is how often aggregate stats / backend health are pushed
// to connected WebSocket clients.
const wsBroadcastInterval = 5 * time.Second

// broadcastWSEvents periodically pushes aggregate stats and backend health
// events to all connected WebSocket clients. This lets the UI stop polling the
// REST endpoints once the WebSocket is connected.
func (s *Server) broadcastWSEvents() {
	defer s.wg.Done()

	ticker := time.NewTicker(wsBroadcastInterval)
	defer ticker.Stop()

	// lastHealth tracks the last reported health per backend so we only emit
	// BackendHealthEvent on transitions.
	lastHealth := make(map[string]bool)

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.wsHub == nil || s.backends == nil {
				continue
			}

			var totalConnections, activeConnections, bytesSent, bytesReceived int64
			for _, b := range s.backends.All() {
				st := b.Stats()
				totalConnections += st.TotalConnections
				activeConnections += st.ActiveConnections
				bytesSent += st.BytesSent
				bytesReceived += st.BytesReceived

				healthy := b.IsHealthy()
				if prev, ok := lastHealth[b.Name()]; !ok || prev != healthy {
					lastHealth[b.Name()] = healthy
					s.wsHub.Broadcast(apiserver.EventBackendHealth, apiserver.BackendHealthEvent{
						Name:    b.Name(),
						Healthy: healthy,
					})
				}
			}

			s.wsHub.Broadcast(apiserver.EventStats, apiserver.StatsEvent{
				ActiveConnections: activeConnections,
				TotalConnections:  totalConnections,
				BytesSent:         bytesSent,
				BytesReceived:     bytesReceived,
			})
		}
	}
}

// serveHTTP handles HTTP proxy connections.
func (s *Server) serveHTTP(ctx context.Context) {
	defer s.wg.Done()

	// Acquire read lock to safely read bandwidthConfig
	s.mu.RLock()
	bandwidthCfg := s.bandwidthConfig
	s.mu.RUnlock()

	handler := proxy.NewHTTPHandler(proxy.HTTPHandlerConfig{
		GetBackend:       s.getBackend,
		DialTimeout:      s.config.Server.HTTP.ReadTimeout.Duration(),
		Authenticate:     s.authenticateUser,
		NegotiateAuth:    s.negotiateAuthHook(),
		AuthRequired:     s.isAuthRequired(),
		DialNetwork:      s.config.Network.AddressFamily(),
		AccessCheck:      s.accessCheck,
		RateLimitUser:    s.allowUser,
		AccessLogger:     s.accessLogger,
		Bandwidth:        bandwidthCfg,
		OnConnect:        s.onConnect,
		OnError:          s.onError,
		CacheInterceptor: s.cacheInterceptor,
		MITM:             s.mitmInterceptor,
		RecordMetrics: func(protocol, method, status string, duration time.Duration, sent, recv int64) {
			s.metricsCollector.RecordRequest(protocol, method, status, duration)
			s.metricsCollector.RecordRequestSize(protocol, recv)
			s.metricsCollector.RecordResponseSize(protocol, sent)
			s.metricsCollector.RecordBytes("", sent, recv)
		},
	})

	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				logging.Error("HTTP accept error", "error", err)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleHTTPConn(ctx, conn, handler)
		}()
	}
}

// handleHTTPConn handles a single HTTP connection.
func (s *Server) handleHTTPConn(ctx context.Context, conn net.Conn, handler *proxy.HTTPHandler) {
	// Add request ID
	ctx = util.WithRequestID(ctx, generateRequestID())

	// Process-wide connection ceiling (network.max_connections).
	if !s.acquireGlobalConn() {
		logging.Warn("global connection limit exceeded",
			"max", s.config.Network.MaxConnections,
			"client", conn.RemoteAddr().String(),
		)
		_, _ = conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nConnection: close\r\n\r\n")) //nolint:errcheck // Best effort error response
		conn.Close()
		return
	}
	defer s.releaseGlobalConn()

	// Connection limiting for resource-constrained devices (OpenWrt)
	maxConns := s.config.Server.HTTP.MaxConnections
	if maxConns > 0 {
		current := atomic.AddInt32(&s.httpActiveConns, 1)
		defer atomic.AddInt32(&s.httpActiveConns, -1)

		if current > int32(maxConns) { //nolint:gosec // G115: maxConns is a small config value
			logging.Warn("HTTP connection limit exceeded",
				"current", current,
				"max", maxConns,
				"client", conn.RemoteAddr().String(),
			)
			_, _ = conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nConnection: close\r\n\r\n")) //nolint:errcheck // Best effort error response
			conn.Close()
			return
		}
	}

	// Rate limiting
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logging.Warn("Non-TCP connection to HTTP proxy", "addr", conn.RemoteAddr().String())
		conn.Close()
		return
	}
	clientIP := tcpAddr.IP.String()
	clientPort := fmt.Sprintf("%d", tcpAddr.Port)

	if limiter := s.snapshotRateLimiterIP(); limiter != nil {
		if !limiter.Allow(clientIP) {
			s.metricsCollector.RecordRateLimit("ip")
			_, _ = conn.Write([]byte("HTTP/1.1 429 Too Many Requests\r\n\r\n")) //nolint:errcheck // Best effort error response
			conn.Close()
			return
		}
	}

	// Track connection in API. The connection ID is threaded into the context so
	// the onConnect hook can populate the destination host/backend once known.
	if s.api != nil && s.api.ConnectionTracker() != nil {
		connID := s.api.ConnectionTracker().Add(clientIP, clientPort, "", "", "HTTP")
		defer s.closeTrackedConn(connID)
		ctx = withConnID(ctx, connID)
	}

	// Track connection metrics
	startTime := time.Now()
	done := s.metricsCollector.RecordConnection("http", "")

	handler.ServeConn(ctx, conn)

	done(time.Since(startTime))
}

// serveSOCKS5 handles SOCKS5 proxy connections.
func (s *Server) serveSOCKS5(ctx context.Context) {
	defer s.wg.Done()

	// Acquire read lock to safely read bandwidthConfig
	s.mu.RLock()
	bandwidthCfg := s.bandwidthConfig
	s.mu.RUnlock()

	handler := proxy.NewSOCKS5Handler(proxy.SOCKS5HandlerConfig{
		GetBackend:           s.getBackend,
		AuthenticateWithInfo: s.authenticateUser,
		AuthRequired:         s.isAuthRequired(),
		DialTimeout:          30 * time.Second,
		DialNetwork:          s.config.Network.AddressFamily(),
		AccessCheck:          s.accessCheck,
		RateLimitUser:        s.allowUser,
		AccessLogger:         s.accessLogger,
		Bandwidth:            bandwidthCfg,
		OnConnect:            s.onConnect,
		OnError:              s.onError,
	})

	for {
		conn, err := s.socks5Listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				logging.Error("SOCKS5 accept error", "error", err)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSOCKS5Conn(ctx, conn, handler)
		}()
	}
}

// handleSOCKS5Conn handles a single SOCKS5 connection.
func (s *Server) handleSOCKS5Conn(ctx context.Context, conn net.Conn, handler *proxy.SOCKS5Handler) {
	// Add request ID
	ctx = util.WithRequestID(ctx, generateRequestID())

	// Process-wide connection ceiling (network.max_connections).
	if !s.acquireGlobalConn() {
		logging.Warn("global connection limit exceeded",
			"max", s.config.Network.MaxConnections,
			"client", conn.RemoteAddr().String(),
		)
		conn.Close()
		return
	}
	defer s.releaseGlobalConn()

	// Connection limiting for resource-constrained devices (OpenWrt)
	maxConns := s.config.Server.SOCKS5.MaxConnections
	if maxConns > 0 {
		current := atomic.AddInt32(&s.socks5ActiveConns, 1)
		defer atomic.AddInt32(&s.socks5ActiveConns, -1)

		if current > int32(maxConns) { //nolint:gosec // G115: maxConns is a small config value
			logging.Warn("SOCKS5 connection limit exceeded",
				"current", current,
				"max", maxConns,
				"client", conn.RemoteAddr().String(),
			)
			conn.Close()
			return
		}
	}

	// Rate limiting
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logging.Warn("Non-TCP connection to SOCKS5 proxy", "addr", conn.RemoteAddr().String())
		conn.Close()
		return
	}
	clientIP := tcpAddr.IP.String()
	clientPort := fmt.Sprintf("%d", tcpAddr.Port)

	if limiter := s.snapshotRateLimiterIP(); limiter != nil {
		if !limiter.Allow(clientIP) {
			s.metricsCollector.RecordRateLimit("ip")
			conn.Close()
			return
		}
	}

	// Track connection in API. The connection ID is threaded into the context so
	// the onConnect hook can populate the destination host/backend once known.
	if s.api != nil && s.api.ConnectionTracker() != nil {
		connID := s.api.ConnectionTracker().Add(clientIP, clientPort, "", "", "SOCKS5")
		defer s.closeTrackedConn(connID)
		ctx = withConnID(ctx, connID)
	}

	// Track connection metrics
	startTime := time.Now()
	done := s.metricsCollector.RecordConnection("socks5", "")

	handler.ServeConn(ctx, conn)

	done(time.Since(startTime))
}

// getBackend returns a backend for a domain.
func (s *Server) getBackend(domain, clientIP string) backend.Backend {
	return s.router.GetBackendForDomain(domain, clientIP)
}

// snapshotAccessController returns the current access controller under a read
// lock. ReloadConfig swaps s.accessController under s.mu.Lock(), so request-path
// readers must take s.mu.RLock() to avoid a data race.
func (s *Server) snapshotAccessController() *accesscontrol.Controller {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessController
}

// snapshotRateLimiterIP returns the current per-IP rate limiter under a read
// lock. ReloadConfig may swap s.rateLimiterIP under s.mu.Lock().
func (s *Server) snapshotRateLimiterIP() *ratelimit.KeyedLimiter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rateLimiterIP
}

// snapshotRateLimiterUser returns the current per-user rate limiter under a read
// lock. ReloadConfig may swap s.rateLimiterUser under s.mu.Lock().
func (s *Server) snapshotRateLimiterUser() *ratelimit.KeyedLimiter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rateLimiterUser
}

// isAuthRequired checks if authentication is required based on config.
func (s *Server) isAuthRequired() bool {
	// If using new multi-provider configuration
	if len(s.config.Auth.Providers) > 0 {
		for _, p := range s.config.Auth.Providers {
			if p.Enabled && p.Type != "none" {
				return true
			}
		}
		return false
	}

	return false
}

func (s *Server) accessCheck(clientIP string) (bool, string) {
	ac := s.snapshotAccessController()
	if ac == nil {
		return true, ""
	}
	result := ac.Check(clientIP)
	if result.Action == accesscontrol.ActionDeny {
		return false, string(result.Reason)
	}
	return true, ""
}

func (s *Server) allowUser(username, clientIP string) bool {
	limiter := s.snapshotRateLimiterUser()
	if limiter == nil {
		return true
	}

	key := username
	if key == "" {
		key = "anonymous:" + clientIP
	} else {
		key = "user:" + key
	}

	if !limiter.Allow(key) {
		s.metricsCollector.RecordRateLimit("user")
		return false
	}

	return true
}

// authenticate validates credentials.
func (s *Server) authenticateUser(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	user, err := s.authenticator.Authenticate(ctx, username, password)
	if err != nil {
		s.metricsCollector.RecordAuthAttempt(s.authenticator.Type(), false, "invalid_credentials")
		return nil, err
	}
	s.metricsCollector.RecordAuthAttempt(s.authenticator.Type(), true, "")
	return user, nil
}

// onConnect is called when a connection is established. It populates the tracked
// connection's destination host and backend (which are unknown at Add time) and
// broadcasts a connection.new event so the dashboard can display the live
// destination instead of an empty column.
func (s *Server) onConnect(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
	backendName := ""
	if be != nil {
		backendName = be.Name()
	}

	logging.DebugContext(ctx, "Connection established",
		"host", host,
		"backend", backendName,
		"client", conn.RemoteAddr().String(),
	)

	connID := connIDFromContext(ctx)
	if connID == "" || s.api == nil {
		return
	}
	tracker := s.api.ConnectionTracker()
	if tracker == nil {
		return
	}

	updated, ok := tracker.SetDestination(connID, host, backendName)
	if !ok {
		return
	}

	if s.wsHub != nil {
		s.wsHub.Broadcast(apiserver.EventConnectionNew, apiserver.ConnectionEvent{
			Protocol: updated.Protocol,
			Host:     updated.Host,
			Backend:  updated.Backend,
			ClientIP: updated.ClientIP,
		})
	}
}

// closeTrackedConn removes a connection from the tracker and broadcasts a
// connection.close event so the dashboard can drop it from the live view.
func (s *Server) closeTrackedConn(connID string) {
	if s.api == nil {
		return
	}
	tracker := s.api.ConnectionTracker()
	if tracker == nil {
		return
	}

	conn, ok := tracker.Get(connID)
	tracker.Remove(connID)
	if !ok || s.wsHub == nil {
		return
	}

	s.wsHub.Broadcast(apiserver.EventConnectionClose, apiserver.ConnectionEvent{
		Protocol: conn.Protocol,
		Host:     conn.Host,
		Backend:  conn.Backend,
		ClientIP: conn.ClientIP,
	})
}

// onError is called when an error occurs.
func (s *Server) onError(ctx context.Context, conn net.Conn, host string, err error) {
	backendName := util.GetBackend(ctx)
	if backendName != "" {
		s.metricsCollector.RecordBackendError(backendName, "connection")
	}

	logging.ErrorContext(ctx, "Connection error",
		"host", host,
		"error", err,
		"client", conn.RemoteAddr().String(),
	)
}

// Running returns whether the server is running.
func (s *Server) Running() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// connIDContextKey is the context key under which the API connection-tracker ID
// is stored so the onConnect hook can correlate a live connection with its
// tracked record once the destination host/backend are known.
type connIDContextKeyType struct{}

var connIDContextKey connIDContextKeyType

// withConnID returns a context carrying the connection-tracker ID.
func withConnID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, connIDContextKey, id)
}

// connIDFromContext extracts the connection-tracker ID from the context, or ""
// if absent.
func connIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(connIDContextKey).(string); ok {
		return id
	}
	return ""
}

// extractPort extracts the port from a listen address (e.g., ":8080" -> "8080").
func extractPort(listen, defaultPort string) string {
	if listen == "" {
		return defaultPort
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Maybe just a port like ":8080"
		if len(listen) > 0 && listen[0] == ':' {
			return listen[1:]
		}
		return defaultPort
	}
	return port
}

// API returns the API server instance.
func (s *Server) API() *apiserver.API {
	return s.api
}
