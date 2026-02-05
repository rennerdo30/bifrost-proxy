// Package server provides the Bifrost server implementation.
package server

import (
	"context"
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
}

// New creates a new Bifrost server.
func New(cfg *config.ServerConfig) (*Server, error) {
	// Initialize logging
	if err := logging.Setup(cfg.Logging); err != nil {
		return nil, fmt.Errorf("setup logging: %w", err)
	}

	// Create backends
	factory := backend.NewFactory()
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

	if err := srv.setupHealthChecks(cfg); err != nil {
		return nil, err
	}

	return srv, nil
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
		s.healthManager.Register(backendCfg.Name, checker, checkCfg.Interval, func(name string, result health.Result) {
			if ho, ok := backendForCheck.(backend.HealthOverride); ok {
				ho.SetHealth(result)
			}
		})
	}

	return nil
}

func createAuthenticator(cfg config.AuthConfig) (auth.Authenticator, error) {
	factory := auth.NewFactory()

	// Check if using new multi-provider configuration
	if len(cfg.Providers) > 0 {
		providers := convertProvidersConfig(cfg.Providers)
		return factory.CreateChain(providers)
	}

	// Legacy single-mode configuration - convert to new format
	provider := convertLegacyConfig(cfg)
	return factory.Create(provider)
}

// convertProvidersConfig converts config.AuthProvider slice to auth.ProviderConfig slice.
func convertProvidersConfig(providers []config.AuthProvider) []auth.ProviderConfig {
	result := make([]auth.ProviderConfig, 0, len(providers))

	for _, p := range providers {
		providerCfg := auth.ProviderConfig{
			Name:     p.Name,
			Type:     p.Type,
			Enabled:  p.Enabled,
			Priority: p.Priority,
		}

		// Use new Config map if provided, otherwise convert legacy config
		if p.Config != nil {
			providerCfg.Config = p.Config
		} else {
			providerCfg.Config = convertLegacyProviderConfig(p)
		}

		result = append(result, providerCfg)
	}

	return result
}

// convertLegacyConfig converts legacy single-mode config to ProviderConfig.
func convertLegacyConfig(cfg config.AuthConfig) auth.ProviderConfig {
	mode := cfg.Mode
	if mode == "" {
		mode = "none"
	}

	provider := auth.ProviderConfig{
		Name:     mode,
		Type:     mode,
		Enabled:  true,
		Priority: 1,
	}

	switch mode {
	case "native":
		if cfg.Native != nil {
			users := make([]map[string]any, 0, len(cfg.Native.Users))
			for _, u := range cfg.Native.Users {
				users = append(users, map[string]any{
					"username":      u.Username,
					"password_hash": u.PasswordHash,
				})
			}
			provider.Config = map[string]any{"users": users}
		}
	case "system":
		if cfg.System != nil {
			provider.Config = map[string]any{
				"service":        cfg.System.Service,
				"allowed_users":  cfg.System.AllowedUsers,
				"allowed_groups": cfg.System.AllowedGroups,
			}
		}
	case "ldap":
		if cfg.LDAP != nil {
			provider.Config = map[string]any{
				"url":                  cfg.LDAP.URL,
				"base_dn":              cfg.LDAP.BaseDN,
				"bind_dn":              cfg.LDAP.BindDN,
				"bind_password":        cfg.LDAP.BindPassword,
				"user_filter":          cfg.LDAP.UserFilter,
				"group_filter":         cfg.LDAP.GroupFilter,
				"require_group":        cfg.LDAP.RequireGroup,
				"tls":                  cfg.LDAP.TLS,
				"insecure_skip_verify": cfg.LDAP.InsecureSkipVerify,
			}
		}
	case "oauth":
		if cfg.OAuth != nil {
			provider.Config = map[string]any{
				"provider":      cfg.OAuth.Provider,
				"client_id":     cfg.OAuth.ClientID,
				"client_secret": cfg.OAuth.ClientSecret,
				"issuer_url":    cfg.OAuth.IssuerURL,
				"scopes":        cfg.OAuth.Scopes,
			}
		}
	}

	return provider
}

// convertLegacyProviderConfig converts legacy type-specific config to map[string]any.
func convertLegacyProviderConfig(p config.AuthProvider) map[string]any {
	switch p.Type {
	case "native":
		if p.Native != nil {
			users := make([]map[string]any, 0, len(p.Native.Users))
			for _, u := range p.Native.Users {
				users = append(users, map[string]any{
					"username":      u.Username,
					"password_hash": u.PasswordHash,
				})
			}
			return map[string]any{"users": users}
		}
	case "system":
		if p.System != nil {
			return map[string]any{
				"service":        p.System.Service,
				"allowed_users":  p.System.AllowedUsers,
				"allowed_groups": p.System.AllowedGroups,
			}
		}
	case "ldap":
		if p.LDAP != nil {
			return map[string]any{
				"url":                  p.LDAP.URL,
				"base_dn":              p.LDAP.BaseDN,
				"bind_dn":              p.LDAP.BindDN,
				"bind_password":        p.LDAP.BindPassword,
				"user_filter":          p.LDAP.UserFilter,
				"group_filter":         p.LDAP.GroupFilter,
				"require_group":        p.LDAP.RequireGroup,
				"tls":                  p.LDAP.TLS,
				"insecure_skip_verify": p.LDAP.InsecureSkipVerify,
			}
		}
	case "oauth":
		if p.OAuth != nil {
			return map[string]any{
				"provider":      p.OAuth.Provider,
				"client_id":     p.OAuth.ClientID,
				"client_secret": p.OAuth.ClientSecret,
				"issuer_url":    p.OAuth.IssuerURL,
				"scopes":        p.OAuth.Scopes,
			}
		}
	}
	return nil
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
	s.mu.Unlock()

	logging.Info("Stopping Bifrost server")

	// Close listeners to stop accepting new connections
	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.socks5Listener != nil {
		s.socks5Listener.Close()
	}

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
		AuthRequired:     s.isAuthRequired(),
		AccessCheck:      s.accessCheck,
		RateLimitUser:    s.allowUser,
		AccessLogger:     s.accessLogger,
		Bandwidth:        bandwidthCfg,
		OnConnect:        s.onConnect,
		OnError:          s.onError,
		CacheInterceptor: s.cacheInterceptor,
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

	if s.rateLimiterIP != nil {
		if !s.rateLimiterIP.Allow(clientIP) {
			s.metricsCollector.RecordRateLimit("ip")
			_, _ = conn.Write([]byte("HTTP/1.1 429 Too Many Requests\r\n\r\n")) //nolint:errcheck // Best effort error response
			conn.Close()
			return
		}
	}

	// Track connection in API
	var connID string
	if s.api != nil && s.api.ConnectionTracker() != nil {
		connID = s.api.ConnectionTracker().Add(clientIP, clientPort, "", "", "HTTP")
		defer s.api.ConnectionTracker().Remove(connID)
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

	if s.rateLimiterIP != nil {
		if !s.rateLimiterIP.Allow(clientIP) {
			s.metricsCollector.RecordRateLimit("ip")
			conn.Close()
			return
		}
	}

	// Track connection in API
	var connID string
	if s.api != nil && s.api.ConnectionTracker() != nil {
		connID = s.api.ConnectionTracker().Add(clientIP, clientPort, "", "", "SOCKS5")
		defer s.api.ConnectionTracker().Remove(connID)
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
	// Legacy single-mode configuration
	return s.config.Auth.Mode != "none" && s.config.Auth.Mode != ""
}

func (s *Server) accessCheck(clientIP string) (bool, string) {
	if s.accessController == nil {
		return true, ""
	}
	result := s.accessController.Check(clientIP)
	if result.Action == accesscontrol.ActionDeny {
		return false, string(result.Reason)
	}
	return true, ""
}

func (s *Server) allowUser(username, clientIP string) bool {
	if s.rateLimiterUser == nil {
		return true
	}

	key := username
	if key == "" {
		key = "anonymous:" + clientIP
	} else {
		key = "user:" + key
	}

	if !s.rateLimiterUser.Allow(key) {
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

// onConnect is called when a connection is established.
func (s *Server) onConnect(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
	logging.DebugContext(ctx, "Connection established",
		"host", host,
		"backend", be.Name(),
		"client", conn.RemoteAddr().String(),
	)
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
