// Package server provides the REST API for Bifrost server.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/net/websocket"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/cache"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/health"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
)

// API provides the REST API for Bifrost server.
type API struct {
	backends       *backend.Manager
	backendFactory *backend.Factory
	healthManager  *health.Manager
	cacheManager   *cache.Manager
	token          string
	getConfig      func() interface{}
	getFullConfig  func() *config.ServerConfig
	reloadConfig   func() error
	saveConfig     func(*config.ServerConfig) error
	configPath     string
	wsHub          *WebSocketHub
	pacGenerator   *PACGenerator
	requestLog     *RequestLog
	connTracker    *ConnectionTracker
	cacheAPI       *CacheAPI
	meshAPI        *MeshAPI
}

// Config holds API configuration.
type Config struct {
	Backends         *backend.Manager
	HealthManager    *health.Manager
	CacheManager     *cache.Manager
	Token            string
	GetConfig        func() interface{}               // Returns sanitized config
	GetFullConfig    func() *config.ServerConfig      // Returns full config for editing
	ReloadConfig     func() error                     // Triggers config reload
	SaveConfig       func(*config.ServerConfig) error // Saves config to file
	ConfigPath       string                           // Path to config file
	ProxyHost        string                           // Proxy host for PAC file
	ProxyPort        string                           // HTTP proxy port for PAC file
	SOCKS5Port       string                           // SOCKS5 port for PAC file
	EnableRequestLog bool                             // Enable request logging
	RequestLogSize   int                              // Max requests to keep
}

// New creates a new API server.
func New(cfg Config) *API {
	// Default ports if not specified
	proxyPort := cfg.ProxyPort
	if proxyPort == "" {
		proxyPort = "8080"
	}
	socks5Port := cfg.SOCKS5Port
	if socks5Port == "" {
		socks5Port = "1080"
	}

	// Create PAC generator
	var pacGen *PACGenerator
	if cfg.GetFullConfig != nil {
		pacGen = NewPACGenerator(cfg.GetFullConfig, cfg.ProxyHost, proxyPort, socks5Port)
	}

	// Create request log
	requestLogSize := cfg.RequestLogSize
	if requestLogSize <= 0 {
		requestLogSize = 1000
	}
	requestLog := NewRequestLog(requestLogSize, cfg.EnableRequestLog)

	// Create cache API if cache manager is provided
	var cacheAPI *CacheAPI
	if cfg.CacheManager != nil {
		cacheAPI = NewCacheAPI(cfg.CacheManager)
	}

	// Create mesh API for P2P mesh networking
	meshAPI := NewMeshAPI()

	return &API{
		backends:       cfg.Backends,
		backendFactory: backend.NewFactory(),
		healthManager:  cfg.HealthManager,
		cacheManager:   cfg.CacheManager,
		token:          cfg.Token,
		getConfig:      cfg.GetConfig,
		getFullConfig:  cfg.GetFullConfig,
		reloadConfig:   cfg.ReloadConfig,
		saveConfig:     cfg.SaveConfig,
		configPath:     cfg.ConfigPath,
		pacGenerator:   pacGen,
		requestLog:     requestLog,
		connTracker:    NewConnectionTracker(),
		cacheAPI:       cacheAPI,
		meshAPI:        meshAPI,
	}
}

// ConnectionTracker returns the connection tracker for tracking active connections.
func (a *API) ConnectionTracker() *ConnectionTracker {
	return a.connTracker
}

// RequestLog returns the request log for adding entries.
func (a *API) RequestLog() *RequestLog {
	return a.requestLog
}

// Router returns the HTTP router for the API.
func (a *API) Router() http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(a.securityHeadersMiddleware)

	// Auth middleware if token is set
	if a.token != "" {
		r.Use(a.authMiddleware)
	}

	// Routes
	r.Get("/api/v1/health", a.handleHealth)
	r.Get("/api/v1/version", a.handleVersion)
	r.Get("/api/v1/status", a.handleStatus)
	r.Get("/api/v1/stats", a.handleStats)

	// Backend routes
	r.Route("/api/v1/backends", func(r chi.Router) {
		r.Get("/", a.handleListBackends)
		r.Post("/", a.handleAddBackend)
		r.Get("/{name}", a.handleGetBackend)
		r.Delete("/{name}", a.handleRemoveBackend)
		r.Get("/{name}/stats", a.handleGetBackendStats)
		r.Post("/{name}/test", a.handleTestBackend)
	})

	// Config routes
	r.Route("/api/v1/config", func(r chi.Router) {
		r.Get("/", a.handleGetConfig)
		r.Get("/full", a.handleGetFullConfig)
		r.Get("/meta", a.handleGetConfigMeta)
		r.Put("/", a.handleSaveConfig)
		r.Post("/validate", a.handleValidateConfig)
		r.Post("/reload", a.handleReloadConfig)
	})

	return r
}

// RouterWithWebSocket returns a router with WebSocket and static file support.
func (a *API) RouterWithWebSocket(hub *WebSocketHub) http.Handler {
	// Store the hub reference for broadcasting events
	a.wsHub = hub

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(a.securityHeadersMiddleware)

	// Auth middleware if token is set
	if a.token != "" {
		r.Group(func(r chi.Router) {
			r.Use(a.authMiddleware)
			r.Use(a.csrfMiddleware)
			a.addAPIRoutes(r)

			// WebSocket route (with auth - uses query param token for WS connections)
			if hub != nil {
				r.Handle("/api/v1/ws", websocket.Handler(hub.ServeWS))
			}
		})
	} else {
		r.Use(a.csrfMiddleware)
		a.addAPIRoutes(r)

		// WebSocket route (no auth when token not configured)
		if hub != nil {
			r.Handle("/api/v1/ws", websocket.Handler(hub.ServeWS))
		}
	}

	// PAC file routes (no auth required for browser auto-config)
	if a.pacGenerator != nil {
		r.Get("/proxy.pac", a.pacGenerator.HandlePAC)
		r.Get("/wpad.dat", a.pacGenerator.HandlePAC)
	}

	// Static files for Web UI (no auth)
	staticHandler := StaticHandler()
	r.Get("/", staticHandler.ServeHTTP)
	r.NotFound(staticHandler.ServeHTTP)

	return r
}

// addAPIRoutes adds all API routes to the router.
func (a *API) addAPIRoutes(r chi.Router) {
	r.Get("/api/v1/health", a.handleHealth)
	r.Get("/api/v1/version", a.handleVersion)
	r.Get("/api/v1/status", a.handleStatus)
	r.Get("/api/v1/stats", a.handleStats)

	r.Route("/api/v1/backends", func(r chi.Router) {
		r.Get("/", a.handleListBackends)
		r.Post("/", a.handleAddBackend)
		r.Get("/{name}", a.handleGetBackend)
		r.Delete("/{name}", a.handleRemoveBackend)
		r.Get("/{name}/stats", a.handleGetBackendStats)
		r.Post("/{name}/test", a.handleTestBackend)
	})

	r.Route("/api/v1/config", func(r chi.Router) {
		r.Get("/", a.handleGetConfig)
		r.Get("/full", a.handleGetFullConfig)
		r.Get("/meta", a.handleGetConfigMeta)
		r.Put("/", a.handleSaveConfig)
		r.Post("/validate", a.handleValidateConfig)
		r.Post("/reload", a.handleReloadConfig)
	})

	// Request log routes
	r.Route("/api/v1/requests", func(r chi.Router) {
		r.Get("/", a.handleGetRequests)
		r.Get("/stats", a.handleGetRequestStats)
		r.Delete("/", a.handleClearRequests)
	})

	// Connection tracking routes
	r.Route("/api/v1/connections", func(r chi.Router) {
		r.Get("/", a.handleGetConnections)
		r.Get("/clients", a.handleGetClients)
	})

	// Routing rules endpoints
	r.Route("/api/v1/routes", func(r chi.Router) {
		r.Get("/", a.handleListRoutes)
		r.Post("/", a.handleAddRoute)
		r.Delete("/{name}", a.handleRemoveRoute)
	})

	// Cache routes
	if a.cacheAPI != nil {
		a.cacheAPI.RegisterRoutes(r)
	}

	// Mesh networking routes
	if a.meshAPI != nil {
		a.meshAPI.RegisterRoutes(r)
	}
}

func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no token is configured, allow all requests
		if a.token == "" {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("Authorization")
		if token == "" {
			// Fallback to query parameter for WebSocket connections
			token = r.URL.Query().Get("token")
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware provides CSRF protection for mutating requests.
// Requires X-Requested-With header on POST/PUT/DELETE requests.
// This prevents CSRF attacks because custom headers cannot be sent cross-origin
// without CORS preflight approval (which is not configured).
func (a *API) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check mutating methods
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			// Require X-Requested-With header (standard CSRF mitigation)
			if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
				http.Error(w, "CSRF validation failed: missing X-Requested-With header", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds common security headers to all responses.
func (a *API) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// XSS protection (legacy, but still useful)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content Security Policy
		// Allow self, inline styles/scripts for React/Vite, and WebSockets
		// All assets (including fonts) are now served from 'self'
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"font-src 'self'; " +
			"img-src 'self' data: https:; " +
			"connect-src 'self' ws: wss:; " +
			"frame-ancestors 'none'"
		w.Header().Set("Content-Security-Policy", csp)

		next.ServeHTTP(w, r)
	})
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	}

	if a.healthManager != nil && !a.healthManager.IsHealthy() {
		response["status"] = "degraded"
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleVersion(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, version.GetInfo())
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":   "running",
		"time":     time.Now().Format(time.RFC3339),
		"version":  version.Short(),
		"backends": len(a.backends.All()),
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	// Aggregate stats from all backends
	var totalConnections int64
	var totalBytesSent int64
	var totalBytesReceived int64
	var activeConnections int64
	healthyBackends := 0

	backends := a.backends.All()
	for _, b := range backends {
		stats := b.Stats()
		totalConnections += stats.TotalConnections
		totalBytesSent += stats.BytesSent
		totalBytesReceived += stats.BytesReceived
		activeConnections += stats.ActiveConnections
		if b.IsHealthy() {
			healthyBackends++
		}
	}

	response := map[string]interface{}{
		"total_connections":  totalConnections,
		"active_connections": activeConnections,
		"bytes_sent":         totalBytesSent,
		"bytes_received":     totalBytesReceived,
		"backends": map[string]interface{}{
			"total":   len(backends),
			"healthy": healthyBackends,
		},
		"time": time.Now().Format(time.RFC3339),
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleListBackends(w http.ResponseWriter, r *http.Request) {
	backends := a.backends.All()
	response := make([]map[string]interface{}, 0, len(backends))

	for _, b := range backends {
		stats := b.Stats()
		response = append(response, map[string]interface{}{
			"name":    b.Name(),
			"type":    b.Type(),
			"healthy": b.IsHealthy(),
			"stats":   stats,
		})
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleGetBackend(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	b, err := a.backends.Get(name)
	if err != nil {
		http.Error(w, "Backend not found", http.StatusNotFound)
		return
	}

	stats := b.Stats()
	response := map[string]interface{}{
		"name":    b.Name(),
		"type":    b.Type(),
		"healthy": b.IsHealthy(),
		"stats":   stats,
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleGetBackendStats(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	b, err := a.backends.Get(name)
	if err != nil {
		http.Error(w, "Backend not found", http.StatusNotFound)
		return
	}

	a.writeJSON(w, http.StatusOK, b.Stats())
}

// handleAddBackend adds a new backend to the manager.
func (a *API) handleAddBackend(w http.ResponseWriter, r *http.Request) {
	var cfg config.BackendConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
		return
	}

	// Validate required fields
	if cfg.Name == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Backend name is required",
		})
		return
	}
	if cfg.Type == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Backend type is required",
		})
		return
	}

	// Check if backend already exists
	if _, err := a.backends.Get(cfg.Name); err == nil {
		a.writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error":   "Backend already exists",
			"backend": cfg.Name,
		})
		return
	}

	// Create the backend using the factory
	newBackend, err := a.backendFactory.Create(cfg)
	if err != nil {
		slog.Error("failed to create backend", "name", cfg.Name, "type", cfg.Type, "error", err)
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Failed to create backend",
			"message": err.Error(),
		})
		return
	}

	// Add to manager
	if err := a.backends.Add(newBackend); err != nil {
		slog.Error("failed to add backend to manager", "name", cfg.Name, "error", err)
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to add backend",
			"message": err.Error(),
		})
		return
	}

	// Start the backend if enabled
	if cfg.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := newBackend.Start(ctx); err != nil {
			slog.Warn("failed to start backend", "name", cfg.Name, "error", err)
			// Don't fail the request, just warn - the backend is added but not started
		}
	}

	slog.Info("backend added via API", "name", cfg.Name, "type", cfg.Type, "enabled", cfg.Enabled)
	a.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":  "created",
		"backend": cfg.Name,
		"type":    cfg.Type,
	})
}

// handleRemoveBackend removes a backend from the manager.
func (a *API) handleRemoveBackend(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	// Get the backend first to stop it
	b, err := a.backends.Get(name)
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "Backend not found",
			"backend": name,
		})
		return
	}

	// Stop the backend gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Stop(ctx); err != nil {
		slog.Warn("error stopping backend during removal", "name", name, "error", err)
		// Continue with removal even if stop fails
	}

	// Remove from manager
	if err := a.backends.Remove(name); err != nil {
		slog.Error("failed to remove backend", "name", name, "error", err)
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to remove backend",
			"message": err.Error(),
		})
		return
	}

	slog.Info("backend removed via API", "name", name)
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "removed",
		"backend": name,
	})
}

// handleTestBackend tests connectivity through a specific backend.
func (a *API) handleTestBackend(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	b, err := a.backends.Get(name)
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "Backend not found",
			"backend": name,
		})
		return
	}

	// Parse optional test parameters
	var testReq struct {
		Target  string `json:"target"`
		Timeout string `json:"timeout"`
	}
	// Ignore decode errors - use defaults
	_ = json.NewDecoder(r.Body).Decode(&testReq) //nolint:errcheck // Default values used on error

	target := testReq.Target
	if target == "" {
		target = "google.com:443" // Default test target
	}

	timeout := 10 * time.Second
	if testReq.Timeout != "" {
		if d, parseErr := time.ParseDuration(testReq.Timeout); parseErr == nil {
			timeout = d
		}
	}

	// Perform connectivity test
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	conn, err := b.Dial(ctx, "tcp", target)
	duration := time.Since(start)

	if err != nil {
		slog.Warn("backend test failed", "name", name, "target", target, "error", err)
		a.writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "failed",
			"backend":  name,
			"target":   target,
			"error":    err.Error(),
			"duration": duration.String(),
		})
		return
	}
	conn.Close()

	slog.Info("backend test succeeded", "name", name, "target", target, "duration", duration)
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"backend":  name,
		"target":   target,
		"duration": duration.String(),
		"healthy":  b.IsHealthy(),
	})
}

// handleListRoutes lists all configured routes.
func (a *API) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	if a.getFullConfig == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Config retrieval not available",
		})
		return
	}

	cfg := a.getFullConfig()
	if cfg == nil {
		a.writeJSON(w, http.StatusOK, []config.RouteConfig{})
		return
	}

	a.writeJSON(w, http.StatusOK, cfg.Routes)
}

// handleAddRoute adds a new route to the configuration.
func (a *API) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	if a.getFullConfig == nil || a.saveConfig == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Config management not available",
		})
		return
	}

	var newRoute config.RouteConfig
	if err := json.NewDecoder(r.Body).Decode(&newRoute); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
		return
	}

	// Validate required fields
	if newRoute.Name == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Route name is required",
		})
		return
	}
	if len(newRoute.Domains) == 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "At least one domain pattern is required",
		})
		return
	}
	if newRoute.Backend == "" && len(newRoute.Backends) == 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Backend or backends is required",
		})
		return
	}

	// Get current config
	cfg := a.getFullConfig()
	if cfg == nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to get current config",
		})
		return
	}

	// Check if route with same name already exists
	for _, route := range cfg.Routes {
		if route.Name == newRoute.Name {
			a.writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error": "Route with this name already exists",
				"route": newRoute.Name,
			})
			return
		}
	}

	// Validate backend exists
	if newRoute.Backend != "" {
		if _, err := a.backends.Get(newRoute.Backend); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":   "Backend not found",
				"backend": newRoute.Backend,
			})
			return
		}
	}
	for _, backendName := range newRoute.Backends {
		if _, err := a.backends.Get(backendName); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":   "Backend not found",
				"backend": backendName,
			})
			return
		}
	}

	// Add route to config
	cfg.Routes = append(cfg.Routes, newRoute)

	// Save config
	if err := a.saveConfig(cfg); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to save config",
			"message": err.Error(),
		})
		return
	}

	// Reload config to apply changes
	if a.reloadConfig != nil {
		if err := a.reloadConfig(); err != nil {
			slog.Warn("failed to reload config after adding route", "route", newRoute.Name, "error", err)
			a.writeJSON(w, http.StatusCreated, map[string]interface{}{
				"status":           "created",
				"route":            newRoute.Name,
				"warning":          "Config saved but reload failed",
				"reload_error":     err.Error(),
				"restart_required": true,
			})
			return
		}
	}

	slog.Info("route added via API", "name", newRoute.Name, "domains", newRoute.Domains, "backend", newRoute.Backend)
	a.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":  "created",
		"route":   newRoute.Name,
		"domains": newRoute.Domains,
		"backend": newRoute.Backend,
	})
}

// handleRemoveRoute removes a route from the configuration.
func (a *API) handleRemoveRoute(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if a.getFullConfig == nil || a.saveConfig == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Config management not available",
		})
		return
	}

	// Get current config
	cfg := a.getFullConfig()
	if cfg == nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to get current config",
		})
		return
	}

	// Find and remove route
	found := false
	newRoutes := make([]config.RouteConfig, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		if route.Name == name {
			found = true
			continue
		}
		newRoutes = append(newRoutes, route)
	}

	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Route not found",
			"route": name,
		})
		return
	}

	cfg.Routes = newRoutes

	// Save config
	if err := a.saveConfig(cfg); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Failed to save config",
			"message": err.Error(),
		})
		return
	}

	// Reload config to apply changes
	if a.reloadConfig != nil {
		if err := a.reloadConfig(); err != nil {
			slog.Warn("failed to reload config after removing route", "route", name, "error", err)
			a.writeJSON(w, http.StatusOK, map[string]interface{}{
				"status":           "removed",
				"route":            name,
				"warning":          "Config saved but reload failed",
				"reload_error":     err.Error(),
				"restart_required": true,
			})
			return
		}
	}

	slog.Info("route removed via API", "name", name)
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "removed",
		"route":  name,
	})
}

func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if a.getConfig == nil {
		a.writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Config retrieval not available",
		})
		return
	}

	cfg := a.getConfig()
	a.writeJSON(w, http.StatusOK, cfg)
}

func (a *API) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if a.reloadConfig == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Config reload not available",
		})
		return
	}

	if err := a.reloadConfig(); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "Config reload failed",
			"message": err.Error(),
		})
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Config reloaded successfully",
		"time":    time.Now().Format(time.RFC3339),
	})
}

func (a *API) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data) //nolint:errcheck // Best effort HTTP response
}

// handleGetRequests returns recent request log entries.
func (a *API) handleGetRequests(w http.ResponseWriter, r *http.Request) {
	if a.requestLog == nil || !a.requestLog.IsEnabled() {
		a.writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled":  false,
			"message":  "Request logging is disabled",
			"requests": []RequestLogEntry{},
		})
		return
	}

	// Parse and validate query params
	limitStr := r.URL.Query().Get("limit")
	sinceStr := r.URL.Query().Get("since")

	var entries []RequestLogEntry
	if sinceStr != "" {
		sinceID, err := strconv.ParseInt(sinceStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid 'since' parameter: must be an integer", http.StatusBadRequest)
			return
		}
		entries = a.requestLog.GetSince(sinceID)
	} else if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			http.Error(w, "invalid 'limit' parameter: must be an integer", http.StatusBadRequest)
			return
		}
		if limit <= 0 {
			http.Error(w, "invalid 'limit' parameter: must be positive", http.StatusBadRequest)
			return
		}
		entries = a.requestLog.GetRecent(limit)
	} else {
		entries = a.requestLog.GetRecent(100) // Default to last 100
	}

	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":  true,
		"requests": entries,
	})
}

// handleGetRequestStats returns request log statistics.
func (a *API) handleGetRequestStats(w http.ResponseWriter, r *http.Request) {
	if a.requestLog == nil {
		a.writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
		})
		return
	}

	a.writeJSON(w, http.StatusOK, a.requestLog.Stats())
}

// handleClearRequests clears the request log.
func (a *API) handleClearRequests(w http.ResponseWriter, r *http.Request) {
	if a.requestLog != nil {
		a.requestLog.Clear()
	}

	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Request log cleared",
	})
}

// handleGetConnections returns all active connections.
func (a *API) handleGetConnections(w http.ResponseWriter, r *http.Request) {
	connections := a.connTracker.GetAll()
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"connections": connections,
		"count":       len(connections),
		"time":        time.Now().Format(time.RFC3339),
	})
}

// handleGetClients returns unique connected clients with summaries.
func (a *API) handleGetClients(w http.ResponseWriter, r *http.Request) {
	clients := a.connTracker.GetUniqueClients()
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
		"time":    time.Now().Format(time.RFC3339),
	})
}
