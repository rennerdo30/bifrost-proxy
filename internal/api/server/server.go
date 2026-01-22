// Package server provides the REST API for Bifrost server.
package server

import (
	"crypto/subtle"
	"encoding/json"
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
	backends      *backend.Manager
	healthManager *health.Manager
	cacheManager  *cache.Manager
	token         string
	getConfig     func() interface{}
	getFullConfig func() *config.ServerConfig
	reloadConfig  func() error
	saveConfig    func(*config.ServerConfig) error
	configPath    string
	wsHub         *WebSocketHub
	pacGenerator  *PACGenerator
	requestLog    *RequestLog
	connTracker   *ConnectionTracker
	cacheAPI      *CacheAPI
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

	return &API{
		backends:      cfg.Backends,
		healthManager: cfg.HealthManager,
		cacheManager:  cfg.CacheManager,
		token:         cfg.Token,
		getConfig:     cfg.GetConfig,
		getFullConfig: cfg.GetFullConfig,
		reloadConfig:  cfg.ReloadConfig,
		saveConfig:    cfg.SaveConfig,
		configPath:    cfg.ConfigPath,
		pacGenerator:  pacGen,
		requestLog:    requestLog,
		connTracker:   NewConnectionTracker(),
		cacheAPI:      cacheAPI,
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
		r.Get("/{name}", a.handleGetBackend)
		r.Get("/{name}/stats", a.handleGetBackendStats)
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
			a.addAPIRoutes(r)

			// WebSocket route (with auth - uses query param token for WS connections)
			if hub != nil {
				r.Handle("/api/v1/ws", websocket.Handler(hub.ServeWS))
			}
		})
	} else {
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
		r.Get("/{name}", a.handleGetBackend)
		r.Get("/{name}/stats", a.handleGetBackendStats)
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

	// Cache routes
	if a.cacheAPI != nil {
		a.cacheAPI.RegisterRoutes(r)
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
	json.NewEncoder(w).Encode(data)
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
