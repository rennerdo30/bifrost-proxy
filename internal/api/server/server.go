// Package server provides the REST API for Bifrost server.
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/net/websocket"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/health"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
)

// API provides the REST API for Bifrost server.
type API struct {
	backends      *backend.Manager
	healthManager *health.Manager
	token         string
	getConfig     func() interface{}
	reloadConfig  func() error
}

// Config holds API configuration.
type Config struct {
	Backends      *backend.Manager
	HealthManager *health.Manager
	Token         string
	GetConfig     func() interface{}     // Returns sanitized config
	ReloadConfig  func() error           // Triggers config reload
}

// New creates a new API server.
func New(cfg Config) *API {
	return &API{
		backends:      cfg.Backends,
		healthManager: cfg.HealthManager,
		token:         cfg.Token,
		getConfig:     cfg.GetConfig,
		reloadConfig:  cfg.ReloadConfig,
	}
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
		r.Post("/reload", a.handleReloadConfig)
	})

	return r
}

// RouterWithWebSocket returns a router with WebSocket and static file support.
func (a *API) RouterWithWebSocket(hub *WebSocketHub) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Auth middleware if token is set (skip for WebSocket and static)
	if a.token != "" {
		r.Group(func(r chi.Router) {
			r.Use(a.authMiddleware)
			a.addAPIRoutes(r)
		})
	} else {
		a.addAPIRoutes(r)
	}

	// WebSocket route (no auth)
	if hub != nil {
		r.Handle("/api/v1/ws", websocket.Handler(hub.ServeWS))
	}

	// Static files for Web UI (no auth)
	r.Handle("/", StaticHandler())
	r.Handle("/*", StaticHandler())

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
		r.Post("/reload", a.handleReloadConfig)
	})
}

func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		if token != a.token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

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
