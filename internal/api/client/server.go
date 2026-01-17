// Package client provides the REST API for Bifrost client.
package client

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/rennerdo30/bifrost-proxy/internal/debug"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// API provides the REST API for Bifrost client.
type API struct {
	router          *router.ClientRouter
	debugger        *debug.Logger
	serverConnected func() bool
	token           string
	vpnManager      *vpn.Manager
}

// Config holds API configuration.
type Config struct {
	Router          *router.ClientRouter
	Debugger        *debug.Logger
	ServerConnected func() bool
	Token           string
	VPNManager      *vpn.Manager
}

// New creates a new API server.
func New(cfg Config) *API {
	return &API{
		router:          cfg.Router,
		debugger:        cfg.Debugger,
		serverConnected: cfg.ServerConnected,
		token:           cfg.Token,
		vpnManager:      cfg.VPNManager,
	}
}

// Handler returns the HTTP handler for the API.
func (a *API) Handler() http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(securityHeadersMiddleware)

	// Auth middleware if token is set
	if a.token != "" {
		r.Use(a.authMiddleware)
	}

	// CORS for local development
	r.Use(corsMiddleware)

	// Routes
	a.addAPIRoutes(r)

	return r
}

// HandlerWithUI returns a handler with API routes and static file support for Web UI.
func (a *API) HandlerWithUI() http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(securityHeadersMiddleware)

	// CORS for local development
	r.Use(corsMiddleware)

	// Auth middleware if token is set (skip for static)
	if a.token != "" {
		r.Group(func(r chi.Router) {
			r.Use(a.authMiddleware)
			a.addAPIRoutes(r)
		})
	} else {
		a.addAPIRoutes(r)
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

	// Debug routes
	r.Route("/api/v1/debug", func(r chi.Router) {
		r.Get("/entries", a.handleGetDebugEntries)
		r.Get("/entries/last/{count}", a.handleGetLastDebugEntries)
		r.Delete("/entries", a.handleClearDebugEntries)
		r.Get("/errors", a.handleGetDebugErrors)
	})

	// Routes routes
	r.Route("/api/v1/routes", func(r chi.Router) {
		r.Get("/", a.handleGetRoutes)
		r.Get("/test", a.handleTestRoute)
	})

	// VPN routes
	r.Route("/api/v1/vpn", func(r chi.Router) {
		r.Get("/status", a.handleVPNStatus)
		r.Post("/enable", a.handleVPNEnable)
		r.Post("/disable", a.handleVPNDisable)
		r.Get("/connections", a.handleVPNConnections)

		// Split tunnel routes
		r.Route("/split", func(r chi.Router) {
			r.Get("/rules", a.handleVPNSplitRules)
			r.Post("/apps", a.handleVPNSplitAddApp)
			r.Delete("/apps/{name}", a.handleVPNSplitRemoveApp)
			r.Post("/domains", a.handleVPNSplitAddDomain)
			r.Post("/ips", a.handleVPNSplitAddIP)
		})

		// DNS routes
		r.Get("/dns/cache", a.handleVPNDNSCache)
	})
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Allow requests from localhost/127.0.0.1 on any port (for local web UI)
		// For same-origin requests, Origin header may be empty
		allowedOrigin := ""
		if origin == "" {
			// Same-origin request, no CORS headers needed
			allowedOrigin = ""
		} else if isLocalOrigin(origin) {
			allowedOrigin = origin
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLocalOrigin checks if the origin is from localhost or 127.0.0.1
func isLocalOrigin(origin string) bool {
	// Check common local origins
	localPrefixes := []string{
		"http://localhost",
		"https://localhost",
		"http://127.0.0.1",
		"https://127.0.0.1",
		"http://[::1]",
		"https://[::1]",
	}
	for _, prefix := range localPrefixes {
		if len(origin) >= len(prefix) && origin[:len(prefix)] == prefix {
			// Check that what follows is either empty, a colon (port), or a slash
			rest := origin[len(prefix):]
			if rest == "" || rest[0] == ':' || rest[0] == '/' {
				return true
			}
		}
	}
	return false
}

// securityHeadersMiddleware adds common security headers to all responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// XSS protection (legacy, but still useful)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content Security Policy for API responses
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		next.ServeHTTP(w, r)
	})
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	if a.serverConnected != nil && !a.serverConnected() {
		status = "degraded"
	}

	response := map[string]interface{}{
		"status": status,
		"time":   time.Now().Format(time.RFC3339),
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleVersion(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, version.GetInfo())
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	serverStatus := "disconnected"
	if a.serverConnected != nil && a.serverConnected() {
		serverStatus = "connected"
	}

	response := map[string]interface{}{
		"status":        "running",
		"server_status": serverStatus,
		"time":          time.Now().Format(time.RFC3339),
		"version":       version.Short(),
	}

	if a.debugger != nil {
		response["debug_entries"] = a.debugger.Count()
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleGetDebugEntries(w http.ResponseWriter, r *http.Request) {
	if a.debugger == nil {
		a.writeJSON(w, http.StatusOK, []debug.Entry{})
		return
	}

	entries := a.debugger.GetEntries()
	a.writeJSON(w, http.StatusOK, entries)
}

func (a *API) handleGetLastDebugEntries(w http.ResponseWriter, r *http.Request) {
	if a.debugger == nil {
		a.writeJSON(w, http.StatusOK, []debug.Entry{})
		return
	}

	// Parse count from URL
	countStr := chi.URLParam(r, "count")
	count := 100
	if countStr != "" {
		var n int
		_ = json.Unmarshal([]byte(countStr), &n)
		if n > 0 {
			count = n
		}
	}

	entries := a.debugger.GetLastEntries(count)
	a.writeJSON(w, http.StatusOK, entries)
}

func (a *API) handleClearDebugEntries(w http.ResponseWriter, r *http.Request) {
	if a.debugger != nil {
		a.debugger.Clear()
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"message": "cleared"})
}

func (a *API) handleGetDebugErrors(w http.ResponseWriter, r *http.Request) {
	if a.debugger == nil {
		a.writeJSON(w, http.StatusOK, []debug.Entry{})
		return
	}

	entries := a.debugger.FindErrors()
	a.writeJSON(w, http.StatusOK, entries)
}

func (a *API) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	if a.router == nil {
		a.writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	routes := a.router.Routes()
	response := make([]map[string]interface{}, 0, len(routes))

	for _, route := range routes {
		response = append(response, map[string]interface{}{
			"name":     route.Name,
			"patterns": route.Matcher.Patterns(),
			"action":   string(route.Action),
			"priority": route.Priority,
		})
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleTestRoute(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	action := "server"
	if a.router != nil {
		action = string(a.router.Match(domain))
	}

	response := map[string]interface{}{
		"domain": domain,
		"action": action,
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// VPN handlers

func (a *API) handleVPNStatus(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		a.writeJSON(w, http.StatusOK, vpn.VPNStats{Status: vpn.StatusDisabled})
		return
	}

	a.writeJSON(w, http.StatusOK, a.vpnManager.Status())
}

func (a *API) handleVPNEnable(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		http.Error(w, "VPN not configured", http.StatusBadRequest)
		return
	}

	if err := a.vpnManager.Start(context.Background()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (a *API) handleVPNDisable(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		http.Error(w, "VPN not configured", http.StatusBadRequest)
		return
	}

	if err := a.vpnManager.Stop(context.Background()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (a *API) handleVPNConnections(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		a.writeJSON(w, http.StatusOK, []vpn.ConnectionInfo{})
		return
	}

	a.writeJSON(w, http.StatusOK, a.vpnManager.Connections())
}

func (a *API) handleVPNSplitRules(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		a.writeJSON(w, http.StatusOK, vpn.SplitTunnelConfig{})
		return
	}

	a.writeJSON(w, http.StatusOK, a.vpnManager.SplitTunnelRules())
}

func (a *API) handleVPNSplitAddApp(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		http.Error(w, "VPN not configured", http.StatusBadRequest)
		return
	}

	var req struct {
		Name string `json:"name"`
		Path string `json:"path,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := a.vpnManager.AddSplitTunnelApp(vpn.AppRule{Name: req.Name, Path: req.Path}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

func (a *API) handleVPNSplitRemoveApp(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		http.Error(w, "VPN not configured", http.StatusBadRequest)
		return
	}

	name := chi.URLParam(r, "name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := a.vpnManager.RemoveSplitTunnelApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (a *API) handleVPNSplitAddDomain(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		http.Error(w, "VPN not configured", http.StatusBadRequest)
		return
	}

	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Pattern == "" {
		http.Error(w, "pattern is required", http.StatusBadRequest)
		return
	}

	if err := a.vpnManager.AddSplitTunnelDomain(req.Pattern); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

func (a *API) handleVPNSplitAddIP(w http.ResponseWriter, r *http.Request) {
	if a.vpnManager == nil {
		http.Error(w, "VPN not configured", http.StatusBadRequest)
		return
	}

	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.CIDR == "" {
		http.Error(w, "cidr is required", http.StatusBadRequest)
		return
	}

	if err := a.vpnManager.AddSplitTunnelIP(req.CIDR); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

func (a *API) handleVPNDNSCache(w http.ResponseWriter, r *http.Request) {
	// DNS cache is internal to VPN manager
	// Return empty for now - would need to expose from VPN manager
	a.writeJSON(w, http.StatusOK, []interface{}{})
}
