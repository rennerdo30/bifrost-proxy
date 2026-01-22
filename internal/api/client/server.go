// Package client provides the REST API for Bifrost client.
package client

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gopkg.in/yaml.v3"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/debug"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// VPNManager defines the interface for VPN management operations
type VPNManager interface {
	Status() vpn.VPNStats
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Connections() []vpn.ConnectionInfo
	SplitTunnelRules() vpn.SplitTunnelConfig
	AddSplitTunnelApp(app vpn.AppRule) error
	RemoveSplitTunnelApp(name string) error
	AddSplitTunnelDomain(pattern string) error
	AddSplitTunnelIP(cidr string) error
}

// ServerInfo represents a configured server.
type ServerInfo struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	IsDefault bool   `json:"is_default"`
	Latency   int    `json:"latency_ms,omitempty"`
	Status    string `json:"status"`
}

// QuickSettings represents settings accessible from the quick GUI.
type QuickSettings struct {
	AutoConnect       bool   `json:"auto_connect"`
	StartMinimized    bool   `json:"start_minimized"`
	ShowNotifications bool   `json:"show_notifications"`
	VPNEnabled        bool   `json:"vpn_enabled"`
	CurrentServer     string `json:"current_server"`
}

// ConfigUpdateResponse represents the response from a config update.
type ConfigUpdateResponse struct {
	Status          string   `json:"status"`
	RestartRequired bool     `json:"restart_required"`
	RestartFields   []string `json:"restart_fields,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// ConfigValidationResult represents the result of config validation.
type ConfigValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// restartRequiredFields contains field paths that require client restart when changed.
var restartRequiredFields = []string{
	"proxy.http.listen",
	"proxy.socks5.listen",
	"web_ui.listen",
	"api.listen",
	"vpn.enabled",
	"vpn.tun",
	"mesh.enabled",
	"mesh.device",
}

// API provides the REST API for Bifrost client.
type API struct {
	router          *router.ClientRouter
	debugger        *debug.Logger
	serverConnected func() bool
	token           string
	vpnManager      VPNManager
	configGetter    func() interface{}
	configUpdater   func(map[string]interface{}) error
	configReloader  func() error
	logSubscribers  map[chan LogEntry]struct{}
	logMu           sync.RWMutex

	// Additional fields for desktop app support
	serverAddress   string
	httpProxyAddr   string
	socks5ProxyAddr string
	startTime       time.Time
	connector       func() error
	disconnector    func() error
	serversGetter   func() []ServerInfo
	serverSelector  func(string) error
	settingsGetter  func() *QuickSettings
	settingsUpdater func(*QuickSettings) error
	bytesSent       func() int64
	bytesReceived   func() int64
	activeConns     func() int
}

// LogEntry represents a log entry for streaming.
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Config holds API configuration.
type Config struct {
	Router          *router.ClientRouter
	Debugger        *debug.Logger
	ServerConnected func() bool
	Token           string
	VPNManager      VPNManager
	ConfigGetter    func() interface{}
	ConfigUpdater   func(map[string]interface{}) error
	ConfigReloader  func() error

	// Additional fields for desktop app support
	ServerAddress   string
	HTTPProxyAddr   string
	SOCKS5ProxyAddr string
	Connector       func() error
	Disconnector    func() error
	ServersGetter   func() []ServerInfo
	ServerSelector  func(string) error
	SettingsGetter  func() *QuickSettings
	SettingsUpdater func(*QuickSettings) error
	BytesSent       func() int64
	BytesReceived   func() int64
	ActiveConns     func() int
}

// New creates a new API server.
func New(cfg Config) *API {
	return &API{
		router:          cfg.Router,
		debugger:        cfg.Debugger,
		serverConnected: cfg.ServerConnected,
		token:           cfg.Token,
		vpnManager:      cfg.VPNManager,
		configGetter:    cfg.ConfigGetter,
		configUpdater:   cfg.ConfigUpdater,
		configReloader:  cfg.ConfigReloader,
		logSubscribers:  make(map[chan LogEntry]struct{}),
		serverAddress:   cfg.ServerAddress,
		httpProxyAddr:   cfg.HTTPProxyAddr,
		socks5ProxyAddr: cfg.SOCKS5ProxyAddr,
		startTime:       time.Now(),
		connector:       cfg.Connector,
		disconnector:    cfg.Disconnector,
		serversGetter:   cfg.ServersGetter,
		serverSelector:  cfg.ServerSelector,
		settingsGetter:  cfg.SettingsGetter,
		settingsUpdater: cfg.SettingsUpdater,
		bytesSent:       cfg.BytesSent,
		bytesReceived:   cfg.BytesReceived,
		activeConns:     cfg.ActiveConns,
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

	// CORS for local development
	r.Use(corsMiddleware)

	// API routes with security headers
	r.Route("/api", func(r chi.Router) {
		r.Use(apiSecurityHeaders)
		if a.token != "" {
			r.Use(a.authMiddleware)
		}
		r.Get("/v1/health", a.handleHealth)
		r.Get("/v1/version", a.handleVersion)
		r.Get("/v1/status", a.handleStatus)
		r.Post("/v1/connect", a.handleConnect)
		r.Post("/v1/disconnect", a.handleDisconnect)
		r.Get("/v1/servers", a.handleGetServers)
		r.Post("/v1/server/select", a.handleSelectServer)
		r.Get("/v1/settings", a.handleGetSettings)
		r.Post("/v1/settings", a.handleUpdateSettings)
		r.Route("/v1/config", func(r chi.Router) {
			r.Get("/", a.handleGetConfig)
			r.Put("/", a.handleUpdateConfig)
			r.Post("/reload", a.handleReloadConfig)
			r.Post("/validate", a.handleValidateConfig)
			r.Get("/defaults", a.handleGetConfigDefaults)
			r.Post("/export", a.handleExportConfig)
			r.Post("/import", a.handleImportConfig)
		})
		r.Route("/v1/logs", func(r chi.Router) {
			r.Get("/", a.handleGetLogs)
			r.Get("/stream", a.handleLogStream)
		})
		r.Route("/v1/debug", func(r chi.Router) {
			r.Get("/entries", a.handleGetDebugEntries)
			r.Get("/entries/last/{count}", a.handleGetLastDebugEntries)
			r.Delete("/entries", a.handleClearDebugEntries)
			r.Get("/errors", a.handleGetDebugErrors)
		})
		r.Route("/v1/routes", func(r chi.Router) {
			r.Get("/", a.handleGetRoutes)
			r.Get("/test", a.handleTestRoute)
		})
		r.Route("/v1/vpn", func(r chi.Router) {
			r.Get("/status", a.handleVPNStatus)
			r.Post("/enable", a.handleVPNEnable)
			r.Post("/disable", a.handleVPNDisable)
			r.Get("/connections", a.handleVPNConnections)
			r.Route("/split", func(r chi.Router) {
				r.Get("/rules", a.handleVPNSplitRules)
				r.Post("/apps", a.handleVPNSplitAddApp)
				r.Delete("/apps/{name}", a.handleVPNSplitRemoveApp)
				r.Post("/domains", a.handleVPNSplitAddDomain)
				r.Post("/ips", a.handleVPNSplitAddIP)
			})
			r.Get("/dns/cache", a.handleVPNDNSCache)
		})
	})

	// Static files for Web UI - serve everything else
	// Use Mount to properly handle all non-API routes
	r.Mount("/", StaticHandler())

	return r
}

// apiSecurityHeaders adds security headers for API responses only.
func apiSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// addAPIRoutes adds all API routes to the router.
func (a *API) addAPIRoutes(r chi.Router) {
	r.Get("/api/v1/health", a.handleHealth)
	r.Get("/api/v1/version", a.handleVersion)
	r.Get("/api/v1/status", a.handleStatus)

	// Connection routes for desktop app
	r.Post("/api/v1/connect", a.handleConnect)
	r.Post("/api/v1/disconnect", a.handleDisconnect)

	// Server management routes for desktop app
	r.Get("/api/v1/servers", a.handleGetServers)
	r.Post("/api/v1/server/select", a.handleSelectServer)

	// Quick settings routes for desktop app
	r.Get("/api/v1/settings", a.handleGetSettings)
	r.Post("/api/v1/settings", a.handleUpdateSettings)

	// Config routes
	r.Route("/api/v1/config", func(r chi.Router) {
		r.Get("/", a.handleGetConfig)
		r.Put("/", a.handleUpdateConfig)
		r.Post("/reload", a.handleReloadConfig)
		r.Post("/validate", a.handleValidateConfig)
		r.Get("/defaults", a.handleGetConfigDefaults)
		r.Post("/export", a.handleExportConfig)
		r.Post("/import", a.handleImportConfig)
	})

	// Log routes
	r.Route("/api/v1/logs", func(r chi.Router) {
		r.Get("/", a.handleGetLogs)
		r.Get("/stream", a.handleLogStream)
	})

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

		// Remove "Bearer " prefix if present (case-insensitive)
		if len(token) > 7 && strings.EqualFold(token[:7], "Bearer ") {
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
	serverConnected := false
	if a.serverConnected != nil && a.serverConnected() {
		serverConnected = true
	}

	// Calculate uptime
	uptime := time.Since(a.startTime).Round(time.Second).String()

	// Get VPN status
	vpnEnabled := false
	vpnStatus := "disabled"
	if a.vpnManager != nil {
		stats := a.vpnManager.Status()
		vpnEnabled = stats.Status == vpn.StatusConnected
		vpnStatus = string(stats.Status)
	}

	// Get debug entries count
	debugEntries := 0
	if a.debugger != nil {
		debugEntries = a.debugger.Count()
	}

	// Get bytes transferred and active connections
	var bytesSent, bytesReceived int64
	var activeConns int
	if a.bytesSent != nil {
		bytesSent = a.bytesSent()
	}
	if a.bytesReceived != nil {
		bytesReceived = a.bytesReceived()
	}
	if a.activeConns != nil {
		activeConns = a.activeConns()
	}

	response := map[string]interface{}{
		"status":             "running",
		"version":            version.Short(),
		"server_connected":   serverConnected,
		"server_address":     a.serverAddress,
		"http_proxy":         a.httpProxyAddr,
		"socks5_proxy":       a.socks5ProxyAddr,
		"vpn_enabled":        vpnEnabled,
		"vpn_status":         vpnStatus,
		"debug_entries":      debugEntries,
		"uptime":             uptime,
		"bytes_sent":         bytesSent,
		"bytes_received":     bytesReceived,
		"active_connections": activeConns,
		"timestamp":          time.Now().Format(time.RFC3339),
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
	buf, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	w.Write(buf)
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

// Config handlers

func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if a.configGetter == nil {
		http.Error(w, "config not available", http.StatusServiceUnavailable)
		return
	}

	config := a.configGetter()
	a.writeJSON(w, http.StatusOK, config)
}

func (a *API) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if a.configUpdater == nil {
		http.Error(w, "config updates not supported", http.StatusServiceUnavailable)
		return
	}

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := a.configUpdater(updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check which fields require restart
	restartFields := a.checkRestartRequired(updates)

	response := ConfigUpdateResponse{
		Status:          "updated",
		RestartRequired: len(restartFields) > 0,
		RestartFields:   restartFields,
	}

	a.writeJSON(w, http.StatusOK, response)
}

// checkRestartRequired checks which updated fields require a restart.
func (a *API) checkRestartRequired(updates map[string]interface{}) []string {
	var restartFields []string

	// Flatten the updates to dot notation paths
	paths := flattenMap(updates, "")

	for _, path := range paths {
		for _, field := range restartRequiredFields {
			if strings.HasPrefix(path, field) {
				restartFields = append(restartFields, path)
				break
			}
		}
	}

	return restartFields
}

// flattenMap flattens a nested map to dot-notation paths.
func flattenMap(m map[string]interface{}, prefix string) []string {
	var paths []string

	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		switch val := v.(type) {
		case map[string]interface{}:
			paths = append(paths, flattenMap(val, path)...)
		default:
			paths = append(paths, path)
		}
	}

	return paths
}

func (a *API) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result := ConfigValidationResult{
		Valid: true,
	}

	// Get current config and merge updates
	if a.configGetter != nil {
		currentConfig := a.configGetter()

		// Convert current config to map
		configBytes, err := json.Marshal(currentConfig)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, "failed to read current config")
			a.writeJSON(w, http.StatusOK, result)
			return
		}

		var configMap map[string]interface{}
		if err := json.Unmarshal(configBytes, &configMap); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, "failed to parse current config")
			a.writeJSON(w, http.StatusOK, result)
			return
		}

		// Merge updates into config
		mergeMap(configMap, updates)

		// Convert back to ClientConfig and validate
		mergedBytes, err := json.Marshal(configMap)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, "failed to serialize merged config")
			a.writeJSON(w, http.StatusOK, result)
			return
		}

		var cfg config.ClientConfig
		if err := json.Unmarshal(mergedBytes, &cfg); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, "invalid config format: "+err.Error())
			a.writeJSON(w, http.StatusOK, result)
			return
		}

		if err := cfg.Validate(); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Check for restart-required fields
	restartFields := a.checkRestartRequired(updates)
	if len(restartFields) > 0 {
		result.Warnings = append(result.Warnings, "Changes to these fields require client restart: "+strings.Join(restartFields, ", "))
	}

	a.writeJSON(w, http.StatusOK, result)
}

// mergeMap merges src into dst recursively.
func mergeMap(dst, src map[string]interface{}) {
	for k, v := range src {
		if srcMap, ok := v.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				mergeMap(dstMap, srcMap)
				continue
			}
		}
		dst[k] = v
	}
}

func (a *API) handleGetConfigDefaults(w http.ResponseWriter, r *http.Request) {
	defaults := config.DefaultClientConfig()
	a.writeJSON(w, http.StatusOK, defaults)
}

func (a *API) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	if a.configGetter == nil {
		http.Error(w, "config not available", http.StatusServiceUnavailable)
		return
	}

	// Get format from query parameter (default: yaml)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "yaml"
	}

	cfg := a.configGetter()

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=bifrost-client-config.json")
		json.NewEncoder(w).Encode(cfg)
	case "yaml":
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", "attachment; filename=bifrost-client-config.yaml")
		yaml.NewEncoder(w).Encode(cfg)
	default:
		http.Error(w, "unsupported format, use 'json' or 'yaml'", http.StatusBadRequest)
	}
}

func (a *API) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	if a.configUpdater == nil {
		http.Error(w, "config updates not supported", http.StatusServiceUnavailable)
		return
	}

	// Get format from query parameter or content-type
	format := r.URL.Query().Get("format")
	if format == "" {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "yaml") {
			format = "yaml"
		} else {
			format = "json"
		}
	}

	var cfg config.ClientConfig
	var err error

	switch format {
	case "yaml":
		err = yaml.NewDecoder(r.Body).Decode(&cfg)
	case "json":
		err = json.NewDecoder(r.Body).Decode(&cfg)
	default:
		http.Error(w, "unsupported format", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "failed to parse config: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate the imported config
	if err := cfg.Validate(); err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Convert to map and update
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		http.Error(w, "failed to process config", http.StatusInternalServerError)
		return
	}

	var updates map[string]interface{}
	if err := json.Unmarshal(cfgBytes, &updates); err != nil {
		http.Error(w, "failed to process config", http.StatusInternalServerError)
		return
	}

	if err := a.configUpdater(updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check restart requirements
	restartFields := a.checkRestartRequired(updates)

	response := ConfigUpdateResponse{
		Status:          "imported",
		RestartRequired: len(restartFields) > 0,
		RestartFields:   restartFields,
	}

	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if a.configReloader == nil {
		http.Error(w, "config reload not supported", http.StatusServiceUnavailable)
		return
	}

	if err := a.configReloader(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

// Log handlers

func (a *API) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	level := r.URL.Query().Get("level")

	limit := 100
	offset := 0

	if limitStr != "" {
		if l, err := json.Number(limitStr).Int64(); err == nil && l > 0 {
			limit = int(l)
		}
	}
	if offsetStr != "" {
		if o, err := json.Number(offsetStr).Int64(); err == nil && o >= 0 {
			offset = int(o)
		}
	}

	// Get logs from debugger if available (for now return debug entries as logs)
	entries := []LogEntry{}
	if a.debugger != nil {
		debugEntries := a.debugger.GetLastEntries(limit + offset)
		startIdx := offset
		if startIdx > len(debugEntries) {
			startIdx = len(debugEntries)
		}
		endIdx := offset + limit
		if endIdx > len(debugEntries) {
			endIdx = len(debugEntries)
		}

		for _, entry := range debugEntries[startIdx:endIdx] {
			logLevel := "info"
			if entry.Error != "" {
				logLevel = "error"
			}

			if level != "" && level != logLevel {
				continue
			}

			url := entry.Host + entry.Path
			entries = append(entries, LogEntry{
				Timestamp: entry.Timestamp.Format(time.RFC3339),
				Level:     logLevel,
				Message:   entry.Method + " " + url,
				Fields: map[string]interface{}{
					"method":      entry.Method,
					"url":         url,
					"status_code": entry.StatusCode,
					"duration_ms": entry.Duration.Milliseconds(),
					"action":      entry.Action,
					"error":       entry.Error,
				},
			})
		}
	}

	response := map[string]interface{}{
		"entries": entries,
		"total":   len(entries),
		"limit":   limit,
		"offset":  offset,
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) handleLogStream(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Create a channel for this subscriber
	ch := make(chan LogEntry, 100)

	// Register subscriber
	a.logMu.Lock()
	a.logSubscribers[ch] = struct{}{}
	a.logMu.Unlock()

	defer func() {
		a.logMu.Lock()
		delete(a.logSubscribers, ch)
		a.logMu.Unlock()
		close(ch)
	}()

	// Get flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send initial connection message
	data, _ := json.Marshal(map[string]string{"type": "connected"})
	w.Write([]byte("data: " + string(data) + "\n\n"))
	flusher.Flush()

	// Stream logs
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			w.Write([]byte("data: " + string(data) + "\n\n"))
			flusher.Flush()
		}
	}
}

// BroadcastLog sends a log entry to all connected SSE clients.
func (a *API) BroadcastLog(entry LogEntry) {
	a.logMu.RLock()
	defer a.logMu.RUnlock()

	for ch := range a.logSubscribers {
		select {
		case ch <- entry:
		default:
			// Drop if channel is full
		}
	}
}

// Desktop app handlers

func (a *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	if a.connector == nil {
		// No connector configured, return success (already connected or no-op)
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "connected"})
		return
	}

	if err := a.connector(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "connected"})
}

func (a *API) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if a.disconnector == nil {
		// No disconnector configured, return success (already disconnected or no-op)
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
		return
	}

	if err := a.disconnector(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

func (a *API) handleGetServers(w http.ResponseWriter, r *http.Request) {
	if a.serversGetter == nil {
		// Return empty list if no getter configured
		a.writeJSON(w, http.StatusOK, []ServerInfo{})
		return
	}

	servers := a.serversGetter()
	if servers == nil {
		servers = []ServerInfo{}
	}
	a.writeJSON(w, http.StatusOK, servers)
}

func (a *API) handleSelectServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Server == "" {
		http.Error(w, "server name is required", http.StatusBadRequest)
		return
	}

	if a.serverSelector == nil {
		// No selector configured, acknowledge the request but do nothing
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "selected", "server": req.Server})
		return
	}

	if err := a.serverSelector(req.Server); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "selected", "server": req.Server})
}

func (a *API) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if a.settingsGetter == nil {
		// Return default settings if no getter configured
		vpnEnabled := false
		if a.vpnManager != nil {
			vpnEnabled = a.vpnManager.Status().Status == vpn.StatusConnected
		}
		settings := &QuickSettings{
			AutoConnect:       false,
			StartMinimized:    false,
			ShowNotifications: true,
			VPNEnabled:        vpnEnabled,
			CurrentServer:     "",
		}
		a.writeJSON(w, http.StatusOK, settings)
		return
	}

	settings := a.settingsGetter()
	if settings == nil {
		settings = &QuickSettings{}
	}
	a.writeJSON(w, http.StatusOK, settings)
}

func (a *API) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var settings QuickSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if a.settingsUpdater != nil {
		if err := a.settingsUpdater(&settings); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Handle VPN enable/disable if VPN manager is configured
	if a.vpnManager != nil {
		currentStatus := a.vpnManager.Status().Status == vpn.StatusConnected
		if settings.VPNEnabled && !currentStatus {
			if err := a.vpnManager.Start(context.Background()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if !settings.VPNEnabled && currentStatus {
			if err := a.vpnManager.Stop(context.Background()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	a.writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
