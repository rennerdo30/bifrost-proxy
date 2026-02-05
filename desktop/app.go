// Package main contains the Wails application bindings for Bifrost Quick Access.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// App struct holds the application state and provides methods
// that are exposed to the frontend via Wails bindings.
type App struct {
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	preferences *Preferences
	startTime   time.Time

	// Embedded client
	client     *client.Client
	clientCfg  *config.ClientConfig
	configPath string
}

// StatusResponse represents the client status from the API.
type StatusResponse struct {
	Status          string    `json:"status"`
	Version         string    `json:"version"`
	ServerConnected bool      `json:"server_connected"`
	ServerAddress   string    `json:"server_address"`
	HTTPProxy       string    `json:"http_proxy"`
	SOCKS5Proxy     string    `json:"socks5_proxy"`
	VPNEnabled      bool      `json:"vpn_enabled"`
	VPNStatus       string    `json:"vpn_status"`
	DebugEntries    int       `json:"debug_entries"`
	Uptime          string    `json:"uptime"`
	BytesSent       int64     `json:"bytes_sent"`
	BytesReceived   int64     `json:"bytes_received"`
	ActiveConns     int       `json:"active_connections"`
	LastError       string    `json:"last_error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// ServerInfo represents a configured server.
type ServerInfo struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	IsDefault bool   `json:"is_default"`
	Latency   int    `json:"latency_ms,omitempty"`
	Status    string `json:"status"`
}

// ServerConfig represents server configuration for add/edit operations.
type ServerConfig struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	IsDefault bool   `json:"is_default,omitempty"`
}

// Preferences stores user preferences for the quick access GUI.
type Preferences struct {
	AutoConnect       bool   `json:"auto_connect"`
	StartMinimized    bool   `json:"start_minimized"`
	ShowNotifications bool   `json:"show_notifications"`
	DefaultServer     string `json:"default_server"`
	WindowX           int    `json:"window_x"`
	WindowY           int    `json:"window_y"`
}

// QuickSettings represents settings accessible from the quick GUI.
type QuickSettings struct {
	AutoConnect       bool   `json:"auto_connect"`
	StartMinimized    bool   `json:"start_minimized"`
	ShowNotifications bool   `json:"show_notifications"`
	VPNEnabled        bool   `json:"vpn_enabled"`
	CurrentServer     string `json:"current_server"`
}

// ProxySettings represents configurable proxy settings for the desktop app.
type ProxySettings struct {
	ServerAddress   string `json:"server_address"`
	ServerProtocol  string `json:"server_protocol"`
	HTTPProxyPort   int    `json:"http_proxy_port"`
	SOCKS5ProxyPort int    `json:"socks5_proxy_port"`
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{
		preferences: &Preferences{
			AutoConnect:       false,
			StartMinimized:    false,
			ShowNotifications: true,
		},
		startTime: time.Now(),
	}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.loadPreferences()

	slog.Info("bifrost quick access starting")

	// Load and start the embedded client
	if err := a.initClient(); err != nil {
		slog.Error("failed to initialize client", "error", err)
		// Continue anyway - user can configure via settings
	}

	slog.Info("bifrost quick access started")
}

// shutdown is called when the app terminates.
func (a *App) shutdown(ctx context.Context) {
	a.savePreferences()

	// Stop the embedded client
	if a.client != nil {
		if err := a.client.Stop(ctx); err != nil {
			slog.Error("failed to stop client", "error", err)
		}
	}

	if a.cancel != nil {
		a.cancel()
	}

	slog.Info("bifrost quick access shutdown")
}

// initClient initializes and starts the embedded proxy client.
func (a *App) initClient() error {
	// Find config file
	configPath := a.findConfigFile()
	if configPath == "" {
		// Create default config if none exists
		configPath = a.createDefaultConfig()
	}
	a.configPath = configPath
	slog.Info("using config file", "path", configPath)

	if configPath == "" {
		return fmt.Errorf("no config file found and could not create default")
	}

	// Load config
	cfg := config.DefaultClientConfig()
	if err := config.LoadAndValidate(configPath, &cfg); err != nil {
		slog.Warn("failed to load config file, using defaults", "error", err)
		cfg = config.DefaultClientConfig()
	}

	// Ensure API server is enabled for the desktop app
	cfg.API.Enabled = true
	if cfg.API.Listen == "" {
		cfg.API.Listen = "127.0.0.1:7383"
	}

	a.clientCfg = &cfg

	slog.Info("client config loaded",
		"api_enabled", cfg.API.Enabled,
		"api_listen", cfg.API.Listen,
		"http_proxy", cfg.Proxy.HTTP.Listen,
		"socks5_proxy", cfg.Proxy.SOCKS5.Listen,
	)

	// Create client
	c, err := client.New(a.clientCfg)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	a.client = c

	// Set config path so the embedded client can save config changes
	c.SetConfigPath(a.configPath)

	// Start client
	if err := c.Start(a.ctx); err != nil {
		return fmt.Errorf("start client: %w", err)
	}

	slog.Info("embedded proxy client started",
		"http_proxy", a.clientCfg.Proxy.HTTP.Listen,
		"socks5_proxy", a.clientCfg.Proxy.SOCKS5.Listen,
		"api", a.clientCfg.API.Listen,
	)

	return nil
}

// findConfigFile looks for a config file in standard locations.
func (a *App) findConfigFile() string {
	// Check common locations
	locations := []string{
		"client-config.yaml",
		"bifrost-client.yaml",
	}

	// Add user config dir
	if configDir, err := os.UserConfigDir(); err == nil {
		locations = append(locations,
			filepath.Join(configDir, "bifrost", "client-config.yaml"),
			filepath.Join(configDir, "bifrost", "config.yaml"),
		)
	}

	// Add home dir
	if homeDir, err := os.UserHomeDir(); err == nil {
		locations = append(locations,
			filepath.Join(homeDir, ".bifrost", "client-config.yaml"),
			filepath.Join(homeDir, ".config", "bifrost", "client-config.yaml"),
		)
	}

	for _, path := range locations {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// createDefaultConfig creates a default config file.
func (a *App) createDefaultConfig() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}

	bifrostDir := filepath.Join(configDir, "bifrost")
	if err := os.MkdirAll(bifrostDir, 0700); err != nil {
		slog.Warn("failed to create config dir", "error", err)
		return ""
	}

	configPath := filepath.Join(bifrostDir, "client-config.yaml")

	// Create default config
	defaultCfg := config.DefaultClientConfig()

	// Save it
	if err := config.Save(configPath, &defaultCfg); err != nil {
		slog.Warn("failed to save default config", "error", err)
		return ""
	}

	slog.Info("created default config", "path", configPath)
	return configPath
}

// Connect establishes connection to the Bifrost server.
func (a *App) Connect() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.client == nil {
		return fmt.Errorf("client not initialized")
	}

	// The client automatically maintains server connection
	// Just verify it's running
	if !a.client.Running() {
		if err := a.client.Start(a.ctx); err != nil {
			return fmt.Errorf("failed to start client: %w", err)
		}
	}

	slog.Info("connected to server")
	return nil
}

// Disconnect disconnects from the Bifrost server.
func (a *App) Disconnect() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.client == nil {
		return nil
	}

	if err := a.client.Stop(a.ctx); err != nil {
		return fmt.Errorf("failed to stop client: %w", err)
	}

	slog.Info("disconnected from server")
	return nil
}

// GetStatus returns the current connection status.
func (a *App) GetStatus() (*StatusResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := &StatusResponse{
		Status:    "running",
		Version:   version.Short(),
		Timestamp: time.Now(),
		Uptime:    time.Since(a.startTime).Round(time.Second).String(),
	}

	if a.client == nil {
		status.Status = "not_initialized"
		status.LastError = "client not initialized"
		return status, nil
	}

	if !a.client.Running() {
		status.Status = "stopped"
		return status, nil
	}

	// Get config info
	if a.clientCfg != nil {
		status.HTTPProxy = a.clientCfg.Proxy.HTTP.Listen
		status.SOCKS5Proxy = a.clientCfg.Proxy.SOCKS5.Listen
		status.ServerAddress = a.clientCfg.Server.Address
		status.ServerConnected = a.clientCfg.Server.Address != ""
	}

	// Get VPN status
	if vpnMgr := a.client.VPNManager(); vpnMgr != nil {
		vpnStatus := vpnMgr.Status()
		status.VPNEnabled = vpnStatus.Status == vpn.StatusConnected
		status.VPNStatus = string(vpnStatus.Status)
	} else {
		status.VPNStatus = "disabled"
	}

	// Get debug entries count
	entries := a.client.GetDebugEntries()
	status.DebugEntries = len(entries)

	return status, nil
}

// GetServers returns the list of configured servers.
func (a *App) GetServers() ([]ServerInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	servers := []ServerInfo{}

	if a.clientCfg == nil {
		return servers, nil
	}

	// Get the currently active server address
	activeAddress := a.clientCfg.Server.Address

	// Return servers from the Servers slice
	if len(a.clientCfg.Servers) > 0 {
		for _, s := range a.clientCfg.Servers {
			status := "available"
			// Check if this is the active server
			if s.Address == activeAddress && a.client != nil && a.client.Running() {
				status = "connected"
			}

			servers = append(servers, ServerInfo{
				Name:      s.Name,
				Address:   s.Address,
				Protocol:  s.Protocol,
				Username:  s.Username,
				Password:  s.Password,
				IsDefault: s.IsDefault,
				Status:    status,
			})
		}
	} else if a.clientCfg.Server.Address != "" {
		// Backwards compatibility: if no named servers but Server is configured
		status := "available"
		if a.client != nil && a.client.Running() {
			status = "connected"
		}

		servers = append(servers, ServerInfo{
			Name:      "Default Server",
			Address:   a.clientCfg.Server.Address,
			Protocol:  a.clientCfg.Server.Protocol,
			Username:  a.clientCfg.Server.Username,
			Password:  a.clientCfg.Server.Password,
			IsDefault: true,
			Status:    status,
		})
	}

	return servers, nil
}

// SelectServer selects a server to connect to.
func (a *App) SelectServer(serverName string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.clientCfg == nil {
		return fmt.Errorf("config not loaded")
	}

	// Find the server by name
	var selectedServer *config.NamedServer
	for i := range a.clientCfg.Servers {
		if a.clientCfg.Servers[i].Name == serverName {
			selectedServer = &a.clientCfg.Servers[i]
			break
		}
	}

	if selectedServer == nil {
		// Check legacy Server field for backwards compatibility
		if a.clientCfg.Server.Address != "" && serverName == "Default Server" {
			// Already using the default server
			a.preferences.DefaultServer = serverName
			return nil
		}
		return fmt.Errorf("server not found: %s", serverName)
	}

	// Update the active Server connection with the selected server's settings
	a.clientCfg.Server.Address = selectedServer.Address
	a.clientCfg.Server.Protocol = selectedServer.Protocol
	a.clientCfg.Server.Username = selectedServer.Username
	a.clientCfg.Server.Password = selectedServer.Password

	// Update preferences
	a.preferences.DefaultServer = serverName

	// Save config
	if a.configPath != "" {
		if err := config.Save(a.configPath, a.clientCfg); err != nil {
			slog.Error("failed to save config after server selection", "error", err)
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	slog.Info("selected server", "server", serverName, "address", selectedServer.Address)
	return nil
}

// AddServer adds a new server to the configuration.
func (a *App) AddServer(server *ServerConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.clientCfg == nil {
		return fmt.Errorf("config not loaded")
	}

	if server.Name == "" {
		return fmt.Errorf("server name is required")
	}

	if server.Address == "" {
		return fmt.Errorf("server address is required")
	}

	// Check for duplicate names
	for _, s := range a.clientCfg.Servers {
		if s.Name == server.Name {
			return fmt.Errorf("server with name '%s' already exists", server.Name)
		}
	}

	// Set default protocol if not specified
	protocol := server.Protocol
	if protocol == "" {
		protocol = "http"
	}

	// If this is set as default, clear default flag from other servers
	if server.IsDefault {
		for i := range a.clientCfg.Servers {
			a.clientCfg.Servers[i].IsDefault = false
		}
	}

	// If this is the first server, make it the default
	if len(a.clientCfg.Servers) == 0 {
		server.IsDefault = true
	}

	newServer := config.NamedServer{
		Name:      server.Name,
		Address:   server.Address,
		Protocol:  protocol,
		Username:  server.Username,
		Password:  server.Password,
		IsDefault: server.IsDefault,
	}

	a.clientCfg.Servers = append(a.clientCfg.Servers, newServer)

	// If this is the default server, also set it as the active server
	if server.IsDefault {
		a.clientCfg.Server.Address = newServer.Address
		a.clientCfg.Server.Protocol = newServer.Protocol
		a.clientCfg.Server.Username = newServer.Username
		a.clientCfg.Server.Password = newServer.Password
		a.preferences.DefaultServer = server.Name
	}

	// Save config
	if a.configPath != "" {
		if err := config.Save(a.configPath, a.clientCfg); err != nil {
			slog.Error("failed to save config after adding server", "error", err)
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	slog.Info("added server", "name", server.Name, "address", server.Address)
	return nil
}

// UpdateServer updates an existing server configuration.
func (a *App) UpdateServer(originalName string, server *ServerConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.clientCfg == nil {
		return fmt.Errorf("config not loaded")
	}

	if server.Name == "" {
		return fmt.Errorf("server name is required")
	}

	if server.Address == "" {
		return fmt.Errorf("server address is required")
	}

	// Find the server by original name
	var serverIndex = -1
	for i := range a.clientCfg.Servers {
		if a.clientCfg.Servers[i].Name == originalName {
			serverIndex = i
			break
		}
	}

	if serverIndex == -1 {
		return fmt.Errorf("server not found: %s", originalName)
	}

	// If renaming, check for duplicate names
	if server.Name != originalName {
		for _, s := range a.clientCfg.Servers {
			if s.Name == server.Name {
				return fmt.Errorf("server with name '%s' already exists", server.Name)
			}
		}
	}

	// Set default protocol if not specified
	protocol := server.Protocol
	if protocol == "" {
		protocol = "http"
	}

	// If this is set as default, clear default flag from other servers
	if server.IsDefault {
		for i := range a.clientCfg.Servers {
			a.clientCfg.Servers[i].IsDefault = false
		}
	}

	// Update the server
	a.clientCfg.Servers[serverIndex] = config.NamedServer{
		Name:      server.Name,
		Address:   server.Address,
		Protocol:  protocol,
		Username:  server.Username,
		Password:  server.Password,
		IsDefault: server.IsDefault,
	}

	// If this is the default server or was the active server, update the active connection
	if server.IsDefault || a.clientCfg.Server.Address == a.clientCfg.Servers[serverIndex].Address {
		a.clientCfg.Server.Address = server.Address
		a.clientCfg.Server.Protocol = protocol
		a.clientCfg.Server.Username = server.Username
		a.clientCfg.Server.Password = server.Password
		a.preferences.DefaultServer = server.Name
	}

	// Save config
	if a.configPath != "" {
		if err := config.Save(a.configPath, a.clientCfg); err != nil {
			slog.Error("failed to save config after updating server", "error", err)
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	slog.Info("updated server", "original_name", originalName, "new_name", server.Name)
	return nil
}

// DeleteServer removes a server from the configuration.
func (a *App) DeleteServer(serverName string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.clientCfg == nil {
		return fmt.Errorf("config not loaded")
	}

	// Find the server by name
	var serverIndex = -1
	var wasDefault bool
	var wasActive bool
	for i := range a.clientCfg.Servers {
		if a.clientCfg.Servers[i].Name == serverName {
			serverIndex = i
			wasDefault = a.clientCfg.Servers[i].IsDefault
			wasActive = a.clientCfg.Servers[i].Address == a.clientCfg.Server.Address
			break
		}
	}

	if serverIndex == -1 {
		return fmt.Errorf("server not found: %s", serverName)
	}

	// Remove the server
	a.clientCfg.Servers = append(a.clientCfg.Servers[:serverIndex], a.clientCfg.Servers[serverIndex+1:]...)

	// If the deleted server was the default or active, select a new default
	if (wasDefault || wasActive) && len(a.clientCfg.Servers) > 0 {
		// Set the first server as the new default
		a.clientCfg.Servers[0].IsDefault = true
		a.clientCfg.Server.Address = a.clientCfg.Servers[0].Address
		a.clientCfg.Server.Protocol = a.clientCfg.Servers[0].Protocol
		a.clientCfg.Server.Username = a.clientCfg.Servers[0].Username
		a.clientCfg.Server.Password = a.clientCfg.Servers[0].Password
		a.preferences.DefaultServer = a.clientCfg.Servers[0].Name
	} else if len(a.clientCfg.Servers) == 0 {
		// No servers left, clear the active connection
		a.clientCfg.Server.Address = ""
		a.clientCfg.Server.Protocol = "http"
		a.clientCfg.Server.Username = ""
		a.clientCfg.Server.Password = ""
		a.preferences.DefaultServer = ""
	}

	// Save config
	if a.configPath != "" {
		if err := config.Save(a.configPath, a.clientCfg); err != nil {
			slog.Error("failed to save config after deleting server", "error", err)
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	slog.Info("deleted server", "name", serverName)
	return nil
}

// SetDefaultServer sets a server as the default.
func (a *App) SetDefaultServer(serverName string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.clientCfg == nil {
		return fmt.Errorf("config not loaded")
	}

	// Find the server by name
	var found bool
	for i := range a.clientCfg.Servers {
		if a.clientCfg.Servers[i].Name == serverName {
			a.clientCfg.Servers[i].IsDefault = true
			found = true
		} else {
			a.clientCfg.Servers[i].IsDefault = false
		}
	}

	if !found {
		return fmt.Errorf("server not found: %s", serverName)
	}

	// Save config
	if a.configPath != "" {
		if err := config.Save(a.configPath, a.clientCfg); err != nil {
			slog.Error("failed to save config after setting default server", "error", err)
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	slog.Info("set default server", "name", serverName)
	return nil
}

// GetQuickSettings returns the current quick settings.
func (a *App) GetQuickSettings() (*QuickSettings, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	vpnEnabled := false
	if a.client != nil {
		if vpnMgr := a.client.VPNManager(); vpnMgr != nil {
			vpnEnabled = vpnMgr.Status().Status == vpn.StatusConnected
		}
	}

	return &QuickSettings{
		AutoConnect:       a.preferences.AutoConnect,
		StartMinimized:    a.preferences.StartMinimized,
		ShowNotifications: a.preferences.ShowNotifications,
		VPNEnabled:        vpnEnabled,
		CurrentServer:     a.preferences.DefaultServer,
	}, nil
}

// UpdateQuickSettings updates the quick settings.
func (a *App) UpdateQuickSettings(settings *QuickSettings) error {
	a.mu.Lock()
	a.preferences.AutoConnect = settings.AutoConnect
	a.preferences.StartMinimized = settings.StartMinimized
	a.preferences.ShowNotifications = settings.ShowNotifications
	a.preferences.DefaultServer = settings.CurrentServer
	a.mu.Unlock()

	a.savePreferences()

	// Update VPN state if changed
	if settings.VPNEnabled {
		return a.EnableVPN()
	}
	return a.DisableVPN()
}

// EnableVPN enables the VPN mode.
func (a *App) EnableVPN() error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.client == nil {
		return fmt.Errorf("client not initialized")
	}

	vpnMgr := a.client.VPNManager()
	if vpnMgr == nil {
		return fmt.Errorf("VPN not configured")
	}

	if err := vpnMgr.Start(a.ctx); err != nil {
		return fmt.Errorf("failed to enable VPN: %w", err)
	}

	slog.Info("VPN enabled")
	return nil
}

// DisableVPN disables the VPN mode.
func (a *App) DisableVPN() error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.client == nil {
		return nil
	}

	vpnMgr := a.client.VPNManager()
	if vpnMgr == nil {
		return nil
	}

	if err := vpnMgr.Stop(a.ctx); err != nil {
		return fmt.Errorf("failed to disable VPN: %w", err)
	}

	slog.Info("VPN disabled")
	return nil
}

// OpenWebDashboard opens the web dashboard in the default browser.
func (a *App) OpenWebDashboard() error {
	// Use the API listen address if configured (API server serves the Web UI)
	url := "http://127.0.0.1:7383"
	if a.clientCfg != nil && a.clientCfg.API.Listen != "" {
		url = "http://" + a.clientCfg.API.Listen
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	slog.Info("opened web dashboard", "url", url)
	return nil
}

// Quit exits the application.
func (a *App) Quit() error {
	a.savePreferences()
	// The Wails runtime will handle the actual quit
	return nil
}

// IsConnected returns whether we're connected to the server.
func (a *App) IsConnected() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.client == nil {
		return false
	}
	return a.client.Running()
}

// GetProxyAddresses returns the proxy listen addresses.
func (a *App) GetProxyAddresses() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := map[string]string{
		"http":   "",
		"socks5": "",
	}

	if a.clientCfg != nil {
		result["http"] = a.clientCfg.Proxy.HTTP.Listen
		result["socks5"] = a.clientCfg.Proxy.SOCKS5.Listen
	}

	return result
}

// GetProxySettings returns the current proxy settings.
func (a *App) GetProxySettings() (*ProxySettings, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	settings := &ProxySettings{
		ServerProtocol:  "http",
		HTTPProxyPort:   3128,
		SOCKS5ProxyPort: 1081,
	}

	if a.clientCfg != nil {
		settings.ServerAddress = a.clientCfg.Server.Address
		settings.ServerProtocol = a.clientCfg.Server.Protocol
		if settings.ServerProtocol == "" {
			settings.ServerProtocol = "http"
		}

		// Extract ports from listen addresses
		if a.clientCfg.Proxy.HTTP.Listen != "" {
			if port := extractPort(a.clientCfg.Proxy.HTTP.Listen); port > 0 {
				settings.HTTPProxyPort = port
			}
		}
		if a.clientCfg.Proxy.SOCKS5.Listen != "" {
			if port := extractPort(a.clientCfg.Proxy.SOCKS5.Listen); port > 0 {
				settings.SOCKS5ProxyPort = port
			}
		}
	}

	return settings, nil
}

// UpdateProxySettings updates the proxy settings.
func (a *App) UpdateProxySettings(settings *ProxySettings) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.clientCfg == nil {
		return fmt.Errorf("config not loaded")
	}

	// Update server settings
	a.clientCfg.Server.Address = settings.ServerAddress
	a.clientCfg.Server.Protocol = settings.ServerProtocol

	// Update proxy listen addresses (keep 127.0.0.1 as the bind address)
	if settings.HTTPProxyPort > 0 {
		a.clientCfg.Proxy.HTTP.Listen = fmt.Sprintf("127.0.0.1:%d", settings.HTTPProxyPort)
	}
	if settings.SOCKS5ProxyPort > 0 {
		a.clientCfg.Proxy.SOCKS5.Listen = fmt.Sprintf("127.0.0.1:%d", settings.SOCKS5ProxyPort)
	}

	// Save the updated config
	if a.configPath != "" {
		if err := config.Save(a.configPath, a.clientCfg); err != nil {
			slog.Error("failed to save config", "error", err)
			return fmt.Errorf("failed to save config: %w", err)
		}
		slog.Info("proxy settings saved", "path", a.configPath)
	}

	return nil
}

// RestartClient restarts the embedded client with the updated configuration.
func (a *App) RestartClient() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.client != nil {
		slog.Info("stopping client for restart")
		if err := a.client.Stop(a.ctx); err != nil {
			slog.Error("failed to stop client", "error", err)
		}
		a.client = nil
	}

	// Reload config if we have a config path
	if a.configPath != "" {
		cfg := config.DefaultClientConfig()
		if err := config.LoadAndValidate(a.configPath, &cfg); err != nil {
			slog.Warn("failed to reload config, using current", "error", err)
		} else {
			// Ensure API stays enabled
			cfg.API.Enabled = true
			if cfg.API.Listen == "" {
				cfg.API.Listen = "127.0.0.1:7383"
			}
			a.clientCfg = &cfg
		}
	}

	if a.clientCfg == nil {
		return fmt.Errorf("no config available")
	}

	// Create new client
	c, err := client.New(a.clientCfg)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	a.client = c

	// Set config path so the embedded client can save config changes
	if a.configPath != "" {
		c.SetConfigPath(a.configPath)
	}

	// Start client
	if err := c.Start(a.ctx); err != nil {
		return fmt.Errorf("start client: %w", err)
	}

	slog.Info("client restarted successfully",
		"http_proxy", a.clientCfg.Proxy.HTTP.Listen,
		"socks5_proxy", a.clientCfg.Proxy.SOCKS5.Listen,
	)

	return nil
}

// extractPort extracts the port number from an address string like "127.0.0.1:3128".
func extractPort(addr string) int {
	if addr == "" {
		return 0
	}
	// Find the last colon (handles IPv6)
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			port := 0
			for j := i + 1; j < len(addr); j++ {
				if addr[j] >= '0' && addr[j] <= '9' {
					port = port*10 + int(addr[j]-'0')
				}
			}
			return port
		}
	}
	return 0
}

// loadPreferences loads user preferences from disk.
func (a *App) loadPreferences() {
	configDir, err := os.UserConfigDir()
	if err != nil {
		slog.Warn("failed to get config dir", "error", err)
		return
	}

	prefsPath := filepath.Join(configDir, "bifrost", "quick-preferences.json")
	data, err := os.ReadFile(prefsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to read preferences", "error", err)
		}
		return
	}

	if err := json.Unmarshal(data, a.preferences); err != nil {
		slog.Warn("failed to parse preferences", "error", err)
	}
}

// savePreferences saves user preferences to disk.
func (a *App) savePreferences() {
	configDir, err := os.UserConfigDir()
	if err != nil {
		slog.Warn("failed to get config dir", "error", err)
		return
	}

	bifrostDir := filepath.Join(configDir, "bifrost")
	if err := os.MkdirAll(bifrostDir, 0700); err != nil {
		slog.Warn("failed to create config dir", "error", err)
		return
	}

	prefsPath := filepath.Join(bifrostDir, "quick-preferences.json")

	a.mu.RLock()
	data, err := json.MarshalIndent(a.preferences, "", "  ")
	a.mu.RUnlock()

	if err != nil {
		slog.Warn("failed to marshal preferences", "error", err)
		return
	}

	if err := os.WriteFile(prefsPath, data, 0600); err != nil {
		slog.Warn("failed to write preferences", "error", err)
	}
}
