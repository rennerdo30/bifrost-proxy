package client

import (
	"fmt"

	apiclient "github.com/rennerdo30/bifrost-proxy/internal/api/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

func (c *Client) getQuickSettings() *apiclient.QuickSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()

	vpnEnabled := false
	if c.vpnManager != nil {
		vpnEnabled = c.vpnManager.Status().Status == vpn.StatusConnected
	}

	currentServer := c.config.Server.Address

	return &apiclient.QuickSettings{
		AutoConnect:        c.config.Tray.AutoConnect,
		StartMinimized:     c.config.Tray.StartMinimized,
		ShowNotifications:  c.config.Tray.ShowNotifications,
		VPNEnabled:         vpnEnabled,
		SystemProxyEnabled: c.config.SystemProxy.Enabled,
		CurrentServer:      currentServer,
	}
}

// updateQuickSettings updates the quick settings.
func (c *Client) updateQuickSettings(settings *apiclient.QuickSettings) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config.Tray.AutoConnect = settings.AutoConnect
	c.config.Tray.StartMinimized = settings.StartMinimized
	c.config.Tray.ShowNotifications = settings.ShowNotifications

	// Handle System Proxy toggle
	if c.config.SystemProxy.Enabled != settings.SystemProxyEnabled {
		c.config.SystemProxy.Enabled = settings.SystemProxyEnabled
		if settings.SystemProxyEnabled {
			// Enable
			proxyAddr := c.config.Proxy.HTTP.Listen
			if proxyAddr == "" {
				proxyAddr = c.config.Proxy.SOCKS5.Listen
			}
			if proxyAddr != "" {
				if err := c.sysProxyManager.SetProxy(proxyAddr); err != nil {
					logging.Error("Failed to enable system proxy via quick settings", "error", err)
				}
			}
		} else {
			// Disable
			if err := c.sysProxyManager.ClearProxy(); err != nil {
				logging.Error("Failed to disable system proxy via quick settings", "error", err)
			}
		}
	}

	// Note: VPN toggle is handled by the API handler itself (handleUpdateSettings calls handler logic),
	// or we could handle it here, but looking at server.go handleUpdateSettings:
	// It calls SettingsUpdater first, THEN handles VPN toggle itself.
	// So we don't need to touch VPN here, just config.

	// Note: CurrentServer update logic implies changing the server config.
	// The API handler handles server selection separately via /server/select usually,
	// but updateQuickSettings might receive it.
	// QuickSettings struct has CurrentServer string.
	// If it's different, we might want to update it.
	if settings.CurrentServer != "" && settings.CurrentServer != c.config.Server.Address {
		c.config.Server.Address = settings.CurrentServer
		// Reconnecting logic might be needed if we change server address live,
		// but currently we just update config.
	}

	// Save to file if path is set
	if c.configPath != "" {
		if err := config.Save(c.configPath, c.config); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	return nil
}
