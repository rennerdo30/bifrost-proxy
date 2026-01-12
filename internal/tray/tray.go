// Package tray provides system tray integration for Bifrost client.
package tray

import (
	"context"
	_ "embed"

	"fyne.io/systray"
)

// Status represents the tray icon status.
type Status int

const (
	StatusDisconnected Status = iota
	StatusConnected
	StatusWarning
	StatusError
)

// Tray provides system tray functionality.
type Tray struct {
	status    Status
	onConnect func()
	onDisconnect func()
	onOpenUI func()
	onQuit   func()
}

// Config holds tray configuration.
type Config struct {
	OnConnect    func()
	OnDisconnect func()
	OnOpenUI     func()
	OnQuit       func()
}

// New creates a new system tray.
func New(cfg Config) *Tray {
	return &Tray{
		status:       StatusDisconnected,
		onConnect:    cfg.OnConnect,
		onDisconnect: cfg.OnDisconnect,
		onOpenUI:     cfg.OnOpenUI,
		onQuit:       cfg.OnQuit,
	}
}

// Run starts the system tray (blocks).
func (t *Tray) Run(ctx context.Context) {
	systray.Run(t.onReady, t.onExit)
}

// SetStatus updates the tray icon status.
func (t *Tray) SetStatus(status Status) {
	t.status = status
	t.updateIcon()
}

// SetTooltip updates the tray tooltip.
func (t *Tray) SetTooltip(tooltip string) {
	systray.SetTooltip(tooltip)
}

func (t *Tray) onReady() {
	systray.SetTitle("Bifrost")
	systray.SetTooltip("Bifrost Proxy Client")
	t.updateIcon()

	// Menu items
	mStatus := systray.AddMenuItem("Status: Disconnected", "Connection status")
	mStatus.Disable()

	systray.AddSeparator()

	mConnect := systray.AddMenuItem("Connect", "Connect to server")
	mDisconnect := systray.AddMenuItem("Disconnect", "Disconnect from server")
	mDisconnect.Hide()

	systray.AddSeparator()

	mOpenUI := systray.AddMenuItem("Open Dashboard", "Open web dashboard")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Quit Bifrost")

	// Handle menu clicks
	go func() {
		for {
			select {
			case <-mConnect.ClickedCh:
				if t.onConnect != nil {
					t.onConnect()
				}
				mConnect.Hide()
				mDisconnect.Show()
				mStatus.SetTitle("Status: Connected")
				t.SetStatus(StatusConnected)

			case <-mDisconnect.ClickedCh:
				if t.onDisconnect != nil {
					t.onDisconnect()
				}
				mDisconnect.Hide()
				mConnect.Show()
				mStatus.SetTitle("Status: Disconnected")
				t.SetStatus(StatusDisconnected)

			case <-mOpenUI.ClickedCh:
				if t.onOpenUI != nil {
					t.onOpenUI()
				}

			case <-mQuit.ClickedCh:
				if t.onQuit != nil {
					t.onQuit()
				}
				systray.Quit()
			}
		}
	}()
}

func (t *Tray) onExit() {
	// Cleanup
}

func (t *Tray) updateIcon() {
	var icon []byte
	switch t.status {
	case StatusConnected:
		icon = iconConnected
	case StatusWarning:
		icon = iconWarning
	case StatusError:
		icon = iconError
	default:
		icon = iconDisconnected
	}
	systray.SetIcon(icon)
}

// Quit quits the system tray.
func (t *Tray) Quit() {
	systray.Quit()
}
