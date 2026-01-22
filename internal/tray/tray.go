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

// MenuItem represents a menu item interface for abstraction.
type MenuItem interface {
	SetTitle(title string)
	SetTooltip(tooltip string)
	Enable()
	Disable()
	Show()
	Hide()
	Clicked() <-chan struct{}
}

// SystrayAdapter provides an interface for systray operations.
// This allows mocking the systray package for testing.
type SystrayAdapter interface {
	Run(onReady func(), onExit func())
	SetIcon(iconBytes []byte)
	SetTitle(title string)
	SetTooltip(tooltip string)
	AddMenuItem(title string, tooltip string) MenuItem
	AddSeparator()
	Quit()
}

// realMenuItem wraps systray.MenuItem to implement MenuItem interface.
type realMenuItem struct {
	item *systray.MenuItem
}

func (m *realMenuItem) SetTitle(title string)     { m.item.SetTitle(title) }
func (m *realMenuItem) SetTooltip(tooltip string) { m.item.SetTooltip(tooltip) }
func (m *realMenuItem) Enable()                   { m.item.Enable() }
func (m *realMenuItem) Disable()                  { m.item.Disable() }
func (m *realMenuItem) Show()                     { m.item.Show() }
func (m *realMenuItem) Hide()                     { m.item.Hide() }
func (m *realMenuItem) Clicked() <-chan struct{}  { return m.item.ClickedCh }

// realSystrayAdapter implements SystrayAdapter using the real systray package.
type realSystrayAdapter struct{}

func (a *realSystrayAdapter) Run(onReady func(), onExit func()) {
	systray.Run(onReady, onExit)
}

func (a *realSystrayAdapter) SetIcon(iconBytes []byte) {
	systray.SetIcon(iconBytes)
}

func (a *realSystrayAdapter) SetTitle(title string) {
	systray.SetTitle(title)
}

func (a *realSystrayAdapter) SetTooltip(tooltip string) {
	systray.SetTooltip(tooltip)
}

func (a *realSystrayAdapter) AddMenuItem(title string, tooltip string) MenuItem {
	return &realMenuItem{item: systray.AddMenuItem(title, tooltip)}
}

func (a *realSystrayAdapter) AddSeparator() {
	systray.AddSeparator()
}

func (a *realSystrayAdapter) Quit() {
	systray.Quit()
}

// defaultAdapter is the default systray adapter.
var defaultAdapter SystrayAdapter = &realSystrayAdapter{}

// Tray provides system tray functionality.
type Tray struct {
	status       Status
	onConnect    func()
	onDisconnect func()
	onOpenUI     func()
	onOpenQuick  func()
	onQuit       func()
	adapter      SystrayAdapter
}

// Config holds tray configuration.
type Config struct {
	OnConnect    func()
	OnDisconnect func()
	OnOpenUI     func()
	OnOpenQuick  func()
	OnQuit       func()
}

// New creates a new system tray.
func New(cfg Config) *Tray {
	return &Tray{
		status:       StatusDisconnected,
		onConnect:    cfg.OnConnect,
		onDisconnect: cfg.OnDisconnect,
		onOpenUI:     cfg.OnOpenUI,
		onOpenQuick:  cfg.OnOpenQuick,
		onQuit:       cfg.OnQuit,
		adapter:      defaultAdapter,
	}
}

// NewWithAdapter creates a new system tray with a custom adapter (for testing).
func NewWithAdapter(cfg Config, adapter SystrayAdapter) *Tray {
	return &Tray{
		status:       StatusDisconnected,
		onConnect:    cfg.OnConnect,
		onDisconnect: cfg.OnDisconnect,
		onOpenUI:     cfg.OnOpenUI,
		onOpenQuick:  cfg.OnOpenQuick,
		onQuit:       cfg.OnQuit,
		adapter:      adapter,
	}
}

// Run starts the system tray (blocks).
func (t *Tray) Run(ctx context.Context) {
	t.adapter.Run(t.onReady, t.onExit)
}

// SetStatus updates the tray icon status.
func (t *Tray) SetStatus(status Status) {
	t.status = status
	t.updateIcon()
}

// SetTooltip updates the tray tooltip.
func (t *Tray) SetTooltip(tooltip string) {
	t.adapter.SetTooltip(tooltip)
}

func (t *Tray) onReady() {
	t.adapter.SetTitle("Bifrost")
	t.adapter.SetTooltip("Bifrost Proxy Client")
	t.updateIcon()

	// Menu items
	mStatus := t.adapter.AddMenuItem("Status: Disconnected", "Connection status")
	mStatus.Disable()

	t.adapter.AddSeparator()

	mConnect := t.adapter.AddMenuItem("Connect", "Connect to server")
	mDisconnect := t.adapter.AddMenuItem("Disconnect", "Disconnect from server")
	mDisconnect.Hide()

	t.adapter.AddSeparator()

	mOpenQuick := t.adapter.AddMenuItem("Quick Access", "Open quick access popup")
	mOpenUI := t.adapter.AddMenuItem("Open Dashboard", "Open web dashboard")

	t.adapter.AddSeparator()

	mQuit := t.adapter.AddMenuItem("Quit", "Quit Bifrost")

	// Handle menu clicks
	go func() {
		for {
			select {
			case <-mConnect.Clicked():
				if t.onConnect != nil {
					t.onConnect()
				}
				mConnect.Hide()
				mDisconnect.Show()
				mStatus.SetTitle("Status: Connected")
				t.SetStatus(StatusConnected)

			case <-mDisconnect.Clicked():
				if t.onDisconnect != nil {
					t.onDisconnect()
				}
				mDisconnect.Hide()
				mConnect.Show()
				mStatus.SetTitle("Status: Disconnected")
				t.SetStatus(StatusDisconnected)

			case <-mOpenQuick.Clicked():
				if t.onOpenQuick != nil {
					t.onOpenQuick()
				}

			case <-mOpenUI.Clicked():
				if t.onOpenUI != nil {
					t.onOpenUI()
				}

			case <-mQuit.Clicked():
				if t.onQuit != nil {
					t.onQuit()
				}
				t.adapter.Quit()
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
	t.adapter.SetIcon(icon)
}

// Quit quits the system tray.
func (t *Tray) Quit() {
	t.adapter.Quit()
}
