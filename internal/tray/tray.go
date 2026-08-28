// Package tray provides system tray integration for Bifrost client.
package tray

import (
	"context"
	"sync"
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

// Tray provides system tray functionality.
type Tray struct {
	// statusMu guards status: SetStatus is called from the client's Stop path
	// and from the tray's own click loop, while updateIcon reads it from the
	// systray ready callback.
	statusMu     sync.Mutex
	status       Status
	onConnect    func()
	onDisconnect func()
	onOpenUI     func()
	onOpenQuick  func()
	onQuit       func()
	showQuickGUI bool
	adapter      SystrayAdapter
	notifier     Notifier

	// done ends the menu-click worker when systray exits. fyne.io/systray
	// is process-lifetime/one-shot, so one channel per Tray is sufficient.
	done     chan struct{}
	exitOnce sync.Once
	quitOnce sync.Once
}

// Config holds tray configuration.
type Config struct {
	OnConnect    func()
	OnDisconnect func()
	OnOpenUI     func()
	OnOpenQuick  func()
	OnQuit       func()

	// ShowQuickGUI controls whether the "Quick Access" menu entry is shown.
	// When false the entry is omitted so the OnOpenQuick callback is never
	// reachable from the tray.
	ShowQuickGUI bool
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
		showQuickGUI: cfg.ShowQuickGUI,
		adapter:      defaultAdapter,
		notifier:     defaultNotifier,
		done:         make(chan struct{}),
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
		showQuickGUI: cfg.ShowQuickGUI,
		adapter:      adapter,
		notifier:     defaultNotifier,
		done:         make(chan struct{}),
	}
}

// SetNotifier overrides the desktop notifier (primarily for testing).
func (t *Tray) SetNotifier(n Notifier) {
	t.notifier = n
}

// Notify shows a desktop notification with the given title and message.
// It returns an error if the underlying notifier fails. A nil notifier is a
// no-op so the tray can be used without notification support.
func (t *Tray) Notify(title, message string) error {
	if t.notifier == nil {
		return nil
	}
	return t.notifier.Notify(title, message)
}

// Run starts the system tray and blocks until it exits. Canceling ctx asks
// the adapter to quit so callers do not need a second shutdown channel.
func (t *Tray) Run(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			t.Quit()
		case <-t.done:
		}
	}()

	t.adapter.Run(t.onReady, t.onExit)
}

// SetStatus updates the tray icon status.
func (t *Tray) SetStatus(status Status) {
	t.statusMu.Lock()
	t.status = status
	t.statusMu.Unlock()
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

	// The Quick Access entry is only shown when ShowQuickGUI is configured. When
	// hidden, quickClicked stays nil so its case in the select below never fires.
	var quickClicked <-chan struct{}
	if t.showQuickGUI {
		mOpenQuick := t.adapter.AddMenuItem("Quick Access", "Open quick access popup")
		quickClicked = mOpenQuick.Clicked()
	}
	mOpenUI := t.adapter.AddMenuItem("Open Dashboard", "Open web dashboard")

	t.adapter.AddSeparator()

	mQuit := t.adapter.AddMenuItem("Quit", "Quit Bifrost")

	// Handle menu clicks
	go func() {
		for {
			select {
			case <-t.done:
				return

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

			case <-quickClicked:
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
				t.Quit()
			}
		}
	}()
}

func (t *Tray) onExit() {
	t.exitOnce.Do(func() { close(t.done) })
}

func (t *Tray) updateIcon() {
	t.statusMu.Lock()
	status := t.status
	t.statusMu.Unlock()

	var icon []byte
	switch status {
	case StatusConnected:
		icon = iconConnected
	case StatusWarning:
		icon = iconWarning
	case StatusError:
		icon = iconError
	default:
		icon = iconDisconnected
	}
	t.adapter.SetIcon(platformIcon(icon))
}

// Quit quits the system tray. It is safe for the context watcher, menu item,
// and application shutdown path to converge here concurrently.
func (t *Tray) Quit() {
	t.quitOnce.Do(t.adapter.Quit)
}
