// Package tray provides system tray integration for Bifrost client.
package tray

import (
	"fyne.io/systray"
)

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
