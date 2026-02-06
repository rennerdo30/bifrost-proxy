//go:build !cgo

package tray

import "log/slog"

// noopMenuItem is a no-op menu item for builds without CGo.
type noopMenuItem struct {
	clickCh chan struct{}
}

func (m *noopMenuItem) SetTitle(_ string)     {}
func (m *noopMenuItem) SetTooltip(_ string)   {}
func (m *noopMenuItem) Enable()               {}
func (m *noopMenuItem) Disable()              {}
func (m *noopMenuItem) Show()                 {}
func (m *noopMenuItem) Hide()                 {}
func (m *noopMenuItem) Clicked() <-chan struct{} { return m.clickCh }

// noopSystrayAdapter is a no-op adapter used when CGo is not available.
type noopSystrayAdapter struct{}

func (a *noopSystrayAdapter) Run(onReady func(), _ func()) {
	slog.Warn("system tray not available (built without CGo)")
	onReady()
}

func (a *noopSystrayAdapter) SetIcon(_ []byte)      {}
func (a *noopSystrayAdapter) SetTitle(_ string)      {}
func (a *noopSystrayAdapter) SetTooltip(_ string)    {}
func (a *noopSystrayAdapter) AddMenuItem(_, _ string) MenuItem {
	return &noopMenuItem{clickCh: make(chan struct{})}
}
func (a *noopSystrayAdapter) AddSeparator() {}
func (a *noopSystrayAdapter) Quit()         {}

// defaultAdapter is the no-op systray adapter for non-CGo builds.
var defaultAdapter SystrayAdapter = &noopSystrayAdapter{}
