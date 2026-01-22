package tray

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMenuItem implements MenuItem interface for testing.
type mockMenuItem struct {
	mu        sync.Mutex
	title     string
	tooltip   string
	enabled   bool
	visible   bool
	clickedCh chan struct{}
}

func newMockMenuItem(title, tooltip string) *mockMenuItem {
	return &mockMenuItem{
		title:     title,
		tooltip:   tooltip,
		enabled:   true,
		visible:   true,
		clickedCh: make(chan struct{}, 10),
	}
}

func (m *mockMenuItem) SetTitle(title string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.title = title
}

func (m *mockMenuItem) SetTooltip(tooltip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tooltip = tooltip
}

func (m *mockMenuItem) Enable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = true
}

func (m *mockMenuItem) Disable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = false
}

func (m *mockMenuItem) Show() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.visible = true
}

func (m *mockMenuItem) Hide() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.visible = false
}

func (m *mockMenuItem) Clicked() <-chan struct{} {
	return m.clickedCh
}

func (m *mockMenuItem) Click() {
	m.clickedCh <- struct{}{}
}

func (m *mockMenuItem) GetTitle() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.title
}

func (m *mockMenuItem) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

func (m *mockMenuItem) IsVisible() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.visible
}

// mockSystrayAdapter implements SystrayAdapter for testing.
type mockSystrayAdapter struct {
	mu            sync.Mutex
	icon          []byte
	title         string
	tooltip       string
	menuItems     []*mockMenuItem
	separatorCnt  int
	quitCalled    bool
	onReadyCalled bool
	onExitCalled  bool
	runBlocking   bool
}

func newMockAdapter() *mockSystrayAdapter {
	return &mockSystrayAdapter{
		menuItems: make([]*mockMenuItem, 0),
	}
}

func (a *mockSystrayAdapter) Run(onReady func(), onExit func()) {
	a.mu.Lock()
	a.onReadyCalled = true
	blocking := a.runBlocking
	a.mu.Unlock()

	onReady()

	if blocking {
		// Block until quit is called
		for {
			a.mu.Lock()
			if a.quitCalled {
				a.mu.Unlock()
				break
			}
			a.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}

	a.mu.Lock()
	a.onExitCalled = true
	a.mu.Unlock()
	onExit()
}

func (a *mockSystrayAdapter) SetIcon(iconBytes []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.icon = iconBytes
}

func (a *mockSystrayAdapter) SetTitle(title string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.title = title
}

func (a *mockSystrayAdapter) SetTooltip(tooltip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tooltip = tooltip
}

func (a *mockSystrayAdapter) AddMenuItem(title string, tooltip string) MenuItem {
	a.mu.Lock()
	defer a.mu.Unlock()
	item := newMockMenuItem(title, tooltip)
	a.menuItems = append(a.menuItems, item)
	return item
}

func (a *mockSystrayAdapter) AddSeparator() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.separatorCnt++
}

func (a *mockSystrayAdapter) Quit() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.quitCalled = true
}

func (a *mockSystrayAdapter) GetIcon() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.icon
}

func (a *mockSystrayAdapter) GetTitle() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.title
}

func (a *mockSystrayAdapter) GetTooltip() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tooltip
}

func (a *mockSystrayAdapter) GetMenuItem(index int) *mockMenuItem {
	a.mu.Lock()
	defer a.mu.Unlock()
	if index >= 0 && index < len(a.menuItems) {
		return a.menuItems[index]
	}
	return nil
}

func (a *mockSystrayAdapter) GetSeparatorCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.separatorCnt
}

func (a *mockSystrayAdapter) IsQuitCalled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quitCalled
}

func (a *mockSystrayAdapter) WasOnReadyCalled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.onReadyCalled
}

func (a *mockSystrayAdapter) WasOnExitCalled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.onExitCalled
}

func TestNew(t *testing.T) {
	var connectCalled, disconnectCalled, openUICalled, openQuickCalled, quitCalled bool

	cfg := Config{
		OnConnect:    func() { connectCalled = true },
		OnDisconnect: func() { disconnectCalled = true },
		OnOpenUI:     func() { openUICalled = true },
		OnOpenQuick:  func() { openQuickCalled = true },
		OnQuit:       func() { quitCalled = true },
	}

	tray := New(cfg)
	require.NotNil(t, tray, "New should not return nil")

	assert.Equal(t, StatusDisconnected, tray.status, "initial status should be StatusDisconnected")

	// Verify callbacks are set
	assert.NotNil(t, tray.onConnect, "onConnect callback should be set")
	assert.NotNil(t, tray.onDisconnect, "onDisconnect callback should be set")
	assert.NotNil(t, tray.onOpenUI, "onOpenUI callback should be set")
	assert.NotNil(t, tray.onOpenQuick, "onOpenQuick callback should be set")
	assert.NotNil(t, tray.onQuit, "onQuit callback should be set")

	// Call callbacks to verify they work
	tray.onConnect()
	tray.onDisconnect()
	tray.onOpenUI()
	tray.onOpenQuick()
	tray.onQuit()

	assert.True(t, connectCalled, "connect callback should have been called")
	assert.True(t, disconnectCalled, "disconnect callback should have been called")
	assert.True(t, openUICalled, "openUI callback should have been called")
	assert.True(t, openQuickCalled, "openQuick callback should have been called")
	assert.True(t, quitCalled, "quit callback should have been called")
}

func TestNew_NilCallbacks(t *testing.T) {
	cfg := Config{}

	tray := New(cfg)
	require.NotNil(t, tray, "New should not return nil")

	// All callbacks should be nil
	assert.Nil(t, tray.onConnect, "onConnect should be nil")
	assert.Nil(t, tray.onDisconnect, "onDisconnect should be nil")
	assert.Nil(t, tray.onOpenUI, "onOpenUI should be nil")
	assert.Nil(t, tray.onOpenQuick, "onOpenQuick should be nil")
	assert.Nil(t, tray.onQuit, "onQuit should be nil")
}

func TestNewWithAdapter(t *testing.T) {
	adapter := newMockAdapter()
	cfg := Config{
		OnConnect: func() {},
	}

	tray := NewWithAdapter(cfg, adapter)
	require.NotNil(t, tray)
	assert.Equal(t, StatusDisconnected, tray.status)
	assert.Equal(t, adapter, tray.adapter)
}

func TestStatus_Constants(t *testing.T) {
	assert.Equal(t, Status(0), StatusDisconnected, "StatusDisconnected should be 0")
	assert.Equal(t, Status(1), StatusConnected, "StatusConnected should be 1")
	assert.Equal(t, Status(2), StatusWarning, "StatusWarning should be 2")
	assert.Equal(t, Status(3), StatusError, "StatusError should be 3")
}

func TestTray_SetStatus(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	tests := []struct {
		status       Status
		expectedIcon []byte
	}{
		{StatusDisconnected, iconDisconnected},
		{StatusConnected, iconConnected},
		{StatusWarning, iconWarning},
		{StatusError, iconError},
	}

	for _, tt := range tests {
		t.Run("status_"+string(rune('0'+tt.status)), func(t *testing.T) {
			tray.SetStatus(tt.status)
			assert.Equal(t, tt.status, tray.status, "status should be updated")
			assert.Equal(t, tt.expectedIcon, adapter.GetIcon(), "icon should be updated")
		})
	}
}

func TestTray_SetTooltip(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	tray.SetTooltip("Test Tooltip")
	assert.Equal(t, "Test Tooltip", adapter.GetTooltip())

	tray.SetTooltip("Another Tooltip")
	assert.Equal(t, "Another Tooltip", adapter.GetTooltip())
}

func TestTray_Run(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	// Run should call the adapter's Run method
	tray.Run(context.Background())

	assert.True(t, adapter.WasOnReadyCalled(), "onReady should have been called")
	assert.True(t, adapter.WasOnExitCalled(), "onExit should have been called")
}

func TestTray_onReady_SetsUpMenu(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	tray.Run(context.Background())

	// Verify title and tooltip were set
	assert.Equal(t, "Bifrost", adapter.GetTitle())
	assert.Equal(t, "Bifrost Proxy Client", adapter.GetTooltip())

	// Verify menu items were created (6 items: Status, Connect, Disconnect, Quick Access, Open Dashboard, Quit)
	assert.Equal(t, 6, len(adapter.menuItems))

	// Verify separators were added (3 separators)
	assert.Equal(t, 3, adapter.GetSeparatorCount())

	// Verify menu item titles
	assert.Equal(t, "Status: Disconnected", adapter.GetMenuItem(0).GetTitle())
	assert.Equal(t, "Connect", adapter.GetMenuItem(1).GetTitle())
	assert.Equal(t, "Disconnect", adapter.GetMenuItem(2).GetTitle())
	assert.Equal(t, "Quick Access", adapter.GetMenuItem(3).GetTitle())
	assert.Equal(t, "Open Dashboard", adapter.GetMenuItem(4).GetTitle())
	assert.Equal(t, "Quit", adapter.GetMenuItem(5).GetTitle())

	// Verify initial states
	assert.False(t, adapter.GetMenuItem(0).IsEnabled(), "Status should be disabled")
	assert.True(t, adapter.GetMenuItem(1).IsVisible(), "Connect should be visible")
	assert.False(t, adapter.GetMenuItem(2).IsVisible(), "Disconnect should be hidden initially")
}

func TestTray_onReady_ConnectClick(t *testing.T) {
	adapter := newMockAdapter()
	var connectCalled atomic.Bool

	tray := NewWithAdapter(Config{
		OnConnect: func() { connectCalled.Store(true) },
	}, adapter)

	tray.Run(context.Background())

	// Give the goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Simulate connect click
	adapter.GetMenuItem(1).Click()

	// Wait for the click to be processed
	time.Sleep(50 * time.Millisecond)

	assert.True(t, connectCalled.Load(), "OnConnect should have been called")
	assert.False(t, adapter.GetMenuItem(1).IsVisible(), "Connect should be hidden after click")
	assert.True(t, adapter.GetMenuItem(2).IsVisible(), "Disconnect should be visible after click")
	assert.Equal(t, "Status: Connected", adapter.GetMenuItem(0).GetTitle())
	assert.Equal(t, StatusConnected, tray.status)
}

func TestTray_onReady_DisconnectClick(t *testing.T) {
	adapter := newMockAdapter()
	var disconnectCalled atomic.Bool

	tray := NewWithAdapter(Config{
		OnDisconnect: func() { disconnectCalled.Store(true) },
	}, adapter)

	tray.Run(context.Background())

	// Give the goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// First connect to enable disconnect
	adapter.GetMenuItem(1).Click()
	time.Sleep(50 * time.Millisecond)

	// Then disconnect
	adapter.GetMenuItem(2).Click()
	time.Sleep(50 * time.Millisecond)

	assert.True(t, disconnectCalled.Load(), "OnDisconnect should have been called")
	assert.True(t, adapter.GetMenuItem(1).IsVisible(), "Connect should be visible after disconnect")
	assert.False(t, adapter.GetMenuItem(2).IsVisible(), "Disconnect should be hidden after click")
	assert.Equal(t, "Status: Disconnected", adapter.GetMenuItem(0).GetTitle())
	assert.Equal(t, StatusDisconnected, tray.status)
}

func TestTray_onReady_OpenQuickClick(t *testing.T) {
	adapter := newMockAdapter()
	var openQuickCalled atomic.Bool

	tray := NewWithAdapter(Config{
		OnOpenQuick: func() { openQuickCalled.Store(true) },
	}, adapter)

	tray.Run(context.Background())
	time.Sleep(50 * time.Millisecond)

	// Simulate quick access click
	adapter.GetMenuItem(3).Click()
	time.Sleep(50 * time.Millisecond)

	assert.True(t, openQuickCalled.Load(), "OnOpenQuick should have been called")
}

func TestTray_onReady_OpenUIClick(t *testing.T) {
	adapter := newMockAdapter()
	var openUICalled atomic.Bool

	tray := NewWithAdapter(Config{
		OnOpenUI: func() { openUICalled.Store(true) },
	}, adapter)

	tray.Run(context.Background())
	time.Sleep(50 * time.Millisecond)

	// Simulate open dashboard click
	adapter.GetMenuItem(4).Click()
	time.Sleep(50 * time.Millisecond)

	assert.True(t, openUICalled.Load(), "OnOpenUI should have been called")
}

func TestTray_onReady_QuitClick(t *testing.T) {
	adapter := newMockAdapter()
	var quitCalled atomic.Bool

	tray := NewWithAdapter(Config{
		OnQuit: func() { quitCalled.Store(true) },
	}, adapter)

	tray.Run(context.Background())
	time.Sleep(50 * time.Millisecond)

	// Simulate quit click
	adapter.GetMenuItem(5).Click()
	time.Sleep(50 * time.Millisecond)

	assert.True(t, quitCalled.Load(), "OnQuit should have been called")
	assert.True(t, adapter.IsQuitCalled(), "adapter.Quit should have been called")
}

func TestTray_onReady_NilCallbacks(t *testing.T) {
	adapter := newMockAdapter()

	// Create tray with nil callbacks
	tray := NewWithAdapter(Config{}, adapter)

	tray.Run(context.Background())
	time.Sleep(50 * time.Millisecond)

	// Click all menu items - should not panic
	adapter.GetMenuItem(1).Click() // Connect
	time.Sleep(50 * time.Millisecond)

	adapter.GetMenuItem(2).Click() // Disconnect
	time.Sleep(50 * time.Millisecond)

	adapter.GetMenuItem(3).Click() // Quick Access
	time.Sleep(50 * time.Millisecond)

	adapter.GetMenuItem(4).Click() // Open Dashboard
	time.Sleep(50 * time.Millisecond)

	adapter.GetMenuItem(5).Click() // Quit
	time.Sleep(50 * time.Millisecond)

	// If we get here without panic, the test passes
	assert.True(t, adapter.IsQuitCalled())
}

func TestTray_onExit(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	// onExit should not panic
	tray.onExit()
}

func TestTray_updateIcon(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	tests := []struct {
		status       Status
		expectedIcon []byte
		name         string
	}{
		{StatusDisconnected, iconDisconnected, "disconnected"},
		{StatusConnected, iconConnected, "connected"},
		{StatusWarning, iconWarning, "warning"},
		{StatusError, iconError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tray.status = tt.status
			tray.updateIcon()
			assert.Equal(t, tt.expectedIcon, adapter.GetIcon())
		})
	}
}

func TestTray_updateIcon_DefaultCase(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	// Set an invalid status to trigger default case
	tray.status = Status(999)
	tray.updateIcon()

	// Default case should use disconnected icon
	assert.Equal(t, iconDisconnected, adapter.GetIcon())
}

func TestTray_Quit(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	tray.Quit()
	assert.True(t, adapter.IsQuitCalled(), "adapter.Quit should have been called")
}

func TestTray_StatusString(t *testing.T) {
	// Test that status values are distinct
	statuses := []Status{StatusDisconnected, StatusConnected, StatusWarning, StatusError}
	for i, s1 := range statuses {
		for j, s2 := range statuses {
			if i == j {
				assert.Equal(t, s1, s2)
			} else {
				assert.NotEqual(t, s1, s2, "statuses at indices %d and %d should be different", i, j)
			}
		}
	}
}

func TestConfig_AllFields(t *testing.T) {
	// Test that Config can hold all callback types
	cfg := Config{
		OnConnect:    func() {},
		OnDisconnect: func() {},
		OnOpenUI:     func() {},
		OnOpenQuick:  func() {},
		OnQuit:       func() {},
	}

	assert.NotNil(t, cfg.OnConnect)
	assert.NotNil(t, cfg.OnDisconnect)
	assert.NotNil(t, cfg.OnOpenUI)
	assert.NotNil(t, cfg.OnOpenQuick)
	assert.NotNil(t, cfg.OnQuit)
}

func TestMenuItem_Interface(t *testing.T) {
	// Verify that mockMenuItem implements MenuItem interface
	var _ MenuItem = (*mockMenuItem)(nil)

	item := newMockMenuItem("Test", "Tooltip")

	item.SetTitle("New Title")
	assert.Equal(t, "New Title", item.GetTitle())

	item.SetTooltip("New Tooltip")
	assert.Equal(t, "New Tooltip", item.tooltip)

	item.Disable()
	assert.False(t, item.IsEnabled())

	item.Enable()
	assert.True(t, item.IsEnabled())

	item.Hide()
	assert.False(t, item.IsVisible())

	item.Show()
	assert.True(t, item.IsVisible())

	// Test Clicked returns a channel
	ch := item.Clicked()
	assert.NotNil(t, ch)
}

func TestSystrayAdapter_Interface(t *testing.T) {
	// Verify that mockSystrayAdapter implements SystrayAdapter interface
	var _ SystrayAdapter = (*mockSystrayAdapter)(nil)
}

func TestRealMenuItem_Interface(t *testing.T) {
	// Verify that realMenuItem implements MenuItem interface
	var _ MenuItem = (*realMenuItem)(nil)
}

func TestRealSystrayAdapter_Interface(t *testing.T) {
	// Verify that realSystrayAdapter implements SystrayAdapter interface
	var _ SystrayAdapter = (*realSystrayAdapter)(nil)
}

func TestDefaultAdapter_IsSet(t *testing.T) {
	// Verify that defaultAdapter is set
	assert.NotNil(t, defaultAdapter)

	// Verify it's a realSystrayAdapter
	_, ok := defaultAdapter.(*realSystrayAdapter)
	assert.True(t, ok, "defaultAdapter should be a *realSystrayAdapter")
}

func TestTray_IconsAreValid(t *testing.T) {
	// Verify that all icon variables are non-empty
	assert.NotEmpty(t, iconConnected, "iconConnected should not be empty")
	assert.NotEmpty(t, iconDisconnected, "iconDisconnected should not be empty")
	assert.NotEmpty(t, iconWarning, "iconWarning should not be empty")
	assert.NotEmpty(t, iconError, "iconError should not be empty")
}

func TestTray_RunWithContext(t *testing.T) {
	adapter := newMockAdapter()
	tray := NewWithAdapter(Config{}, adapter)

	ctx := context.Background()
	tray.Run(ctx)

	// Verify Run was called
	assert.True(t, adapter.WasOnReadyCalled())
}

func TestMockAdapter_MenuItemCount(t *testing.T) {
	adapter := newMockAdapter()

	// Initially no items
	assert.Equal(t, 0, len(adapter.menuItems))

	// Add items
	adapter.AddMenuItem("Item 1", "Tooltip 1")
	adapter.AddMenuItem("Item 2", "Tooltip 2")
	adapter.AddMenuItem("Item 3", "Tooltip 3")

	assert.Equal(t, 3, len(adapter.menuItems))
}

func TestMockAdapter_GetMenuItem_OutOfBounds(t *testing.T) {
	adapter := newMockAdapter()
	adapter.AddMenuItem("Item 1", "Tooltip 1")

	// Valid index
	assert.NotNil(t, adapter.GetMenuItem(0))

	// Invalid indices
	assert.Nil(t, adapter.GetMenuItem(-1))
	assert.Nil(t, adapter.GetMenuItem(1))
	assert.Nil(t, adapter.GetMenuItem(100))
}
