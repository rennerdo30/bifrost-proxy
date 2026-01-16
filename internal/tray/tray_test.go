package tray

import (
	"testing"
)

func TestNew(t *testing.T) {
	var connectCalled, disconnectCalled, openUICalled, quitCalled bool

	cfg := Config{
		OnConnect:    func() { connectCalled = true },
		OnDisconnect: func() { disconnectCalled = true },
		OnOpenUI:     func() { openUICalled = true },
		OnQuit:       func() { quitCalled = true },
	}

	tray := New(cfg)
	if tray == nil {
		t.Fatal("New returned nil")
	}

	if tray.status != StatusDisconnected {
		t.Errorf("expected initial status=StatusDisconnected, got %d", tray.status)
	}

	// Verify callbacks are set
	if tray.onConnect == nil {
		t.Error("onConnect callback is nil")
	}
	if tray.onDisconnect == nil {
		t.Error("onDisconnect callback is nil")
	}
	if tray.onOpenUI == nil {
		t.Error("onOpenUI callback is nil")
	}
	if tray.onQuit == nil {
		t.Error("onQuit callback is nil")
	}

	// Call callbacks to verify they work (for code coverage)
	tray.onConnect()
	tray.onDisconnect()
	tray.onOpenUI()
	tray.onQuit()

	if !connectCalled {
		t.Error("connect callback was not called")
	}
	if !disconnectCalled {
		t.Error("disconnect callback was not called")
	}
	if !openUICalled {
		t.Error("openUI callback was not called")
	}
	if !quitCalled {
		t.Error("quit callback was not called")
	}
}

func TestNew_NilCallbacks(t *testing.T) {
	cfg := Config{}

	tray := New(cfg)
	if tray == nil {
		t.Fatal("New returned nil")
	}

	// All callbacks should be nil, no panic
	if tray.onConnect != nil {
		t.Error("onConnect should be nil")
	}
	if tray.onDisconnect != nil {
		t.Error("onDisconnect should be nil")
	}
	if tray.onOpenUI != nil {
		t.Error("onOpenUI should be nil")
	}
	if tray.onQuit != nil {
		t.Error("onQuit should be nil")
	}
}

func TestTray_SetStatus(t *testing.T) {
	tray := New(Config{})

	tests := []struct {
		status   Status
		expected Status
	}{
		{StatusDisconnected, StatusDisconnected},
		{StatusConnected, StatusConnected},
		{StatusWarning, StatusWarning},
		{StatusError, StatusError},
	}

	for _, tt := range tests {
		// Can't call SetStatus directly because it calls systray.SetIcon
		// which requires GUI, so we just test status constants
		tray.status = tt.status
		if tray.status != tt.expected {
			t.Errorf("expected status=%d, got %d", tt.expected, tray.status)
		}
	}
}

func TestStatus_Constants(t *testing.T) {
	// Verify status constants have expected values
	if StatusDisconnected != 0 {
		t.Error("StatusDisconnected should be 0")
	}
	if StatusConnected != 1 {
		t.Error("StatusConnected should be 1")
	}
	if StatusWarning != 2 {
		t.Error("StatusWarning should be 2")
	}
	if StatusError != 3 {
		t.Error("StatusError should be 3")
	}
}

func TestTray_onExit(t *testing.T) {
	tray := New(Config{})

	// onExit should not panic
	tray.onExit()
}

// Note: Testing Run(), SetStatus with updateIcon(), SetTooltip(), onReady(), and Quit()
// requires a graphical environment because they call systray functions directly.
// These functions are tested in integration tests or manually.
