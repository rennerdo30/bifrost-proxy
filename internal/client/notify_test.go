package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/tray"
)

// noopMenuItem implements tray.MenuItem for tests.
type noopMenuItem struct{ ch chan struct{} }

func (m *noopMenuItem) SetTitle(string)          {}
func (m *noopMenuItem) SetTooltip(string)        {}
func (m *noopMenuItem) Enable()                  {}
func (m *noopMenuItem) Disable()                 {}
func (m *noopMenuItem) Show()                    {}
func (m *noopMenuItem) Hide()                    {}
func (m *noopMenuItem) Clicked() <-chan struct{} { return m.ch }

// noopAdapter implements tray.SystrayAdapter for tests; the tray is never run.
type noopAdapter struct{}

func (a *noopAdapter) Run(func(), func()) {}
func (a *noopAdapter) SetIcon([]byte)     {}
func (a *noopAdapter) SetTitle(string)    {}
func (a *noopAdapter) SetTooltip(string)  {}
func (a *noopAdapter) AddMenuItem(string, string) tray.MenuItem {
	return &noopMenuItem{ch: make(chan struct{})}
}
func (a *noopAdapter) AddSeparator() {}
func (a *noopAdapter) Quit()         {}

func newNotifyTestAdapter() tray.SystrayAdapter { return &noopAdapter{} }

// recordingNotifier records notifications sent through the tray.
type recordingNotifier struct {
	titles   []string
	messages []string
}

func (r *recordingNotifier) Notify(title, message string) error {
	r.titles = append(r.titles, title)
	r.messages = append(r.messages, message)
	return nil
}

func newNotifyTestClient(t *testing.T, showNotifications bool) (*Client, *recordingNotifier) {
	t.Helper()

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}
	cfg.Tray.ShowNotifications = showNotifications

	client, err := New(cfg)
	require.NoError(t, err)

	rec := &recordingNotifier{}
	tr := tray.NewWithAdapter(tray.Config{}, newNotifyTestAdapter())
	tr.SetNotifier(rec)
	client.tray = tr

	return client, rec
}

func TestNotifySendsWhenEnabled(t *testing.T) {
	client, rec := newNotifyTestClient(t, true)

	client.notify("Connected")

	require.Len(t, rec.titles, 1)
	assert.Equal(t, "Bifrost", rec.titles[0])
	assert.Equal(t, "Connected", rec.messages[0])
}

func TestNotifySkippedWhenDisabled(t *testing.T) {
	client, rec := newNotifyTestClient(t, false)

	client.notify("Connected")

	assert.Empty(t, rec.titles, "notification should not be sent when disabled")
}

func TestNotifyNoTrayIsNoop(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy:  config.ClientProxySettings{HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"}},
		Server: config.ServerConnection{Address: "localhost:7080", Protocol: "http"},
	}
	cfg.Tray.ShowNotifications = true
	client, err := New(cfg)
	require.NoError(t, err)
	client.tray = nil

	// Should not panic.
	client.notify("Connected")
}
