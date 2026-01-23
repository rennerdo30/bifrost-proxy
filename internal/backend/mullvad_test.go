package backend

import (
	"context"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/mullvad"
	"github.com/stretchr/testify/assert"
)

func createMullvadTestClient() *mullvad.Client {
	client, _ := mullvad.NewClient("1234567890123456")
	return client
}

func TestNewMullvadBackend(t *testing.T) {
	cfg := MullvadConfig{
		Name:      "test-mullvad",
		AccountID: "1234567890123456",
		Country:   "DE",
	}

	b := NewMullvadBackend(cfg, createMullvadTestClient())
	assert.NotNil(t, b)
	assert.Equal(t, "test-mullvad", b.Name())
	assert.Equal(t, "mullvad", b.Type())
}

func TestNewMullvadBackend_Defaults(t *testing.T) {
	cfg := MullvadConfig{
		Name:      "test",
		AccountID: "1234567890123456",
	}

	b := NewMullvadBackend(cfg, createMullvadTestClient())

	// Check defaults are applied
	assert.Equal(t, "wireguard", b.config.Protocol)
	assert.Equal(t, 30*time.Minute, b.config.RefreshInterval)
}

func TestNewMullvadBackend_CustomConfig(t *testing.T) {
	cfg := MullvadConfig{
		Name:            "custom",
		AccountID:       "1234567890123456",
		Country:         "SE",
		City:            "Stockholm",
		Protocol:        "openvpn",
		RefreshInterval: 1 * time.Hour,
	}

	b := NewMullvadBackend(cfg, createMullvadTestClient())

	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, "SE", b.config.Country)
	assert.Equal(t, "Stockholm", b.config.City)
	assert.Equal(t, 1*time.Hour, b.config.RefreshInterval)
}

func TestMullvadBackend_Dial_NotStarted(t *testing.T) {
	cfg := MullvadConfig{Name: "test", AccountID: "1234567890123456"}
	b := NewMullvadBackend(cfg, createMullvadTestClient())

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestMullvadBackend_DialTimeout_NotStarted(t *testing.T) {
	cfg := MullvadConfig{Name: "test", AccountID: "1234567890123456"}
	b := NewMullvadBackend(cfg, createMullvadTestClient())

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestMullvadBackend_IsHealthy_NotStarted(t *testing.T) {
	cfg := MullvadConfig{Name: "test", AccountID: "1234567890123456"}
	b := NewMullvadBackend(cfg, createMullvadTestClient())

	assert.False(t, b.IsHealthy())
}

func TestMullvadBackend_Stats(t *testing.T) {
	cfg := MullvadConfig{Name: "test-mullvad", AccountID: "1234567890123456"}
	b := NewMullvadBackend(cfg, createMullvadTestClient())

	stats := b.Stats()
	assert.Equal(t, "test-mullvad", stats.Name)
	assert.Equal(t, "mullvad", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestMullvadBackend_Stop_NotRunning(t *testing.T) {
	cfg := MullvadConfig{Name: "test", AccountID: "1234567890123456"}
	b := NewMullvadBackend(cfg, createMullvadTestClient())

	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestMullvadBackend_SelectedServer_NilWhenNotStarted(t *testing.T) {
	cfg := MullvadConfig{Name: "test", AccountID: "1234567890123456"}
	b := NewMullvadBackend(cfg, createMullvadTestClient())

	server := b.SelectedServer()
	assert.Nil(t, server)
}
