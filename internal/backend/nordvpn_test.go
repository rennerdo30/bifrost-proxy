package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewNordVPNBackend(t *testing.T) {
	cfg := NordVPNConfig{
		Name:    "test-nordvpn",
		Country: "US",
	}

	b := NewNordVPNBackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-nordvpn", b.Name())
	assert.Equal(t, "nordvpn", b.Type())
}

func TestNewNordVPNBackend_Defaults(t *testing.T) {
	cfg := NordVPNConfig{
		Name: "test",
	}

	b := NewNordVPNBackend(cfg)

	// Check defaults are applied
	assert.Equal(t, "wireguard", b.config.Protocol)
	assert.Equal(t, 70, b.config.MaxLoad)
	assert.Equal(t, 30*time.Minute, b.config.RefreshInterval)
}

func TestNewNordVPNBackend_CustomConfig(t *testing.T) {
	cfg := NordVPNConfig{
		Name:            "custom",
		Country:         "DE",
		City:            "Berlin",
		Protocol:        "openvpn",
		MaxLoad:         50,
		RefreshInterval: 1 * time.Hour,
		Features:        []string{"p2p"},
	}

	b := NewNordVPNBackend(cfg)

	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, 50, b.config.MaxLoad)
	assert.Equal(t, 1*time.Hour, b.config.RefreshInterval)
	assert.Equal(t, []string{"p2p"}, b.config.Features)
}

func TestNordVPNBackend_Dial_NotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestNordVPNBackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestNordVPNBackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	assert.False(t, b.IsHealthy())
}

func TestNordVPNBackend_Stats(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test-nordvpn"})

	stats := b.Stats()
	assert.Equal(t, "test-nordvpn", stats.Name)
	assert.Equal(t, "nordvpn", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestNordVPNBackend_Stop_NotRunning(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestNordVPNBackend_SelectedServer_NilWhenNotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	server := b.SelectedServer()
	assert.Nil(t, server)
}
