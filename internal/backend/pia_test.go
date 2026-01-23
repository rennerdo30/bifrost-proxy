package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewPIABackend(t *testing.T) {
	cfg := PIAConfig{
		Name:     "test-pia",
		Username: "p1234567",
		Password: "password",
		Country:  "US",
	}

	b := NewPIABackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-pia", b.Name())
	assert.Equal(t, "pia", b.Type())
}

func TestNewPIABackend_Defaults(t *testing.T) {
	cfg := PIAConfig{
		Name:     "test",
		Username: "p1234567",
		Password: "password",
	}

	b := NewPIABackend(cfg)

	// Check defaults are applied
	assert.Equal(t, "wireguard", b.config.Protocol)
	assert.Equal(t, 30*time.Minute, b.config.RefreshInterval)
}

func TestNewPIABackend_CustomConfig(t *testing.T) {
	cfg := PIAConfig{
		Name:            "custom",
		Username:        "p1234567",
		Password:        "password",
		Country:         "NL",
		Protocol:        "openvpn",
		PortForwarding:  true,
		RefreshInterval: 1 * time.Hour,
	}

	b := NewPIABackend(cfg)

	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, "NL", b.config.Country)
	assert.True(t, b.config.PortForwarding)
	assert.Equal(t, 1*time.Hour, b.config.RefreshInterval)
}

func TestPIABackend_Dial_NotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestPIABackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestPIABackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	assert.False(t, b.IsHealthy())
}

func TestPIABackend_Stats(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test-pia", Username: "user", Password: "pass"})

	stats := b.Stats()
	assert.Equal(t, "test-pia", stats.Name)
	assert.Equal(t, "pia", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestPIABackend_Stop_NotRunning(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestPIABackend_SelectedServer_NilWhenNotStarted(t *testing.T) {
	b := NewPIABackend(PIAConfig{Name: "test", Username: "user", Password: "pass"})

	server := b.SelectedServer()
	assert.Nil(t, server)
}
