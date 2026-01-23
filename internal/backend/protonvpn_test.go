package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewProtonVPNBackend(t *testing.T) {
	cfg := ProtonVPNConfig{
		Name:     "test-proton",
		Username: "user+pmp",
		Password: "password",
		Country:  "CH",
	}

	b := NewProtonVPNBackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-proton", b.Name())
	assert.Equal(t, "protonvpn", b.Type())
}

func TestNewProtonVPNBackend_Defaults(t *testing.T) {
	cfg := ProtonVPNConfig{
		Name:     "test",
		Username: "user+pmp",
		Password: "password",
	}

	b := NewProtonVPNBackend(cfg)

	// Check defaults are applied - ProtonVPN only supports OpenVPN
	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, 2, b.config.Tier) // TierPlus = 2
	assert.Equal(t, 30*time.Minute, b.config.RefreshInterval)
}

func TestNewProtonVPNBackend_CustomConfig(t *testing.T) {
	cfg := ProtonVPNConfig{
		Name:            "custom",
		Username:        "user+pmp",
		Password:        "password",
		Country:         "SE",
		City:            "Stockholm",
		Tier:            2, // TierPlus
		SecureCore:      true,
		RefreshInterval: 1 * time.Hour,
	}

	b := NewProtonVPNBackend(cfg)

	// Protocol should always be openvpn
	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, "SE", b.config.Country)
	assert.Equal(t, "Stockholm", b.config.City)
	assert.Equal(t, 2, b.config.Tier)
	assert.True(t, b.config.SecureCore)
	assert.Equal(t, 1*time.Hour, b.config.RefreshInterval)
}

func TestNewProtonVPNBackend_AllowsWireGuard(t *testing.T) {
	cfg := ProtonVPNConfig{
		Name:     "test",
		Username: "user+pmp",
		Password: "password",
		Protocol: "wireguard", // WireGuard can be set (though manual credentials only support OpenVPN)
	}

	b := NewProtonVPNBackend(cfg)

	// WireGuard is allowed to be set (validation happens at runtime)
	assert.Equal(t, "wireguard", b.config.Protocol)
}

func TestProtonVPNBackend_Dial_NotStarted(t *testing.T) {
	b := NewProtonVPNBackend(ProtonVPNConfig{Name: "test", Username: "user", Password: "pass"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestProtonVPNBackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewProtonVPNBackend(ProtonVPNConfig{Name: "test", Username: "user", Password: "pass"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestProtonVPNBackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewProtonVPNBackend(ProtonVPNConfig{Name: "test", Username: "user", Password: "pass"})

	assert.False(t, b.IsHealthy())
}

func TestProtonVPNBackend_Stats(t *testing.T) {
	b := NewProtonVPNBackend(ProtonVPNConfig{Name: "test-proton", Username: "user", Password: "pass"})

	stats := b.Stats()
	assert.Equal(t, "test-proton", stats.Name)
	assert.Equal(t, "protonvpn", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestProtonVPNBackend_Stop_NotRunning(t *testing.T) {
	b := NewProtonVPNBackend(ProtonVPNConfig{Name: "test", Username: "user", Password: "pass"})

	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestProtonVPNBackend_SelectedServer_NilWhenNotStarted(t *testing.T) {
	b := NewProtonVPNBackend(ProtonVPNConfig{Name: "test", Username: "user", Password: "pass"})

	server := b.SelectedServer()
	assert.Nil(t, server)
}
