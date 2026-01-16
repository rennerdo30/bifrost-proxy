package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewWireGuardBackend(t *testing.T) {
	cfg := WireGuardConfig{
		Name:       "test-wg",
		PrivateKey: "private_key",
		Address:    "10.0.0.2/24",
		DNS:        []string{"8.8.8.8"},
		Peer: WireGuardPeer{
			PublicKey:  "public_key",
			Endpoint:   "vpn.example.com:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		},
	}

	b := NewWireGuardBackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-wg", b.Name())
	assert.Equal(t, "wireguard", b.Type())
}

func TestNewWireGuardBackend_DefaultMTU(t *testing.T) {
	cfg := WireGuardConfig{
		Name: "test-wg",
		// MTU is 0, should default to 1420
	}

	b := NewWireGuardBackend(cfg)
	assert.Equal(t, 1420, b.config.MTU)
}

func TestNewWireGuardBackend_CustomMTU(t *testing.T) {
	cfg := WireGuardConfig{
		Name: "test-wg",
		MTU:  1400,
	}

	b := NewWireGuardBackend(cfg)
	assert.Equal(t, 1400, b.config.MTU)
}

func TestWireGuardBackend_Dial_NotStarted(t *testing.T) {
	b := NewWireGuardBackend(WireGuardConfig{Name: "test"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestWireGuardBackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewWireGuardBackend(WireGuardConfig{Name: "test"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestWireGuardBackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewWireGuardBackend(WireGuardConfig{Name: "test"})

	assert.False(t, b.IsHealthy())
}

func TestWireGuardBackend_Stats(t *testing.T) {
	b := NewWireGuardBackend(WireGuardConfig{Name: "test-wg"})

	stats := b.Stats()
	assert.Equal(t, "test-wg", stats.Name)
	assert.Equal(t, "wireguard", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestWireGuardBackend_Stop_NotStarted(t *testing.T) {
	b := NewWireGuardBackend(WireGuardConfig{Name: "test"})

	// Stop should be safe to call even when not started
	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestWireGuardBackend_Start_InvalidAddress(t *testing.T) {
	cfg := WireGuardConfig{
		Name:       "test-wg",
		PrivateKey: "private_key",
		Address:    "invalid-address",
	}

	b := NewWireGuardBackend(cfg)
	err := b.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse address")
}

func TestWireGuardBackend_Start_InvalidDNS(t *testing.T) {
	cfg := WireGuardConfig{
		Name:       "test-wg",
		PrivateKey: "private_key",
		Address:    "10.0.0.2/24",
		DNS:        []string{"invalid-dns"},
	}

	b := NewWireGuardBackend(cfg)
	err := b.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse dns")
}

func TestWireGuardBackend_buildConfig(t *testing.T) {
	cfg := WireGuardConfig{
		Name:       "test-wg",
		PrivateKey: "test_private_key",
		Address:    "10.0.0.2/24",
		Peer: WireGuardPeer{
			PublicKey:           "test_public_key",
			Endpoint:            "vpn.example.com:51820",
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
			PresharedKey:        "test_psk",
		},
	}

	b := NewWireGuardBackend(cfg)
	configStr := b.buildConfig()

	assert.Contains(t, configStr, "private_key=test_private_key")
	assert.Contains(t, configStr, "public_key=test_public_key")
	assert.Contains(t, configStr, "preshared_key=test_psk")
	assert.Contains(t, configStr, "endpoint=vpn.example.com:51820")
	assert.Contains(t, configStr, "allowed_ip=0.0.0.0/0")
	assert.Contains(t, configStr, "allowed_ip=::/0")
	assert.Contains(t, configStr, "persistent_keepalive_interval=25")
}

func TestWireGuardBackend_buildConfig_NoPresharedKey(t *testing.T) {
	cfg := WireGuardConfig{
		Name:       "test-wg",
		PrivateKey: "test_private_key",
		Peer: WireGuardPeer{
			PublicKey: "test_public_key",
		},
	}

	b := NewWireGuardBackend(cfg)
	configStr := b.buildConfig()

	assert.Contains(t, configStr, "private_key=test_private_key")
	assert.Contains(t, configStr, "public_key=test_public_key")
	assert.NotContains(t, configStr, "preshared_key")
	assert.NotContains(t, configStr, "endpoint")
	assert.NotContains(t, configStr, "persistent_keepalive_interval")
}

func TestWireGuardBackend_recordError(t *testing.T) {
	b := NewWireGuardBackend(WireGuardConfig{Name: "test"})

	assert.Equal(t, int64(0), b.stats.errors.Load())
	assert.Equal(t, "", b.stats.lastError)

	b.recordError(assert.AnError)

	assert.Equal(t, int64(1), b.stats.errors.Load())
	assert.Equal(t, assert.AnError.Error(), b.stats.lastError)
	assert.False(t, b.stats.lastErrorTime.IsZero())
}

func TestWireGuardConfig_Struct(t *testing.T) {
	cfg := WireGuardConfig{
		Name:       "my-wg",
		PrivateKey: "private",
		Address:    "10.0.0.2/24",
		DNS:        []string{"1.1.1.1", "8.8.8.8"},
		MTU:        1420,
		Peer: WireGuardPeer{
			PublicKey:           "public",
			Endpoint:            "vpn.example.com:51820",
			AllowedIPs:          []string{"0.0.0.0/0"},
			PersistentKeepalive: 25,
			PresharedKey:        "psk",
		},
	}

	assert.Equal(t, "my-wg", cfg.Name)
	assert.Equal(t, "private", cfg.PrivateKey)
	assert.Equal(t, "10.0.0.2/24", cfg.Address)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, cfg.DNS)
	assert.Equal(t, 1420, cfg.MTU)
	assert.Equal(t, "public", cfg.Peer.PublicKey)
	assert.Equal(t, "vpn.example.com:51820", cfg.Peer.Endpoint)
	assert.Equal(t, []string{"0.0.0.0/0"}, cfg.Peer.AllowedIPs)
	assert.Equal(t, 25, cfg.Peer.PersistentKeepalive)
	assert.Equal(t, "psk", cfg.Peer.PresharedKey)
}
