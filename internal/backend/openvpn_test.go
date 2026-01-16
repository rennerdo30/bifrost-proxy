package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewOpenVPNBackend(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-openvpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-openvpn", b.Name())
	assert.Equal(t, "openvpn", b.Type())
}

func TestNewOpenVPNBackend_Defaults(t *testing.T) {
	cfg := OpenVPNConfig{
		Name: "test",
	}

	b := NewOpenVPNBackend(cfg)
	assert.Equal(t, "openvpn", b.config.Binary)
	assert.Equal(t, "127.0.0.1", b.config.ManagementAddr)
	assert.Equal(t, 7505, b.config.ManagementPort)
	assert.Equal(t, 60*time.Second, b.config.ConnectTimeout)
}

func TestNewOpenVPNBackend_CustomConfig(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:           "test",
		Binary:         "/custom/openvpn",
		ManagementAddr: "192.168.1.1",
		ManagementPort: 8000,
		ConnectTimeout: 30 * time.Second,
	}

	b := NewOpenVPNBackend(cfg)
	assert.Equal(t, "/custom/openvpn", b.config.Binary)
	assert.Equal(t, "192.168.1.1", b.config.ManagementAddr)
	assert.Equal(t, 8000, b.config.ManagementPort)
	assert.Equal(t, 30*time.Second, b.config.ConnectTimeout)
}

func TestOpenVPNBackend_Dial_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestOpenVPNBackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestOpenVPNBackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	assert.False(t, b.IsHealthy())
}

func TestOpenVPNBackend_Stats(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test-openvpn"})

	stats := b.Stats()
	assert.Equal(t, "test-openvpn", stats.Name)
	assert.Equal(t, "openvpn", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestOpenVPNBackend_Stop_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	// Stop should be safe to call even when not started
	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestOpenVPNBackend_Start_MissingConfigFile(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test",
		ConfigFile: "/nonexistent/path/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)
	err := b.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config file")
}

func TestOpenVPNBackend_recordError(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	assert.Equal(t, int64(0), b.stats.errors.Load())
	assert.Equal(t, "", b.stats.lastError)

	b.recordError(assert.AnError)

	assert.Equal(t, int64(1), b.stats.errors.Load())
	assert.Equal(t, assert.AnError.Error(), b.stats.lastError)
	assert.False(t, b.stats.lastErrorTime.IsZero())
}

func TestOpenVPNBackend_cleanupTempFiles(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	// Set temp file paths (not real files, just test cleanup logic)
	b.tempConfigFile = "/tmp/test-config"
	b.tempAuthFile = "/tmp/test-auth"

	// Cleanup should clear the paths (actual file removal will fail silently for non-existent files)
	b.cleanupTempFiles()

	assert.Equal(t, "", b.tempConfigFile)
	assert.Equal(t, "", b.tempAuthFile)
}

func TestOpenVPNConfig_InlineContent(t *testing.T) {
	cfg := OpenVPNConfig{
		Name: "inline-test",
		ConfigContent: `
client
dev tun
proto udp
remote vpn.example.com 1194
`,
		Username: "testuser",
		Password: "testpass",
	}

	assert.Equal(t, "inline-test", cfg.Name)
	assert.Contains(t, cfg.ConfigContent, "client")
	assert.Contains(t, cfg.ConfigContent, "remote vpn.example.com 1194")
	assert.Equal(t, "testuser", cfg.Username)
	assert.Equal(t, "testpass", cfg.Password)
}

func TestOpenVPNConfig_Struct(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:           "my-vpn",
		ConfigFile:     "/path/to/config.ovpn",
		ConfigContent:  "content",
		AuthFile:       "/path/to/auth",
		Username:       "user",
		Password:       "pass",
		ManagementAddr: "127.0.0.1",
		ManagementPort: 7505,
		Binary:         "/usr/sbin/openvpn",
		ExtraArgs:      []string{"--verb", "3"},
		ConnectTimeout: 60 * time.Second,
	}

	assert.Equal(t, "my-vpn", cfg.Name)
	assert.Equal(t, "/path/to/config.ovpn", cfg.ConfigFile)
	assert.Equal(t, "content", cfg.ConfigContent)
	assert.Equal(t, "/path/to/auth", cfg.AuthFile)
	assert.Equal(t, "user", cfg.Username)
	assert.Equal(t, "pass", cfg.Password)
	assert.Equal(t, "127.0.0.1", cfg.ManagementAddr)
	assert.Equal(t, 7505, cfg.ManagementPort)
	assert.Equal(t, "/usr/sbin/openvpn", cfg.Binary)
	assert.Equal(t, []string{"--verb", "3"}, cfg.ExtraArgs)
	assert.Equal(t, 60*time.Second, cfg.ConnectTimeout)
}
