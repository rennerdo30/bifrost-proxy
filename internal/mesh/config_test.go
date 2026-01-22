package mesh

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/device"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.False(t, config.Enabled)
	assert.Empty(t, config.NetworkID)
	assert.Equal(t, "10.100.0.0/16", config.NetworkCIDR)
	assert.Empty(t, config.PeerName)

	// Device defaults
	assert.Equal(t, "tap", config.Device.Type)
	assert.Equal(t, "mesh0", config.Device.Name)
	assert.Equal(t, 1400, config.Device.MTU)

	// Discovery defaults
	assert.Equal(t, 30*time.Second, config.Discovery.HeartbeatInterval)
	assert.Equal(t, 90*time.Second, config.Discovery.PeerTimeout)

	// STUN defaults
	assert.Len(t, config.STUN.Servers, 2)
	assert.Equal(t, 5*time.Second, config.STUN.Timeout)

	// TURN defaults
	assert.True(t, config.TURN.Enabled)
	assert.Empty(t, config.TURN.Servers)

	// Connection defaults
	assert.True(t, config.Connection.DirectConnect)
	assert.True(t, config.Connection.RelayEnabled)
	assert.True(t, config.Connection.RelayViaPeers)
	assert.Equal(t, 30*time.Second, config.Connection.ConnectTimeout)
	assert.Equal(t, 25*time.Second, config.Connection.KeepAliveInterval)

	// Security defaults
	assert.True(t, config.Security.RequireEncryption)
	assert.Empty(t, config.Security.PrivateKey)
	assert.Empty(t, config.Security.AllowedPeers)
}

func TestConfigValidate(t *testing.T) {
	t.Run("disabled config skips validation", func(t *testing.T) {
		config := Config{Enabled: false}
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing network_id", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkCIDR = "10.100.0.0/16"
		config.Discovery.Server = "localhost:7080"

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "network_id is required")
	})

	t.Run("missing network_cidr", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.NetworkCIDR = ""
		config.Discovery.Server = "localhost:7080"

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "network_cidr is required")
	})

	t.Run("invalid network_cidr format", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.NetworkCIDR = "invalid-cidr"
		config.Discovery.Server = "localhost:7080"

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network_cidr")
	})

	t.Run("invalid device type", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.Type = "invalid"

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device type must be 'tun' or 'tap'")
	})

	t.Run("valid device type tun", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.Type = "tun"

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid device type tap", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.Type = "tap"

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("empty device type defaults", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.Type = ""

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("MTU too small", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.MTU = 100

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU too small")
	})

	t.Run("MTU too large", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.MTU = 100000

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU too large")
	})

	t.Run("MTU zero gets default", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.MTU = 0

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 1400, config.Device.MTU)
	})

	t.Run("MTU negative gets default", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Device.MTU = -100

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 1400, config.Device.MTU)
	})

	t.Run("missing discovery server", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = ""

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "discovery server is required")
	})

	t.Run("heartbeat interval zero gets default", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Discovery.HeartbeatInterval = 0

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 30*time.Second, config.Discovery.HeartbeatInterval)
	})

	t.Run("peer timeout zero gets default", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Discovery.PeerTimeout = 0

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 90*time.Second, config.Discovery.PeerTimeout)
	})

	t.Run("connect timeout zero gets default", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Connection.ConnectTimeout = 0

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 30*time.Second, config.Connection.ConnectTimeout)
	})

	t.Run("keepalive interval zero gets default", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"
		config.Connection.KeepAliveInterval = 0

		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 25*time.Second, config.Connection.KeepAliveInterval)
	})

	t.Run("valid complete config", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.NetworkCIDR = "192.168.100.0/24"
		config.PeerName = "test-peer"
		config.Discovery.Server = "localhost:7080"
		config.Discovery.Token = "secret-token"

		err := config.Validate()
		assert.NoError(t, err)
	})
}

func TestDeviceConfigToDeviceConfig(t *testing.T) {
	t.Run("TAP device", func(t *testing.T) {
		dc := DeviceConfig{
			Type:       "tap",
			Name:       "mesh0",
			MTU:        1400,
			MACAddress: "aa:bb:cc:dd:ee:ff",
		}

		cfg := dc.ToDeviceConfig("10.100.0.1/16")

		assert.Equal(t, device.DeviceTAP, cfg.Type)
		assert.Equal(t, "mesh0", cfg.Name)
		assert.Equal(t, "10.100.0.1/16", cfg.Address)
		assert.Equal(t, 1400, cfg.MTU)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", cfg.TAP.MACAddress)
	})

	t.Run("TUN device", func(t *testing.T) {
		dc := DeviceConfig{
			Type: "tun",
			Name: "tun0",
			MTU:  1500,
		}

		cfg := dc.ToDeviceConfig("10.0.0.1/24")

		assert.Equal(t, device.DeviceTUN, cfg.Type)
		assert.Equal(t, "tun0", cfg.Name)
		assert.Equal(t, "10.0.0.1/24", cfg.Address)
		assert.Equal(t, 1500, cfg.MTU)
	})

	t.Run("empty type defaults to TAP", func(t *testing.T) {
		dc := DeviceConfig{
			Type: "",
			Name: "default",
			MTU:  1400,
		}

		cfg := dc.ToDeviceConfig("10.0.0.1/24")

		assert.Equal(t, device.DeviceTAP, cfg.Type)
	})
}

func TestConfigNetworkPrefix(t *testing.T) {
	t.Run("valid IPv4 prefix", func(t *testing.T) {
		config := Config{
			NetworkCIDR: "10.100.0.0/16",
		}

		prefix, err := config.NetworkPrefix()
		require.NoError(t, err)

		assert.True(t, prefix.IsValid())
		assert.Equal(t, 16, prefix.Bits())
		assert.Equal(t, netip.MustParseAddr("10.100.0.0"), prefix.Addr())
	})

	t.Run("valid IPv4 /24 prefix", func(t *testing.T) {
		config := Config{
			NetworkCIDR: "192.168.1.0/24",
		}

		prefix, err := config.NetworkPrefix()
		require.NoError(t, err)

		assert.True(t, prefix.IsValid())
		assert.Equal(t, 24, prefix.Bits())
	})

	t.Run("valid IPv6 prefix", func(t *testing.T) {
		config := Config{
			NetworkCIDR: "fd00::/64",
		}

		prefix, err := config.NetworkPrefix()
		require.NoError(t, err)

		assert.True(t, prefix.IsValid())
		assert.Equal(t, 64, prefix.Bits())
	})

	t.Run("invalid prefix", func(t *testing.T) {
		config := Config{
			NetworkCIDR: "invalid",
		}

		_, err := config.NetworkPrefix()
		assert.Error(t, err)
	})

	t.Run("empty prefix", func(t *testing.T) {
		config := Config{
			NetworkCIDR: "",
		}

		_, err := config.NetworkPrefix()
		assert.Error(t, err)
	})
}

func TestTURNServer(t *testing.T) {
	server := TURNServer{
		URL:      "turn:turn.example.com:3478",
		Username: "user",
		Password: "pass",
	}

	assert.Equal(t, "turn:turn.example.com:3478", server.URL)
	assert.Equal(t, "user", server.Username)
	assert.Equal(t, "pass", server.Password)
}

func TestSTUNConfig(t *testing.T) {
	config := STUNConfig{
		Servers: []string{
			"stun:stun1.example.com:19302",
			"stun:stun2.example.com:19302",
		},
		Timeout: 10 * time.Second,
	}

	assert.Len(t, config.Servers, 2)
	assert.Equal(t, 10*time.Second, config.Timeout)
}

func TestConnectionConfig(t *testing.T) {
	config := ConnectionConfig{
		DirectConnect:     false,
		RelayEnabled:      false,
		RelayViaPeers:     false,
		ConnectTimeout:    60 * time.Second,
		KeepAliveInterval: 15 * time.Second,
	}

	assert.False(t, config.DirectConnect)
	assert.False(t, config.RelayEnabled)
	assert.False(t, config.RelayViaPeers)
	assert.Equal(t, 60*time.Second, config.ConnectTimeout)
	assert.Equal(t, 15*time.Second, config.KeepAliveInterval)
}

func TestSecurityConfig(t *testing.T) {
	config := SecurityConfig{
		PrivateKey:        "base64privatekey",
		AllowedPeers:      []string{"peer1", "peer2"},
		RequireEncryption: true,
	}

	assert.Equal(t, "base64privatekey", config.PrivateKey)
	assert.Len(t, config.AllowedPeers, 2)
	assert.True(t, config.RequireEncryption)
}

func TestDiscoveryConfig(t *testing.T) {
	config := DiscoveryConfig{
		Server:            "discovery.example.com:7080",
		HeartbeatInterval: 45 * time.Second,
		PeerTimeout:       120 * time.Second,
		Token:             "auth-token",
	}

	assert.Equal(t, "discovery.example.com:7080", config.Server)
	assert.Equal(t, 45*time.Second, config.HeartbeatInterval)
	assert.Equal(t, 120*time.Second, config.PeerTimeout)
	assert.Equal(t, "auth-token", config.Token)
}
