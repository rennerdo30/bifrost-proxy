// Package mesh provides Hamachi-like mesh networking functionality.
package mesh

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/device"
)

// Config contains mesh network configuration.
type Config struct {
	// Enabled controls whether mesh networking is active (default: false).
	Enabled bool `yaml:"enabled" json:"enabled"`

	// NetworkID is the unique identifier for this mesh network.
	NetworkID string `yaml:"network_id" json:"network_id"`

	// NetworkCIDR is the CIDR block for virtual IP allocation (e.g., "10.100.0.0/16").
	NetworkCIDR string `yaml:"network_cidr" json:"network_cidr"`

	// PeerName is the friendly name for this peer in the network.
	PeerName string `yaml:"peer_name" json:"peer_name"`

	// Device contains network device configuration.
	Device DeviceConfig `yaml:"device" json:"device"`

	// Discovery contains peer discovery settings.
	Discovery DiscoveryConfig `yaml:"discovery" json:"discovery"`

	// STUN contains STUN server configuration for NAT traversal.
	STUN STUNConfig `yaml:"stun" json:"stun"`

	// TURN contains TURN server configuration for relay.
	TURN TURNConfig `yaml:"turn" json:"turn"`

	// Connection contains P2P connection settings.
	Connection ConnectionConfig `yaml:"connection" json:"connection"`

	// Security contains security settings.
	Security SecurityConfig `yaml:"security" json:"security"`
}

// DeviceConfig contains network device settings for mesh networking.
type DeviceConfig struct {
	// Type is the device type: "tun" (Layer 3) or "tap" (Layer 2).
	Type string `yaml:"type" json:"type"`

	// Name is the interface name (e.g., "mesh0").
	Name string `yaml:"name" json:"name"`

	// MTU is the Maximum Transmission Unit (default: 1400).
	MTU int `yaml:"mtu" json:"mtu"`

	// MACAddress is the MAC address for TAP devices (auto-generated if empty).
	MACAddress string `yaml:"mac_address,omitempty" json:"mac_address,omitempty"`
}

// DiscoveryConfig contains peer discovery settings.
type DiscoveryConfig struct {
	// Server is the discovery server address (e.g., "bifrost.example.com:8080").
	Server string `yaml:"server" json:"server"`

	// HeartbeatInterval is how often to send heartbeats (default: 30s).
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`

	// PeerTimeout is how long before a peer is considered offline (default: 90s).
	PeerTimeout time.Duration `yaml:"peer_timeout" json:"peer_timeout"`

	// Token is the authentication token for the discovery server.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`
}

// STUNConfig contains STUN server configuration.
type STUNConfig struct {
	// Servers is a list of STUN server addresses.
	Servers []string `yaml:"servers" json:"servers"`

	// Timeout is the timeout for STUN requests (default: 5s).
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
}

// TURNConfig contains TURN server configuration.
type TURNConfig struct {
	// Servers is a list of TURN server configurations.
	Servers []TURNServer `yaml:"servers" json:"servers"`

	// Enabled controls whether TURN relay is enabled (default: true).
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// TURNServer contains a single TURN server configuration.
type TURNServer struct {
	// URL is the TURN server URL (e.g., "turn:turn.example.com:3478").
	URL string `yaml:"url" json:"url"`

	// Username for TURN authentication.
	Username string `yaml:"username" json:"username"`

	// Password for TURN authentication.
	Password string `yaml:"password" json:"password"`
}

// ConnectionConfig contains P2P connection settings.
type ConnectionConfig struct {
	// DirectConnect controls whether to attempt direct P2P connections (default: true).
	DirectConnect bool `yaml:"direct_connect" json:"direct_connect"`

	// RelayEnabled controls whether to use relay when direct fails (default: true).
	RelayEnabled bool `yaml:"relay_enabled" json:"relay_enabled"`

	// RelayViaPeers controls whether to relay through other peers (default: true).
	RelayViaPeers bool `yaml:"relay_via_peers" json:"relay_via_peers"`

	// ConnectTimeout is the timeout for establishing connections (default: 30s).
	ConnectTimeout time.Duration `yaml:"connect_timeout" json:"connect_timeout"`

	// KeepAliveInterval is the interval for keep-alive packets (default: 25s).
	KeepAliveInterval time.Duration `yaml:"keep_alive_interval" json:"keep_alive_interval"`
}

// SecurityConfig contains security settings.
type SecurityConfig struct {
	// PrivateKey is the Ed25519 private key for this peer (base64 encoded).
	// If empty, a new key pair will be generated.
	PrivateKey string `yaml:"private_key,omitempty" json:"private_key,omitempty"`

	// AllowedPeers is a list of allowed peer public keys (empty = allow all).
	AllowedPeers []string `yaml:"allowed_peers,omitempty" json:"allowed_peers,omitempty"`

	// RequireEncryption controls whether all connections must be encrypted (default: true).
	RequireEncryption bool `yaml:"require_encryption" json:"require_encryption"`
}

// DefaultConfig returns a mesh configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:     false, // Disabled by default
		NetworkID:   "",
		NetworkCIDR: "10.100.0.0/16",
		PeerName:    "",
		Device: DeviceConfig{
			Type: "tap", // TAP for Layer 2 (Hamachi-like)
			Name: "mesh0",
			MTU:  1400,
		},
		Discovery: DiscoveryConfig{
			HeartbeatInterval: 30 * time.Second,
			PeerTimeout:       90 * time.Second,
		},
		STUN: STUNConfig{
			Servers: []string{
				"stun:stun.l.google.com:19302",
				"stun:stun1.l.google.com:19302",
			},
			Timeout: 5 * time.Second,
		},
		TURN: TURNConfig{
			Enabled: true,
			Servers: []TURNServer{},
		},
		Connection: ConnectionConfig{
			DirectConnect:     true,
			RelayEnabled:      true,
			RelayViaPeers:     true,
			ConnectTimeout:    30 * time.Second,
			KeepAliveInterval: 25 * time.Second,
		},
		Security: SecurityConfig{
			RequireEncryption: true,
		},
	}
}

// Validate validates the mesh configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // No validation needed if disabled
	}

	if c.NetworkID == "" {
		return errors.New("mesh: network_id is required")
	}

	if c.NetworkCIDR == "" {
		return errors.New("mesh: network_cidr is required")
	}

	// Validate CIDR
	prefix, err := netip.ParsePrefix(c.NetworkCIDR)
	if err != nil {
		return fmt.Errorf("mesh: invalid network_cidr: %w", err)
	}
	if !prefix.IsValid() {
		return errors.New("mesh: invalid network_cidr prefix")
	}

	// Validate device type
	if c.Device.Type != "" && c.Device.Type != "tun" && c.Device.Type != "tap" {
		return fmt.Errorf("mesh: device type must be 'tun' or 'tap', got '%s'", c.Device.Type)
	}

	if c.Device.MTU <= 0 {
		c.Device.MTU = 1400
	}
	if c.Device.MTU < 576 {
		return fmt.Errorf("mesh: MTU too small: %d (min 576)", c.Device.MTU)
	}
	if c.Device.MTU > 65535 {
		return fmt.Errorf("mesh: MTU too large: %d (max 65535)", c.Device.MTU)
	}

	if c.Discovery.Server == "" {
		return errors.New("mesh: discovery server is required")
	}

	if c.Discovery.HeartbeatInterval <= 0 {
		c.Discovery.HeartbeatInterval = 30 * time.Second
	}

	if c.Discovery.PeerTimeout <= 0 {
		c.Discovery.PeerTimeout = 90 * time.Second
	}

	if c.Connection.ConnectTimeout <= 0 {
		c.Connection.ConnectTimeout = 30 * time.Second
	}

	if c.Connection.KeepAliveInterval <= 0 {
		c.Connection.KeepAliveInterval = 25 * time.Second
	}

	return nil
}

// ToDeviceConfig converts mesh device config to device.Config.
func (c *DeviceConfig) ToDeviceConfig(address string) device.Config {
	deviceType := device.DeviceTAP // Default to TAP for Layer 2
	if c.Type == "tun" {
		deviceType = device.DeviceTUN
	}

	return device.Config{
		Type:    deviceType,
		Name:    c.Name,
		Address: address,
		MTU:     c.MTU,
		TAP: device.TAPConfig{
			MACAddress: c.MACAddress,
		},
	}
}

// NetworkPrefix returns the parsed network prefix.
func (c *Config) NetworkPrefix() (netip.Prefix, error) {
	return netip.ParsePrefix(c.NetworkCIDR)
}
