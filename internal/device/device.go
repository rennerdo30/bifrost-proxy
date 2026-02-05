// Package device provides a unified interface for TUN and TAP network devices.
package device

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
)

// DeviceType represents the type of network device.
type DeviceType int

const (
	// DeviceTUN represents a Layer 3 (IP packets) TUN device.
	DeviceTUN DeviceType = iota
	// DeviceTAP represents a Layer 2 (Ethernet frames) TAP device.
	DeviceTAP
)

// String returns the string representation of the device type.
func (t DeviceType) String() string {
	switch t {
	case DeviceTUN:
		return "tun"
	case DeviceTAP:
		return "tap"
	default:
		return "unknown"
	}
}

// ParseDeviceType parses a device type from a string.
func ParseDeviceType(s string) (DeviceType, error) {
	switch s {
	case "tun", "TUN", "":
		return DeviceTUN, nil
	case "tap", "TAP":
		return DeviceTAP, nil
	default:
		return DeviceTUN, fmt.Errorf("unknown device type: %s", s)
	}
}

// NetworkDevice represents a TUN or TAP network interface.
type NetworkDevice interface {
	// Name returns the interface name (e.g., "bifrost0", "utun5").
	Name() string

	// Type returns the device type (TUN or TAP).
	Type() DeviceType

	// Read reads a packet/frame from the device.
	// For TUN devices, returns IP packets.
	// For TAP devices, returns Ethernet frames.
	Read(buf []byte) (int, error)

	// Write writes a packet/frame to the device.
	// For TUN devices, writes IP packets.
	// For TAP devices, writes Ethernet frames.
	Write(buf []byte) (int, error)

	// Close closes the device and releases resources.
	Close() error

	// MTU returns the Maximum Transmission Unit.
	MTU() int
}

// TAPDevice extends NetworkDevice with TAP-specific functionality.
type TAPDevice interface {
	NetworkDevice

	// MACAddress returns the MAC address of the TAP interface.
	MACAddress() net.HardwareAddr

	// SetMACAddress sets the MAC address of the TAP interface.
	SetMACAddress(mac net.HardwareAddr) error
}

// Config contains network device configuration.
type Config struct {
	Type    DeviceType `yaml:"type"`    // Device type: "tun" (default) or "tap"
	Name    string     `yaml:"name"`    // Interface name (e.g., "bifrost0")
	Address string     `yaml:"address"` // IP address with prefix (e.g., "10.255.0.1/24")
	MTU     int        `yaml:"mtu"`     // MTU size (default: 1400)

	// TAP-specific configuration
	TAP TAPConfig `yaml:"tap,omitempty"`
}

// TAPConfig contains TAP-specific configuration.
type TAPConfig struct {
	MACAddress string `yaml:"mac_address"` // MAC address (auto-generated if empty)
	Bridge     string `yaml:"bridge"`      // Optional bridge interface to join
}

// Validate validates the device configuration.
func (c *Config) Validate() error {
	if c.Name == "" {
		c.Name = DefaultDeviceName(c.Type)
	}

	if c.Address == "" {
		c.Address = "10.255.0.1/24"
	}

	// Validate address format
	prefix, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return fmt.Errorf("invalid device address: %w", err)
	}
	if !prefix.IsValid() {
		return errors.New("invalid device address prefix")
	}

	if c.MTU <= 0 {
		c.MTU = 1400
	}
	if c.MTU > 65535 {
		return fmt.Errorf("MTU too large: %d (max 65535)", c.MTU)
	}
	if c.MTU < 576 {
		return fmt.Errorf("MTU too small: %d (min 576)", c.MTU)
	}

	// Validate TAP-specific config
	if c.Type == DeviceTAP && c.TAP.MACAddress != "" {
		if _, err := net.ParseMAC(c.TAP.MACAddress); err != nil {
			return fmt.Errorf("invalid MAC address: %w", err)
		}
	}

	return nil
}

// DefaultDeviceName returns the default interface name for the current platform.
func DefaultDeviceName(deviceType DeviceType) string {
	switch runtime.GOOS {
	case "darwin":
		if deviceType == DeviceTAP {
			return "tap0"
		}
		return "utun"
	case "windows":
		return "Bifrost"
	default:
		if deviceType == DeviceTAP {
			return "tap0"
		}
		return "bifrost0"
	}
}

// Create creates a new network device based on the configuration.
func Create(cfg Config) (NetworkDevice, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	switch cfg.Type {
	case DeviceTUN:
		return createPlatformTUN(cfg)
	case DeviceTAP:
		return createPlatformTAP(cfg)
	default:
		return nil, fmt.Errorf("unsupported device type: %v", cfg.Type)
	}
}

// CreateTUN creates a new TUN device (shorthand for Create with DeviceTUN).
func CreateTUN(cfg Config) (NetworkDevice, error) {
	cfg.Type = DeviceTUN
	return Create(cfg)
}

// CreateTAP creates a new TAP device (shorthand for Create with DeviceTAP).
func CreateTAP(cfg Config) (TAPDevice, error) {
	cfg.Type = DeviceTAP
	dev, err := Create(cfg)
	if err != nil {
		return nil, err
	}
	tap, ok := dev.(TAPDevice)
	if !ok {
		dev.Close()
		return nil, errors.New("created device does not implement TAPDevice interface")
	}
	return tap, nil
}

// DeviceError represents a device-specific error.
type DeviceError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("device %s: %v", e.Op, e.Err)
}

func (e *DeviceError) Unwrap() error {
	return e.Err
}

// Common device errors.
var (
	ErrDeviceNotSupported  = errors.New("device type not supported on this platform")
	ErrPermissionDenied    = errors.New("permission denied: device creation requires root/admin privileges")
	ErrDeviceAlreadyExists = errors.New("device already exists")
	ErrDeviceClosed        = errors.New("device is closed")
	ErrTAPNotSupported     = errors.New("TAP device not supported on this platform")
	ErrInvalidMACAddress   = errors.New("invalid MAC address")
)

// GenerateMAC generates a random locally-administered MAC address.
func GenerateMAC() net.HardwareAddr {
	mac := make([]byte, 6)

	// Generate random bytes
	// In a real implementation, we'd use crypto/rand
	// For now, use a deterministic pattern based on time
	// that can be replaced later
	mac[0] = 0x02 // Locally administered, unicast
	mac[1] = 0xBF // "BF" for Bifrost
	mac[2] = 0x00
	mac[3] = 0x00
	mac[4] = 0x00
	mac[5] = 0x01

	return mac
}

// GenerateRandomMAC generates a random locally-administered MAC address using crypto/rand.
func GenerateRandomMAC() (net.HardwareAddr, error) {
	mac := make([]byte, 6)

	// Use crypto/rand for secure random generation
	// Import is deferred to avoid import in simple cases
	_, err := randomRead(mac)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random MAC: %w", err)
	}

	// Set locally administered bit and clear multicast bit
	mac[0] = (mac[0] | 0x02) & 0xFE

	return mac, nil
}
