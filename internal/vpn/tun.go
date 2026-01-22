package vpn

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/rennerdo30/bifrost-proxy/internal/device"
)

// TUNDevice represents a TUN network interface.
// This is an alias to the device.NetworkDevice interface for backwards compatibility.
type TUNDevice = device.NetworkDevice

// TUNConfig contains TUN device configuration.
type TUNConfig struct {
	Name    string `yaml:"name"`    // Interface name (e.g., "bifrost0")
	Address string `yaml:"address"` // IP address with prefix (e.g., "10.255.0.1/24")
	MTU     int    `yaml:"mtu"`     // MTU size (default: 1400)
}

// Validate validates the TUN configuration.
func (c *TUNConfig) Validate() error {
	if c.Name == "" {
		c.Name = defaultTUNName()
	}

	if c.Address == "" {
		c.Address = "10.255.0.1/24"
	}

	// Validate address format
	prefix, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}
	if !prefix.IsValid() {
		return errors.New("invalid TUN address prefix")
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

	return nil
}

// defaultTUNName returns the default TUN interface name for the current platform.
func defaultTUNName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun" // macOS will assign a number
	case "windows":
		return "Bifrost"
	default:
		return "bifrost0"
	}
}

// CreateTUN creates a new TUN device using the unified device package.
// The implementation is platform-specific.
func CreateTUN(cfg TUNConfig) (TUNDevice, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Convert to device.Config and create using the device package
	deviceCfg := device.Config{
		Type:    device.DeviceTUN,
		Name:    cfg.Name,
		Address: cfg.Address,
		MTU:     cfg.MTU,
	}

	return device.Create(deviceCfg)
}

// TUNError represents a TUN-specific error.
// This is an alias to device.DeviceError for backwards compatibility.
type TUNError = device.DeviceError

// Common TUN errors - re-exported from device package.
var (
	ErrTUNNotSupported     = device.ErrDeviceNotSupported
	ErrTUNPermissionDenied = device.ErrPermissionDenied
	ErrTUNAlreadyExists    = device.ErrDeviceAlreadyExists
	ErrTUNClosed           = device.ErrDeviceClosed
)
