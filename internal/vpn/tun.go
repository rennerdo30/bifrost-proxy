package vpn

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
)

// TUNDevice represents a TUN network interface.
type TUNDevice interface {
	// Name returns the interface name (e.g., "bifrost0", "utun5").
	Name() string

	// Read reads a packet from the TUN device.
	// Returns the number of bytes read.
	Read(packet []byte) (int, error)

	// Write writes a packet to the TUN device.
	// Returns the number of bytes written.
	Write(packet []byte) (int, error)

	// Close closes the TUN device.
	Close() error

	// MTU returns the MTU of the interface.
	MTU() int
}

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

// CreateTUN creates a new TUN device.
// The implementation is platform-specific.
func CreateTUN(cfg TUNConfig) (TUNDevice, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return createPlatformTUN(cfg)
}

// TUNError represents a TUN-specific error.
type TUNError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *TUNError) Error() string {
	return fmt.Sprintf("tun %s: %v", e.Op, e.Err)
}

func (e *TUNError) Unwrap() error {
	return e.Err
}

// Common TUN errors.
var (
	ErrTUNNotSupported    = errors.New("TUN not supported on this platform")
	ErrTUNPermissionDenied = errors.New("permission denied: TUN creation requires root/admin privileges")
	ErrTUNAlreadyExists   = errors.New("TUN interface already exists")
	ErrTUNClosed          = errors.New("TUN device is closed")
)
