package sysproxy

import (
	"fmt"
)

// Config holds configuration for system proxy settings.
type Config struct {
	// Address is the proxy address (host:port).
	Address string
	// Enabled determines if system proxy should be set.
	Enabled bool
}

// Manager allows managing system proxy settings.
type Manager interface {
	// SetProxy sets the system proxy to the specified address.
	SetProxy(address string) error
	// ClearProxy clears (unsets) the system proxy.
	ClearProxy() error
}

// New returns a new system proxy manager for the current platform.
func New() Manager {
	return newPlatformManager()
}

// ErrNotSupported is returned when the platform does not support system proxy configuration.
var ErrNotSupported = fmt.Errorf("system proxy configuration not supported on this platform")
