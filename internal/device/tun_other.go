//go:build !linux && !darwin && !windows

package device

// createPlatformTUN returns an error on unsupported platforms.
func createPlatformTUN(cfg Config) (NetworkDevice, error) {
	return nil, ErrDeviceNotSupported
}
