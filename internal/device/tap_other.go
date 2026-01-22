//go:build !linux && !darwin && !windows

package device

// createPlatformTAP returns an error on unsupported platforms.
func createPlatformTAP(cfg Config) (NetworkDevice, error) {
	return nil, ErrTAPNotSupported
}
