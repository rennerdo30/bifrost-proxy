//go:build !linux && !darwin && !windows

package vpn

import (
	"errors"
)

// createPlatformTUN returns an error on unsupported platforms.
func createPlatformTUN(cfg TUNConfig) (TUNDevice, error) {
	return nil, errors.New("TUN device not supported on this platform")
}
