//go:build !linux && !darwin && !windows

package vpn

// newPlatformProcessLookup returns a no-op process lookup for unsupported platforms.
func newPlatformProcessLookup() ProcessLookup {
	return &noopProcessLookup{}
}
