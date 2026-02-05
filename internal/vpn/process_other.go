//go:build !linux && !darwin && !windows

package vpn

import "net/netip"

// noopProcessLookup is a no-op implementation for unsupported platforms.
type noopProcessLookup struct{}

func (*noopProcessLookup) LookupBySocket(_, _ netip.AddrPort, _ string) (*ProcessInfo, error) {
	return nil, nil
}

// newPlatformProcessLookup returns a no-op process lookup for unsupported platforms.
func newPlatformProcessLookup() ProcessLookup {
	return &noopProcessLookup{}
}
