package vpn

import (
	"net/netip"
)

// ProcessInfo contains information about a process.
type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// ProcessLookup provides process identification from network sockets.
type ProcessLookup interface {
	// LookupBySocket finds the process associated with a network socket.
	// Parameters:
	//   - local: Local address and port of the socket
	//   - remote: Remote address and port of the socket
	//   - proto: Protocol ("tcp" or "udp")
	// Returns the process info or nil if not found.
	LookupBySocket(local, remote netip.AddrPort, proto string) (*ProcessInfo, error)
}

// NewProcessLookup creates a platform-specific process lookup implementation.
func NewProcessLookup() ProcessLookup {
	return newPlatformProcessLookup()
}
