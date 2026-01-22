package p2p

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// NATType represents the type of NAT detected.
type NATType int

const (
	// NATTypeUnknown means NAT type could not be determined.
	NATTypeUnknown NATType = iota

	// NATTypeNone means no NAT (public IP).
	NATTypeNone

	// NATTypeFullCone means full cone NAT (endpoint-independent mapping and filtering).
	// Any external host can send packets to the mapped port.
	NATTypeFullCone

	// NATTypeRestrictedCone means restricted cone NAT (endpoint-independent mapping, address-dependent filtering).
	// Only hosts we've sent to can send back.
	NATTypeRestrictedCone

	// NATTypePortRestricted means port-restricted cone NAT (endpoint-independent mapping, address+port-dependent filtering).
	// Only the exact host:port we've sent to can send back.
	NATTypePortRestricted

	// NATTypeSymmetric means symmetric NAT (endpoint-dependent mapping).
	// Different mapping for each destination - hardest to traverse.
	NATTypeSymmetric
)

// String returns a human-readable string for the NAT type.
func (t NATType) String() string {
	switch t {
	case NATTypeNone:
		return "none"
	case NATTypeFullCone:
		return "full_cone"
	case NATTypeRestrictedCone:
		return "restricted_cone"
	case NATTypePortRestricted:
		return "port_restricted"
	case NATTypeSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// IsFriendly returns true if this NAT type is relatively easy to traverse.
func (t NATType) IsFriendly() bool {
	return t == NATTypeNone || t == NATTypeFullCone || t == NATTypeRestrictedCone || t == NATTypePortRestricted
}

// NATInfo contains information about the detected NAT.
type NATInfo struct {
	// Type is the detected NAT type.
	Type NATType `json:"type"`

	// MappedAddress is our public IP:port from STUN.
	MappedAddress netip.AddrPort `json:"mapped_address"`

	// LocalAddress is our local IP:port.
	LocalAddress netip.AddrPort `json:"local_address"`

	// IsBehindNAT indicates whether we're behind a NAT.
	IsBehindNAT bool `json:"is_behind_nat"`

	// Hairpin indicates whether hairpin routing works.
	Hairpin bool `json:"hairpin"`

	// DetectedAt is when the NAT was last detected.
	DetectedAt time.Time `json:"detected_at"`
}

// NATDetector detects NAT type and characteristics.
type NATDetector struct {
	stunClient *STUNClient
	servers    []string
	timeout    time.Duration
	cachedInfo *NATInfo
	mu         sync.RWMutex
}

// NewNATDetector creates a new NAT detector.
func NewNATDetector(servers []string, timeout time.Duration) *NATDetector {
	if len(servers) == 0 {
		servers = DefaultSTUNServers()
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &NATDetector{
		stunClient: NewSTUNClient(servers, timeout),
		servers:    servers,
		timeout:    timeout,
	}
}

// Detect performs NAT detection.
func (d *NATDetector) Detect(ctx context.Context) (*NATInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Perform STUN binding to get our mapped address
	result1, err := d.stunClient.Bind(ctx)
	if err != nil {
		return nil, err
	}

	// Get local address
	localPort := d.stunClient.GetLocalPort()
	localAddr := netip.AddrPortFrom(netip.Addr{}, uint16(localPort))

	// Determine if we're behind NAT by comparing local and mapped addresses
	isBehindNAT := true // Assume NAT unless proven otherwise

	// Simple NAT type detection
	// For full detection, we'd need multiple STUN servers with different behaviors
	natType := NATTypeUnknown

	// Try a second STUN server to detect symmetric NAT
	if len(d.servers) > 1 {
		client2 := NewSTUNClient(d.servers[1:], d.timeout)
		defer client2.Close()

		result2, err := client2.Bind(ctx)
		if err == nil {
			// Compare mapped addresses from different servers
			if result1.MappedAddress == result2.MappedAddress {
				// Same mapping for different destinations - not symmetric
				natType = NATTypePortRestricted // Conservative estimate
			} else {
				// Different mapping - symmetric NAT
				natType = NATTypeSymmetric
			}
		}
	} else {
		// Can't detect fully with only one server
		natType = NATTypePortRestricted // Conservative estimate
	}

	info := &NATInfo{
		Type:          natType,
		MappedAddress: result1.MappedAddress,
		LocalAddress:  localAddr,
		IsBehindNAT:   isBehindNAT,
		Hairpin:       false, // Would need additional tests
		DetectedAt:    time.Now(),
	}

	// Cache the result
	d.mu.Lock()
	d.cachedInfo = info
	d.mu.Unlock()

	return info, nil
}

// GetCachedInfo returns the cached NAT info.
func (d *NATDetector) GetCachedInfo() *NATInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cachedInfo
}

// GetMappedAddress returns the most recently detected mapped address.
func (d *NATDetector) GetMappedAddress() (netip.AddrPort, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.cachedInfo == nil {
		return netip.AddrPort{}, false
	}
	return d.cachedInfo.MappedAddress, true
}

// Close closes the NAT detector.
func (d *NATDetector) Close() error {
	return d.stunClient.Close()
}

// CanTraverse returns whether two NAT types can likely establish a direct connection.
func CanTraverse(nat1, nat2 NATType) bool {
	// Both open or full cone - always works
	if nat1.IsFriendly() && nat2.IsFriendly() {
		return true
	}

	// One symmetric - only works with full cone on the other side
	if nat1 == NATTypeSymmetric || nat2 == NATTypeSymmetric {
		return nat1 == NATTypeFullCone || nat2 == NATTypeFullCone
	}

	// Both restricted but not symmetric - usually works with hole punching
	return true
}

// RecommendedTraversalStrategy returns the recommended strategy for connecting.
func RecommendedTraversalStrategy(nat1, nat2 NATType) string {
	if !CanTraverse(nat1, nat2) {
		return "relay"
	}

	if nat1 == NATTypeNone || nat2 == NATTypeNone {
		return "direct"
	}

	if nat1 == NATTypeFullCone && nat2 == NATTypeFullCone {
		return "direct"
	}

	if nat1 == NATTypeSymmetric || nat2 == NATTypeSymmetric {
		if nat1 == NATTypeFullCone || nat2 == NATTypeFullCone {
			return "direct_to_full_cone"
		}
		return "relay"
	}

	return "hole_punch"
}
