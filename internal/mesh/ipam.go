package mesh

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// IPAllocator manages virtual IP address allocation for a mesh network.
type IPAllocator interface {
	// Allocate allocates an IP address for a peer.
	Allocate(peerID string) (netip.Addr, error)

	// AllocateSpecific allocates a specific IP address for a peer.
	AllocateSpecific(peerID string, addr netip.Addr) error

	// Release releases an IP address allocation.
	Release(peerID string) error

	// GetIP returns the IP address for a peer.
	GetIP(peerID string) (netip.Addr, bool)

	// GetPeer returns the peer ID for an IP address.
	GetPeer(addr netip.Addr) (string, bool)

	// Available returns the number of available addresses.
	Available() int

	// Used returns the number of used addresses.
	Used() int
}

// Lease represents an IP address lease.
type Lease struct {
	PeerID    string     `json:"peer_id"`
	Address   netip.Addr `json:"address"`
	Allocated time.Time  `json:"allocated"`
	Expires   time.Time  `json:"expires,omitempty"`
	Static    bool       `json:"static"`
}

// PoolAllocator allocates IP addresses from a pool.
type PoolAllocator struct {
	prefix   netip.Prefix
	leases   map[string]*Lease     // PeerID -> Lease
	byAddr   map[netip.Addr]string // Address -> PeerID
	reserved map[netip.Addr]bool   // Reserved addresses (network, broadcast, gateway)
	leaseTTL time.Duration
	mu       sync.RWMutex
}

// PoolConfig contains IP pool configuration.
type PoolConfig struct {
	// NetworkCIDR is the network CIDR (e.g., "10.100.0.0/16").
	NetworkCIDR string

	// GatewayAddress is the gateway IP (usually first usable address).
	// If empty, it won't be reserved.
	GatewayAddress string

	// LeaseTTL is the lease duration (0 = no expiry).
	LeaseTTL time.Duration

	// ReservedAddresses is a list of additional addresses to reserve.
	ReservedAddresses []string
}

// Common IPAM errors.
var (
	ErrNoAvailableAddress = errors.New("ipam: no available address in pool")
	ErrAddressInUse       = errors.New("ipam: address already in use")
	ErrAddressOutOfRange  = errors.New("ipam: address out of pool range")
	ErrPeerNotFound       = errors.New("ipam: peer not found")
	ErrAddressReserved    = errors.New("ipam: address is reserved")
)

// NewPoolAllocator creates a new IP pool allocator.
func NewPoolAllocator(config PoolConfig) (*PoolAllocator, error) {
	prefix, err := netip.ParsePrefix(config.NetworkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}

	allocator := &PoolAllocator{
		prefix:   prefix,
		leases:   make(map[string]*Lease),
		byAddr:   make(map[netip.Addr]string),
		reserved: make(map[netip.Addr]bool),
		leaseTTL: config.LeaseTTL,
	}

	// Reserve network and broadcast addresses for IPv4
	if prefix.Addr().Is4() {
		// Reserve network address (first address)
		networkAddr := prefix.Addr()
		allocator.reserved[networkAddr] = true

		// Reserve broadcast address (last address)
		broadcastAddr := lastAddr(prefix)
		allocator.reserved[broadcastAddr] = true
	}

	// Reserve gateway address if specified
	if config.GatewayAddress != "" {
		gwAddr, err := netip.ParseAddr(config.GatewayAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid gateway address: %w", err)
		}
		allocator.reserved[gwAddr] = true
	} else {
		// Reserve first usable address as default gateway
		firstUsable := prefix.Addr().Next()
		if prefix.Contains(firstUsable) {
			allocator.reserved[firstUsable] = true
		}
	}

	// Reserve additional addresses
	for _, addrStr := range config.ReservedAddresses {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid reserved address %q: %w", addrStr, err)
		}
		allocator.reserved[addr] = true
	}

	return allocator, nil
}

// Allocate allocates an IP address for a peer.
func (a *PoolAllocator) Allocate(peerID string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if peer already has an allocation
	if lease, exists := a.leases[peerID]; exists {
		if !lease.isExpired() {
			return lease.Address, nil
		}
		// Expired lease, clean up
		delete(a.byAddr, lease.Address)
		delete(a.leases, peerID)
	}

	// Find an available address
	addr := a.prefix.Addr()
	for a.prefix.Contains(addr) {
		if !a.isAddressUsed(addr) {
			return a.allocateAddress(peerID, addr, false), nil
		}
		addr = addr.Next()
	}

	return netip.Addr{}, ErrNoAvailableAddress
}

// AllocateSpecific allocates a specific IP address for a peer.
func (a *PoolAllocator) AllocateSpecific(peerID string, addr netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if address is in range
	if !a.prefix.Contains(addr) {
		return ErrAddressOutOfRange
	}

	// Check if address is reserved
	if a.reserved[addr] {
		return ErrAddressReserved
	}

	// Check if address is already in use by another peer
	if existingPeer, exists := a.byAddr[addr]; exists {
		if existingPeer != peerID {
			lease := a.leases[existingPeer]
			if lease != nil && !lease.isExpired() {
				return ErrAddressInUse
			}
			// Expired lease, clean up
			delete(a.byAddr, addr)
			delete(a.leases, existingPeer)
		}
	}

	// Remove any existing allocation for this peer
	if oldLease, exists := a.leases[peerID]; exists {
		delete(a.byAddr, oldLease.Address)
	}

	a.allocateAddress(peerID, addr, true)
	return nil
}

// allocateAddress allocates an address (must hold write lock).
func (a *PoolAllocator) allocateAddress(peerID string, addr netip.Addr, static bool) netip.Addr {
	now := time.Now()
	var expires time.Time
	if a.leaseTTL > 0 && !static {
		expires = now.Add(a.leaseTTL)
	}

	lease := &Lease{
		PeerID:    peerID,
		Address:   addr,
		Allocated: now,
		Expires:   expires,
		Static:    static,
	}

	a.leases[peerID] = lease
	a.byAddr[addr] = peerID

	return addr
}

// Release releases an IP address allocation.
func (a *PoolAllocator) Release(peerID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	lease, exists := a.leases[peerID]
	if !exists {
		return ErrPeerNotFound
	}

	delete(a.byAddr, lease.Address)
	delete(a.leases, peerID)

	return nil
}

// GetIP returns the IP address for a peer.
func (a *PoolAllocator) GetIP(peerID string) (netip.Addr, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	lease, exists := a.leases[peerID]
	if !exists || lease.isExpired() {
		return netip.Addr{}, false
	}

	return lease.Address, true
}

// GetPeer returns the peer ID for an IP address.
func (a *PoolAllocator) GetPeer(addr netip.Addr) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	peerID, exists := a.byAddr[addr]
	if !exists {
		return "", false
	}

	// Verify lease hasn't expired
	if lease, ok := a.leases[peerID]; ok && lease.isExpired() {
		return "", false
	}

	return peerID, true
}

// Available returns the number of available addresses.
func (a *PoolAllocator) Available() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	total := a.totalAddresses()
	used := len(a.reserved) + len(a.leases)

	available := total - used
	if available < 0 {
		return 0
	}
	return available
}

// Used returns the number of used addresses.
func (a *PoolAllocator) Used() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.leases)
}

// Renew renews a lease for a peer.
func (a *PoolAllocator) Renew(peerID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	lease, exists := a.leases[peerID]
	if !exists {
		return ErrPeerNotFound
	}

	if a.leaseTTL > 0 && !lease.Static {
		lease.Expires = time.Now().Add(a.leaseTTL)
	}

	return nil
}

// Expire removes expired leases.
func (a *PoolAllocator) Expire() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	count := 0
	for peerID, lease := range a.leases {
		if lease.isExpired() {
			delete(a.byAddr, lease.Address)
			delete(a.leases, peerID)
			count++
		}
	}

	return count
}

// GetAllLeases returns all current leases.
func (a *PoolAllocator) GetAllLeases() []Lease {
	a.mu.RLock()
	defer a.mu.RUnlock()

	leases := make([]Lease, 0, len(a.leases))
	for _, lease := range a.leases {
		if !lease.isExpired() {
			leases = append(leases, *lease)
		}
	}

	return leases
}

// Prefix returns the network prefix.
func (a *PoolAllocator) Prefix() netip.Prefix {
	return a.prefix
}

// isAddressUsed checks if an address is used or reserved (must hold lock).
func (a *PoolAllocator) isAddressUsed(addr netip.Addr) bool {
	if a.reserved[addr] {
		return true
	}

	if peerID, exists := a.byAddr[addr]; exists {
		// Check if lease is still valid
		if lease, ok := a.leases[peerID]; ok && !lease.isExpired() {
			return true
		}
	}

	return false
}

// totalAddresses returns the total number of addresses in the pool.
func (a *PoolAllocator) totalAddresses() int {
	bits := a.prefix.Bits()
	if a.prefix.Addr().Is4() {
		return 1 << (32 - bits)
	}
	// For IPv6, cap at a reasonable number
	hostBits := 128 - bits
	if hostBits > 24 {
		hostBits = 24 // Cap at ~16M addresses
	}
	return 1 << hostBits
}

// isExpired checks if a lease is expired.
func (l *Lease) isExpired() bool {
	if l.Static || l.Expires.IsZero() {
		return false
	}
	return time.Now().After(l.Expires)
}

// TTL returns the remaining time-to-live for the lease.
func (l *Lease) TTL() time.Duration {
	if l.Static || l.Expires.IsZero() {
		return -1 // No expiry
	}
	ttl := time.Until(l.Expires)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// lastAddr returns the last address in a prefix (for broadcast calculation).
func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	bits := prefix.Bits()

	if addr.Is4() {
		hostBits := 32 - bits
		hostMask := uint32((1 << hostBits) - 1)
		addrBytes := addr.As4()
		addrInt := uint32(addrBytes[0])<<24 | uint32(addrBytes[1])<<16 | uint32(addrBytes[2])<<8 | uint32(addrBytes[3])
		lastInt := addrInt | hostMask
		return netip.AddrFrom4([4]byte{
			byte(lastInt >> 24),
			byte(lastInt >> 16),
			byte(lastInt >> 8),
			byte(lastInt),
		})
	}

	// For IPv6, this is simplified
	return addr
}

// StartExpiryWorker starts a background goroutine that periodically expires old leases.
func (a *PoolAllocator) StartExpiryWorker(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				a.Expire()
			case <-stopCh:
				return
			}
		}
	}()
}
