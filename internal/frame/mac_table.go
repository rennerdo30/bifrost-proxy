package frame

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// MACEntry represents an entry in the MAC address table.
type MACEntry struct {
	MAC       net.HardwareAddr // MAC address
	PeerID    string           // Peer ID that owns this MAC
	VirtualIP netip.Addr       // Virtual IP address (if known)
	LastSeen  time.Time        // Last time traffic was seen from this MAC
	LearnedAt time.Time        // When this entry was first learned
	Static    bool             // Whether this is a static entry (won't expire)
}

// MACTable maintains a mapping between MAC addresses and peer identities.
// It provides thread-safe operations for learning and looking up MAC addresses.
type MACTable struct {
	entries  map[string]*MACEntry // Key is MAC address string
	byPeerID map[string][]string  // PeerID -> list of MAC address strings
	maxAge   time.Duration        // Maximum age before entry expires
	mu       sync.RWMutex
}

// MACTableConfig contains configuration for the MAC table.
type MACTableConfig struct {
	MaxAge time.Duration // Maximum age before entry expires (0 = never expire)
}

// DefaultMACTableConfig returns sensible defaults.
func DefaultMACTableConfig() MACTableConfig {
	return MACTableConfig{
		MaxAge: 5 * time.Minute,
	}
}

// NewMACTable creates a new MAC address table.
func NewMACTable(cfg MACTableConfig) *MACTable {
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 5 * time.Minute
	}

	return &MACTable{
		entries:  make(map[string]*MACEntry),
		byPeerID: make(map[string][]string),
		maxAge:   cfg.MaxAge,
	}
}

// Learn adds or updates a MAC address entry.
func (t *MACTable) Learn(mac net.HardwareAddr, peerID string) {
	t.LearnWithIP(mac, peerID, netip.Addr{})
}

// LearnWithIP adds or updates a MAC address entry with an associated IP.
func (t *MACTable) LearnWithIP(mac net.HardwareAddr, peerID string, ip netip.Addr) {
	macStr := mac.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.entries[macStr]
	if exists {
		// Update existing entry
		oldPeerID := entry.PeerID
		entry.PeerID = peerID
		entry.LastSeen = now
		if ip.IsValid() {
			entry.VirtualIP = ip
		}

		// Update peer ID mapping if it changed
		if oldPeerID != peerID {
			t.removePeerMAC(oldPeerID, macStr)
			t.addPeerMAC(peerID, macStr)
		}
	} else {
		// Create new entry
		entry = &MACEntry{
			MAC:       mac,
			PeerID:    peerID,
			VirtualIP: ip,
			LastSeen:  now,
			LearnedAt: now,
			Static:    false,
		}
		t.entries[macStr] = entry
		t.addPeerMAC(peerID, macStr)
	}
}

// LearnStatic adds a static (non-expiring) MAC address entry.
func (t *MACTable) LearnStatic(mac net.HardwareAddr, peerID string, ip netip.Addr) {
	macStr := mac.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := &MACEntry{
		MAC:       mac,
		PeerID:    peerID,
		VirtualIP: ip,
		LastSeen:  now,
		LearnedAt: now,
		Static:    true,
	}
	t.entries[macStr] = entry
	t.addPeerMAC(peerID, macStr)
}

// Lookup returns the peer ID for a given MAC address.
func (t *MACTable) Lookup(mac net.HardwareAddr) (string, bool) {
	macStr := mac.String()

	t.mu.RLock()
	entry, exists := t.entries[macStr]
	t.mu.RUnlock()

	if !exists {
		return "", false
	}

	// Check if entry has expired
	if !entry.Static && time.Since(entry.LastSeen) > t.maxAge {
		t.Remove(mac)
		return "", false
	}

	return entry.PeerID, true
}

// LookupEntry returns the full entry for a given MAC address.
func (t *MACTable) LookupEntry(mac net.HardwareAddr) (*MACEntry, bool) {
	macStr := mac.String()

	t.mu.RLock()
	entry, exists := t.entries[macStr]
	t.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Check if entry has expired
	if !entry.Static && time.Since(entry.LastSeen) > t.maxAge {
		t.Remove(mac)
		return nil, false
	}

	return entry, true
}

// LookupByIP returns the MAC address for a given IP address.
func (t *MACTable) LookupByIP(ip netip.Addr) (net.HardwareAddr, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, entry := range t.entries {
		if entry.VirtualIP == ip {
			if !entry.Static && time.Since(entry.LastSeen) > t.maxAge {
				continue // Expired
			}
			return entry.MAC, true
		}
	}

	return nil, false
}

// GetPeerMACs returns all MAC addresses for a given peer ID.
func (t *MACTable) GetPeerMACs(peerID string) []net.HardwareAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()

	macStrs, exists := t.byPeerID[peerID]
	if !exists {
		return nil
	}

	macs := make([]net.HardwareAddr, 0, len(macStrs))
	for _, macStr := range macStrs {
		if entry, ok := t.entries[macStr]; ok {
			if !entry.Static && time.Since(entry.LastSeen) > t.maxAge {
				continue // Expired
			}
			macs = append(macs, entry.MAC)
		}
	}

	return macs
}

// Remove removes a MAC address entry.
func (t *MACTable) Remove(mac net.HardwareAddr) {
	macStr := mac.String()

	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, exists := t.entries[macStr]; exists {
		t.removePeerMAC(entry.PeerID, macStr)
		delete(t.entries, macStr)
	}
}

// RemovePeer removes all MAC addresses for a peer.
func (t *MACTable) RemovePeer(peerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	macStrs, exists := t.byPeerID[peerID]
	if !exists {
		return
	}

	for _, macStr := range macStrs {
		delete(t.entries, macStr)
	}
	delete(t.byPeerID, peerID)
}

// Expire removes all expired entries.
func (t *MACTable) Expire() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	count := 0
	for macStr, entry := range t.entries {
		if !entry.Static && time.Since(entry.LastSeen) > t.maxAge {
			t.removePeerMAC(entry.PeerID, macStr)
			delete(t.entries, macStr)
			count++
		}
	}

	return count
}

// Clear removes all entries.
func (t *MACTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.entries = make(map[string]*MACEntry)
	t.byPeerID = make(map[string][]string)
}

// Count returns the number of entries.
func (t *MACTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

// All returns all entries (for debugging/monitoring).
func (t *MACTable) All() []*MACEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entries := make([]*MACEntry, 0, len(t.entries))
	for _, entry := range t.entries {
		if !entry.Static && time.Since(entry.LastSeen) > t.maxAge {
			continue // Expired
		}
		// Clone the entry to avoid race conditions
		clone := *entry
		entries = append(entries, &clone)
	}

	return entries
}

// addPeerMAC adds a MAC to the peer's MAC list (must hold write lock).
func (t *MACTable) addPeerMAC(peerID, macStr string) {
	macs := t.byPeerID[peerID]
	for _, m := range macs {
		if m == macStr {
			return // Already exists
		}
	}
	t.byPeerID[peerID] = append(macs, macStr)
}

// removePeerMAC removes a MAC from the peer's MAC list (must hold write lock).
func (t *MACTable) removePeerMAC(peerID, macStr string) {
	macs := t.byPeerID[peerID]
	for i, m := range macs {
		if m == macStr {
			t.byPeerID[peerID] = append(macs[:i], macs[i+1:]...)
			if len(t.byPeerID[peerID]) == 0 {
				delete(t.byPeerID, peerID)
			}
			return
		}
	}
}

// StartExpiryWorker starts a background goroutine that periodically expires old entries.
func (t *MACTable) StartExpiryWorker(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				t.Expire()
			case <-stopCh:
				return
			}
		}
	}()
}
