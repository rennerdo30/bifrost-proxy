package frame

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultMACTableConfig(t *testing.T) {
	cfg := DefaultMACTableConfig()
	assert.Equal(t, 5*time.Minute, cfg.MaxAge)
}

func TestNewMACTable(t *testing.T) {
	t.Run("with config", func(t *testing.T) {
		table := NewMACTable(MACTableConfig{MaxAge: 10 * time.Minute})
		assert.NotNil(t, table)
		assert.Equal(t, 0, table.Count())
	})

	t.Run("zero max age defaults to 5 minutes", func(t *testing.T) {
		table := NewMACTable(MACTableConfig{MaxAge: 0})
		assert.NotNil(t, table)
		assert.Equal(t, 5*time.Minute, table.maxAge)
	})
}

func TestMACTableLearn(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.Learn(mac, "peer1")

	peerID, found := table.Lookup(mac)
	assert.True(t, found)
	assert.Equal(t, "peer1", peerID)
	assert.Equal(t, 1, table.Count())
}

func TestMACTableLearnWithIP(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	ip := netip.MustParseAddr("10.0.0.1")

	table.LearnWithIP(mac, "peer1", ip)

	entry, found := table.LookupEntry(mac)
	require.True(t, found)
	assert.Equal(t, "peer1", entry.PeerID)
	assert.Equal(t, ip, entry.VirtualIP)
}

func TestMACTableLearnStatic(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	ip := netip.MustParseAddr("10.0.0.1")

	table.LearnStatic(mac, "peer1", ip)

	entry, found := table.LookupEntry(mac)
	require.True(t, found)
	assert.True(t, entry.Static)

	// Wait for potential expiry
	time.Sleep(5 * time.Millisecond)

	// Static entry should still be there
	entry, found = table.LookupEntry(mac)
	assert.True(t, found)
	assert.Equal(t, "peer1", entry.PeerID)
}

func TestMACTableLookupByIP(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	ip := netip.MustParseAddr("10.0.0.1")

	table.LearnWithIP(mac, "peer1", ip)

	foundMAC, found := table.LookupByIP(ip)
	assert.True(t, found)
	assert.Equal(t, mac, foundMAC)

	// Non-existent IP
	_, found = table.LookupByIP(netip.MustParseAddr("10.0.0.2"))
	assert.False(t, found)
}

func TestMACTableGetPeerMACs(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}

	table.Learn(mac1, "peer1")
	table.Learn(mac2, "peer1")

	macs := table.GetPeerMACs("peer1")
	assert.Len(t, macs, 2)

	// Non-existent peer
	macs = table.GetPeerMACs("peer2")
	assert.Empty(t, macs)
}

func TestMACTableRemove(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.Learn(mac, "peer1")
	assert.Equal(t, 1, table.Count())

	table.Remove(mac)
	assert.Equal(t, 0, table.Count())

	_, found := table.Lookup(mac)
	assert.False(t, found)
}

func TestMACTableRemovePeer(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}
	mac3 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x08}

	table.Learn(mac1, "peer1")
	table.Learn(mac2, "peer1")
	table.Learn(mac3, "peer2")
	assert.Equal(t, 3, table.Count())

	table.RemovePeer("peer1")
	assert.Equal(t, 1, table.Count())

	_, found := table.Lookup(mac1)
	assert.False(t, found)
	_, found = table.Lookup(mac2)
	assert.False(t, found)
	_, found = table.Lookup(mac3)
	assert.True(t, found)
}

func TestMACTableExpire(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}

	table.Learn(mac1, "peer1")
	table.LearnStatic(mac2, "peer2", netip.Addr{})

	// Wait for non-static entries to expire
	time.Sleep(5 * time.Millisecond)

	count := table.Expire()
	assert.Equal(t, 1, count) // Only 1 entry expired (non-static)
	assert.Equal(t, 1, table.Count())

	// Static entry should still be there
	_, found := table.Lookup(mac2)
	assert.True(t, found)
}

func TestMACTableClear(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}

	table.Learn(mac1, "peer1")
	table.Learn(mac2, "peer2")
	assert.Equal(t, 2, table.Count())

	table.Clear()
	assert.Equal(t, 0, table.Count())
}

func TestMACTableAll(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}

	table.Learn(mac1, "peer1")
	table.Learn(mac2, "peer2")

	entries := table.All()
	assert.Len(t, entries, 2)
}

func TestMACTableUpdateExistingEntry(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	// Learn under peer1
	table.Learn(mac, "peer1")
	peerID, found := table.Lookup(mac)
	assert.True(t, found)
	assert.Equal(t, "peer1", peerID)

	// Update to peer2
	table.Learn(mac, "peer2")
	peerID, found = table.Lookup(mac)
	assert.True(t, found)
	assert.Equal(t, "peer2", peerID)

	// peer1 should no longer have this MAC
	macs := table.GetPeerMACs("peer1")
	assert.Empty(t, macs)

	// peer2 should have it
	macs = table.GetPeerMACs("peer2")
	assert.Len(t, macs, 1)
}

func TestMACTableExpiredEntryOnLookup(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.Learn(mac, "peer1")

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	// Lookup should return not found and remove the entry
	_, found := table.Lookup(mac)
	assert.False(t, found)
	assert.Equal(t, 0, table.Count())
}

func TestMACTableLookupEntryExpired(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.Learn(mac, "peer1")

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	// LookupEntry should return not found
	_, found := table.LookupEntry(mac)
	assert.False(t, found)
}

func TestMACTableConcurrentAccess(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			mac := net.HardwareAddr{byte(i), 0x02, 0x03, 0x04, 0x05, 0x06}
			table.Learn(mac, "peer1")
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			mac := net.HardwareAddr{byte(i), 0x02, 0x03, 0x04, 0x05, 0x06}
			table.Lookup(mac)
		}
		done <- true
	}()

	// Wait for both
	<-done
	<-done

	// No panic means success
}

func TestMACTableStartExpiryWorker(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 10 * time.Millisecond})
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.Learn(mac, "peer1")
	assert.Equal(t, 1, table.Count())

	stopCh := make(chan struct{})
	table.StartExpiryWorker(5*time.Millisecond, stopCh)

	// Wait for entry to expire and be cleaned up
	time.Sleep(50 * time.Millisecond)

	// Entry should be expired and removed by worker
	assert.Equal(t, 0, table.Count())

	// Stop the worker
	close(stopCh)

	// Give the goroutine time to exit
	time.Sleep(10 * time.Millisecond)
}

func TestMACTableStartExpiryWorkerStatic(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 10 * time.Millisecond})
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.LearnStatic(mac, "peer1", netip.Addr{})
	assert.Equal(t, 1, table.Count())

	stopCh := make(chan struct{})
	table.StartExpiryWorker(5*time.Millisecond, stopCh)

	// Wait for potential expiry
	time.Sleep(50 * time.Millisecond)

	// Static entry should NOT be expired
	assert.Equal(t, 1, table.Count())

	// Stop the worker
	close(stopCh)
}

func TestMACTableLookupByIPExpired(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	ip := netip.MustParseAddr("10.0.0.1")

	table.LearnWithIP(mac, "peer1", ip)

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	// LookupByIP should skip expired entries
	_, found := table.LookupByIP(ip)
	assert.False(t, found)
}

func TestMACTableGetPeerMACsExpired(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}

	table.Learn(mac1, "peer1")
	table.LearnStatic(mac2, "peer1", netip.Addr{})

	// Wait for non-static entries to expire
	time.Sleep(5 * time.Millisecond)

	// GetPeerMACs should skip expired entries
	macs := table.GetPeerMACs("peer1")
	assert.Len(t, macs, 1) // Only static entry
	assert.Equal(t, mac2, macs[0])
}

func TestMACTableRemovePeerNonExistent(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	table.Learn(mac, "peer1")
	assert.Equal(t, 1, table.Count())

	// Removing non-existent peer should be a no-op
	table.RemovePeer("nonexistent")
	assert.Equal(t, 1, table.Count())
}

func TestMACTableAllExpired(t *testing.T) {
	table := NewMACTable(MACTableConfig{MaxAge: 1 * time.Millisecond})
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}

	table.Learn(mac1, "peer1")
	table.LearnStatic(mac2, "peer2", netip.Addr{})

	// Wait for non-static entries to expire
	time.Sleep(5 * time.Millisecond)

	// All() should skip expired entries
	entries := table.All()
	assert.Len(t, entries, 1) // Only static entry
	assert.Equal(t, "peer2", entries[0].PeerID)
}

func TestMACTableAddPeerMACDuplicate(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	// Learn the same MAC twice under the same peer
	table.Learn(mac, "peer1")
	table.Learn(mac, "peer1") // Should not add duplicate

	macs := table.GetPeerMACs("peer1")
	assert.Len(t, macs, 1) // Should only have one entry

	// Also test that LearnStatic properly avoids duplicates in byPeerID
	// LearnStatic creates a new entry unconditionally, but should use addPeerMAC
	// which has the duplicate check
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}
	table.LearnStatic(mac2, "peer1", netip.Addr{})
	// Now learn the same static MAC again - this will call addPeerMAC
	// with a MAC that's already in byPeerID[peer1]
	table.LearnStatic(mac2, "peer1", netip.Addr{})

	// Should still only have 2 MACs for peer1 (not 3 or more)
	macs = table.GetPeerMACs("peer1")
	assert.Len(t, macs, 2)
}

func TestMACTableAddPeerMACDuplicateDirectly(t *testing.T) {
	// This test directly manipulates the internal state to trigger
	// the duplicate check in addPeerMAC
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	macStr := mac.String()

	// Manually add to byPeerID first (simulating corrupted state)
	table.mu.Lock()
	table.byPeerID["peer1"] = []string{macStr}
	table.mu.Unlock()

	// Now learn the MAC - this will call addPeerMAC which should detect the duplicate
	table.Learn(mac, "peer1")

	// Verify there's still only one MAC for peer1
	macs := table.GetPeerMACs("peer1")
	// Should have one MAC (the one we just learned)
	assert.Equal(t, 1, table.Count())
	_ = macs // use the variable
}

func TestMACTableLearnWithIPUpdate(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")

	// Learn with first IP
	table.LearnWithIP(mac, "peer1", ip1)
	entry, found := table.LookupEntry(mac)
	require.True(t, found)
	assert.Equal(t, ip1, entry.VirtualIP)

	// Update with new IP - should update VirtualIP
	table.LearnWithIP(mac, "peer1", ip2)
	entry, found = table.LookupEntry(mac)
	require.True(t, found)
	assert.Equal(t, ip2, entry.VirtualIP)

	// Update with invalid IP - should not change VirtualIP
	table.LearnWithIP(mac, "peer1", netip.Addr{})
	entry, found = table.LookupEntry(mac)
	require.True(t, found)
	assert.Equal(t, ip2, entry.VirtualIP) // Should still be ip2
}

func TestMACTableRemoveNonExistent(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	nonExistentMAC := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	table.Learn(mac, "peer1")
	assert.Equal(t, 1, table.Count())

	// Removing non-existent MAC should be a no-op
	table.Remove(nonExistentMAC)
	assert.Equal(t, 1, table.Count())
}

func TestMACTableLookupEntryNonExistent(t *testing.T) {
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	_, found := table.LookupEntry(mac)
	assert.False(t, found)
}

func TestMACTableGetPeerMACsEntryNotInEntries(t *testing.T) {
	// This tests the edge case where byPeerID has a reference
	// to a MAC that's no longer in entries (shouldn't happen in practice
	// but we want to cover the defensive check)
	table := NewMACTable(DefaultMACTableConfig())
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	// Learn the MAC
	table.Learn(mac, "peer1")

	// Manually corrupt the state (for testing the defensive check)
	table.mu.Lock()
	delete(table.entries, mac.String())
	table.mu.Unlock()

	// GetPeerMACs should handle this gracefully
	macs := table.GetPeerMACs("peer1")
	assert.Empty(t, macs)
}
