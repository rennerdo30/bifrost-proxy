package mesh

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPoolAllocator(t *testing.T) {
	t.Run("valid IPv4 config", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)
		require.NotNil(t, allocator)

		prefix := allocator.Prefix()
		assert.Equal(t, "10.100.0.0/24", prefix.String())
	})

	t.Run("valid IPv6 config", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "fd00::/64",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)
		require.NotNil(t, allocator)
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "invalid",
		}

		_, err := NewPoolAllocator(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network CIDR")
	})

	t.Run("with gateway address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR:    "10.100.0.0/24",
			GatewayAddress: "10.100.0.1",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// Gateway should be reserved, cannot allocate it
		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("10.100.0.1"))
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAddressReserved)
	})

	t.Run("with invalid gateway address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR:    "10.100.0.0/24",
			GatewayAddress: "invalid",
		}

		_, err := NewPoolAllocator(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid gateway address")
	})

	t.Run("with reserved addresses", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR:       "10.100.0.0/24",
			ReservedAddresses: []string{"10.100.0.10", "10.100.0.20"},
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// Reserved addresses cannot be allocated
		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("10.100.0.10"))
		assert.ErrorIs(t, err, ErrAddressReserved)

		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("10.100.0.20"))
		assert.ErrorIs(t, err, ErrAddressReserved)
	})

	t.Run("with invalid reserved address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR:       "10.100.0.0/24",
			ReservedAddresses: []string{"invalid"},
		}

		_, err := NewPoolAllocator(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid reserved address")
	})

	t.Run("with lease TTL", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    1 * time.Hour,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)
		assert.Equal(t, 1*time.Hour, allocator.leaseTTL)
	})

	t.Run("default gateway is reserved", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// First usable address should be reserved as gateway
		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("10.100.0.1"))
		assert.ErrorIs(t, err, ErrAddressReserved)
	})
}

func TestPoolAllocatorAllocate(t *testing.T) {
	t.Run("allocate addresses sequentially", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/28", // Small pool for testing
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// Allocate first address (should skip reserved)
		ip1, err := allocator.Allocate("peer1")
		require.NoError(t, err)
		assert.True(t, ip1.IsValid())

		// Allocate second address
		ip2, err := allocator.Allocate("peer2")
		require.NoError(t, err)
		assert.True(t, ip2.IsValid())
		assert.NotEqual(t, ip1, ip2)
	})

	t.Run("same peer gets same IP", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		ip1, err := allocator.Allocate("peer1")
		require.NoError(t, err)

		// Same peer should get same IP
		ip2, err := allocator.Allocate("peer1")
		require.NoError(t, err)
		assert.Equal(t, ip1, ip2)
	})

	t.Run("pool exhaustion", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/30", // Only 4 addresses, 3 reserved
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// Allocate available address
		_, err = allocator.Allocate("peer1")
		require.NoError(t, err)

		// Pool should be exhausted
		_, err = allocator.Allocate("peer2")
		assert.ErrorIs(t, err, ErrNoAvailableAddress)
	})

	t.Run("expired lease gets reallocated", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/28",
			LeaseTTL:    10 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		ip1, err := allocator.Allocate("peer1")
		require.NoError(t, err)

		// Wait for lease to expire
		time.Sleep(20 * time.Millisecond)

		// Peer1's lease is expired, new allocation should get a new IP
		// (or same IP if it's first available)
		ip2, err := allocator.Allocate("peer1")
		require.NoError(t, err)
		assert.True(t, ip2.IsValid())
		// The expired lease should be cleaned up and reallocated
		assert.Equal(t, ip1, ip2) // Same peer gets same address slot
	})
}

func TestPoolAllocatorAllocateSpecific(t *testing.T) {
	t.Run("allocate specific address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		targetIP := netip.MustParseAddr("10.100.0.50")
		err = allocator.AllocateSpecific("peer1", targetIP)
		require.NoError(t, err)

		ip, found := allocator.GetIP("peer1")
		assert.True(t, found)
		assert.Equal(t, targetIP, ip)
	})

	t.Run("address out of range", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("192.168.1.1"))
		assert.ErrorIs(t, err, ErrAddressOutOfRange)
	})

	t.Run("address reserved", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// Network address is reserved
		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("10.100.0.0"))
		assert.ErrorIs(t, err, ErrAddressReserved)
	})

	t.Run("address in use by another peer", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		targetIP := netip.MustParseAddr("10.100.0.50")
		err = allocator.AllocateSpecific("peer1", targetIP)
		require.NoError(t, err)

		err = allocator.AllocateSpecific("peer2", targetIP)
		assert.ErrorIs(t, err, ErrAddressInUse)
	})

	t.Run("peer can reallocate to different address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		ip1 := netip.MustParseAddr("10.100.0.50")
		ip2 := netip.MustParseAddr("10.100.0.60")

		err = allocator.AllocateSpecific("peer1", ip1)
		require.NoError(t, err)

		// Same peer can allocate different address (releases old one)
		err = allocator.AllocateSpecific("peer1", ip2)
		require.NoError(t, err)

		ip, found := allocator.GetIP("peer1")
		assert.True(t, found)
		assert.Equal(t, ip2, ip)

		// Old address should be released
		peerID, found := allocator.GetPeer(ip1)
		assert.False(t, found)
		assert.Empty(t, peerID)
	})

	t.Run("take over expired lease", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    10 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		targetIP := netip.MustParseAddr("10.100.0.50")

		// Peer1 allocates the address
		err = allocator.AllocateSpecific("peer1", targetIP)
		require.NoError(t, err)

		// Manually set lease to dynamic so it can expire
		allocator.mu.Lock()
		if lease, ok := allocator.leases["peer1"]; ok {
			lease.Static = false
			lease.Expires = time.Now().Add(10 * time.Millisecond)
		}
		allocator.mu.Unlock()

		// Wait for lease to expire
		time.Sleep(20 * time.Millisecond)

		// Peer2 should be able to take over the expired lease
		err = allocator.AllocateSpecific("peer2", targetIP)
		require.NoError(t, err)

		peerID, found := allocator.GetPeer(targetIP)
		assert.True(t, found)
		assert.Equal(t, "peer2", peerID)
	})
}

func TestPoolAllocatorRelease(t *testing.T) {
	t.Run("release existing allocation", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		ip, err := allocator.Allocate("peer1")
		require.NoError(t, err)

		err = allocator.Release("peer1")
		require.NoError(t, err)

		// IP should no longer be associated with peer
		_, found := allocator.GetIP("peer1")
		assert.False(t, found)

		// IP should no longer be associated with anyone
		_, found = allocator.GetPeer(ip)
		assert.False(t, found)
	})

	t.Run("release non-existent peer", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		err = allocator.Release("nonexistent")
		assert.ErrorIs(t, err, ErrPeerNotFound)
	})
}

func TestPoolAllocatorGetIP(t *testing.T) {
	t.Run("get existing allocation", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		allocated, err := allocator.Allocate("peer1")
		require.NoError(t, err)

		ip, found := allocator.GetIP("peer1")
		assert.True(t, found)
		assert.Equal(t, allocated, ip)
	})

	t.Run("get non-existent allocation", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		_, found := allocator.GetIP("nonexistent")
		assert.False(t, found)
	})

	t.Run("get expired allocation", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    10 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		_, err = allocator.Allocate("peer1")
		require.NoError(t, err)

		time.Sleep(20 * time.Millisecond)

		_, found := allocator.GetIP("peer1")
		assert.False(t, found)
	})
}

func TestPoolAllocatorGetPeer(t *testing.T) {
	t.Run("get peer for allocated address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		ip, err := allocator.Allocate("peer1")
		require.NoError(t, err)

		peerID, found := allocator.GetPeer(ip)
		assert.True(t, found)
		assert.Equal(t, "peer1", peerID)
	})

	t.Run("get peer for unallocated address", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		_, found := allocator.GetPeer(netip.MustParseAddr("10.100.0.50"))
		assert.False(t, found)
	})

	t.Run("get peer for expired lease", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    10 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		ip, err := allocator.Allocate("peer1")
		require.NoError(t, err)

		time.Sleep(20 * time.Millisecond)

		_, found := allocator.GetPeer(ip)
		assert.False(t, found)
	})
}

func TestPoolAllocatorAvailableAndUsed(t *testing.T) {
	config := PoolConfig{
		NetworkCIDR: "10.100.0.0/28", // 16 addresses, 3 reserved (network, gateway, broadcast)
	}

	allocator, err := NewPoolAllocator(config)
	require.NoError(t, err)

	initialAvailable := allocator.Available()
	initialUsed := allocator.Used()

	assert.Equal(t, 0, initialUsed)
	assert.Greater(t, initialAvailable, 0)

	// Allocate an address
	_, err = allocator.Allocate("peer1")
	require.NoError(t, err)

	assert.Equal(t, initialAvailable-1, allocator.Available())
	assert.Equal(t, 1, allocator.Used())

	// Allocate another
	_, err = allocator.Allocate("peer2")
	require.NoError(t, err)

	assert.Equal(t, initialAvailable-2, allocator.Available())
	assert.Equal(t, 2, allocator.Used())

	// Release one
	err = allocator.Release("peer1")
	require.NoError(t, err)

	assert.Equal(t, initialAvailable-1, allocator.Available())
	assert.Equal(t, 1, allocator.Used())
}

func TestPoolAllocatorRenew(t *testing.T) {
	t.Run("renew existing lease", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    100 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		_, err = allocator.Allocate("peer1")
		require.NoError(t, err)

		// Wait a bit
		time.Sleep(50 * time.Millisecond)

		// Renew
		err = allocator.Renew("peer1")
		require.NoError(t, err)

		// Wait some more
		time.Sleep(60 * time.Millisecond)

		// Should still be valid (original would have expired)
		ip, found := allocator.GetIP("peer1")
		assert.True(t, found)
		assert.True(t, ip.IsValid())
	})

	t.Run("renew non-existent peer", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    100 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		err = allocator.Renew("nonexistent")
		assert.ErrorIs(t, err, ErrPeerNotFound)
	})

	t.Run("renew static lease does nothing", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    100 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// AllocateSpecific creates static leases
		err = allocator.AllocateSpecific("peer1", netip.MustParseAddr("10.100.0.50"))
		require.NoError(t, err)

		// Static lease renew should not error
		err = allocator.Renew("peer1")
		require.NoError(t, err)
	})
}

func TestPoolAllocatorExpire(t *testing.T) {
	t.Run("expire removes old leases", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    10 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		_, err = allocator.Allocate("peer1")
		require.NoError(t, err)

		_, err = allocator.Allocate("peer2")
		require.NoError(t, err)

		assert.Equal(t, 2, allocator.Used())

		time.Sleep(20 * time.Millisecond)

		count := allocator.Expire()
		assert.Equal(t, 2, count)
		assert.Equal(t, 0, allocator.Used())
	})

	t.Run("expire does not remove static leases", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			LeaseTTL:    10 * time.Millisecond,
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		// Dynamic lease
		_, err = allocator.Allocate("peer1")
		require.NoError(t, err)

		// Static lease
		err = allocator.AllocateSpecific("peer2", netip.MustParseAddr("10.100.0.50"))
		require.NoError(t, err)

		assert.Equal(t, 2, allocator.Used())

		time.Sleep(20 * time.Millisecond)

		count := allocator.Expire()
		assert.Equal(t, 1, count) // Only dynamic lease expired
		assert.Equal(t, 1, allocator.Used())

		// Static lease should still exist
		ip, found := allocator.GetIP("peer2")
		assert.True(t, found)
		assert.Equal(t, netip.MustParseAddr("10.100.0.50"), ip)
	})

	t.Run("expire with no TTL does nothing", func(t *testing.T) {
		config := PoolConfig{
			NetworkCIDR: "10.100.0.0/24",
			// No LeaseTTL - leases never expire
		}

		allocator, err := NewPoolAllocator(config)
		require.NoError(t, err)

		_, err = allocator.Allocate("peer1")
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		count := allocator.Expire()
		assert.Equal(t, 0, count)
		assert.Equal(t, 1, allocator.Used())
	})
}

func TestPoolAllocatorGetAllLeases(t *testing.T) {
	config := PoolConfig{
		NetworkCIDR: "10.100.0.0/24",
	}

	allocator, err := NewPoolAllocator(config)
	require.NoError(t, err)

	// No leases initially
	leases := allocator.GetAllLeases()
	assert.Empty(t, leases)

	// Add some leases
	_, err = allocator.Allocate("peer1")
	require.NoError(t, err)

	err = allocator.AllocateSpecific("peer2", netip.MustParseAddr("10.100.0.50"))
	require.NoError(t, err)

	leases = allocator.GetAllLeases()
	assert.Len(t, leases, 2)

	// Verify lease contents
	peerIDs := make(map[string]bool)
	for _, lease := range leases {
		peerIDs[lease.PeerID] = true
		assert.True(t, lease.Address.IsValid())
		assert.False(t, lease.Allocated.IsZero())
	}
	assert.True(t, peerIDs["peer1"])
	assert.True(t, peerIDs["peer2"])
}

func TestPoolAllocatorGetAllLeasesExcludesExpired(t *testing.T) {
	config := PoolConfig{
		NetworkCIDR: "10.100.0.0/24",
		LeaseTTL:    10 * time.Millisecond,
	}

	allocator, err := NewPoolAllocator(config)
	require.NoError(t, err)

	_, err = allocator.Allocate("peer1")
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	leases := allocator.GetAllLeases()
	assert.Empty(t, leases)
}

func TestLeaseIsExpired(t *testing.T) {
	t.Run("static lease never expires", func(t *testing.T) {
		lease := &Lease{
			Static: true,
		}
		assert.False(t, lease.isExpired())
	})

	t.Run("zero expiry never expires", func(t *testing.T) {
		lease := &Lease{
			Static:  false,
			Expires: time.Time{},
		}
		assert.False(t, lease.isExpired())
	})

	t.Run("future expiry not expired", func(t *testing.T) {
		lease := &Lease{
			Static:  false,
			Expires: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, lease.isExpired())
	})

	t.Run("past expiry is expired", func(t *testing.T) {
		lease := &Lease{
			Static:  false,
			Expires: time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, lease.isExpired())
	})
}

func TestLeaseTTL(t *testing.T) {
	t.Run("static lease returns -1", func(t *testing.T) {
		lease := &Lease{
			Static: true,
		}
		assert.Equal(t, time.Duration(-1), lease.TTL())
	})

	t.Run("zero expiry returns -1", func(t *testing.T) {
		lease := &Lease{
			Static:  false,
			Expires: time.Time{},
		}
		assert.Equal(t, time.Duration(-1), lease.TTL())
	})

	t.Run("future expiry returns positive TTL", func(t *testing.T) {
		lease := &Lease{
			Static:  false,
			Expires: time.Now().Add(1 * time.Hour),
		}
		ttl := lease.TTL()
		assert.Greater(t, ttl, time.Duration(0))
		assert.LessOrEqual(t, ttl, 1*time.Hour)
	})

	t.Run("past expiry returns 0", func(t *testing.T) {
		lease := &Lease{
			Static:  false,
			Expires: time.Now().Add(-1 * time.Hour),
		}
		assert.Equal(t, time.Duration(0), lease.TTL())
	})
}

func TestLastAddr(t *testing.T) {
	t.Run("IPv4 /24", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.100.0.0/24")
		last := lastAddr(prefix)
		assert.Equal(t, netip.MustParseAddr("10.100.0.255"), last)
	})

	t.Run("IPv4 /28", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.100.0.0/28")
		last := lastAddr(prefix)
		assert.Equal(t, netip.MustParseAddr("10.100.0.15"), last)
	})

	t.Run("IPv4 /30", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.100.0.0/30")
		last := lastAddr(prefix)
		assert.Equal(t, netip.MustParseAddr("10.100.0.3"), last)
	})

	t.Run("IPv4 /16", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.100.0.0/16")
		last := lastAddr(prefix)
		assert.Equal(t, netip.MustParseAddr("10.100.255.255"), last)
	})
}

func TestPoolAllocatorStartExpiryWorker(t *testing.T) {
	config := PoolConfig{
		NetworkCIDR: "10.100.0.0/24",
		LeaseTTL:    50 * time.Millisecond,
	}

	allocator, err := NewPoolAllocator(config)
	require.NoError(t, err)

	stopCh := make(chan struct{})

	// Start expiry worker
	allocator.StartExpiryWorker(30*time.Millisecond, stopCh)

	// Allocate and wait
	_, err = allocator.Allocate("peer1")
	require.NoError(t, err)

	assert.Equal(t, 1, allocator.Used())

	// Wait for expiry (lease TTL + worker interval)
	time.Sleep(100 * time.Millisecond)

	// Lease should be expired by worker
	assert.Equal(t, 0, allocator.Used())

	// Stop the worker
	close(stopCh)
}

func TestPoolAllocatorConcurrentAccess(t *testing.T) {
	config := PoolConfig{
		NetworkCIDR: "10.100.0.0/16", // Large pool
	}

	allocator, err := NewPoolAllocator(config)
	require.NoError(t, err)

	var wg sync.WaitGroup

	// Concurrent allocations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			peerID := "peer" + string(rune('A'+i%26)) + string(rune('0'+i%10))
			allocator.Allocate(peerID)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = allocator.Available()
			_ = allocator.Used()
			_ = allocator.GetAllLeases()
		}()
	}

	wg.Wait()
}

func TestPoolAllocatorTotalAddresses(t *testing.T) {
	t.Run("IPv4 /24 has 256 addresses", func(t *testing.T) {
		config := PoolConfig{NetworkCIDR: "10.100.0.0/24"}
		allocator, _ := NewPoolAllocator(config)
		assert.Equal(t, 256, allocator.totalAddresses())
	})

	t.Run("IPv4 /28 has 16 addresses", func(t *testing.T) {
		config := PoolConfig{NetworkCIDR: "10.100.0.0/28"}
		allocator, _ := NewPoolAllocator(config)
		assert.Equal(t, 16, allocator.totalAddresses())
	})

	t.Run("IPv6 /64 is capped", func(t *testing.T) {
		config := PoolConfig{NetworkCIDR: "fd00::/64"}
		allocator, _ := NewPoolAllocator(config)
		// Should be capped at 2^24
		assert.Equal(t, 1<<24, allocator.totalAddresses())
	})
}

func BenchmarkAllocate(b *testing.B) {
	config := PoolConfig{
		NetworkCIDR: "10.0.0.0/8", // Large pool
	}

	allocator, _ := NewPoolAllocator(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allocator.Allocate("peer" + string(rune(i)))
	}
}

func BenchmarkGetIP(b *testing.B) {
	config := PoolConfig{
		NetworkCIDR: "10.0.0.0/8",
	}

	allocator, _ := NewPoolAllocator(config)

	// Pre-allocate
	for i := 0; i < 1000; i++ {
		allocator.Allocate("peer" + string(rune(i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allocator.GetIP("peer" + string(rune(i%1000)))
	}
}
