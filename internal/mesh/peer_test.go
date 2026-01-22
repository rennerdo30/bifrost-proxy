package mesh

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewPeer(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	assert.Equal(t, "peer1", peer.ID)
	assert.Equal(t, "Test Peer", peer.Name)
	assert.Equal(t, PeerStatusDiscovered, peer.Status)
	assert.NotNil(t, peer.Endpoints)
	assert.Empty(t, peer.Endpoints)
	assert.NotNil(t, peer.Metadata)
	assert.Empty(t, peer.Metadata)
	assert.False(t, peer.JoinedAt.IsZero())
	assert.False(t, peer.LastSeen.IsZero())
}

func TestPeerSetVirtualIP(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	ip := netip.MustParseAddr("10.100.0.5")

	peer.SetVirtualIP(ip)

	assert.Equal(t, ip, peer.VirtualIP)
}

func TestPeerSetVirtualMAC(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	peer.SetVirtualMAC(mac)

	assert.Equal(t, mac, peer.VirtualMAC)
}

func TestPeerSetStatus(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	testCases := []PeerStatus{
		PeerStatusDiscovered,
		PeerStatusConnecting,
		PeerStatusConnected,
		PeerStatusRelayed,
		PeerStatusUnreachable,
		PeerStatusOffline,
	}

	for _, status := range testCases {
		peer.SetStatus(status)
		assert.Equal(t, status, peer.Status)
	}
}

func TestPeerSetConnectionType(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	testCases := []ConnectionType{
		ConnectionTypeDirect,
		ConnectionTypeRelayed,
		ConnectionTypeMultiHop,
	}

	for _, connType := range testCases {
		peer.SetConnectionType(connType)
		assert.Equal(t, connType, peer.ConnectionType)
	}
}

func TestPeerUpdateLastSeen(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	originalTime := peer.LastSeen

	time.Sleep(10 * time.Millisecond)
	peer.UpdateLastSeen()

	assert.True(t, peer.LastSeen.After(originalTime))
}

func TestPeerSetLatency(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	latency := 50 * time.Millisecond

	peer.SetLatency(latency)

	assert.Equal(t, latency, peer.Latency)
}

func TestPeerAddEndpoint(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	ep1 := Endpoint{Address: "192.168.1.1", Port: 8080, Type: "local", Priority: 100}
	ep2 := Endpoint{Address: "10.0.0.1", Port: 9090, Type: "reflexive", Priority: 50}

	peer.AddEndpoint(ep1)
	assert.Len(t, peer.Endpoints, 1)

	peer.AddEndpoint(ep2)
	assert.Len(t, peer.Endpoints, 2)

	// Adding duplicate should not add
	peer.AddEndpoint(ep1)
	assert.Len(t, peer.Endpoints, 2)
}

func TestPeerRemoveEndpoint(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	ep1 := Endpoint{Address: "192.168.1.1", Port: 8080, Type: "local", Priority: 100}
	ep2 := Endpoint{Address: "10.0.0.1", Port: 9090, Type: "reflexive", Priority: 50}

	peer.AddEndpoint(ep1)
	peer.AddEndpoint(ep2)
	assert.Len(t, peer.Endpoints, 2)

	peer.RemoveEndpoint("192.168.1.1", 8080)
	assert.Len(t, peer.Endpoints, 1)
	assert.Equal(t, "10.0.0.1", peer.Endpoints[0].Address)

	// Removing non-existent endpoint
	peer.RemoveEndpoint("1.2.3.4", 1234)
	assert.Len(t, peer.Endpoints, 1)
}

func TestPeerClearEndpoints(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	peer.AddEndpoint(Endpoint{Address: "192.168.1.1", Port: 8080})
	peer.AddEndpoint(Endpoint{Address: "10.0.0.1", Port: 9090})
	assert.Len(t, peer.Endpoints, 2)

	peer.ClearEndpoints()
	assert.Empty(t, peer.Endpoints)
}

func TestPeerGetEndpoints(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	ep1 := Endpoint{Address: "192.168.1.1", Port: 8080}
	ep2 := Endpoint{Address: "10.0.0.1", Port: 9090}

	peer.AddEndpoint(ep1)
	peer.AddEndpoint(ep2)

	endpoints := peer.GetEndpoints()
	assert.Len(t, endpoints, 2)

	// Modifying returned slice should not affect original
	endpoints[0].Address = "modified"
	assert.Equal(t, "192.168.1.1", peer.Endpoints[0].Address)
}

func TestPeerMetadata(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	// Initially empty
	_, ok := peer.GetMetadata("key1")
	assert.False(t, ok)

	// Set metadata
	peer.SetMetadata("key1", "value1")
	peer.SetMetadata("key2", "value2")

	val, ok := peer.GetMetadata("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	val, ok = peer.GetMetadata("key2")
	assert.True(t, ok)
	assert.Equal(t, "value2", val)

	// Update existing key
	peer.SetMetadata("key1", "updated")
	val, ok = peer.GetMetadata("key1")
	assert.True(t, ok)
	assert.Equal(t, "updated", val)
}

func TestPeerSetMetadataWithNilMap(t *testing.T) {
	peer := &Peer{
		ID:       "peer1",
		Metadata: nil, // Explicitly nil
	}

	// Should not panic
	peer.SetMetadata("key", "value")

	val, ok := peer.GetMetadata("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)
}

func TestPeerBytesCounters(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	assert.Equal(t, int64(0), peer.BytesSent)
	assert.Equal(t, int64(0), peer.BytesReceived)

	peer.AddBytesSent(100)
	assert.Equal(t, int64(100), peer.BytesSent)

	peer.AddBytesSent(50)
	assert.Equal(t, int64(150), peer.BytesSent)

	peer.AddBytesReceived(200)
	assert.Equal(t, int64(200), peer.BytesReceived)

	peer.AddBytesReceived(75)
	assert.Equal(t, int64(275), peer.BytesReceived)
}

func TestPeerIsConnected(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	// Not connected initially
	assert.False(t, peer.IsConnected())

	// Connected status
	peer.SetStatus(PeerStatusConnected)
	assert.True(t, peer.IsConnected())

	// Relayed status
	peer.SetStatus(PeerStatusRelayed)
	assert.True(t, peer.IsConnected())

	// Disconnected statuses
	for _, status := range []PeerStatus{PeerStatusDiscovered, PeerStatusConnecting, PeerStatusUnreachable, PeerStatusOffline} {
		peer.SetStatus(status)
		assert.False(t, peer.IsConnected())
	}
}

func TestPeerIsReachable(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")

	// Reachable statuses
	for _, status := range []PeerStatus{PeerStatusDiscovered, PeerStatusConnecting, PeerStatusConnected, PeerStatusRelayed} {
		peer.SetStatus(status)
		assert.True(t, peer.IsReachable(), "Status %s should be reachable", status)
	}

	// Unreachable statuses
	peer.SetStatus(PeerStatusUnreachable)
	assert.False(t, peer.IsReachable())

	peer.SetStatus(PeerStatusOffline)
	assert.False(t, peer.IsReachable())
}

func TestPeerClone(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualIP(netip.MustParseAddr("10.100.0.5"))
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	peer.SetVirtualMAC(mac)
	peer.PublicKey = "publickey123"
	peer.SetStatus(PeerStatusConnected)
	peer.SetConnectionType(ConnectionTypeDirect)
	peer.SetLatency(50 * time.Millisecond)
	peer.AddEndpoint(Endpoint{Address: "192.168.1.1", Port: 8080})
	peer.SetMetadata("key1", "value1")
	peer.AddBytesSent(100)
	peer.AddBytesReceived(200)

	clone := peer.Clone()

	// Verify all fields are copied
	assert.Equal(t, peer.ID, clone.ID)
	assert.Equal(t, peer.Name, clone.Name)
	assert.Equal(t, peer.VirtualIP, clone.VirtualIP)
	assert.Equal(t, peer.PublicKey, clone.PublicKey)
	assert.Equal(t, peer.Status, clone.Status)
	assert.Equal(t, peer.ConnectionType, clone.ConnectionType)
	assert.Equal(t, peer.Latency, clone.Latency)
	assert.Equal(t, peer.LastSeen, clone.LastSeen)
	assert.Equal(t, peer.JoinedAt, clone.JoinedAt)
	assert.Equal(t, peer.BytesSent, clone.BytesSent)
	assert.Equal(t, peer.BytesReceived, clone.BytesReceived)

	// Verify MAC is copied correctly
	assert.Equal(t, peer.VirtualMAC, clone.VirtualMAC)

	// Verify slices/maps are independent copies
	assert.Len(t, clone.Endpoints, 1)
	clone.Endpoints[0].Address = "modified"
	assert.Equal(t, "192.168.1.1", peer.Endpoints[0].Address)

	clone.Metadata["key1"] = "modified"
	val, _ := peer.GetMetadata("key1")
	assert.Equal(t, "value1", val)
}

func TestPeerCloneWithNilMAC(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	peer.VirtualMAC = nil

	clone := peer.Clone()
	assert.Nil(t, clone.VirtualMAC)
}

func TestPeerConcurrentAccess(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			peer.SetStatus(PeerStatusConnected)
			peer.SetLatency(time.Duration(i) * time.Millisecond)
			peer.AddBytesSent(int64(i))
			peer.UpdateLastSeen()
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = peer.IsConnected()
			_ = peer.IsReachable()
			_ = peer.Clone()
		}()
	}

	wg.Wait()
}

// PeerRegistry tests

func TestNewPeerRegistry(t *testing.T) {
	registry := NewPeerRegistry()

	assert.NotNil(t, registry)
	assert.NotNil(t, registry.peers)
	assert.NotNil(t, registry.byIP)
	assert.NotNil(t, registry.byMAC)
	assert.Equal(t, 0, registry.Count())
}

func TestPeerRegistryAdd(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualIP(netip.MustParseAddr("10.100.0.5"))
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	peer.SetVirtualMAC(mac)

	registry.Add(peer)

	assert.Equal(t, 1, registry.Count())

	// Retrieve by ID
	p, found := registry.Get("peer1")
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)

	// Retrieve by IP
	p, found = registry.GetByIP(netip.MustParseAddr("10.100.0.5"))
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)

	// Retrieve by MAC
	p, found = registry.GetByMAC(mac)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryAddWithoutIP(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	// No IP set

	registry.Add(peer)

	// Should be retrievable by ID
	p, found := registry.Get("peer1")
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)

	// Not retrievable by IP
	_, found = registry.GetByIP(netip.MustParseAddr("10.100.0.5"))
	assert.False(t, found)
}

func TestPeerRegistryRemove(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualIP(netip.MustParseAddr("10.100.0.5"))
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	peer.SetVirtualMAC(mac)

	registry.Add(peer)
	assert.Equal(t, 1, registry.Count())

	registry.Remove("peer1")
	assert.Equal(t, 0, registry.Count())

	// Not found anymore
	_, found := registry.Get("peer1")
	assert.False(t, found)

	_, found = registry.GetByIP(netip.MustParseAddr("10.100.0.5"))
	assert.False(t, found)

	_, found = registry.GetByMAC(mac)
	assert.False(t, found)
}

func TestPeerRegistryRemoveNonExistent(t *testing.T) {
	registry := NewPeerRegistry()

	// Should not panic
	registry.Remove("nonexistent")
	assert.Equal(t, 0, registry.Count())
}

func TestPeerRegistryGet(t *testing.T) {
	registry := NewPeerRegistry()

	// Not found
	_, found := registry.Get("nonexistent")
	assert.False(t, found)

	// Add and find
	peer := NewPeer("peer1", "Test Peer")
	registry.Add(peer)

	p, found := registry.Get("peer1")
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryGetByIP(t *testing.T) {
	registry := NewPeerRegistry()

	ip := netip.MustParseAddr("10.100.0.5")

	// Not found
	_, found := registry.GetByIP(ip)
	assert.False(t, found)

	// Add and find
	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualIP(ip)
	registry.Add(peer)

	p, found := registry.GetByIP(ip)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryGetByMAC(t *testing.T) {
	registry := NewPeerRegistry()
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Not found
	_, found := registry.GetByMAC(mac)
	assert.False(t, found)

	// Add and find
	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualMAC(mac)
	registry.Add(peer)

	p, found := registry.GetByMAC(mac)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryAll(t *testing.T) {
	registry := NewPeerRegistry()

	// Empty registry
	peers := registry.All()
	assert.Empty(t, peers)

	// Add peers
	peer1 := NewPeer("peer1", "Peer 1")
	peer2 := NewPeer("peer2", "Peer 2")
	peer3 := NewPeer("peer3", "Peer 3")

	registry.Add(peer1)
	registry.Add(peer2)
	registry.Add(peer3)

	peers = registry.All()
	assert.Len(t, peers, 3)
}

func TestPeerRegistryConnected(t *testing.T) {
	registry := NewPeerRegistry()

	peer1 := NewPeer("peer1", "Peer 1")
	peer1.SetStatus(PeerStatusConnected)

	peer2 := NewPeer("peer2", "Peer 2")
	peer2.SetStatus(PeerStatusDiscovered)

	peer3 := NewPeer("peer3", "Peer 3")
	peer3.SetStatus(PeerStatusRelayed)

	registry.Add(peer1)
	registry.Add(peer2)
	registry.Add(peer3)

	connected := registry.Connected()
	assert.Len(t, connected, 2)

	// Verify only connected peers are returned
	ids := make(map[string]bool)
	for _, p := range connected {
		ids[p.ID] = true
	}
	assert.True(t, ids["peer1"])
	assert.True(t, ids["peer3"])
	assert.False(t, ids["peer2"])
}

func TestPeerRegistryCount(t *testing.T) {
	registry := NewPeerRegistry()

	assert.Equal(t, 0, registry.Count())

	registry.Add(NewPeer("peer1", "Peer 1"))
	assert.Equal(t, 1, registry.Count())

	registry.Add(NewPeer("peer2", "Peer 2"))
	assert.Equal(t, 2, registry.Count())

	registry.Remove("peer1")
	assert.Equal(t, 1, registry.Count())
}

func TestPeerRegistryUpdatePeerIP(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	oldIP := netip.MustParseAddr("10.100.0.5")
	newIP := netip.MustParseAddr("10.100.0.10")

	peer.SetVirtualIP(oldIP)
	registry.Add(peer)

	// Verify old IP works
	_, found := registry.GetByIP(oldIP)
	assert.True(t, found)

	// Update IP
	registry.UpdatePeerIP(peer, newIP)

	// Old IP should not work
	_, found = registry.GetByIP(oldIP)
	assert.False(t, found)

	// New IP should work
	p, found := registry.GetByIP(newIP)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
	assert.Equal(t, newIP, p.VirtualIP)
}

func TestPeerRegistryUpdatePeerIPFromInvalid(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	// No initial IP
	registry.Add(peer)

	newIP := netip.MustParseAddr("10.100.0.10")
	registry.UpdatePeerIP(peer, newIP)

	p, found := registry.GetByIP(newIP)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryUpdatePeerIPToInvalid(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	oldIP := netip.MustParseAddr("10.100.0.5")
	peer.SetVirtualIP(oldIP)
	registry.Add(peer)

	// Update to invalid IP
	registry.UpdatePeerIP(peer, netip.Addr{})

	// Old IP should not work
	_, found := registry.GetByIP(oldIP)
	assert.False(t, found)
}

func TestPeerRegistryUpdatePeerMAC(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	oldMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	newMAC, _ := net.ParseMAC("11:22:33:44:55:66")

	peer.SetVirtualMAC(oldMAC)
	registry.Add(peer)

	// Verify old MAC works
	_, found := registry.GetByMAC(oldMAC)
	assert.True(t, found)

	// Update MAC
	registry.UpdatePeerMAC(peer, newMAC)

	// Old MAC should not work
	_, found = registry.GetByMAC(oldMAC)
	assert.False(t, found)

	// New MAC should work
	p, found := registry.GetByMAC(newMAC)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryUpdatePeerMACFromNil(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	// No initial MAC
	registry.Add(peer)

	newMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	registry.UpdatePeerMAC(peer, newMAC)

	p, found := registry.GetByMAC(newMAC)
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestPeerRegistryUpdatePeerMACToNil(t *testing.T) {
	registry := NewPeerRegistry()

	peer := NewPeer("peer1", "Test Peer")
	oldMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	peer.SetVirtualMAC(oldMAC)
	registry.Add(peer)

	// Update to nil MAC
	registry.UpdatePeerMAC(peer, nil)

	// Old MAC should not work
	_, found := registry.GetByMAC(oldMAC)
	assert.False(t, found)
}

func TestPeerRegistryClear(t *testing.T) {
	registry := NewPeerRegistry()

	peer1 := NewPeer("peer1", "Peer 1")
	peer1.SetVirtualIP(netip.MustParseAddr("10.100.0.5"))
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	peer1.SetVirtualMAC(mac1)

	peer2 := NewPeer("peer2", "Peer 2")
	peer2.SetVirtualIP(netip.MustParseAddr("10.100.0.6"))

	registry.Add(peer1)
	registry.Add(peer2)
	assert.Equal(t, 2, registry.Count())

	registry.Clear()

	assert.Equal(t, 0, registry.Count())
	_, found := registry.Get("peer1")
	assert.False(t, found)
	_, found = registry.GetByIP(netip.MustParseAddr("10.100.0.5"))
	assert.False(t, found)
	_, found = registry.GetByMAC(mac1)
	assert.False(t, found)
}

func TestPeerRegistryConcurrentAccess(t *testing.T) {
	registry := NewPeerRegistry()
	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			peer := NewPeer(string(rune('A'+i%26))+string(rune('0'+i)), "Peer")
			peer.SetVirtualIP(netip.MustParseAddr("10.100.0." + string(rune('1'+i%9))))
			registry.Add(peer)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.All()
			_ = registry.Connected()
			_ = registry.Count()
		}()
	}

	wg.Wait()
}

// Test PeerStatus and ConnectionType string values
func TestPeerStatusValues(t *testing.T) {
	assert.Equal(t, PeerStatus("discovered"), PeerStatusDiscovered)
	assert.Equal(t, PeerStatus("connecting"), PeerStatusConnecting)
	assert.Equal(t, PeerStatus("connected"), PeerStatusConnected)
	assert.Equal(t, PeerStatus("relayed"), PeerStatusRelayed)
	assert.Equal(t, PeerStatus("unreachable"), PeerStatusUnreachable)
	assert.Equal(t, PeerStatus("offline"), PeerStatusOffline)
}

func TestConnectionTypeValues(t *testing.T) {
	assert.Equal(t, ConnectionType("direct"), ConnectionTypeDirect)
	assert.Equal(t, ConnectionType("relayed"), ConnectionTypeRelayed)
	assert.Equal(t, ConnectionType("multi_hop"), ConnectionTypeMultiHop)
}

func TestEndpointStruct(t *testing.T) {
	ep := Endpoint{
		Address:  "192.168.1.1",
		Port:     8080,
		Type:     "local",
		Priority: 100,
	}

	assert.Equal(t, "192.168.1.1", ep.Address)
	assert.Equal(t, uint16(8080), ep.Port)
	assert.Equal(t, "local", ep.Type)
	assert.Equal(t, 100, ep.Priority)
}

func TestPeerPublicKey(t *testing.T) {
	peer := NewPeer("peer1", "Test Peer")
	peer.PublicKey = "base64encodedpublickey"

	assert.Equal(t, "base64encodedpublickey", peer.PublicKey)
}

func BenchmarkPeerClone(b *testing.B) {
	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualIP(netip.MustParseAddr("10.100.0.5"))
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	peer.SetVirtualMAC(mac)
	peer.AddEndpoint(Endpoint{Address: "192.168.1.1", Port: 8080})
	peer.SetMetadata("key1", "value1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = peer.Clone()
	}
}

func BenchmarkPeerRegistryAdd(b *testing.B) {
	registry := NewPeerRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peer := NewPeer("peer"+string(rune(i)), "Peer")
		registry.Add(peer)
	}
}

func BenchmarkPeerRegistryGet(b *testing.B) {
	registry := NewPeerRegistry()
	for i := 0; i < 1000; i++ {
		peer := NewPeer("peer"+string(rune(i)), "Peer")
		registry.Add(peer)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.Get("peer" + string(rune(i%1000)))
	}
}
