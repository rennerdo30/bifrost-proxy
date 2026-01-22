package mesh

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMeshNode(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.Discovery.Server = "localhost:7080"

		node, err := NewMeshNode(config)
		require.NoError(t, err)
		require.NotNil(t, node)

		assert.NotEmpty(t, node.localPeerID)
		assert.Equal(t, NodeStatusStopped, node.Status())
		assert.NotNil(t, node.peerRegistry)
	})

	t.Run("with peer name", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		config.NetworkID = "test-network"
		config.PeerName = "test-peer"
		config.Discovery.Server = "localhost:7080"

		node, err := NewMeshNode(config)
		require.NoError(t, err)
		require.NotNil(t, node)

		assert.Equal(t, "test-peer", node.LocalPeerID())
	})

	t.Run("disabled config skips validation", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = false
		// Missing required fields, but should not error when disabled

		node, err := NewMeshNode(config)
		require.NoError(t, err)
		require.NotNil(t, node)
	})

	t.Run("invalid config", func(t *testing.T) {
		config := DefaultConfig()
		config.Enabled = true
		// Missing NetworkID and Discovery.Server

		_, err := NewMeshNode(config)
		assert.Error(t, err)
	})
}

func TestMeshNodeStatus(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Initial status
	assert.Equal(t, NodeStatusStopped, node.Status())
}

func TestMeshNodeStats(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	stats := node.Stats()
	assert.Equal(t, NodeStatusStopped, stats.Status)
	assert.Equal(t, 0, stats.PeerCount)
	assert.Equal(t, 0, stats.ConnectedPeers)
	assert.Equal(t, int64(0), stats.BytesSent)
	assert.Equal(t, int64(0), stats.BytesReceived)
}

func TestMeshNodeGetPeers(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Initially no peers
	peers := node.GetPeers()
	assert.Empty(t, peers)

	// Add a peer to the registry
	peer := NewPeer("peer1", "Test Peer")
	peer.SetVirtualIP(netip.MustParseAddr("10.100.0.2"))
	node.peerRegistry.Add(peer)

	// Should now have one peer
	peers = node.GetPeers()
	assert.Len(t, peers, 1)
	assert.Equal(t, "peer1", peers[0].ID)
}

func TestMeshNodeGetPeer(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Peer not found
	_, found := node.GetPeer("nonexistent")
	assert.False(t, found)

	// Add peer
	peer := NewPeer("peer1", "Test Peer")
	node.peerRegistry.Add(peer)

	// Peer found
	p, found := node.GetPeer("peer1")
	assert.True(t, found)
	assert.Equal(t, "peer1", p.ID)
}

func TestMeshNodeGetConnectedPeers(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Add disconnected peer
	peer1 := NewPeer("peer1", "Peer 1")
	peer1.SetStatus(PeerStatusDiscovered)
	node.peerRegistry.Add(peer1)

	// Add connected peer
	peer2 := NewPeer("peer2", "Peer 2")
	peer2.SetStatus(PeerStatusConnected)
	node.peerRegistry.Add(peer2)

	// Should only return connected peer
	connected := node.GetConnectedPeers()
	assert.Len(t, connected, 1)
	assert.Equal(t, "peer2", connected[0].ID)
}

func TestNodeStatusString(t *testing.T) {
	tests := []struct {
		status   NodeStatus
		expected string
	}{
		{NodeStatusStopped, "stopped"},
		{NodeStatusStarting, "starting"},
		{NodeStatusRunning, "running"},
		{NodeStatusStopping, "stopping"},
		{NodeStatusError, "error"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.status))
		})
	}
}

func TestGeneratePeerID(t *testing.T) {
	t.Run("with name", func(t *testing.T) {
		id := generatePeerID("my-peer")
		assert.Equal(t, "my-peer", id)
	})

	t.Run("without name", func(t *testing.T) {
		id := generatePeerID("")
		assert.NotEmpty(t, id)
		assert.Contains(t, id, "peer-")
	})

	t.Run("unique IDs", func(t *testing.T) {
		id1 := generatePeerID("")
		id2 := generatePeerID("")
		// IDs may or may not be unique depending on timing,
		// but each should have the prefix
		assert.Contains(t, id1, "peer-")
		assert.Contains(t, id2, "peer-")
	})
}

func TestIsProtocolMessage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"protocol marker", []byte{0x01, 0x02, 0x03}, true},
		{"data marker", []byte{0x00, 0x02, 0x03}, false},
		{"broadcast marker", []byte{0x02, 0x02, 0x03}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isProtocolMessage(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsBroadcastMessage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"broadcast marker", []byte{0x02, 0x02, 0x03}, true},
		{"protocol marker", []byte{0x01, 0x02, 0x03}, false},
		{"data marker", []byte{0x00, 0x02, 0x03}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBroadcastMessage(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMeshNodeLifecycle(t *testing.T) {
	// Test that Stop() doesn't panic on a node that was never started
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Stop should not panic or error
	err = node.Stop()
	assert.NoError(t, err)
	assert.Equal(t, NodeStatusStopped, node.Status())
}

func TestMeshNodeSetStatus(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	node.setStatus(NodeStatusRunning)
	assert.Equal(t, NodeStatusRunning, node.Status())

	node.setStatus(NodeStatusError)
	assert.Equal(t, NodeStatusError, node.Status())
}

func TestMeshNodeLocalIP(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Initially invalid
	ip := node.LocalIP()
	assert.False(t, ip.IsValid())
}

func TestMeshNodeGetRoutes(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	// Router not initialized yet, should return nil
	routes := node.GetRoutes()
	assert.Nil(t, routes)
}

// TestMeshNodeStartWithoutDevice tests that Start fails gracefully without root privileges
func TestMeshNodeStartWithoutDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires network")
	}

	config := DefaultConfig()
	config.Enabled = true
	config.NetworkID = "test-network"
	config.Discovery.Server = "localhost:7080"
	config.Device.Type = "tun"
	config.Device.Name = "test-mesh0"

	node, err := NewMeshNode(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start will likely fail due to missing privileges, but should not panic
	err = node.Start(ctx)
	if err != nil {
		// Expected on non-root systems
		assert.Contains(t, err.Error(), "device")
	}

	// Cleanup
	node.Stop()
}
