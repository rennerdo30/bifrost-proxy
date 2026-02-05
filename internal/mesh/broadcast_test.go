package mesh

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadcastType_String(t *testing.T) {
	tests := []struct {
		typ      BroadcastType
		expected string
	}{
		{BroadcastTypeFlood, "flood"},
		{BroadcastTypeMulticast, "multicast"},
		{BroadcastTypeAnycast, "anycast"},
		{BroadcastType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.typ.String())
		})
	}
}

func TestDefaultBroadcastConfig(t *testing.T) {
	cfg := DefaultBroadcastConfig()

	assert.Equal(t, 5*time.Minute, cfg.SeenMsgsTTL)
	assert.Equal(t, 8, cfg.DefaultTTL)
	assert.Equal(t, time.Minute, cfg.CleanupInterval)
}

//nolint:unparam // localPeerID is always "local-peer" in tests but kept for test readability
func createTestRouter(localPeerID string) *MeshRouter {
	return NewMeshRouter(RouterConfig{
		LocalPeerID:  localPeerID,
		LocalIP:      netip.MustParseAddr("10.0.0.1"),
		MaxHops:      8,
		RouteTimeout: 5 * time.Minute,
	})
}

func TestNewBroadcastManager(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()

	bm := NewBroadcastManager("local-peer", router, cfg)
	require.NotNil(t, bm)

	assert.Equal(t, "local-peer", bm.localPeerID)
	assert.Equal(t, router, bm.router)
	assert.NotNil(t, bm.groups)
	assert.NotNil(t, bm.seenMsgs)
	assert.NotNil(t, bm.handlers)
	assert.Equal(t, cfg.SeenMsgsTTL, bm.seenMsgsTTL)
}

func TestBroadcastManager_StartStop(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	err := bm.Start()
	require.NoError(t, err)

	err = bm.Stop()
	require.NoError(t, err)
}

func TestBroadcastManager_SetSendFunc(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	called := false
	bm.SetSendFunc(func(peerID string, data []byte) error {
		called = true
		return nil
	})

	// The sendFunc should be set
	bm.mu.RLock()
	assert.NotNil(t, bm.sendFunc)
	bm.mu.RUnlock()

	// Call the sendFunc to verify it was set correctly
	err := bm.sendFunc("test-peer", []byte("test"))
	require.NoError(t, err)
	assert.True(t, called, "sendFunc should have been called")
}

func TestBroadcastManager_RegisterHandler(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	handled := false
	bm.RegisterHandler(BroadcastTypeFlood, func(msg *BroadcastMessage) {
		handled = true
	})

	bm.mu.RLock()
	handler := bm.handlers[BroadcastTypeFlood]
	bm.mu.RUnlock()

	require.NotNil(t, handler)

	// Call the handler to verify it was set correctly
	handler(&BroadcastMessage{})
	assert.True(t, handled, "handler should have been called")
}

func TestBroadcastManager_JoinLeaveGroup(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Join a group
	bm.JoinGroup("group1", "Test Group")

	groups := bm.GetGroups()
	require.Len(t, groups, 1)
	assert.Equal(t, "group1", groups[0].ID)
	assert.Equal(t, "Test Group", groups[0].Name)
	assert.True(t, groups[0].Members["local-peer"])

	// Join same group again should not duplicate
	bm.JoinGroup("group1", "Test Group")
	groups = bm.GetGroups()
	assert.Len(t, groups, 1)

	// Leave the group
	bm.LeaveGroup("group1")
	groups = bm.GetGroups()
	assert.Len(t, groups, 0)
}

func TestBroadcastManager_GroupMembers(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Add members to a group
	bm.AddGroupMember("group1", "peer1")
	bm.AddGroupMember("group1", "peer2")

	members := bm.GetGroupMembers("group1")
	assert.Len(t, members, 2)
	assert.Contains(t, members, "peer1")
	assert.Contains(t, members, "peer2")

	// Check membership
	assert.True(t, bm.IsGroupMember("group1", "peer1"))
	assert.True(t, bm.IsGroupMember("group1", "peer2"))
	assert.False(t, bm.IsGroupMember("group1", "peer3"))
	assert.False(t, bm.IsGroupMember("nonexistent", "peer1"))

	// Remove member
	bm.RemoveGroupMember("group1", "peer1")
	assert.False(t, bm.IsGroupMember("group1", "peer1"))
	assert.True(t, bm.IsGroupMember("group1", "peer2"))

	// Get members of non-existent group
	members = bm.GetGroupMembers("nonexistent")
	assert.Nil(t, members)
}

func TestBroadcastManager_Broadcast(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	var sentMessages []struct {
		peerID string
		data   []byte
	}
	var mu sync.Mutex

	bm.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentMessages = append(sentMessages, struct {
			peerID string
			data   []byte
		}{peerID, data})
		mu.Unlock()
		return nil
	})

	// Add some direct peers to the router
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.0.0.3"), 20*time.Millisecond)

	// Broadcast a message
	payload := []byte("test broadcast message")
	err := bm.Broadcast(payload, 5)
	require.NoError(t, err)

	// Should have sent to both direct peers
	mu.Lock()
	assert.Len(t, sentMessages, 2)
	mu.Unlock()
}

func TestBroadcastManager_BroadcastDefaultTTL(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Broadcast with TTL <= 0 should use default TTL (8)
	err := bm.Broadcast([]byte("test"), 0)
	require.NoError(t, err)

	err = bm.Broadcast([]byte("test"), -1)
	require.NoError(t, err)
}

func TestBroadcastManager_Multicast(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	var sentMessages []struct {
		peerID string
		data   []byte
	}
	var mu sync.Mutex

	bm.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentMessages = append(sentMessages, struct {
			peerID string
			data   []byte
		}{peerID, data})
		mu.Unlock()
		return nil
	})

	// Add peers to router
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)

	// Multicast a message
	payload := []byte("test multicast message")
	err := bm.Multicast("group1", payload, 0) // 0 should use default TTL
	require.NoError(t, err)
}

func TestBroadcastManager_Anycast(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Test anycast to non-existent group
	err := bm.Anycast("nonexistent", []byte("test"))
	require.NoError(t, err) // Should return nil for non-existent group

	// Add group with local peer as member
	bm.JoinGroup("group1", "Test Group")

	handled := false
	bm.RegisterHandler(BroadcastTypeAnycast, func(msg *BroadcastMessage) {
		handled = true
	})

	// Anycast where we're a member should deliver locally
	err = bm.Anycast("group1", []byte("test anycast"))
	require.NoError(t, err)
	assert.True(t, handled)
}

func TestBroadcastManager_AnycastToRemotePeer(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	var sentToPeer string
	bm.SetSendFunc(func(peerID string, data []byte) error {
		sentToPeer = peerID
		return nil
	})

	// Add remote peers with routes (different latencies)
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 100*time.Millisecond)
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond) // Closer

	// Create group with remote members only
	bm.AddGroupMember("group1", "peer1")
	bm.AddGroupMember("group1", "peer2")

	// Anycast should send to closest peer (peer2)
	err := bm.Anycast("group1", []byte("test"))
	require.NoError(t, err)
	assert.Equal(t, "peer2", sentToPeer)
}

func TestBroadcastManager_AnycastNoRoutes(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Create group with members but no routes to them
	bm.AddGroupMember("group1", "peer1")
	bm.AddGroupMember("group1", "peer2")

	// Anycast with no routes should return nil
	err := bm.Anycast("group1", []byte("test"))
	require.NoError(t, err)
}

func TestBroadcastManager_HandleMessage(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	var received *BroadcastMessage
	bm.RegisterHandler(BroadcastTypeFlood, func(msg *BroadcastMessage) {
		received = msg
	})

	// Create a message
	originalMsg := &BroadcastMessage{
		ID:        "msg123",
		Type:      BroadcastTypeFlood,
		SrcPeerID: "peer1",
		TTL:       1,
		Timestamp: time.Now(),
		Payload:   []byte("test payload"),
	}

	// Serialize and handle
	data := serializeBroadcastMessage(originalMsg)
	err := bm.HandleMessage("peer1", data)
	require.NoError(t, err)

	require.NotNil(t, received)
	assert.Equal(t, "msg123", received.ID)
	assert.Equal(t, BroadcastTypeFlood, received.Type)
	assert.Equal(t, []byte("test payload"), received.Payload)

	// Handle same message again - should be ignored (dedup)
	received = nil
	err = bm.HandleMessage("peer1", data)
	require.NoError(t, err)
	assert.Nil(t, received) // Should not deliver duplicate
}

func TestBroadcastManager_HandleMessageInvalid(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Handle invalid data
	err := bm.HandleMessage("peer1", []byte{0, 1})
	assert.Error(t, err)
}

func TestBroadcastManager_HandleMessageForward(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	var forwardedTo []string
	var mu sync.Mutex

	bm.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		forwardedTo = append(forwardedTo, peerID)
		mu.Unlock()
		return nil
	})

	// Add peers to router
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Create a message with TTL > 1 (should be forwarded)
	originalMsg := &BroadcastMessage{
		ID:        "msgforward",
		Type:      BroadcastTypeFlood,
		SrcPeerID: "peer3", // Original sender
		TTL:       3,
		Timestamp: time.Now(),
		Payload:   []byte("forward me"),
	}

	data := serializeBroadcastMessage(originalMsg)
	err := bm.HandleMessage("peer1", data) // Received from peer1
	require.NoError(t, err)

	// Should forward to peer2 only (not back to peer1 or original sender peer3)
	mu.Lock()
	assert.Contains(t, forwardedTo, "peer2")
	assert.NotContains(t, forwardedTo, "peer1") // Don't send back to sender
	mu.Unlock()
}

func TestBroadcastManager_HandleMessageNoForwardLowTTL(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	var forwardedTo []string
	var mu sync.Mutex

	bm.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		forwardedTo = append(forwardedTo, peerID)
		mu.Unlock()
		return nil
	})

	// Add peers to router
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Create a message with TTL = 1 (should NOT be forwarded)
	originalMsg := &BroadcastMessage{
		ID:        "msgnofwd",
		Type:      BroadcastTypeFlood,
		SrcPeerID: "peer3",
		TTL:       1, // TTL 1 means don't forward
		Timestamp: time.Now(),
		Payload:   []byte("dont forward"),
	}

	data := serializeBroadcastMessage(originalMsg)
	err := bm.HandleMessage("peer1", data)
	require.NoError(t, err)

	// Should not forward since TTL is 1
	mu.Lock()
	assert.Empty(t, forwardedTo)
	mu.Unlock()
}

func TestBroadcastManager_DeliverLocallyMulticast(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	received := false
	bm.RegisterHandler(BroadcastTypeMulticast, func(msg *BroadcastMessage) {
		received = true
	})

	// Create a multicast message to a group we're not a member of
	msg := &BroadcastMessage{
		ID:        "multicast1",
		Type:      BroadcastTypeMulticast,
		SrcPeerID: "peer1",
		GroupID:   "group1",
		TTL:       1,
		Timestamp: time.Now(),
		Payload:   []byte("test"),
	}

	data := serializeBroadcastMessage(msg)
	err := bm.HandleMessage("peer1", data)
	require.NoError(t, err)

	// Should NOT deliver locally since we're not a member
	assert.False(t, received)

	// Now join the group
	bm.JoinGroup("group1", "Test Group")

	// Handle a new message (new ID to avoid dedup)
	msg.ID = "multicast2"
	data = serializeBroadcastMessage(msg)
	err = bm.HandleMessage("peer1", data)
	require.NoError(t, err)

	// Now it should be delivered
	assert.True(t, received)
}

func TestSerializeDeserializeBroadcastMessage(t *testing.T) {
	originalMsg := &BroadcastMessage{
		ID:        "test-id-123",
		Type:      BroadcastTypeMulticast,
		SrcPeerID: "sender-peer-id",
		GroupID:   "group-123",
		TTL:       5,
		Timestamp: time.Now().Round(time.Nanosecond),
		Payload:   []byte("hello world"),
	}

	// Serialize
	data := serializeBroadcastMessage(originalMsg)
	require.NotEmpty(t, data)

	// Deserialize
	recovered, err := deserializeBroadcastMessage(data)
	require.NoError(t, err)

	assert.Equal(t, originalMsg.ID, recovered.ID)
	assert.Equal(t, originalMsg.Type, recovered.Type)
	assert.Equal(t, originalMsg.SrcPeerID, recovered.SrcPeerID)
	assert.Equal(t, originalMsg.GroupID, recovered.GroupID)
	assert.Equal(t, originalMsg.TTL, recovered.TTL)
	assert.Equal(t, originalMsg.Payload, recovered.Payload)
	// Timestamp comparison with tolerance for precision
	assert.WithinDuration(t, originalMsg.Timestamp, recovered.Timestamp, time.Microsecond)
}

func TestSerializeDeserializeBroadcastMessage_EmptyFields(t *testing.T) {
	originalMsg := &BroadcastMessage{
		ID:        "test",
		Type:      BroadcastTypeFlood,
		SrcPeerID: "peer",
		GroupID:   "", // Empty
		TTL:       1,
		Timestamp: time.Now(),
		Payload:   []byte{}, // Empty
	}

	data := serializeBroadcastMessage(originalMsg)
	recovered, err := deserializeBroadcastMessage(data)
	require.NoError(t, err)

	assert.Equal(t, originalMsg.ID, recovered.ID)
	assert.Equal(t, originalMsg.GroupID, recovered.GroupID)
	assert.Empty(t, recovered.Payload)
}

func TestDeserializeBroadcastMessage_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{1, 2}},
		{"missing id", []byte{0, 5, 10}},
		{"truncated src", []byte{0, 5, 2, 'a', 'b', 10}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := deserializeBroadcastMessage(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestIsBroadcastMAC(t *testing.T) {
	tests := []struct {
		name     string
		mac      net.HardwareAddr
		expected bool
	}{
		{"broadcast", net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, true},
		{"unicast", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, false},
		{"multicast", net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, false},
		{"empty", net.HardwareAddr{}, true}, // Empty returns true (all bytes are 0xFF vacuously)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isBroadcastMAC(tt.mac))
		})
	}
}

func TestIsMulticastMAC(t *testing.T) {
	tests := []struct {
		name     string
		mac      net.HardwareAddr
		expected bool
	}{
		{"multicast", net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, true},
		{"broadcast", net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, true}, // Broadcast is also multicast
		{"unicast", net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, false},
		{"empty", net.HardwareAddr{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isMulticastMAC(tt.mac))
		})
	}
}

func TestMacToGroupID(t *testing.T) {
	mac := net.HardwareAddr{0x01, 0x00, 0x5E, 0xAB, 0xCD, 0xEF}
	groupID := macToGroupID(mac)
	assert.Equal(t, "01005eabcdef", groupID)
}

func TestEthernetBroadcastHandler(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	handler := NewEthernetBroadcastHandler(bm)
	require.NotNil(t, handler)

	// Test with broadcast MAC
	broadcastMAC := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	err := handler.HandleFrame(broadcastMAC, []byte("broadcast frame"))
	require.NoError(t, err)

	// Test with multicast MAC
	multicastMAC := net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}
	err = handler.HandleFrame(multicastMAC, []byte("multicast frame"))
	require.NoError(t, err)

	// Test with unicast MAC (should do nothing)
	unicastMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	err = handler.HandleFrame(unicastMAC, []byte("unicast frame"))
	require.NoError(t, err)
}

func TestBroadcastManager_CleanupSeenMsgs(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := BroadcastConfig{
		SeenMsgsTTL:     100 * time.Millisecond,
		DefaultTTL:      8,
		CleanupInterval: time.Minute,
	}
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Add some seen messages
	bm.mu.Lock()
	bm.seenMsgs["old-msg"] = time.Now().Add(-200 * time.Millisecond) // Expired
	bm.seenMsgs["new-msg"] = time.Now()                              // Not expired
	bm.mu.Unlock()

	// Run cleanup
	bm.cleanupSeenMsgs()

	bm.mu.RLock()
	_, hasOld := bm.seenMsgs["old-msg"]
	_, hasNew := bm.seenMsgs["new-msg"]
	bm.mu.RUnlock()

	assert.False(t, hasOld, "old message should be cleaned up")
	assert.True(t, hasNew, "new message should still exist")
}

func TestBroadcastManager_GenerateMessageID(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	id1 := bm.generateMessageID([]byte("payload1"))
	id2 := bm.generateMessageID([]byte("payload2"))

	// IDs should be 16 characters (hex)
	assert.Len(t, id1, 16)
	assert.Len(t, id2, 16)

	// Different payloads should generate different IDs (with high probability)
	assert.NotEqual(t, id1, id2)
}

func TestBroadcastManager_SendToPeerNoSendFunc(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Don't set sendFunc
	msg := &BroadcastMessage{
		ID:        "test",
		Type:      BroadcastTypeFlood,
		SrcPeerID: "local-peer",
		TTL:       1,
		Timestamp: time.Now(),
		Payload:   []byte("test"),
	}

	// Should not panic, just return nil
	err := bm.sendToPeer("peer1", msg)
	assert.NoError(t, err)
}

func TestBroadcastManager_RemoveGroupMemberNonExistent(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultBroadcastConfig()
	bm := NewBroadcastManager("local-peer", router, cfg)

	// Should not panic when removing from non-existent group
	bm.RemoveGroupMember("nonexistent", "peer1")
}
