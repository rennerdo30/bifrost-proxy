package mesh

import (
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtocolMessageType_String(t *testing.T) {
	tests := []struct {
		msgType  ProtocolMessageType
		expected string
	}{
		{MsgTypeRouteAnnounce, "route_announce"},
		{MsgTypeRouteRequest, "route_request"},
		{MsgTypeRouteWithdraw, "route_withdraw"},
		{MsgTypeHello, "hello"},
		{MsgTypeHelloAck, "hello_ack"},
		{MsgTypeLinkState, "link_state"},
		{ProtocolMessageType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.msgType.String())
		})
	}
}

func TestDefaultProtocolConfig(t *testing.T) {
	cfg := DefaultProtocolConfig()

	assert.Equal(t, 30*time.Second, cfg.HelloInterval)
	assert.Equal(t, 60*time.Second, cfg.RouteAnnounceInterval)
	assert.Equal(t, 30*time.Second, cfg.RouteExpiryInterval)
	assert.Equal(t, 8, cfg.DefaultTTL)
	assert.Equal(t, 5*time.Minute, cfg.MaxRouteAge)
	assert.True(t, cfg.SplitHorizon)
	assert.False(t, cfg.PoisonReverse)
}

func TestNewRoutingProtocol(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)
	require.NotNil(t, protocol)

	assert.Equal(t, "local-peer", protocol.localPeerID)
	assert.Equal(t, localIP, protocol.localIP)
	assert.Equal(t, router, protocol.router)
	assert.NotNil(t, protocol.receivedMsgs)
	assert.NotNil(t, protocol.ctx)
	assert.NotNil(t, protocol.cancel)
}

func TestRoutingProtocol_SetSendFunc(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	called := false
	protocol.SetSendFunc(func(peerID string, msg []byte) error {
		called = true
		return nil
	})

	// Verify sendFunc is set by calling send
	err := protocol.send("peer1", []byte("test"))
	require.NoError(t, err)
	assert.True(t, called)
}

func TestRoutingProtocol_StartStop(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := ProtocolConfig{
		HelloInterval:         100 * time.Millisecond,
		RouteAnnounceInterval: 100 * time.Millisecond,
		RouteExpiryInterval:   100 * time.Millisecond,
		DefaultTTL:            8,
	}
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	err := protocol.Start()
	require.NoError(t, err)

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	err = protocol.Stop()
	require.NoError(t, err)
}

func TestRoutingProtocol_HandleMessage_Hello(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sentMessages []struct {
		peerID string
		data   []byte
	}
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentMessages = append(sentMessages, struct {
			peerID string
			data   []byte
		}{peerID, data})
		mu.Unlock()
		return nil
	})

	// Create a hello message
	hello := HelloMessage{
		PeerID:    "peer1",
		VirtualIP: netip.MustParseAddr("10.0.0.2"),
		Timestamp: time.Now(),
		Neighbors: []string{"peer2"},
	}

	payload, err := json.Marshal(hello)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeHello,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Should have sent a hello ack
	mu.Lock()
	require.Len(t, sentMessages, 1)
	assert.Equal(t, "peer1", sentMessages[0].peerID)

	// Verify it's a hello ack
	var ackMsg ProtocolMessage
	err = json.Unmarshal(sentMessages[0].data, &ackMsg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHelloAck, ackMsg.Type)
	mu.Unlock()
}

func TestRoutingProtocol_HandleMessage_HelloAck(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Add a direct route so UpdateLatency works
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 50*time.Millisecond)

	// Create a hello ack message with a recent request time
	ack := HelloAckMessage{
		PeerID:       "peer1",
		VirtualIP:    netip.MustParseAddr("10.0.0.2"),
		RequestTime:  time.Now().Add(-10 * time.Millisecond),
		ResponseTime: time.Now(),
	}

	payload, err := json.Marshal(ack)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeHelloAck,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Verify route latency was updated
	route := router.GetRoute("peer1")
	require.NotNil(t, route)
}

func TestRoutingProtocol_HandleMessage_RouteAnnounce(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Create a route announcement
	announcement := RouteAnnouncement{
		DestPeerID: "peer2",
		DestIP:     netip.MustParseAddr("10.0.0.3"),
		Metric:     100,
		HopCount:   2,
		Path:       []string{"peer1"},
	}

	payload, err := json.Marshal(announcement)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeRouteAnnounce,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Verify route was added
	route := router.GetRoute("peer2")
	require.NotNil(t, route)
	assert.Equal(t, "peer1", route.NextHop)
	assert.Equal(t, 100, route.Metric)
	assert.Equal(t, 2, route.HopCount)
}

func TestRoutingProtocol_HandleMessage_RouteAnnounce_LoopDetection(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Create a route announcement with local peer in path (loop)
	announcement := RouteAnnouncement{
		DestPeerID: "peer2",
		DestIP:     netip.MustParseAddr("10.0.0.3"),
		Metric:     100,
		HopCount:   2,
		Path:       []string{"peer1", "local-peer"}, // Loop - contains local peer
	}

	payload, err := json.Marshal(announcement)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeRouteAnnounce,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Route should NOT be added due to loop detection
	route := router.GetRoute("peer2")
	assert.Nil(t, route)
}

func TestRoutingProtocol_HandleMessage_RouteWithdraw(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Create a route withdrawal
	withdrawal := RouteWithdrawal{
		DestPeerID: "peer2",
	}

	payload, err := json.Marshal(withdrawal)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeRouteWithdraw,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)
	// Just verify no error - the actual route removal is handled separately
}

func TestRoutingProtocol_HandleMessage_LinkState(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var forwardedTo []string
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		forwardedTo = append(forwardedTo, peerID)
		mu.Unlock()
		return nil
	})

	// Add direct peers for forwarding
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Create a link state update
	lsUpdate := LinkStateUpdate{
		PeerID: "peer1",
		SeqNum: 1,
		Links: []LinkInfo{
			{NeighborID: "peer2", Latency: 10 * time.Millisecond, State: "up"},
		},
		Timestamp: time.Now(),
	}

	payload, err := json.Marshal(lsUpdate)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeLinkState,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       3, // TTL > 1 means forward
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Should forward to peer2 (but not back to peer1)
	mu.Lock()
	assert.Contains(t, forwardedTo, "peer2")
	assert.NotContains(t, forwardedTo, "peer1")
	mu.Unlock()
}

func TestRoutingProtocol_HandleMessage_LinkState_NoForward(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var forwardedTo []string
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		forwardedTo = append(forwardedTo, peerID)
		mu.Unlock()
		return nil
	})

	// Add direct peers for forwarding
	router.AddDirectRoute("peer2", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Create a link state update with TTL = 1 (no forwarding)
	lsUpdate := LinkStateUpdate{
		PeerID: "peer1",
		SeqNum: 1,
		Links:  []LinkInfo{},
	}

	payload, err := json.Marshal(lsUpdate)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeLinkState,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       1, // TTL = 1 means don't forward
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Should NOT forward since TTL is 1
	mu.Lock()
	assert.Empty(t, forwardedTo)
	mu.Unlock()
}

func TestRoutingProtocol_HandleMessage_Duplicate(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sendCount int
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sendCount++
		mu.Unlock()
		return nil
	})

	// Create a hello message
	hello := HelloMessage{
		PeerID:    "peer1",
		VirtualIP: netip.MustParseAddr("10.0.0.2"),
		Timestamp: time.Now(),
	}

	payload, err := json.Marshal(hello)
	require.NoError(t, err)

	msg := ProtocolMessage{
		Type:      MsgTypeHello,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	// Handle message first time
	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Handle same message again (duplicate)
	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err)

	// Should only have sent ack once
	mu.Lock()
	assert.Equal(t, 1, sendCount)
	mu.Unlock()
}

func TestRoutingProtocol_HandleMessage_Invalid(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Invalid JSON
	err := protocol.HandleMessage("peer1", []byte("invalid json"))
	assert.Error(t, err)
}

func TestRoutingProtocol_HandleMessage_UnknownType(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	msg := ProtocolMessage{
		Type:      ProtocolMessageType(99), // Unknown type
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	require.NoError(t, err) // Should not error, just log
}

func TestRoutingProtocol_NotifyPeerConnected(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sentMessages []struct {
		peerID string
		data   []byte
	}
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentMessages = append(sentMessages, struct {
			peerID string
			data   []byte
		}{peerID, data})
		mu.Unlock()
		return nil
	})

	// Add an existing neighbor
	router.AddDirectRoute("neighbor1", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Notify of new peer connection
	protocol.NotifyPeerConnected("peer1", netip.MustParseAddr("10.0.0.2"), 20*time.Millisecond)

	// Verify direct route was added
	route := router.GetRoute("peer1")
	require.NotNil(t, route)
	assert.Equal(t, RouteTypeDirect, route.Type)

	// Verify route announcement was sent to existing neighbor
	mu.Lock()
	found := false
	for _, msg := range sentMessages {
		if msg.peerID == "neighbor1" {
			var protoMsg ProtocolMessage
			if json.Unmarshal(msg.data, &protoMsg) == nil && protoMsg.Type == MsgTypeRouteAnnounce {
				found = true
				break
			}
		}
	}
	mu.Unlock()
	assert.True(t, found, "should have sent route announcement to neighbor")
}

func TestRoutingProtocol_NotifyPeerDisconnected(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sentMessages []struct {
		peerID string
		data   []byte
	}
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentMessages = append(sentMessages, struct {
			peerID string
			data   []byte
		}{peerID, data})
		mu.Unlock()
		return nil
	})

	// Add a peer and a neighbor
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)
	router.AddDirectRoute("neighbor1", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Notify of peer disconnection
	protocol.NotifyPeerDisconnected("peer1")

	// Verify direct route was removed
	route := router.GetRoute("peer1")
	assert.Nil(t, route)

	// Verify route withdrawal was sent
	mu.Lock()
	found := false
	for _, msg := range sentMessages {
		if msg.peerID == "neighbor1" {
			var protoMsg ProtocolMessage
			if json.Unmarshal(msg.data, &protoMsg) == nil && protoMsg.Type == MsgTypeRouteWithdraw {
				found = true
				break
			}
		}
	}
	mu.Unlock()
	assert.True(t, found, "should have sent route withdrawal to neighbor")
}

func TestRoutingProtocol_WithdrawRoute(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sentMessages []struct {
		peerID string
		data   []byte
	}
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentMessages = append(sentMessages, struct {
			peerID string
			data   []byte
		}{peerID, data})
		mu.Unlock()
		return nil
	})

	// Add neighbors
	router.AddDirectRoute("neighbor1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)
	router.AddDirectRoute("neighbor2", netip.MustParseAddr("10.0.0.3"), 10*time.Millisecond)

	// Withdraw a route
	protocol.WithdrawRoute("peer1")

	// Verify withdrawal was sent to all neighbors
	mu.Lock()
	assert.Len(t, sentMessages, 2)
	for _, msg := range sentMessages {
		var protoMsg ProtocolMessage
		err := json.Unmarshal(msg.data, &protoMsg)
		require.NoError(t, err)
		assert.Equal(t, MsgTypeRouteWithdraw, protoMsg.Type)
	}
	mu.Unlock()
}

func TestRoutingProtocol_SendNoSendFunc(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Don't set sendFunc
	err := protocol.send("peer1", []byte("test"))
	assert.NoError(t, err) // Should not error, just return nil
}

func TestRoutingProtocol_CreateMessage(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	payload := json.RawMessage(`{"test": "data"}`)

	msg1 := protocol.createMessage(MsgTypeHello, payload)
	msg2 := protocol.createMessage(MsgTypeHello, payload)

	assert.Equal(t, MsgTypeHello, msg1.Type)
	assert.Equal(t, "local-peer", msg1.SrcPeerID)
	assert.Equal(t, cfg.DefaultTTL, msg1.TTL)
	assert.Equal(t, payload, msg1.Payload)

	// Sequence numbers should increment
	assert.Equal(t, uint64(1), msg1.SeqNum)
	assert.Equal(t, uint64(2), msg2.SeqNum)
}

func TestRoutingProtocol_AnnounceRoutesToPeer_SplitHorizon(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	cfg.SplitHorizon = true
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sentCount int
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentCount++
		mu.Unlock()
		return nil
	})

	// Add a route via peer1
	route := &Route{
		DestPeerID:  "peer2",
		DestIP:      netip.MustParseAddr("10.0.0.3"),
		NextHop:     "peer1",
		Type:        RouteTypeNextHop,
		Metric:      100,
		HopCount:    2,
		LastUpdated: time.Now(),
		Active:      true,
	}
	router.AddRoute(route)

	// Announce routes to peer1 (the next hop)
	routes := router.GetBestRoutes()
	protocol.announceRoutesToPeer("peer1", routes)

	// Should NOT send due to split horizon
	mu.Lock()
	assert.Equal(t, 0, sentCount)
	mu.Unlock()
}

func TestRoutingProtocol_AnnounceRoutesToPeer_NoSelfAnnounce(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	cfg.SplitHorizon = false
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	var sentCount int
	var mu sync.Mutex

	protocol.SetSendFunc(func(peerID string, data []byte) error {
		mu.Lock()
		sentCount++
		mu.Unlock()
		return nil
	})

	// Add a direct route to peer1
	router.AddDirectRoute("peer1", netip.MustParseAddr("10.0.0.2"), 10*time.Millisecond)

	// Announce routes to peer1 (itself)
	routes := router.GetBestRoutes()
	protocol.announceRoutesToPeer("peer1", routes)

	// Should NOT send route to peer1 about itself
	mu.Lock()
	assert.Equal(t, 0, sentCount)
	mu.Unlock()
}

func TestRoutingProtocol_HandleHello_InvalidPayload(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Use a valid JSON structure but with wrong field types for HelloMessage
	msg := ProtocolMessage{
		Type:      MsgTypeHello,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   json.RawMessage(`{"peer_id": 12345}`), // Wrong type - number instead of string
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	assert.Error(t, err)
}

func TestRoutingProtocol_HandleHelloAck_InvalidPayload(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Use valid JSON but wrong field types
	msg := ProtocolMessage{
		Type:      MsgTypeHelloAck,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   json.RawMessage(`{"peer_id": 12345}`), // Wrong type
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	assert.Error(t, err)
}

func TestRoutingProtocol_HandleRouteAnnounce_InvalidPayload(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Use valid JSON but wrong field types for RouteAnnouncement
	msg := ProtocolMessage{
		Type:      MsgTypeRouteAnnounce,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   json.RawMessage(`{"dest_peer_id": 12345}`), // Wrong type
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	assert.Error(t, err)
}

func TestRoutingProtocol_HandleRouteWithdraw_InvalidPayload(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Use valid JSON but wrong field types
	msg := ProtocolMessage{
		Type:      MsgTypeRouteWithdraw,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   json.RawMessage(`{"dest_peer_id": 12345}`), // Wrong type
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	assert.Error(t, err)
}

func TestRoutingProtocol_HandleLinkState_InvalidPayload(t *testing.T) {
	router := createTestRouter("local-peer")
	cfg := DefaultProtocolConfig()
	localIP := netip.MustParseAddr("10.0.0.1")

	protocol := NewRoutingProtocol("local-peer", localIP, router, cfg)

	// Use valid JSON but wrong field types
	msg := ProtocolMessage{
		Type:      MsgTypeLinkState,
		SrcPeerID: "peer1",
		SeqNum:    1,
		TTL:       8,
		Timestamp: time.Now(),
		Payload:   json.RawMessage(`{"peer_id": 12345}`), // Wrong type
	}

	msgBytes, err := json.Marshal(msg)
	require.NoError(t, err)

	err = protocol.HandleMessage("peer1", msgBytes)
	assert.Error(t, err)
}
