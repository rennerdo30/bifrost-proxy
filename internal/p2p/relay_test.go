package p2p

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelayType_String(t *testing.T) {
	tests := []struct {
		name     string
		rt       RelayType
		expected string
	}{
		{"TURN", RelayTypeTURN, "turn"},
		{"Peer", RelayTypePeer, "peer"},
		{"Unknown", RelayType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.rt.String())
		})
	}
}

func TestDefaultRelayConfig(t *testing.T) {
	config := DefaultRelayConfig()

	assert.True(t, config.Enabled)
	assert.True(t, config.PeerRelayEnabled)
	assert.Equal(t, 3, config.MaxRelayHops)
	assert.Equal(t, 30*time.Second, config.RelayTimeout)
	assert.Nil(t, config.TURNConfig)
}

func TestNewRelayManager(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	require.NotNil(t, rm)
	assert.NotNil(t, rm.relays)
	assert.NotNil(t, rm.peerRelays)
	assert.Equal(t, config, rm.config)
	assert.Nil(t, rm.turnClient) // No TURN config provided
}

func TestNewRelayManager_WithTURNConfig(t *testing.T) {
	turnConfig := &TURNConfig{
		Server:   "turn.example.com:3478",
		Username: "user",
		Password: "pass",
	}

	config := RelayConfig{
		Enabled:          true,
		TURNConfig:       turnConfig,
		PeerRelayEnabled: true,
		MaxRelayHops:     3,
		RelayTimeout:     30 * time.Second,
	}

	rm := NewRelayManager(config)

	require.NotNil(t, rm)
	assert.NotNil(t, rm.turnClient)
}

func TestRelayManager_Start_Disabled(t *testing.T) {
	config := RelayConfig{
		Enabled: false,
	}

	rm := NewRelayManager(config)
	err := rm.Start(context.Background())

	assert.NoError(t, err)
}

func TestRelayManager_Stop(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	// Add a relay
	rm.relays["test"] = &Relay{
		Type:      RelayTypePeer,
		Address:   netip.MustParseAddrPort("192.168.1.1:3478"),
		Available: true,
	}

	err := rm.Stop()
	assert.NoError(t, err)

	// Relays should be cleared
	assert.Empty(t, rm.relays)
	assert.Empty(t, rm.peerRelays)
}

func TestRelayManager_GetRelays_Empty(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	relays := rm.GetRelays()
	assert.Empty(t, relays)
}

func TestRelayManager_GetRelays_OnlyAvailable(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	rm.relays["available"] = &Relay{
		Type:      RelayTypeTURN,
		Address:   netip.MustParseAddrPort("192.168.1.1:3478"),
		Available: true,
	}
	rm.relays["unavailable"] = &Relay{
		Type:      RelayTypePeer,
		Address:   netip.MustParseAddrPort("192.168.1.2:3478"),
		Available: false,
	}

	relays := rm.GetRelays()
	assert.Len(t, relays, 1)
	assert.Equal(t, RelayTypeTURN, relays[0].Type)
}

func TestRelayManager_GetBestRelay_NoRelays(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	relay, err := rm.GetBestRelay("peer-123")
	assert.Nil(t, relay)
	assert.Error(t, err)
	assert.Equal(t, ErrRelayNotAvailable, err)
}

func TestRelayManager_GetBestRelay_SelectsLowestLatency(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	rm.relays["slow"] = &Relay{
		Type:      RelayTypeTURN,
		Address:   netip.MustParseAddrPort("192.168.1.1:3478"),
		Latency:   200 * time.Millisecond,
		Available: true,
	}
	rm.relays["fast"] = &Relay{
		Type:      RelayTypePeer,
		Address:   netip.MustParseAddrPort("192.168.1.2:3478"),
		Latency:   50 * time.Millisecond,
		Available: true,
	}

	relay, err := rm.GetBestRelay("peer-123")
	require.NoError(t, err)
	assert.Equal(t, 50*time.Millisecond, relay.Latency)
}

func TestRelayManager_GetTURNClient(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	// No TURN client configured
	assert.Nil(t, rm.GetTURNClient())

	// With TURN client
	turnConfig := &TURNConfig{
		Server:   "turn.example.com:3478",
		Username: "user",
		Password: "pass",
	}
	config.TURNConfig = turnConfig
	rm = NewRelayManager(config)
	assert.NotNil(t, rm.GetTURNClient())
}

func TestRelayManager_AddPeerRelay_Disabled(t *testing.T) {
	config := RelayConfig{
		Enabled:          true,
		PeerRelayEnabled: false,
	}
	rm := NewRelayManager(config)

	mockConn := &mockP2PConnection{
		peerID:     "peer-123",
		remoteAddr: netip.MustParseAddrPort("192.168.1.1:12345"),
		latency:    50 * time.Millisecond,
	}

	err := rm.AddPeerRelay("peer-123", mockConn)
	assert.Error(t, err)
	assert.Equal(t, ErrPeerNotRelayable, err)
}

func TestRelayManager_AddPeerRelay_Success(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	mockConn := &mockP2PConnection{
		peerID:     "peer-123",
		remoteAddr: netip.MustParseAddrPort("192.168.1.1:12345"),
		latency:    50 * time.Millisecond,
	}

	err := rm.AddPeerRelay("peer-123", mockConn)
	assert.NoError(t, err)

	// Verify peer relay was added
	assert.Contains(t, rm.peerRelays, "peer-123")
	assert.Contains(t, rm.relays, "peer:peer-123")

	relay := rm.relays["peer:peer-123"]
	assert.Equal(t, RelayTypePeer, relay.Type)
	assert.Equal(t, "peer-123", relay.PeerID)
	assert.True(t, relay.Available)
}

func TestRelayManager_RemovePeerRelay(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	mockConn := &mockP2PConnection{
		peerID:     "peer-123",
		remoteAddr: netip.MustParseAddrPort("192.168.1.1:12345"),
		latency:    50 * time.Millisecond,
	}

	// Add peer relay
	err := rm.AddPeerRelay("peer-123", mockConn)
	require.NoError(t, err)

	// Remove peer relay
	rm.RemovePeerRelay("peer-123")

	assert.NotContains(t, rm.peerRelays, "peer-123")
	assert.NotContains(t, rm.relays, "peer:peer-123")
}

func TestRelayManager_RemovePeerRelay_NonExistent(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	// Should not panic when removing non-existent relay
	rm.RemovePeerRelay("nonexistent")
}

func TestRelayManager_CreateRelayedConnection_NoRelay(t *testing.T) {
	config := DefaultRelayConfig()
	rm := NewRelayManager(config)

	connConfig := ConnectionConfig{
		PeerID: "peer-123",
	}

	conn, err := rm.CreateRelayedConnection(context.Background(), connConfig)
	assert.Nil(t, conn)
	assert.Error(t, err)
	assert.Equal(t, ErrRelayNotAvailable, err)
}

func TestWrapRelayMessage(t *testing.T) {
	destPeerID := "dest-peer"
	data := []byte("hello world")

	wrapped := wrapRelayMessage(destPeerID, data)

	// Verify format
	assert.Equal(t, byte(RelayMessageTypeData), wrapped[0])
	assert.Equal(t, byte(len(destPeerID)), wrapped[1])
	assert.Equal(t, destPeerID, string(wrapped[2:2+len(destPeerID)]))
	assert.Equal(t, data, wrapped[2+len(destPeerID):])
}

func TestUnwrapRelayMessage_Success(t *testing.T) {
	destPeerID := "dest-peer"
	data := []byte("hello world")
	wrapped := wrapRelayMessage(destPeerID, data)

	msg, err := unwrapRelayMessage(wrapped)
	require.NoError(t, err)

	assert.Equal(t, RelayMessageTypeData, msg.Type)
	assert.Equal(t, destPeerID, msg.DestPeerID)
	assert.Equal(t, data, msg.Payload)
}

func TestUnwrapRelayMessage_TooShort(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
	}{
		{"Empty", []byte{}},
		{"One byte", []byte{0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := unwrapRelayMessage(tt.msg)
			assert.Nil(t, msg)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid relay message")
		})
	}
}

func TestUnwrapRelayMessage_InvalidDestLength(t *testing.T) {
	// Type + dest length that exceeds actual data
	msg := []byte{0x00, 0xFF, 0x01, 0x02} // dest length 255 but only 2 more bytes

	result, err := unwrapRelayMessage(msg)
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestRelay_Properties(t *testing.T) {
	relay := &Relay{
		Type:      RelayTypeTURN,
		Address:   netip.MustParseAddrPort("203.0.113.1:3478"),
		PeerID:    "",
		Latency:   100 * time.Millisecond,
		Capacity:  80,
		Available: true,
	}

	assert.Equal(t, RelayTypeTURN, relay.Type)
	assert.Equal(t, "turn", relay.Type.String())
	assert.Equal(t, 100*time.Millisecond, relay.Latency)
	assert.Equal(t, 80, relay.Capacity)
	assert.True(t, relay.Available)
}

func TestRelayMessage_Properties(t *testing.T) {
	msg := &RelayMessage{
		Type:       RelayMessageTypeData,
		DestPeerID: "dest-peer",
		SrcPeerID:  "src-peer",
		Payload:    []byte("test payload"),
		TTL:        3,
	}

	assert.Equal(t, RelayMessageTypeData, msg.Type)
	assert.Equal(t, "dest-peer", msg.DestPeerID)
	assert.Equal(t, "src-peer", msg.SrcPeerID)
	assert.Equal(t, []byte("test payload"), msg.Payload)
	assert.Equal(t, 3, msg.TTL)
}

func TestRelayMessageType_Values(t *testing.T) {
	assert.Equal(t, RelayMessageType(0), RelayMessageTypeData)
	assert.Equal(t, RelayMessageType(1), RelayMessageTypeConnect)
	assert.Equal(t, RelayMessageType(2), RelayMessageTypeDisconnect)
}

func TestRelayErrors(t *testing.T) {
	assert.NotNil(t, ErrRelayNotAvailable)
	assert.NotNil(t, ErrRelayFailed)
	assert.NotNil(t, ErrPeerNotRelayable)

	assert.Contains(t, ErrRelayNotAvailable.Error(), "no relay available")
	assert.Contains(t, ErrRelayFailed.Error(), "relay failed")
	assert.Contains(t, ErrPeerNotRelayable.Error(), "not relayable")
}

func TestPeerRelay_CreateConnection(t *testing.T) {
	mockConn := &mockP2PConnection{
		peerID:     "relay-peer",
		remoteAddr: netip.MustParseAddrPort("192.168.1.1:12345"),
		latency:    50 * time.Millisecond,
		state:      ConnectionStateConnected,
	}

	pr := &PeerRelay{
		peerID: "relay-peer",
		conn:   mockConn,
	}

	config := ConnectionConfig{
		PeerID: "target-peer",
	}

	conn, err := pr.CreateConnection(config)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Verify connection properties
	assert.Equal(t, "target-peer", conn.PeerID())
	assert.Equal(t, ConnectionTypeMultiHop, conn.Type())
	assert.Equal(t, ConnectionStateConnected, conn.State())
	// Latency should be relay latency * 2
	assert.Equal(t, 100*time.Millisecond, conn.Latency())
}

func TestPeerRelay_Close(t *testing.T) {
	mockConn := &mockP2PConnection{
		peerID: "relay-peer",
	}

	pr := &PeerRelay{
		peerID:      "relay-peer",
		conn:        mockConn,
		connections: make(map[string]*PeerRelayedConnection),
	}

	// Add a connection
	pr.connections["test"] = &PeerRelayedConnection{
		sendQueue: make(chan []byte, 256),
		recvQueue: make(chan []byte, 256),
	}

	err := pr.Close()
	assert.NoError(t, err)
	assert.Nil(t, pr.connections)
}

func TestPeerRelayedConnection_PeerID(t *testing.T) {
	mockConn := &mockP2PConnection{
		peerID: "relay-peer",
	}

	conn := &PeerRelayedConnection{
		config: ConnectionConfig{
			PeerID: "target-peer",
		},
		relayPeer: mockConn,
		sendQueue: make(chan []byte, 256),
		recvQueue: make(chan []byte, 256),
	}

	assert.Equal(t, "target-peer", conn.PeerID())
}

func TestPeerRelayedConnection_Type(t *testing.T) {
	mockConn := &mockP2PConnection{}

	conn := &PeerRelayedConnection{
		relayPeer: mockConn,
	}

	assert.Equal(t, ConnectionTypeMultiHop, conn.Type())
}

func TestPeerRelayedConnection_LocalAddr(t *testing.T) {
	localAddr := netip.MustParseAddrPort("192.168.1.100:12345")
	mockConn := &mockP2PConnection{
		localAddr: localAddr,
	}

	conn := &PeerRelayedConnection{
		relayPeer: mockConn,
	}

	assert.Equal(t, localAddr, conn.LocalAddr())
}

func TestPeerRelayedConnection_RemoteAddr(t *testing.T) {
	mockConn := &mockP2PConnection{}

	conn := &PeerRelayedConnection{
		relayPeer: mockConn,
	}

	// Remote address is unknown for multi-hop
	assert.Equal(t, netip.AddrPort{}, conn.RemoteAddr())
}

func TestPeerRelayedConnection_State(t *testing.T) {
	tests := []struct {
		name       string
		relayState ConnectionState
		expected   ConnectionState
	}{
		{"Connected", ConnectionStateConnected, ConnectionStateConnected},
		{"Connecting", ConnectionStateConnecting, ConnectionStateDisconnected},
		{"Disconnected", ConnectionStateDisconnected, ConnectionStateDisconnected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockP2PConnection{
				state: tt.relayState,
			}

			conn := &PeerRelayedConnection{
				relayPeer: mockConn,
			}

			assert.Equal(t, tt.expected, conn.State())
		})
	}
}

func TestPeerRelayedConnection_Close(t *testing.T) {
	mockConn := &mockP2PConnection{}

	conn := &PeerRelayedConnection{
		relayPeer: mockConn,
		sendQueue: make(chan []byte, 256),
		recvQueue: make(chan []byte, 256),
	}

	err := conn.Close()
	assert.NoError(t, err)
	assert.True(t, conn.closed)
}

func TestPeerRelayedConnection_Send_Closed(t *testing.T) {
	mockConn := &mockP2PConnection{}

	conn := &PeerRelayedConnection{
		config: ConnectionConfig{
			PeerID: "target-peer",
		},
		relayPeer: mockConn,
		sendQueue: make(chan []byte, 256),
		recvQueue: make(chan []byte, 256),
		closed:    true,
	}

	err := conn.Send([]byte("test"))
	assert.Error(t, err)
	assert.Equal(t, ErrConnectionClosed, err)
}

func TestPeerRelayedConnection_Receive_Closed(t *testing.T) {
	mockConn := &mockP2PConnection{}

	conn := &PeerRelayedConnection{
		relayPeer: mockConn,
		sendQueue: make(chan []byte, 256),
		recvQueue: make(chan []byte, 256),
		closed:    true,
	}

	data, err := conn.Receive()
	assert.Nil(t, data)
	assert.Error(t, err)
	assert.Equal(t, ErrConnectionClosed, err)
}

func TestNewRelayRouter(t *testing.T) {
	// Create a minimal manager for testing
	config := DefaultManagerConfig()
	manager, err := NewP2PManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	router := NewRelayRouter("local-peer", manager, 3)
	require.NotNil(t, router)

	assert.Equal(t, "local-peer", router.localPeerID)
	assert.Equal(t, 3, router.maxHops)
	assert.Equal(t, manager, router.manager)
}

// mockP2PConnection is a mock implementation of P2PConnection for testing
type mockP2PConnection struct {
	peerID     string
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort
	latency    time.Duration
	state      ConnectionState
	sentData   [][]byte
}

func (m *mockP2PConnection) PeerID() string {
	return m.peerID
}

func (m *mockP2PConnection) Send(data []byte) error {
	m.sentData = append(m.sentData, data)
	return nil
}

func (m *mockP2PConnection) Receive() ([]byte, error) {
	return nil, nil
}

func (m *mockP2PConnection) Latency() time.Duration {
	return m.latency
}

func (m *mockP2PConnection) Type() ConnectionType {
	return ConnectionTypeDirect
}

func (m *mockP2PConnection) State() ConnectionState {
	return m.state
}

func (m *mockP2PConnection) LocalAddr() netip.AddrPort {
	return m.localAddr
}

func (m *mockP2PConnection) RemoteAddr() netip.AddrPort {
	return m.remoteAddr
}

func (m *mockP2PConnection) Close() error {
	return nil
}
