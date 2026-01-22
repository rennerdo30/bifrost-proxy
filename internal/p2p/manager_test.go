package p2p

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewP2PManager(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		config := DefaultManagerConfig()
		config.LocalPeerID = "test-peer"

		pm, err := NewP2PManager(config)
		require.NoError(t, err)
		require.NotNil(t, pm)

		assert.Equal(t, "test-peer", pm.localPeerID)
		assert.NotNil(t, pm.connections)
		assert.NotNil(t, pm.endpoints)
		assert.NotNil(t, pm.localKeyPair)
	})

	t.Run("with private key", func(t *testing.T) {
		// Generate a key pair first
		kp, err := GenerateKeyPair()
		require.NoError(t, err)

		config := DefaultManagerConfig()
		config.LocalPeerID = "test-peer"
		config.LocalPrivateKey = kp.PrivateKey[:]

		pm, err := NewP2PManager(config)
		require.NoError(t, err)
		require.NotNil(t, pm)

		assert.Equal(t, kp.PrivateKey[:], pm.localKeyPair.PrivateKey[:])
	})

	t.Run("generates key if not provided", func(t *testing.T) {
		config := DefaultManagerConfig()
		config.LocalPeerID = "test-peer"

		pm, err := NewP2PManager(config)
		require.NoError(t, err)

		assert.NotZero(t, pm.localKeyPair.PrivateKey)
		assert.NotZero(t, pm.localKeyPair.PublicKey)
	})
}

func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	assert.NotEmpty(t, config.STUNServers)
	assert.True(t, config.DirectConnectEnabled)
	assert.True(t, config.RelayEnabled)
	assert.True(t, config.PeerRelayEnabled)
	assert.Equal(t, 30*time.Second, config.ConnectTimeout)
	assert.Equal(t, 25*time.Second, config.KeepAliveInterval)
}

func TestP2PManagerLocalPublicKey(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	pubKey := pm.LocalPublicKey()
	assert.Len(t, pubKey, PublicKeySize)
	assert.NotZero(t, pubKey)
}

func TestP2PManagerSetCallbacks(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	pm.SetCallbacks(ManagerCallbacks{
		OnPeerConnected: func(peerID string, conn P2PConnection) {
			// Callback set
		},
	})

	assert.NotNil(t, pm.callbacks.OnPeerConnected)
}

func TestP2PManagerGetConnection(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	// No connections initially
	conn := pm.GetConnection("nonexistent")
	assert.Nil(t, conn)
}

func TestP2PManagerGetConnections(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	// No connections initially
	conns := pm.GetConnections()
	assert.Empty(t, conns)
}

func TestP2PManagerSendNotConnected(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	err = pm.Send("nonexistent", []byte("test"))
	assert.Equal(t, ErrPeerNotFound, err)
}

func TestP2PManagerDisconnectNotFound(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	err = pm.Disconnect("nonexistent")
	assert.Equal(t, ErrPeerNotFound, err)
}

func TestP2PManagerGetPeerInfo(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	// No peer info for nonexistent peer
	_, err = pm.GetPeerInfo("nonexistent")
	assert.Equal(t, ErrPeerNotFound, err)
}

func TestP2PManagerGetAllPeerInfo(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	// No peer info initially
	infos := pm.GetAllPeerInfo()
	assert.Empty(t, infos)
}

func TestP2PManagerGetStats(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	stats := pm.GetStats()
	assert.Equal(t, 0, stats.ActiveConnections)
	assert.Equal(t, 0, stats.DirectConnections)
	assert.Equal(t, 0, stats.RelayedConnections)
}

func TestP2PManagerStartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires network")
	}

	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start
	err = pm.Start(ctx)
	require.NoError(t, err)

	// LocalEndpoints should be populated
	endpoints := pm.LocalEndpoints()
	assert.NotEmpty(t, endpoints)

	// Stop
	err = pm.Stop()
	assert.NoError(t, err)
}

func TestP2PManagerConnectNoEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires network")
	}

	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = pm.Start(ctx)
	require.NoError(t, err)
	defer pm.Stop()

	// Try to connect with no endpoints
	_, err = pm.Connect(ctx, "peer2", []byte{}, nil)
	assert.Error(t, err)
}

func TestP2PManagerConnectExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires network")
	}

	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = pm.Start(ctx)
	require.NoError(t, err)
	defer pm.Stop()

	// Add a mock connection
	pm.mu.Lock()
	pm.connections["peer2"] = &mockConnection{peerID: "peer2"}
	pm.mu.Unlock()

	// Try to connect again
	_, err = pm.Connect(ctx, "peer2", []byte{}, []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1234"),
	})
	assert.Equal(t, ErrConnectionExists, err)
}

func TestLookupPeerByKey(t *testing.T) {
	config := DefaultManagerConfig()
	config.LocalPeerID = "test-peer"

	pm, err := NewP2PManager(config)
	require.NoError(t, err)

	// Currently returns empty string
	peerID := pm.lookupPeerByKey([]byte{1, 2, 3})
	assert.Empty(t, peerID)
}

// mockConnection implements P2PConnection for testing
type mockConnection struct {
	peerID string
}

func (m *mockConnection) PeerID() string {
	return m.peerID
}

func (m *mockConnection) Send(data []byte) error {
	return nil
}

func (m *mockConnection) Receive() ([]byte, error) {
	return nil, nil
}

func (m *mockConnection) Latency() time.Duration {
	return time.Millisecond
}

func (m *mockConnection) Type() ConnectionType {
	return ConnectionTypeDirect
}

func (m *mockConnection) State() ConnectionState {
	return ConnectionStateConnected
}

func (m *mockConnection) LocalAddr() netip.AddrPort {
	return netip.AddrPort{}
}

func (m *mockConnection) RemoteAddr() netip.AddrPort {
	return netip.AddrPort{}
}

func (m *mockConnection) Close() error {
	return nil
}
