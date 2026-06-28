package p2p

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// localEndpoint returns the loopback endpoint a manager is actually listening on.
func localEndpoint(t *testing.T, pm *P2PManager) netip.AddrPort {
	t.Helper()
	require.NotNil(t, pm.conn)
	udp, ok := pm.conn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udp.Port)) //nolint:gosec // port fits uint16
}

// TestDataPlaneEndToEnd verifies that a marked data frame sent through a direct
// connection is decrypted by the receiving connection and delivered to the
// peer's OnData callback. This guards against the historical dual-reader race
// where inbound frames were never decrypted/delivered.
func TestDataPlaneEndToEnd(t *testing.T) {
	keyA, err := GenerateKeyPair()
	require.NoError(t, err)
	keyB, err := GenerateKeyPair()
	require.NoError(t, err)

	cfgA := DefaultManagerConfig()
	cfgA.LocalPeerID = "peer-a"
	cfgA.LocalPrivateKey = keyA.PrivateKey[:]
	cfgA.RelayEnabled = false
	cfgA.STUNServers = nil

	cfgB := DefaultManagerConfig()
	cfgB.LocalPeerID = "peer-b"
	cfgB.LocalPrivateKey = keyB.PrivateKey[:]
	cfgB.RelayEnabled = false
	cfgB.STUNServers = nil

	pmA, err := NewP2PManager(cfgA)
	require.NoError(t, err)
	pmB, err := NewP2PManager(cfgB)
	require.NoError(t, err)

	// Collect data delivered to each side via OnData.
	dataB := make(chan []byte, 4)
	pmA.SetCallbacks(ManagerCallbacks{})
	pmB.SetCallbacks(ManagerCallbacks{
		OnData: func(_ string, data []byte) {
			cp := make([]byte, len(data))
			copy(cp, data)
			dataB <- cp
		},
	})

	ctx := context.Background()
	require.NoError(t, pmA.Start(ctx))
	defer func() { _ = pmA.Stop() }() //nolint:errcheck // best effort cleanup
	require.NoError(t, pmB.Start(ctx))
	defer func() { _ = pmB.Stop() }() //nolint:errcheck // best effort cleanup

	// Let B resolve A's inbound handshake to the real peer ID.
	pmB.RegisterPeerKey(keyA.PublicKey[:], "peer-a")

	// A connects to B's loopback endpoint.
	bEndpoint := localEndpoint(t, pmB)
	connctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pmA.Connect(connctx, "peer-b", keyB.PublicKey[:], []netip.AddrPort{bEndpoint})
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Wait for B to register the inbound connection from A.
	require.Eventually(t, func() bool {
		return pmB.GetConnection("peer-a") != nil
	}, 3*time.Second, 20*time.Millisecond, "B should accept inbound connection")

	// A sends a marked data frame to B.
	payload := []byte{0x00, 'h', 'e', 'l', 'l', 'o', '-', 'm', 'e', 's', 'h'}
	require.NoError(t, pmA.Send("peer-b", payload))

	select {
	case got := <-dataB:
		require.True(t, bytes.Equal(payload, got), "B should receive decrypted payload, got %v", got)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for decrypted data on B")
	}
}

// TestRegisterPeerKeyIgnoresEmpty verifies empty inputs are ignored.
func TestRegisterPeerKeyIgnoresEmpty(t *testing.T) {
	cfg := DefaultManagerConfig()
	cfg.LocalPeerID = "local"
	pm, err := NewP2PManager(cfg)
	require.NoError(t, err)

	key, err := GenerateKeyPair()
	require.NoError(t, err)

	pm.RegisterPeerKey(nil, "x")
	pm.RegisterPeerKey(key.PublicKey[:], "")
	require.Equal(t, "", pm.lookupPeerByKey(nil))
	require.Equal(t, "", pm.lookupPeerByKey(key.PublicKey[:]))
}
