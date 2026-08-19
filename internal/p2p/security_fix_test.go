package p2p

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshake runs a full init/response exchange between two sessions built from
// the given static key pairs and returns the completed sessions.
func handshake(t *testing.T, initPriv, respPriv []byte) (*CryptoSession, *CryptoSession) {
	t.Helper()

	initiator, err := NewCryptoSession(initPriv)
	require.NoError(t, err)
	responder, err := NewCryptoSession(respPriv)
	require.NoError(t, err)

	initMsg, err := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	require.NoError(t, err)
	resp, err := responder.ProcessHandshakeInit(initMsg)
	require.NoError(t, err)
	require.NoError(t, initiator.ProcessHandshakeResponse(resp))

	return initiator, responder
}

// TestSessionKeysUniquePerHandshake verifies that two handshakes between the
// SAME static key pairs derive DIFFERENT session keys, so that reusing the
// nonce counter (which restarts at 0 each session) never reuses a (key, nonce)
// pair. This is the regression test for the ChaCha20-Poly1305 nonce-reuse
// finding: the ciphertext of the same plaintext at nonce 0 must differ between
// two sessions.
func TestSessionKeysUniquePerHandshake(t *testing.T) {
	initKP, err := GenerateKeyPair()
	require.NoError(t, err)
	respKP, err := GenerateKeyPair()
	require.NoError(t, err)

	plaintext := []byte("the same plaintext at nonce 0")

	initA, respA := handshake(t, initKP.PrivateKey[:], respKP.PrivateKey[:])
	initB, respB := handshake(t, initKP.PrivateKey[:], respKP.PrivateKey[:])

	// Both sessions start their send nonce at 0.
	frameA := initA.Encrypt(plaintext)
	frameB := initB.Encrypt(plaintext)
	require.NotNil(t, frameA)
	require.NotNil(t, frameB)

	// Same nonce (0) in both frames...
	assert.Equal(t, frameA[1:1+NonceSize], frameB[1:1+NonceSize])
	// ...but the ciphertext+tag MUST differ, proving the session keys differ.
	assert.NotEqual(t, frameA[1+NonceSize:], frameB[1+NonceSize:],
		"identical ciphertext across sessions implies key+nonce reuse")

	// Each frame decrypts only under its own session's responder.
	got, err := respA.Decrypt(frameA)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	got, err = respB.Decrypt(frameB)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// Cross-session decryption must fail (different keys).
	_, err = respB.Decrypt(frameA)
	assert.Error(t, err)
}

// TestNonceMonotonicWithinSession verifies nonces strictly increase and every
// frame within a session decrypts correctly and exactly once.
func TestNonceMonotonicWithinSession(t *testing.T) {
	initiator, responder := handshake(t, nil, nil)

	seen := make(map[uint64]struct{})
	for i := 0; i < 5000; i++ {
		frame := initiator.Encrypt([]byte("payload"))
		require.NotNil(t, frame)
		var nonce uint64
		for b := 0; b < 8; b++ {
			nonce |= uint64(frame[1+b]) << (8 * b)
		}
		_, dup := seen[nonce]
		require.False(t, dup, "nonce %d reused within session", nonce)
		seen[nonce] = struct{}{}

		_, err := responder.Decrypt(frame)
		require.NoError(t, err)
	}
}

// TestReplayRejected verifies the sliding-window filter rejects exact replays
// and frames older than the window.
func TestReplayRejected(t *testing.T) {
	initiator, responder := handshake(t, nil, nil)

	frame := initiator.Encrypt([]byte("first"))
	_, err := responder.Decrypt(frame)
	require.NoError(t, err)

	// Exact replay is rejected.
	_, err = responder.Decrypt(frame)
	assert.Equal(t, ErrInvalidNonce, err)

	// Advance well beyond the replay window, then replay an old (within a fresh
	// buffer) frame captured from far behind the window: it must be rejected.
	old := initiator.Encrypt([]byte("old")) // nonce 1
	for i := 0; i < replayWindowBits+10; i++ {
		f := initiator.Encrypt([]byte("advance"))
		_, derr := responder.Decrypt(f)
		require.NoError(t, derr)
	}
	_, err = responder.Decrypt(old)
	assert.Equal(t, ErrInvalidNonce, err, "frame older than the window must be rejected")
}

// TestReplayOutOfOrderWithinWindow verifies that legitimate out-of-order
// delivery within the window is accepted (each nonce still only once).
func TestReplayOutOfOrderWithinWindow(t *testing.T) {
	initiator, responder := handshake(t, nil, nil)

	frames := make([][]byte, 10)
	for i := range frames {
		frames[i] = initiator.Encrypt([]byte("f"))
	}

	// Deliver in reverse order (all within the window).
	for i := len(frames) - 1; i >= 0; i-- {
		_, err := responder.Decrypt(frames[i])
		require.NoError(t, err, "in-window out-of-order frame %d should be accepted", i)
	}

	// Any redelivery is now a replay.
	for i := range frames {
		_, err := responder.Decrypt(frames[i])
		assert.Equal(t, ErrInvalidNonce, err)
	}
}

// newTestManager builds a started-enough manager with a real UDP socket so
// handleNewConnection can send responses.
func newTestManager(t *testing.T, allowUnknown bool) *P2PManager {
	t.Helper()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	pm, err := NewP2PManager(ManagerConfig{
		LocalPeerID:       "local",
		LocalPrivateKey:   kp.PrivateKey[:],
		ConnectTimeout:    time.Second,
		KeepAliveInterval: time.Second,
		AllowUnknownPeers: allowUnknown,
	})
	require.NoError(t, err)

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pm.conn = conn
	t.Cleanup(func() { _ = conn.Close() })

	return pm
}

// TestInboundUnknownPeerRejected verifies the fail-closed inbound path: a
// handshake from a public key that was never registered via RegisterPeerKey is
// rejected and no connection/callback is created.
func TestInboundUnknownPeerRejected(t *testing.T) {
	pm := newTestManager(t, false)

	var mu sync.Mutex
	connected := 0
	pm.SetCallbacks(ManagerCallbacks{
		OnPeerConnected: func(string, P2PConnection) {
			mu.Lock()
			connected++
			mu.Unlock()
		},
	})

	// Attacker knows the (non-secret) local public key and crafts a valid init.
	attacker, err := NewCryptoSession(nil)
	require.NoError(t, err)
	initMsg, err := attacker.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)

	from := netip.MustParseAddrPort("127.0.0.1:40000")
	pm.handleNewConnection(from, initMsg)

	pm.mu.RLock()
	numConns := len(pm.connections)
	pm.mu.RUnlock()
	assert.Equal(t, 0, numConns, "unknown peer must not create a connection")

	mu.Lock()
	assert.Equal(t, 0, connected, "OnPeerConnected must not fire for unknown peer")
	mu.Unlock()
}

// TestInboundKnownPeerAccepted verifies that a peer whose key is registered
// (i.e. learned from discovery) is accepted even with fail-closed defaults.
func TestInboundKnownPeerAccepted(t *testing.T) {
	pm := newTestManager(t, false)

	attacker, err := NewCryptoSession(nil)
	require.NoError(t, err)
	pm.RegisterPeerKey(attacker.LocalPublicKey(), "known-peer")

	initMsg, err := attacker.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)

	from := netip.MustParseAddrPort("127.0.0.1:40001")
	pm.handleNewConnection(from, initMsg)

	pm.mu.RLock()
	_, ok := pm.connections["known-peer"]
	pm.mu.RUnlock()
	assert.True(t, ok, "registered peer should be accepted")
}

// TestInboundUnknownPeerAllowedWhenConfigured verifies the escape hatch.
func TestInboundUnknownPeerAllowedWhenConfigured(t *testing.T) {
	pm := newTestManager(t, true)

	attacker, err := NewCryptoSession(nil)
	require.NoError(t, err)
	initMsg, err := attacker.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)

	from := netip.MustParseAddrPort("127.0.0.1:40002")
	pm.handleNewConnection(from, initMsg)

	pm.mu.RLock()
	numConns := len(pm.connections)
	pm.mu.RUnlock()
	assert.Equal(t, 1, numConns, "AllowUnknownPeers should accept synthetic peer")
}
