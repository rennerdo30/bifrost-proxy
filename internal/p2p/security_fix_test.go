package p2p

import (
	"encoding/binary"
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

// TestHandshakeInitRequiresStaticKeyProof is the regression test for handshake
// spoofing: knowing a peer's (non-secret, discovery-distributed) static public
// key must not be enough to open a session in its name. The attacker copies the
// victim's static public key into an otherwise well-formed initiation; the
// authenticator, which requires the victim's static PRIVATE key, must not
// verify.
func TestHandshakeInitRequiresStaticKeyProof(t *testing.T) {
	pm := newTestManager(t, false)

	victim, err := GenerateKeyPair()
	require.NoError(t, err)
	pm.RegisterPeerKey(victim.PublicKey[:], "victim")

	// The attacker builds a genuine initiation with its own static key, then
	// swaps in the victim's public key to impersonate it.
	attacker, err := NewCryptoSession(nil)
	require.NoError(t, err)
	initMsg, err := attacker.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)
	copy(initMsg[hsOffsetStaticPub:hsOffsetEphPub], victim.PublicKey[:])

	// Directly: the crypto layer must refuse it.
	responder, err := NewCryptoSession(nil)
	require.NoError(t, err)
	_, err = responder.ProcessHandshakeInit(initMsg)
	assert.ErrorIs(t, err, ErrHandshakeUnauthenticated,
		"an initiation claiming a public key without holding its private key must be rejected")

	// End to end: no connection is installed for the impersonated peer.
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40010"), initMsg)

	pm.mu.RLock()
	numConns := len(pm.connections)
	pm.mu.RUnlock()
	assert.Equal(t, 0, numConns, "spoofed handshake must not create a connection")
}

// TestHandshakeInitReplayRejected is the regression test for handshake-slot
// squatting: a verbatim replay of a captured (validly authenticated) initiation
// must not be accepted a second time, because doing so lets an attacker take
// over the victim's connection slot and endpoint and blackhole it.
func TestHandshakeInitReplayRejected(t *testing.T) {
	pm := newTestManager(t, false)

	peer, err := NewCryptoSession(nil)
	require.NoError(t, err)
	pm.RegisterPeerKey(peer.LocalPublicKey(), "peer")

	initMsg, err := peer.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)

	// First delivery is accepted.
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40020"), initMsg)
	pm.mu.RLock()
	_, ok := pm.connections["peer"]
	pm.mu.RUnlock()
	require.True(t, ok, "first authentic handshake should be accepted")

	// Forget the connection as if the peer had gone away, so the replay is not
	// merely rejected by the already-connected check. The entries are dropped
	// directly rather than via Disconnect, because closing the connection also
	// tears down the manager's shared socket and would mask the result.
	pm.mu.Lock()
	delete(pm.connections, "peer")
	delete(pm.endpoints, "peer")
	pm.mu.Unlock()

	// The captured initiation replayed from the attacker's own address must be
	// refused, and must not install a connection pointing at the attacker.
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40021"), initMsg)

	pm.mu.RLock()
	_, ok = pm.connections["peer"]
	pm.mu.RUnlock()
	assert.False(t, ok, "replayed handshake initiation must be rejected")
}

// TestHandshakeTimestampsStrictlyIncrease verifies the property the replay
// check depends on: no two initiations from one process ever share a timestamp,
// and each caller sees a strictly increasing sequence.
//
// This must be concurrent to be meaningful. A sequential loop passes even
// without nextHandshakeTimestamp's compare-and-swap, because a key generation
// plus an X25519 per iteration lets the wall clock advance every time; only
// concurrent callers can read the same nanosecond.
func TestHandshakeTimestampsStrictlyIncrease(t *testing.T) {
	const (
		goroutines  = 64
		perRoutine  = 500
		totalStamps = goroutines * perRoutine
	)

	var wg sync.WaitGroup
	results := make([][]uint64, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			stamps := make([]uint64, perRoutine)
			for i := range stamps {
				stamps[i] = nextHandshakeTimestamp()
			}
			results[g] = stamps
		}(g)
	}
	wg.Wait()

	seen := make(map[uint64]struct{}, totalStamps)
	for g, stamps := range results {
		var prev uint64
		for i, ts := range stamps {
			if _, dup := seen[ts]; dup {
				t.Fatalf("timestamp %d handed out twice (goroutine %d, index %d)", ts, g, i)
			}
			seen[ts] = struct{}{}

			if i > 0 && ts <= prev {
				t.Fatalf("timestamp regressed within one caller: %d after %d", ts, prev)
			}
			prev = ts
		}
	}
	assert.Len(t, seen, totalStamps)
}

// TestHandshakeInitTimestampIsFresh verifies the timestamp actually reaches the
// wire and advances between two initiations built from the same session state.
func TestHandshakeInitTimestampIsFresh(t *testing.T) {
	remote, err := GenerateKeyPair()
	require.NoError(t, err)

	first, err := NewCryptoSession(nil)
	require.NoError(t, err)
	firstMsg, err := first.CreateHandshakeInit(remote.PublicKey[:])
	require.NoError(t, err)

	second, err := NewCryptoSession(nil)
	require.NoError(t, err)
	secondMsg, err := second.CreateHandshakeInit(remote.PublicKey[:])
	require.NoError(t, err)

	onWire := func(msg []byte) uint64 {
		return binary.LittleEndian.Uint64(msg[hsOffsetTimestamp:hsOffsetMAC])
	}

	assert.Equal(t, first.HandshakeTimestamp(), onWire(firstMsg),
		"the timestamp used for derivation must be the one on the wire")
	assert.Greater(t, onWire(secondMsg), onWire(firstMsg))
}

// TestHandshakeResponseTampering verifies the initiator rejects a response that
// is not authenticated by the intended responder, and one that echoes a
// different handshake's timestamp (a replayed/reflected response).
func TestHandshakeResponseTampering(t *testing.T) {
	initKP, err := GenerateKeyPair()
	require.NoError(t, err)
	respKP, err := GenerateKeyPair()
	require.NoError(t, err)

	newExchange := func(t *testing.T) (*CryptoSession, []byte, []byte) {
		t.Helper()
		initiator, err := NewCryptoSession(initKP.PrivateKey[:])
		require.NoError(t, err)
		responder, err := NewCryptoSession(respKP.PrivateKey[:])
		require.NoError(t, err)

		initMsg, err := initiator.CreateHandshakeInit(responder.LocalPublicKey())
		require.NoError(t, err)
		response, err := responder.ProcessHandshakeInit(initMsg)
		require.NoError(t, err)
		return initiator, initMsg, response
	}

	t.Run("tampered ephemeral key", func(t *testing.T) {
		initiator, _, response := newExchange(t)

		// Flipping a bit in the responder's ephemeral key invalidates the MAC.
		response[hsOffsetEphPub] ^= 0x01
		assert.ErrorIs(t, initiator.ProcessHandshakeResponse(response), ErrHandshakeUnauthenticated)
		assert.False(t, initiator.handshakeComplete.Load())
	})

	t.Run("response from an earlier handshake", func(t *testing.T) {
		_, _, oldResponse := newExchange(t)
		initiator, _, _ := newExchange(t)

		// The old response is validly authenticated (same static key pair) but
		// echoes the previous handshake's timestamp, so it must be refused: a
		// replayed response must not be able to resurrect old key material.
		assert.Error(t, initiator.ProcessHandshakeResponse(oldResponse))
		assert.False(t, initiator.handshakeComplete.Load())
	})
}

// TestSessionKeysBoundToTranscript verifies that key derivation is bound to the
// handshake transcript: two sessions whose transcripts differ only in the
// handshake timestamp must derive different keys.
func TestSessionKeysBoundToTranscript(t *testing.T) {
	initiator, responder := handshake(t, nil, nil)

	first := initiator.Encrypt([]byte("bound to transcript"))
	second := initiator.Encrypt([]byte("bound to transcript"))
	require.NotNil(t, first)
	require.NotNil(t, second)

	_, err := responder.Decrypt(first)
	require.NoError(t, err)

	// Re-derive the responder's keys from the same static and ephemeral inputs
	// but a different handshake timestamp. Everything else being equal, the
	// derived keys must differ, so the peer's next frame no longer decrypts.
	// (The second frame carries an unseen nonce, so a failure here is a key
	// mismatch and not the replay filter.)
	responder.handshakeTimestamp++
	require.NoError(t, responder.initializeCiphers())

	_, err = responder.Decrypt(second)
	assert.Error(t, err, "keys must be bound to the handshake timestamp")
}

// TestUnregisterPeerIDRevokesAuthorization verifies that a departed peer's
// public key stops being accepted for inbound sessions. Public keys are not
// secret, so authorization granted by discovery must not outlive the peer.
func TestUnregisterPeerIDRevokesAuthorization(t *testing.T) {
	pm := newTestManager(t, false)

	peer, err := NewCryptoSession(nil)
	require.NoError(t, err)
	pm.RegisterPeerKey(peer.LocalPublicKey(), "departing")

	pm.UnregisterPeerID("departing")

	assert.Empty(t, pm.lookupPeerByKey(peer.LocalPublicKey()),
		"key mapping must be removed on revocation")

	initMsg, err := peer.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40030"), initMsg)

	pm.mu.RLock()
	numConns := len(pm.connections)
	pm.mu.RUnlock()
	assert.Equal(t, 0, numConns, "revoked peer must not be able to reconnect")
}

// TestDisconnectKeepsManagerSocketUsable is the regression test for a
// denial-of-service in the peer-revocation path: DirectConnection.Close used to
// close the manager's single shared UDP socket, which it does not own. The first
// peer to disconnect therefore tore down the whole node's P2P plane — no
// datagram could be sent or received afterwards, and the receive worker spun on
// the resulting ErrClosed. This sits directly under the mesh's onPeerLeft.
func TestDisconnectKeepsManagerSocketUsable(t *testing.T) {
	pm := newTestManager(t, false)

	peer, err := NewCryptoSession(nil)
	require.NoError(t, err)
	pm.RegisterPeerKey(peer.LocalPublicKey(), "peer")

	initMsg, err := peer.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40050"), initMsg)

	pm.mu.RLock()
	_, ok := pm.connections["peer"]
	pm.mu.RUnlock()
	require.True(t, ok)

	require.NoError(t, pm.Disconnect("peer"))

	// The shared socket must still be usable after a peer disconnects.
	_, err = pm.conn.WriteTo([]byte("probe"), net.UDPAddrFromAddrPort(
		netip.MustParseAddrPort("127.0.0.1:40051")))
	require.NoError(t, err, "disconnecting one peer must not close the manager's socket")

	// And a fresh peer must still be able to complete a handshake.
	other, err := NewCryptoSession(nil)
	require.NoError(t, err)
	pm.RegisterPeerKey(other.LocalPublicKey(), "other")

	otherInit, err := other.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40052"), otherInit)

	pm.mu.RLock()
	_, ok = pm.connections["other"]
	pm.mu.RUnlock()
	assert.True(t, ok, "a new peer must still connect after another disconnected")
}

// TestOldHandshakeFormatRejected documents that the wire format is not
// backward compatible: a pre-upgrade 65-byte initiation is rejected outright
// rather than being partially parsed.
func TestOldHandshakeFormatRejected(t *testing.T) {
	pm := newTestManager(t, false)

	peer, err := NewCryptoSession(nil)
	require.NoError(t, err)
	pm.RegisterPeerKey(peer.LocalPublicKey(), "legacy")

	initMsg, err := peer.CreateHandshakeInit(pm.LocalPublicKey())
	require.NoError(t, err)

	legacy := initMsg[:1+PublicKeySize+ephemeralPubSize] // old format: no timestamp, no MAC
	pm.handleNewConnection(netip.MustParseAddrPort("127.0.0.1:40040"), legacy)

	pm.mu.RLock()
	numConns := len(pm.connections)
	pm.mu.RUnlock()
	assert.Equal(t, 0, numConns, "legacy-format handshake must not be accepted")

	responder, err := NewCryptoSession(nil)
	require.NoError(t, err)
	_, err = responder.ProcessHandshakeInit(legacy)
	assert.ErrorIs(t, err, ErrHandshakeFailed)
}
