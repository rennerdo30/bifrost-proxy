package p2p

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// establishedCryptoPair returns two crypto sessions with a completed
// handshake, so each can decrypt what the other encrypts.
func establishedCryptoPair(t *testing.T) (initiator, responder *CryptoSession) {
	t.Helper()

	initiator, err := NewCryptoSession(nil)
	require.NoError(t, err)
	responder, err = NewCryptoSession(nil)
	require.NoError(t, err)

	initMsg, err := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	require.NoError(t, err)
	response, err := responder.ProcessHandshakeInit(initMsg)
	require.NoError(t, err)
	require.NoError(t, initiator.ProcessHandshakeResponse(response))

	return initiator, responder
}

// testDirectConnection returns a DirectConnection whose recvWorker is
// running with an established crypto session, without a real peer.
func testDirectConnection(t *testing.T) (*DirectConnection, *CryptoSession) {
	t.Helper()

	local, remote := establishedCryptoPair(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })

	conn, err := NewDirectConnection(DefaultConnectionConfig(), pc, netip.MustParseAddrPort("127.0.0.1:9"))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	conn.crypto = local
	conn.state.Store(int32(ConnectionStateConnected))
	conn.wg.Add(1)
	go conn.recvWorker()

	return conn, remote
}

func TestDirectConnection_PongRecordsMeasuredLatency(t *testing.T) {
	conn, remote := testDirectConnection(t)

	// A PING was sent 50ms ago and its PONG arrives now: the stored latency
	// must be the measured round-trip, not a write duration or a guess.
	sentAt := time.Now().Add(-50 * time.Millisecond)
	conn.pingSentAt.Store(sentAt.UnixNano())
	conn.deliverDatagram(remote.Encrypt([]byte("PONG")))

	require.Eventually(t, func() bool {
		return conn.Latency() >= 50*time.Millisecond
	}, 2*time.Second, 5*time.Millisecond, "latency should reflect the PING->PONG round-trip")
	assert.Less(t, conn.Latency(), 2*time.Second)
	assert.Zero(t, conn.pingSentAt.Load(), "the outstanding-ping marker must be consumed")
}

func TestDirectConnection_UnsolicitedPongStoresNothing(t *testing.T) {
	conn, remote := testDirectConnection(t)

	// No PING outstanding: a stray PONG must not fabricate a latency.
	conn.deliverDatagram(remote.Encrypt([]byte("PONG")))

	// Follow with a data payload and wait for it, proving the PONG was
	// already processed when we assert.
	conn.deliverDatagram(remote.Encrypt([]byte("payload")))
	select {
	case <-conn.recvQueue:
	case <-time.After(2 * time.Second):
		t.Fatal("payload never delivered")
	}

	assert.Zero(t, conn.Latency())
}

func TestRelayedConnection_RemoteAddrReportsPeerAddress(t *testing.T) {
	rc, err := NewRelayedConnection(DefaultConnectionConfig(), nil)
	require.NoError(t, err)

	// Before Connect: honestly zero.
	assert.False(t, rc.RemoteAddr().IsValid())

	peer := netip.MustParseAddrPort("203.0.113.7:4711")
	rc.remoteAddr = peer
	assert.Equal(t, peer, rc.RemoteAddr())
}
