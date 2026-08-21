package mesh

import (
	"encoding/base64"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/device"
	"github.com/rennerdo30/bifrost-proxy/internal/frame"
	"github.com/rennerdo30/bifrost-proxy/internal/p2p"
)

// recordingDevice is a NetworkDevice that records every frame written to it, so
// tests can assert that unauthorized traffic never reaches the TUN/TAP device.
type recordingDevice struct {
	devType device.DeviceType

	mu     sync.Mutex
	writes [][]byte
}

func (d *recordingDevice) Name() string            { return "test0" }
func (d *recordingDevice) Type() device.DeviceType { return d.devType }
func (d *recordingDevice) MTU() int                { return 1400 }
func (d *recordingDevice) Close() error            { return nil }

func (d *recordingDevice) Read(_ []byte) (int, error) { return 0, net.ErrClosed }

func (d *recordingDevice) Write(buf []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writes = append(d.writes, append([]byte(nil), buf...))
	return len(buf), nil
}

func (d *recordingDevice) writeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.writes)
}

// newAuthzTestNode builds a MeshNode wired to a real P2P manager and a
// recording device, without starting discovery or the device loops.
func newAuthzTestNode(t *testing.T, allowedPeers []string) (*MeshNode, *recordingDevice) {
	t.Helper()

	kp, err := p2p.GenerateKeyPair()
	require.NoError(t, err)

	pm, err := p2p.NewP2PManager(p2p.ManagerConfig{
		LocalPeerID:       "local",
		LocalPrivateKey:   kp.PrivateKey[:],
		ConnectTimeout:    time.Second,
		KeepAliveInterval: time.Second,
	})
	require.NoError(t, err)

	dev := &recordingDevice{devType: device.DeviceTAP}

	node := &MeshNode{
		config: Config{
			Security: SecurityConfig{AllowedPeers: allowedPeers},
			Connection: ConnectionConfig{
				ConnectTimeout: time.Second,
			},
		},
		localPeerID:  "local",
		device:       dev,
		p2pManager:   pm,
		peerRegistry: NewPeerRegistry(),
		macTable:     frame.NewMACTable(frame.MACTableConfig{MaxAge: time.Minute}),
	}

	return node, dev
}

// peerInfoFor builds a discovery announcement for a freshly generated key pair.
func peerInfoFor(t *testing.T, id string) (PeerInfo, string) {
	t.Helper()

	kp, err := p2p.GenerateKeyPair()
	require.NoError(t, err)
	pub := base64.StdEncoding.EncodeToString(kp.PublicKey[:])

	return PeerInfo{
		ID:        id,
		Name:      id,
		PublicKey: pub,
		// No endpoints: onPeerDiscovered stops before dialing, which keeps the
		// test to the authorization decision.
		Endpoints: nil,
	}, pub
}

// TestDiscoveredPeerOutsideAllowlistNeverAuthorized verifies that a peer
// announced by discovery but absent from security.allowed_peers is never
// registered with the P2P manager, so it can never open an inbound session and
// its frames can never reach the device.
func TestDiscoveredPeerOutsideAllowlistNeverAuthorized(t *testing.T) {
	allowed, allowedKey := peerInfoFor(t, "allowed-peer")
	node, dev := newAuthzTestNode(t, []string{allowedKey})

	denied, deniedKey := peerInfoFor(t, "denied-peer")

	node.peerRegistry.Add(NewPeer(allowed.ID, allowed.Name))
	node.peerRegistry.Add(NewPeer(denied.ID, denied.Name))

	node.onPeerDiscovered(denied)
	node.onPeerDiscovered(allowed)

	deniedRaw, err := base64.StdEncoding.DecodeString(deniedKey)
	require.NoError(t, err)
	allowedRaw, err := base64.StdEncoding.DecodeString(allowedKey)
	require.NoError(t, err)

	assert.False(t, node.p2pManager.IsPeerAuthorized(deniedRaw),
		"a peer outside allowed_peers must not be authorized for inbound sessions")
	assert.True(t, node.p2pManager.IsPeerAuthorized(allowedRaw),
		"a peer inside allowed_peers must be authorized")

	assert.Equal(t, 0, dev.writeCount(), "authorization alone must never write to the device")
}

// TestEmptyAllowlistStillRequiresDiscovery documents the deliberate default: an
// empty allowed_peers list is "no explicit allowlist", not "allow anyone" — a
// key that discovery never announced is still unauthorized.
func TestEmptyAllowlistStillRequiresDiscovery(t *testing.T) {
	node, _ := newAuthzTestNode(t, nil)

	announced, announcedKey := peerInfoFor(t, "announced")
	node.peerRegistry.Add(NewPeer(announced.ID, announced.Name))
	node.onPeerDiscovered(announced)

	announcedRaw, err := base64.StdEncoding.DecodeString(announcedKey)
	require.NoError(t, err)
	assert.True(t, node.p2pManager.IsPeerAuthorized(announcedRaw))

	// A key that was never announced is not authorized, even with no allowlist.
	stranger, err := p2p.GenerateKeyPair()
	require.NoError(t, err)
	assert.False(t, node.p2pManager.IsPeerAuthorized(stranger.PublicKey[:]),
		"an unannounced key must not be authorized even without an allowlist")
}

// TestPeerLeaveRevokesAuthorization verifies authorization does not outlive the
// peer: once a peer leaves the mesh, its (non-secret) public key can no longer
// be used to open an inbound session and inject frames into the device.
func TestPeerLeaveRevokesAuthorization(t *testing.T) {
	node, _ := newAuthzTestNode(t, nil)
	node.router = NewMeshRouter(RouterConfig{LocalPeerID: node.localPeerID})
	node.protocol = NewRoutingProtocol(node.localPeerID, netip.Addr{}, node.router, ProtocolConfig{})

	info, key := peerInfoFor(t, "transient")
	node.peerRegistry.Add(NewPeer(info.ID, info.Name))
	node.onPeerDiscovered(info)

	raw, err := base64.StdEncoding.DecodeString(key)
	require.NoError(t, err)
	require.True(t, node.p2pManager.IsPeerAuthorized(raw))

	node.onPeerLeft(info.ID)

	assert.False(t, node.p2pManager.IsPeerAuthorized(raw),
		"a departed peer's key must be revoked, not left authorized for the process lifetime")
}

// TestDataFrameReachesDeviceForConnectedPeer is the positive control for the
// tests above: the data-plane path from an established peer really does end at
// the device, so "no device write" is a meaningful assertion.
func TestDataFrameReachesDeviceForConnectedPeer(t *testing.T) {
	node, dev := newAuthzTestNode(t, nil)

	// Minimal Ethernet frame: dst MAC, src MAC, ethertype.
	ethFrame := make([]byte, 14)
	copy(ethFrame[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(ethFrame[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	ethFrame[12], ethFrame[13] = 0x08, 0x00

	node.onP2PData("connected-peer", append([]byte{markerData}, ethFrame...))

	assert.Equal(t, 1, dev.writeCount(), "data frames from a connected peer reach the device")
}
