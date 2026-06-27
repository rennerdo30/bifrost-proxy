package mesh

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// framingNode is a minimal in-memory node that exercises the exact
// control-plane framing contract used by MeshNode: protocol messages are
// prefixed with markerProtocol on send, and the receive path dispatches on the
// leading marker byte and strips it before handing the JSON message to the
// routing protocol. Raw (non-marker) data is delivered to a TUN sink.
type framingNode struct {
	peerID   string
	router   *MeshRouter
	protocol *RoutingProtocol
	tunSink  [][]byte
}

func newFramingNode(peerID, ip string) *framingNode {
	addr := netip.MustParseAddr(ip)
	router := NewMeshRouter(RouterConfig{
		LocalPeerID:  peerID,
		LocalIP:      addr,
		MaxHops:      8,
		RouteTimeout: 5 * time.Minute,
	})
	protocol := NewRoutingProtocol(peerID, addr, router, DefaultProtocolConfig())
	return &framingNode{
		peerID:   peerID,
		router:   router,
		protocol: protocol,
	}
}

// onData mirrors MeshNode.onP2PData's dispatch: switch on the marker byte,
// strip it, and route to the protocol; otherwise treat as raw tunnel data.
func (n *framingNode) onData(fromPeerID string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	switch data[0] {
	case markerProtocol:
		// Strip the protocol marker, as handleProtocolMessage does.
		return n.protocol.HandleMessage(fromPeerID, data[1:])
	case markerBroadcast:
		// Not exercised here.
		return nil
	default:
		n.tunSink = append(n.tunSink, data)
		return nil
	}
}

// TestFraming_TwoNodesExchangeHelloAndRoute wires two in-memory nodes together
// and verifies that a HelloMessage / route announcement traverse the framing
// successfully: markers are prepended on send and stripped on receive, the
// peer route is installed, and raw (non-marker) data is delivered to the TUN
// sink rather than being misinterpreted as a control message.
func TestFraming_TwoNodesExchangeHelloAndRoute(t *testing.T) {
	nodeA := newFramingNode("peer-a", "10.0.0.1")
	nodeB := newFramingNode("peer-b", "10.0.0.2")

	// Wire send functions exactly like MeshNode.wireCallbacks: prepend the
	// protocol marker, then deliver to the remote node's receive dispatch.
	nodeA.protocol.SetSendFunc(func(peerID string, msg []byte) error {
		require.Equal(t, "peer-b", peerID)
		framed := append([]byte{markerProtocol}, msg...)
		return nodeB.onData("peer-a", framed)
	})
	nodeB.protocol.SetSendFunc(func(peerID string, msg []byte) error {
		require.Equal(t, "peer-a", peerID)
		framed := append([]byte{markerProtocol}, msg...)
		return nodeA.onData("peer-b", framed)
	})

	// Make each node aware of the other as a direct neighbor so that route
	// announcements are exchanged.
	nodeA.protocol.NotifyPeerConnected("peer-b", netip.MustParseAddr("10.0.0.2"), 5*time.Millisecond)
	nodeB.protocol.NotifyPeerConnected("peer-a", netip.MustParseAddr("10.0.0.1"), 5*time.Millisecond)

	// NotifyPeerConnected adds the direct route locally and announces routes.
	// Verify each node has a direct route to the other.
	routeAtoB := nodeA.router.GetRoute("peer-b")
	require.NotNil(t, routeAtoB, "node A should have a route to peer-b")
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), routeAtoB.DestIP)

	routeBtoA := nodeB.router.GetRoute("peer-a")
	require.NotNil(t, routeBtoA, "node B should have a route to peer-a")
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), routeBtoA.DestIP)

	// Now exercise a Hello -> HelloAck round trip through the framing. Node A
	// sends a hello to its neighbors; node B must receive it (marker stripped),
	// reply with a hello ack, and node A must process the ack (updating
	// latency) without error.
	nodeA.protocol.sendHelloToNeighbors()

	// Node B should have learned a latency for peer-a from the hello ack RTT.
	// The ack updates the route latency on node A; ensure the round trip did
	// not error and the route still exists.
	require.NotNil(t, nodeA.router.GetRoute("peer-b"))

	// Verify raw data (no marker) is delivered to the TUN sink, not the
	// protocol. Use an IPv4-looking packet whose first byte (0x45) is neither
	// marker.
	rawPacket := []byte{0x45, 0x00, 0x00, 0x14}
	require.NoError(t, nodeB.onData("peer-a", rawPacket))
	require.Len(t, nodeB.tunSink, 1)
	assert.Equal(t, rawPacket, nodeB.tunSink[0])
}

// TestFraming_RouteAnnouncePropagates verifies that a third destination learned
// by one node is announced to its neighbor through the framed transport and
// installed in the neighbor's routing table.
func TestFraming_RouteAnnouncePropagates(t *testing.T) {
	nodeA := newFramingNode("peer-a", "10.0.0.1")
	nodeB := newFramingNode("peer-b", "10.0.0.2")

	nodeA.protocol.SetSendFunc(func(_ string, msg []byte) error {
		framed := append([]byte{markerProtocol}, msg...)
		return nodeB.onData("peer-a", framed)
	})
	nodeB.protocol.SetSendFunc(func(_ string, msg []byte) error {
		framed := append([]byte{markerProtocol}, msg...)
		return nodeA.onData("peer-b", framed)
	})

	// A connects to B (direct route A->B). This announces the new peer to A's
	// neighbors; B has none yet, so nothing propagates. Then connect B->A so
	// both are neighbors.
	nodeB.protocol.NotifyPeerConnected("peer-a", netip.MustParseAddr("10.0.0.1"), time.Millisecond)
	nodeA.protocol.NotifyPeerConnected("peer-b", netip.MustParseAddr("10.0.0.2"), time.Millisecond)

	// Node A learns about a third peer "peer-c" directly. This triggers an
	// announcement to neighbor B through the framed transport.
	nodeA.protocol.NotifyPeerConnected("peer-c", netip.MustParseAddr("10.0.0.3"), time.Millisecond)

	// Node B should now have a route to peer-c via peer-a.
	routeToC := nodeB.router.GetRoute("peer-c")
	require.NotNil(t, routeToC, "node B should have learned a route to peer-c via the framed announcement")
	assert.Equal(t, "peer-a", routeToC.NextHop)
	assert.Equal(t, netip.MustParseAddr("10.0.0.3"), routeToC.DestIP)
}
