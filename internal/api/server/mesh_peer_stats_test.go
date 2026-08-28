package server

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
)

// TestPeerWithStats_EmitsTheFieldsTheDashboardDeclares guards the fields that
// used to be dropped. The peers endpoints returned a bare mesh.PeerInfo, so
// every stats field the dashboard's MeshPeer type declares arrived undefined
// and rendered blank - even though the Peer being copied from had them all.
func TestPeerWithStats_EmitsTheFieldsTheDashboardDeclares(t *testing.T) {
	peer := mesh.NewPeer("peer-1", "alice")
	peer.PublicKey = "cHVibGljLWtleQ=="
	peer.SetVirtualIP(netip.MustParseAddr("10.42.0.7"))
	peer.SetStatus(mesh.PeerStatusConnected)
	peer.SetConnectionType(mesh.ConnectionTypeDirect)
	peer.SetLatency(12 * time.Millisecond)
	peer.UpdateLastSeen()

	data, err := json.Marshal(newPeerWithStats(peer))
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))

	// Identity, as before.
	assert.Equal(t, "peer-1", got["id"])
	assert.Equal(t, "alice", got["name"])
	assert.Equal(t, "10.42.0.7", got["virtual_ip"])

	// The stats that were previously absent.
	for _, field := range []string{"status", "connection_type", "latency", "last_seen", "joined_at", "bytes_sent", "bytes_received"} {
		assert.Contains(t, got, field, "the dashboard declares %q on MeshPeer", field)
	}

	assert.Equal(t, string(mesh.PeerStatusConnected), got["status"])
	assert.Equal(t, string(mesh.ConnectionTypeDirect), got["connection_type"])
}

// TestPeerWithStats_LatencyIsMilliseconds is the interesting assertion. A Go
// time.Duration marshals to integer nanoseconds, and the dashboard renders this
// value directly as "<n>ms" - so emitting the Duration would have displayed
// 12ms as 12000000ms.
func TestPeerWithStats_LatencyIsMilliseconds(t *testing.T) {
	tests := []struct {
		name    string
		latency time.Duration
		want    float64
	}{
		{"whole milliseconds", 12 * time.Millisecond, 12},
		{"sub-millisecond keeps precision", 500 * time.Microsecond, 0.5},
		{"seconds scale correctly", 2 * time.Second, 2000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := mesh.NewPeer("peer-1", "alice")
			peer.SetLatency(tt.latency)

			data, err := json.Marshal(newPeerWithStats(peer))
			require.NoError(t, err)

			var got struct {
				Latency float64 `json:"latency"`
			}
			require.NoError(t, json.Unmarshal(data, &got))
			assert.InDelta(t, tt.want, got.Latency, 0.0001,
				"latency must be milliseconds, not nanoseconds")
		})
	}
}

// TestPeerWithStats_ByteCountersAreReported covers the counters the UI shows
// per peer, which were also dropped.
func TestPeerWithStats_ByteCountersAreReported(t *testing.T) {
	peer := mesh.NewPeer("peer-1", "alice")
	peer.AddBytesSent(4096)
	peer.AddBytesReceived(8192)

	resp := newPeerWithStats(peer)
	assert.Equal(t, int64(4096), resp.BytesSent)
	assert.Equal(t, int64(8192), resp.BytesReceived)
}
