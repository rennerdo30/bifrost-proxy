package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
)

func TestNewMeshManager_DisabledReturnsNil(t *testing.T) {
	mgr, err := newMeshManager(mesh.Config{Enabled: false})
	require.NoError(t, err)
	assert.Nil(t, mgr, "disabled mesh must yield a nil manager so the API reports it as not configured")
}

func TestNewMeshManager_EnabledConstructsAdapter(t *testing.T) {
	cfg := mesh.DefaultConfig()
	cfg.Enabled = true
	cfg.NetworkID = "test-net"
	cfg.NetworkCIDR = "10.123.0.0/16"
	cfg.PeerName = "test-peer"
	cfg.Discovery.Server = "discovery.example.com:8080"
	cfg.Discovery.HeartbeatInterval = 30 * time.Second
	cfg.Discovery.PeerTimeout = 90 * time.Second

	mgr, err := newMeshManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// Before Start the node is stopped and has no assigned virtual IP, so LocalIP
	// must be the empty string (not a placeholder) per the adapter contract.
	assert.Equal(t, mesh.NodeStatusStopped, mgr.Status())
	assert.Equal(t, "", mgr.LocalIP(), "an unstarted node has no valid virtual IP")
	assert.NotEmpty(t, mgr.LocalPeerID(), "peer ID derives from the configured peer name")
}

func TestMeshManagerAdapter_LocalIPConvertsNetipAddr(t *testing.T) {
	cfg := mesh.DefaultConfig()
	cfg.Enabled = true
	cfg.NetworkID = "test-net"
	cfg.NetworkCIDR = "10.200.0.0/16"
	cfg.PeerName = "peer-x"
	cfg.Discovery.Server = "discovery.example.com:8080"

	node, err := mesh.NewMeshNode(cfg)
	require.NoError(t, err)

	adapter := meshManagerAdapter{MeshNode: node}
	// The adapter must bridge netip.Addr -> string from the same source.
	nodeIP := node.LocalIP()
	if nodeIP.IsValid() {
		assert.Equal(t, nodeIP.String(), adapter.LocalIP())
	} else {
		assert.Equal(t, "", adapter.LocalIP())
	}
}
