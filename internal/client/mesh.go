package client

import (
	apiclient "github.com/rennerdo30/bifrost-proxy/internal/api/client"
	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
)

// meshManagerAdapter adapts *mesh.MeshNode to the apiclient.MeshManager
// interface. The only structural mismatch is LocalIP: the mesh node returns a
// netip.Addr, while the API contract expects a string, so this adapter embeds
// the node and overrides that single method. Everything else is satisfied by
// the embedded *mesh.MeshNode directly.
type meshManagerAdapter struct {
	*mesh.MeshNode
}

// LocalIP returns the node's virtual IP as a string, satisfying
// apiclient.MeshManager. An invalid (zero) address renders as an empty string
// so the API reports no virtual IP rather than a placeholder.
func (m meshManagerAdapter) LocalIP() string {
	ip := m.MeshNode.LocalIP()
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

// compile-time assertion that the adapter satisfies the API interface.
var _ apiclient.MeshManager = meshManagerAdapter{}

// newMeshManager constructs a mesh node from the client's mesh configuration and
// wraps it in the adapter so it can be wired into the client API. It returns nil
// (and no error) when mesh networking is disabled.
func newMeshManager(cfg mesh.Config) (apiclient.MeshManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	node, err := mesh.NewMeshNode(cfg)
	if err != nil {
		return nil, err
	}

	return meshManagerAdapter{MeshNode: node}, nil
}
