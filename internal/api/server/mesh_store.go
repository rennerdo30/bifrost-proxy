package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/websocket"

	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
)

const (
	// meshStateVersion is the schema version of the persisted coordinator state.
	// Bump it whenever the on-disk layout changes incompatibly; unknown versions
	// are refused rather than silently misread.
	meshStateVersion = 1

	// meshStateDirPerm / meshStateFilePerm guard the state file. It contains
	// peer public keys and virtual IPs — not secrets, but not world-readable
	// topology either.
	meshStateDirPerm  os.FileMode = 0o750
	meshStateFilePerm os.FileMode = 0o600

	// meshStateTempPattern is the temp-file pattern used for the atomic
	// write-then-rename that keeps the state file from being truncated on crash.
	meshStateTempPattern = "mesh-state-*.json.tmp"
)

// meshState is the on-disk representation of the coordinator's networks.
type meshState struct {
	Version  int                `json:"version"`
	Networks []meshNetworkState `json:"networks"`
}

// meshNetworkState is a single persisted network and its registered peers.
type meshNetworkState struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	CIDR    string          `json:"cidr"`
	Created time.Time       `json:"created"`
	Peers   []mesh.PeerInfo `json:"peers"`
}

// snapshot builds a serializable copy of the current coordinator state.
func (m *MeshAPI) snapshot() meshState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state := meshState{
		Version:  meshStateVersion,
		Networks: make([]meshNetworkState, 0, len(m.networks)),
	}
	for _, network := range m.networks {
		peers := network.peers.All()
		infos := make([]mesh.PeerInfo, 0, len(peers))
		for _, p := range peers {
			infos = append(infos, mesh.PeerInfo{
				ID:        p.ID,
				Name:      p.Name,
				PublicKey: p.PublicKey,
				VirtualIP: p.VirtualIP.String(),
				Endpoints: p.GetEndpoints(),
				Metadata:  p.Metadata,
			})
		}
		state.Networks = append(state.Networks, meshNetworkState{
			ID:      network.ID,
			Name:    network.Name,
			CIDR:    network.CIDR,
			Created: network.Created,
			Peers:   infos,
		})
	}
	return state
}

// persist writes the current state to disk. It is a no-op when no state path is
// configured (in-memory coordinator). Failures are logged rather than returned:
// the mutation the caller performed has already succeeded in memory, and a
// coordinator that refuses peer registrations because a disk is full would be
// worse than one that loses state on restart.
//
// The caller must NOT hold m.mu — persist takes a read lock itself.
func (m *MeshAPI) persist() {
	if m.statePath == "" {
		return
	}

	if err := m.writeState(m.snapshot()); err != nil {
		slog.Error("failed to persist mesh coordinator state",
			"path", m.statePath,
			"error", err,
		)
	}
}

// writeState serializes state and replaces the state file atomically.
func (m *MeshAPI) writeState(state meshState) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal mesh state: %w", err)
	}

	dir := filepath.Dir(m.statePath)
	if mkErr := os.MkdirAll(dir, meshStateDirPerm); mkErr != nil {
		return fmt.Errorf("create mesh state directory %s: %w", dir, mkErr)
	}

	tmp, err := os.CreateTemp(dir, meshStateTempPattern)
	if err != nil {
		return fmt.Errorf("create mesh state temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // Best effort cleanup; a successful rename makes this a no-op

	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck // Write error already dominates
		return fmt.Errorf("write mesh state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close mesh state temp file: %w", err)
	}
	if err := os.Chmod(tmpName, meshStateFilePerm); err != nil {
		return fmt.Errorf("chmod mesh state temp file: %w", err)
	}
	if err := os.Rename(tmpName, m.statePath); err != nil {
		return fmt.Errorf("replace mesh state file: %w", err)
	}
	return nil
}

// restore loads previously persisted networks and peers. A missing file is not
// an error (first start). A malformed or unsupported file is reported so the
// operator can act, and the coordinator starts empty.
func (m *MeshAPI) restore() error {
	if m.statePath == "" {
		return nil
	}

	data, err := os.ReadFile(m.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read mesh state %s: %w", m.statePath, err)
	}

	var state meshState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse mesh state %s: %w", m.statePath, err)
	}
	if state.Version != meshStateVersion {
		return fmt.Errorf("unsupported mesh state version %d in %s (expected %d)",
			state.Version, m.statePath, meshStateVersion)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ns := range state.Networks {
		allocator, allocErr := mesh.NewPoolAllocator(mesh.PoolConfig{NetworkCIDR: ns.CIDR})
		if allocErr != nil {
			slog.Warn("skipping persisted mesh network with invalid CIDR",
				"network_id", ns.ID,
				"cidr", ns.CIDR,
				"error", allocErr,
			)
			continue
		}

		network := &MeshNetwork{
			ID:          ns.ID,
			Name:        ns.Name,
			CIDR:        ns.CIDR,
			Created:     ns.Created,
			peers:       mesh.NewPeerRegistry(),
			ipAllocator: allocator,
			wsClients:   make(map[string]*websocket.Conn),
		}

		for _, pi := range ns.Peers {
			addr, parseErr := netip.ParseAddr(pi.VirtualIP)
			if parseErr != nil {
				slog.Warn("skipping persisted mesh peer with invalid virtual IP",
					"network_id", ns.ID,
					"peer_id", pi.ID,
					"virtual_ip", pi.VirtualIP,
					"error", parseErr,
				)
				continue
			}
			// Re-pin the peer's previous address so restarting the coordinator
			// does not renumber a running mesh.
			if allocErr := allocator.AllocateSpecific(pi.ID, addr); allocErr != nil {
				slog.Warn("failed to restore mesh peer IP allocation",
					"network_id", ns.ID,
					"peer_id", pi.ID,
					"virtual_ip", pi.VirtualIP,
					"error", allocErr,
				)
				continue
			}

			peer := mesh.NewPeer(pi.ID, pi.Name)
			peer.PublicKey = pi.PublicKey
			peer.Endpoints = pi.Endpoints
			peer.Metadata = pi.Metadata
			peer.SetVirtualIP(addr)
			network.peers.Add(peer)
		}

		m.networks[ns.ID] = network
		slog.Info("restored mesh network",
			"network_id", ns.ID,
			"cidr", ns.CIDR,
			"peers", network.peers.Count(),
		)
	}

	return nil
}
