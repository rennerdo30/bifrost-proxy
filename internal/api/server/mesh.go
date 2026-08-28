package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/mesh"
)

// MeshAPI provides the REST API for mesh network management.
type MeshAPI struct {
	networks map[string]*MeshNetwork
	mu       sync.RWMutex

	// statePath, when non-empty, is the file networks and peers are persisted
	// to so they survive a restart. persistMu serializes writes to it
	// independently of mu so a slow disk cannot block request handling.
	statePath string
	persistMu sync.Mutex
}

// MeshNetwork represents a single mesh network.
type MeshNetwork struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CIDR        string    `json:"cidr"`
	Created     time.Time `json:"created"`
	peers       *mesh.PeerRegistry
	ipAllocator *mesh.PoolAllocator
	wsClients   map[string]*websocket.Conn
	mu          sync.RWMutex
}

// NewMeshAPI creates an in-memory mesh API handler with no persistence.
func NewMeshAPI() *MeshAPI {
	return &MeshAPI{
		networks: make(map[string]*MeshNetwork),
	}
}

// NewMeshAPIWithConfig creates a mesh API handler from the server's mesh config.
// When cfg.StatePath is set, previously persisted networks and peers are
// restored and every subsequent mutation is written back. A restore failure is
// returned so the caller can decide whether to surface it; the returned handler
// is always usable (it simply starts empty).
func NewMeshAPIWithConfig(cfg config.MeshConfig) (*MeshAPI, error) {
	m := &MeshAPI{
		networks:  make(map[string]*MeshNetwork),
		statePath: cfg.StatePath,
	}
	if err := m.restore(); err != nil {
		return m, fmt.Errorf("restore mesh state: %w", err)
	}
	return m, nil
}

// RegisterRoutes registers mesh API routes on a chi router.
func (m *MeshAPI) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/mesh", func(r chi.Router) {
		// Network management
		r.Get("/networks", m.handleListNetworks)
		r.Post("/networks", m.handleCreateNetwork)
		r.Get("/networks/{networkID}", m.handleGetNetwork)
		r.Delete("/networks/{networkID}", m.handleDeleteNetwork)

		// Peer management
		r.Post("/networks/{networkID}/peers", m.handleRegisterPeer)
		r.Get("/networks/{networkID}/peers", m.handleListPeers)
		r.Get("/networks/{networkID}/peers/{peerID}", m.handleGetPeer)
		r.Patch("/networks/{networkID}/peers/{peerID}", m.handleUpdatePeer)
		r.Delete("/networks/{networkID}/peers/{peerID}", m.handleDeregisterPeer)
		r.Post("/networks/{networkID}/peers/{peerID}/heartbeat", m.handleHeartbeat)

		// WebSocket for events
		r.Handle("/networks/{networkID}/events", websocket.Handler(m.handleEvents))
	})
}

// Network request/response types

type createNetworkRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

type networkResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	PeerCount int       `json:"peer_count"`
	Created   time.Time `json:"created"`
}

// Peer request/response types

type registerPeerRequest struct {
	NetworkID string        `json:"network_id"`
	Peer      mesh.PeerInfo `json:"peer"`
}

type registerPeerResponse struct {
	Success   bool            `json:"success"`
	VirtualIP string          `json:"virtual_ip"`
	Message   string          `json:"message,omitempty"`
	Peers     []mesh.PeerInfo `json:"peers,omitempty"`
}

type updatePeerRequest struct {
	Endpoints []mesh.Endpoint   `json:"endpoints,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// handleListNetworks returns all mesh networks.
func (m *MeshAPI) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	networks := make([]networkResponse, 0, len(m.networks))
	for _, network := range m.networks {
		networks = append(networks, networkResponse{
			ID:        network.ID,
			Name:      network.Name,
			CIDR:      network.CIDR,
			PeerCount: network.peers.Count(),
			Created:   network.Created,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"networks": networks,
	})
}

// handleCreateNetwork creates a new mesh network.
func (m *MeshAPI) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "network ID is required", http.StatusBadRequest)
		return
	}

	if req.CIDR == "" {
		req.CIDR = "10.100.0.0/16"
	}

	m.mu.Lock()

	if _, exists := m.networks[req.ID]; exists {
		m.mu.Unlock()
		http.Error(w, "network already exists", http.StatusConflict)
		return
	}

	// Create IP allocator
	allocator, err := mesh.NewPoolAllocator(mesh.PoolConfig{
		NetworkCIDR: req.CIDR,
	})
	if err != nil {
		m.mu.Unlock()
		http.Error(w, "invalid CIDR: "+err.Error(), http.StatusBadRequest)
		return
	}

	network := &MeshNetwork{
		ID:          req.ID,
		Name:        req.Name,
		CIDR:        req.CIDR,
		Created:     time.Now(),
		peers:       mesh.NewPeerRegistry(),
		ipAllocator: allocator,
		wsClients:   make(map[string]*websocket.Conn),
	}

	m.networks[req.ID] = network
	m.mu.Unlock()

	// persist must run without m held (it takes a read lock itself).
	m.persist()

	slog.Info("mesh network created", "network_id", req.ID, "cidr", req.CIDR)

	writeJSON(w, http.StatusCreated, networkResponse{
		ID:        network.ID,
		Name:      network.Name,
		CIDR:      network.CIDR,
		PeerCount: 0,
		Created:   network.Created,
	})
}

// handleGetNetwork returns a specific mesh network.
func (m *MeshAPI) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, networkResponse{
		ID:        network.ID,
		Name:      network.Name,
		CIDR:      network.CIDR,
		PeerCount: network.peers.Count(),
		Created:   network.Created,
	})
}

// handleDeleteNetwork deletes a mesh network.
func (m *MeshAPI) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")

	m.mu.Lock()
	if _, exists := m.networks[networkID]; !exists {
		m.mu.Unlock()
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}
	delete(m.networks, networkID)
	m.mu.Unlock()

	m.persist()

	slog.Info("mesh network deleted", "network_id", networkID)

	w.WriteHeader(http.StatusNoContent)
}

// handleRegisterPeer registers a peer with a mesh network.
func (m *MeshAPI) handleRegisterPeer(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	var req registerPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Peer.ID == "" {
		http.Error(w, "peer ID is required", http.StatusBadRequest)
		return
	}

	// Allocate IP address
	ip, err := network.ipAllocator.Allocate(req.Peer.ID)
	if err != nil {
		http.Error(w, "failed to allocate IP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create peer
	peer := mesh.NewPeer(req.Peer.ID, req.Peer.Name)
	peer.PublicKey = req.Peer.PublicKey
	peer.Endpoints = req.Peer.Endpoints
	peer.Metadata = req.Peer.Metadata
	peer.SetVirtualIP(ip)

	network.peers.Add(peer)
	m.persist()

	// Get all other peers for the response
	allPeers := network.peers.All()
	otherPeers := make([]mesh.PeerInfo, 0, len(allPeers)-1)
	for _, p := range allPeers {
		if p.ID == req.Peer.ID {
			continue
		}
		otherPeers = append(otherPeers, mesh.PeerInfo{
			ID:        p.ID,
			Name:      p.Name,
			PublicKey: p.PublicKey,
			VirtualIP: p.VirtualIP.String(),
			Endpoints: p.GetEndpoints(),
			Metadata:  p.Metadata,
		})
	}

	// Broadcast join event
	network.broadcastEvent(mesh.PeerEvent{
		Type: "join",
		Peer: mesh.PeerInfo{
			ID:        peer.ID,
			Name:      peer.Name,
			PublicKey: peer.PublicKey,
			VirtualIP: ip.String(),
			Endpoints: peer.GetEndpoints(),
		},
		Timestamp: time.Now(),
	})

	slog.Info("peer registered",
		"network_id", networkID,
		"peer_id", req.Peer.ID,
		"virtual_ip", ip.String(),
	)

	writeJSON(w, http.StatusCreated, registerPeerResponse{
		Success:   true,
		VirtualIP: ip.String(),
		Peers:     otherPeers,
	})
}

// handleListPeers returns all peers in a network.
func (m *MeshAPI) handleListPeers(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	allPeers := network.peers.All()
	peers := make([]mesh.PeerInfo, 0, len(allPeers))
	for _, p := range allPeers {
		peers = append(peers, mesh.PeerInfo{
			ID:        p.ID,
			Name:      p.Name,
			PublicKey: p.PublicKey,
			VirtualIP: p.VirtualIP.String(),
			Endpoints: p.GetEndpoints(),
			Metadata:  p.Metadata,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"peers": peers,
	})
}

// handleGetPeer returns a specific peer.
func (m *MeshAPI) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")
	peerID := chi.URLParam(r, "peerID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	peer, exists := network.peers.Get(peerID)
	if !exists {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, mesh.PeerInfo{
		ID:        peer.ID,
		Name:      peer.Name,
		PublicKey: peer.PublicKey,
		VirtualIP: peer.VirtualIP.String(),
		Endpoints: peer.GetEndpoints(),
		Metadata:  peer.Metadata,
	})
}

// handleUpdatePeer updates a peer's information.
func (m *MeshAPI) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")
	peerID := chi.URLParam(r, "peerID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	peer, exists := network.peers.Get(peerID)
	if !exists {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	var req updatePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Update endpoints
	if len(req.Endpoints) > 0 {
		peer.ClearEndpoints()
		for _, ep := range req.Endpoints {
			peer.AddEndpoint(ep)
		}
	}

	// Update metadata
	for k, v := range req.Metadata {
		peer.SetMetadata(k, v)
	}

	peer.UpdateLastSeen()
	m.persist()

	// Broadcast update event
	network.broadcastEvent(mesh.PeerEvent{
		Type: "update",
		Peer: mesh.PeerInfo{
			ID:        peer.ID,
			Name:      peer.Name,
			Endpoints: peer.GetEndpoints(),
			Metadata:  peer.Metadata,
		},
		Timestamp: time.Now(),
	})

	w.WriteHeader(http.StatusNoContent)
}

// handleDeregisterPeer removes a peer from a network.
func (m *MeshAPI) handleDeregisterPeer(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")
	peerID := chi.URLParam(r, "peerID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	peer, exists := network.peers.Get(peerID)
	if !exists {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	// Release IP allocation
	_ = network.ipAllocator.Release(peerID) //nolint:errcheck // Best effort IP release

	// Remove from registry
	network.peers.Remove(peerID)
	m.persist()

	// Broadcast leave event
	network.broadcastEvent(mesh.PeerEvent{
		Type: "leave",
		Peer: mesh.PeerInfo{
			ID:   peer.ID,
			Name: peer.Name,
		},
		Timestamp: time.Now(),
	})

	slog.Info("peer deregistered", "network_id", networkID, "peer_id", peerID)

	w.WriteHeader(http.StatusNoContent)
}

// handleHeartbeat updates a peer's last seen timestamp.
func (m *MeshAPI) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "networkID")
	peerID := chi.URLParam(r, "peerID")

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		http.Error(w, "network not found", http.StatusNotFound)
		return
	}

	peer, exists := network.peers.Get(peerID)
	if !exists {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	peer.UpdateLastSeen()

	// Renew the IP lease. This is not best-effort: Renew only fails when the
	// peer has no lease, which means its address was already reaped and may
	// have been handed to another peer. Reporting 204 there would tell the peer
	// its address is still valid while the allocator disagrees, so the conflict
	// would surface later as unexplained mesh traffic going to the wrong node.
	// 409 tells the peer to re-register and get a fresh lease.
	if err := network.ipAllocator.Renew(peerID); err != nil {
		slog.Warn("mesh peer heartbeat could not renew IP lease",
			"network_id", networkID, "peer_id", peerID, "error", err)
		http.Error(w, "IP lease expired; re-register to obtain a new address",
			http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleEvents handles WebSocket connections for peer events.
func (m *MeshAPI) handleEvents(ws *websocket.Conn) {
	networkID := ws.Request().URL.Query().Get("networkID")
	if networkID == "" {
		// Try to get from path
		networkID = chi.URLParam(ws.Request(), "networkID")
	}

	m.mu.RLock()
	network, exists := m.networks[networkID]
	m.mu.RUnlock()

	if !exists {
		_ = websocket.JSON.Send(ws, map[string]string{"error": "network not found"}) //nolint:errcheck // Best effort error response
		return
	}

	// Generate client ID
	clientID := ws.Request().RemoteAddr

	// Register WebSocket client
	network.mu.Lock()
	network.wsClients[clientID] = ws
	network.mu.Unlock()

	defer func() {
		network.mu.Lock()
		delete(network.wsClients, clientID)
		network.mu.Unlock()
		ws.Close()
	}()

	// Keep connection alive
	for {
		var msg interface{}
		if err := websocket.JSON.Receive(ws, &msg); err != nil {
			break
		}
		// Handle any incoming messages (ping/pong, etc.)
	}
}

// broadcastEvent sends an event to all connected WebSocket clients.
func (n *MeshNetwork) broadcastEvent(event mesh.PeerEvent) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	for _, ws := range n.wsClients {
		if err := websocket.JSON.Send(ws, event); err != nil {
			slog.Debug("failed to send event to client", "error", err)
		}
	}
}

// GetNetwork returns a mesh network by ID.
func (m *MeshAPI) GetNetwork(id string) (*MeshNetwork, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	network, exists := m.networks[id]
	return network, exists
}

// CreateNetwork creates a mesh network programmatically.
func (m *MeshAPI) CreateNetwork(id, name, cidr string) (*MeshNetwork, error) {
	m.mu.Lock()

	if _, exists := m.networks[id]; exists {
		m.mu.Unlock()
		return nil, ErrNetworkExists
	}

	allocator, err := mesh.NewPoolAllocator(mesh.PoolConfig{
		NetworkCIDR: cidr,
	})
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}

	network := &MeshNetwork{
		ID:          id,
		Name:        name,
		CIDR:        cidr,
		Created:     time.Now(),
		peers:       mesh.NewPeerRegistry(),
		ipAllocator: allocator,
		wsClients:   make(map[string]*websocket.Conn),
	}

	m.networks[id] = network
	m.mu.Unlock()

	m.persist()
	return network, nil
}

// Common errors
var (
	ErrNetworkExists   = errors.New("network already exists")
	ErrNetworkNotFound = errors.New("network not found")
)

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data) //nolint:errcheck // Best effort HTTP response
}
