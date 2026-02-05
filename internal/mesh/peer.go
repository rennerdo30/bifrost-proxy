package mesh

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Peer metadata limits
const (
	// MaxMetadataKeys is the maximum number of metadata keys per peer
	MaxMetadataKeys = 50
	// MaxMetadataKeyLen is the maximum length of a metadata key
	MaxMetadataKeyLen = 64
	// MaxMetadataValueLen is the maximum length of a metadata value
	MaxMetadataValueLen = 256
)

// PeerStatus represents the connection status of a peer.
type PeerStatus string

const (
	// PeerStatusDiscovered means the peer was found but not yet connected.
	PeerStatusDiscovered PeerStatus = "discovered"

	// PeerStatusConnecting means a connection is being established.
	PeerStatusConnecting PeerStatus = "connecting"

	// PeerStatusConnected means the peer is directly connected.
	PeerStatusConnected PeerStatus = "connected"

	// PeerStatusRelayed means the peer is connected via relay.
	PeerStatusRelayed PeerStatus = "relayed"

	// PeerStatusUnreachable means the peer cannot be reached.
	PeerStatusUnreachable PeerStatus = "unreachable"

	// PeerStatusOffline means the peer is offline.
	PeerStatusOffline PeerStatus = "offline"
)

// ConnectionType represents how a peer is connected.
type ConnectionType string

const (
	// ConnectionTypeDirect means direct P2P connection.
	ConnectionTypeDirect ConnectionType = "direct"

	// ConnectionTypeRelayed means connection through a TURN server.
	ConnectionTypeRelayed ConnectionType = "relayed"

	// ConnectionTypeMultiHop means connection through other peers.
	ConnectionTypeMultiHop ConnectionType = "multi_hop"
)

// Endpoint represents a network endpoint for a peer.
type Endpoint struct {
	// Address is the IP address or hostname.
	Address string `json:"address"`

	// Port is the port number.
	Port uint16 `json:"port"`

	// Type is the endpoint type: "local", "reflexive", "relay".
	Type string `json:"type"`

	// Priority is used for endpoint selection.
	Priority int `json:"priority"`
}

// Peer represents a peer in the mesh network.
type Peer struct {
	// ID is the unique identifier for this peer.
	ID string `json:"id"`

	// Name is the friendly name for this peer.
	Name string `json:"name"`

	// VirtualIP is the virtual IP address assigned to this peer.
	VirtualIP netip.Addr `json:"virtual_ip"`

	// VirtualMAC is the virtual MAC address for TAP mode.
	VirtualMAC net.HardwareAddr `json:"virtual_mac,omitempty"`

	// PublicKey is the peer's Ed25519 public key (base64 encoded).
	PublicKey string `json:"public_key"`

	// Endpoints is the list of known endpoints for this peer.
	Endpoints []Endpoint `json:"endpoints"`

	// Status is the current connection status.
	Status PeerStatus `json:"status"`

	// ConnectionType is how we're connected to this peer.
	ConnectionType ConnectionType `json:"connection_type,omitempty"`

	// Latency is the measured latency to this peer.
	Latency time.Duration `json:"latency,omitempty"`

	// LastSeen is when we last saw activity from this peer.
	LastSeen time.Time `json:"last_seen"`

	// JoinedAt is when this peer joined the network.
	JoinedAt time.Time `json:"joined_at"`

	// Metadata contains arbitrary peer metadata.
	Metadata map[string]string `json:"metadata,omitempty"`

	// BytesSent is the number of bytes sent to this peer.
	BytesSent int64 `json:"bytes_sent"`

	// BytesReceived is the number of bytes received from this peer.
	BytesReceived int64 `json:"bytes_received"`

	mu sync.RWMutex
}

// NewPeer creates a new peer with the given ID.
func NewPeer(id, name string) *Peer {
	return &Peer{
		ID:        id,
		Name:      name,
		Status:    PeerStatusDiscovered,
		Endpoints: make([]Endpoint, 0),
		Metadata:  make(map[string]string),
		JoinedAt:  time.Now(),
		LastSeen:  time.Now(),
	}
}

// SetVirtualIP sets the peer's virtual IP address.
func (p *Peer) SetVirtualIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.VirtualIP = ip
}

// SetVirtualMAC sets the peer's virtual MAC address.
func (p *Peer) SetVirtualMAC(mac net.HardwareAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.VirtualMAC = mac
}

// SetStatus sets the peer's connection status.
func (p *Peer) SetStatus(status PeerStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Status = status
}

// SetConnectionType sets how we're connected to this peer.
func (p *Peer) SetConnectionType(connType ConnectionType) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ConnectionType = connType
}

// UpdateLastSeen updates the last seen timestamp.
func (p *Peer) UpdateLastSeen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastSeen = time.Now()
}

// SetLatency sets the measured latency.
func (p *Peer) SetLatency(latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Latency = latency
}

// AddEndpoint adds an endpoint to the peer.
func (p *Peer) AddEndpoint(endpoint Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for duplicates
	for _, e := range p.Endpoints {
		if e.Address == endpoint.Address && e.Port == endpoint.Port {
			return
		}
	}

	p.Endpoints = append(p.Endpoints, endpoint)
}

// RemoveEndpoint removes an endpoint from the peer.
func (p *Peer) RemoveEndpoint(address string, port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()

	endpoints := make([]Endpoint, 0, len(p.Endpoints))
	for _, e := range p.Endpoints {
		if !(e.Address == address && e.Port == port) {
			endpoints = append(endpoints, e)
		}
	}
	p.Endpoints = endpoints
}

// ClearEndpoints removes all endpoints.
func (p *Peer) ClearEndpoints() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Endpoints = make([]Endpoint, 0)
}

// GetEndpoints returns a copy of all endpoints.
func (p *Peer) GetEndpoints() []Endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	endpoints := make([]Endpoint, len(p.Endpoints))
	copy(endpoints, p.Endpoints)
	return endpoints
}

// SetMetadata sets a metadata value.
// Returns false if the key/value exceeds limits or max keys reached.
func (p *Peer) SetMetadata(key, value string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Validate key length
	if len(key) > MaxMetadataKeyLen {
		return false
	}

	// Validate value length
	if len(value) > MaxMetadataValueLen {
		return false
	}

	if p.Metadata == nil {
		p.Metadata = make(map[string]string)
	}

	// Check if key already exists (update is allowed)
	if _, exists := p.Metadata[key]; !exists {
		// New key - check max keys limit
		if len(p.Metadata) >= MaxMetadataKeys {
			return false
		}
	}

	p.Metadata[key] = value
	return true
}

// GetMetadata gets a metadata value.
func (p *Peer) GetMetadata(key string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	value, ok := p.Metadata[key]
	return value, ok
}

// AddBytesSent adds to the bytes sent counter.
func (p *Peer) AddBytesSent(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.BytesSent += n
}

// AddBytesReceived adds to the bytes received counter.
func (p *Peer) AddBytesReceived(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.BytesReceived += n
}

// IsConnected returns true if the peer is connected (directly or via relay).
func (p *Peer) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Status == PeerStatusConnected || p.Status == PeerStatusRelayed
}

// IsReachable returns true if the peer might be reachable.
func (p *Peer) IsReachable() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Status != PeerStatusUnreachable && p.Status != PeerStatusOffline
}

// Clone creates a copy of the peer.
func (p *Peer) Clone() *Peer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	clone := &Peer{
		ID:             p.ID,
		Name:           p.Name,
		VirtualIP:      p.VirtualIP,
		PublicKey:      p.PublicKey,
		Status:         p.Status,
		ConnectionType: p.ConnectionType,
		Latency:        p.Latency,
		LastSeen:       p.LastSeen,
		JoinedAt:       p.JoinedAt,
		BytesSent:      p.BytesSent,
		BytesReceived:  p.BytesReceived,
		Endpoints:      make([]Endpoint, len(p.Endpoints)),
		Metadata:       make(map[string]string, len(p.Metadata)),
	}

	if p.VirtualMAC != nil {
		clone.VirtualMAC = make(net.HardwareAddr, len(p.VirtualMAC))
		copy(clone.VirtualMAC, p.VirtualMAC)
	}

	copy(clone.Endpoints, p.Endpoints)
	for k, v := range p.Metadata {
		clone.Metadata[k] = v
	}

	return clone
}

// PeerRegistry manages all known peers in a mesh network.
type PeerRegistry struct {
	peers map[string]*Peer // Keyed by peer ID
	byIP  map[netip.Addr]*Peer
	byMAC map[string]*Peer // Keyed by MAC string
	mu    sync.RWMutex
}

// NewPeerRegistry creates a new peer registry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		peers: make(map[string]*Peer),
		byIP:  make(map[netip.Addr]*Peer),
		byMAC: make(map[string]*Peer),
	}
}

// Add adds a peer to the registry.
func (r *PeerRegistry) Add(peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.peers[peer.ID] = peer

	if peer.VirtualIP.IsValid() {
		r.byIP[peer.VirtualIP] = peer
	}

	if len(peer.VirtualMAC) > 0 {
		r.byMAC[peer.VirtualMAC.String()] = peer
	}
}

// Remove removes a peer from the registry.
func (r *PeerRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	peer, exists := r.peers[id]
	if !exists {
		return
	}

	if peer.VirtualIP.IsValid() {
		delete(r.byIP, peer.VirtualIP)
	}

	if len(peer.VirtualMAC) > 0 {
		delete(r.byMAC, peer.VirtualMAC.String())
	}

	delete(r.peers, id)
}

// Get returns a peer by ID.
func (r *PeerRegistry) Get(id string) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peer, exists := r.peers[id]
	return peer, exists
}

// GetByIP returns a peer by virtual IP.
func (r *PeerRegistry) GetByIP(ip netip.Addr) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peer, exists := r.byIP[ip]
	return peer, exists
}

// GetByMAC returns a peer by virtual MAC.
func (r *PeerRegistry) GetByMAC(mac net.HardwareAddr) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peer, exists := r.byMAC[mac.String()]
	return peer, exists
}

// All returns all peers.
func (r *PeerRegistry) All() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*Peer, 0, len(r.peers))
	for _, peer := range r.peers {
		peers = append(peers, peer)
	}
	return peers
}

// Connected returns all connected peers.
func (r *PeerRegistry) Connected() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*Peer, 0)
	for _, peer := range r.peers {
		if peer.IsConnected() {
			peers = append(peers, peer)
		}
	}
	return peers
}

// Count returns the number of peers.
func (r *PeerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// UpdatePeerIP updates the IP index when a peer's IP changes.
func (r *PeerRegistry) UpdatePeerIP(peer *Peer, newIP netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove old IP mapping
	if peer.VirtualIP.IsValid() {
		delete(r.byIP, peer.VirtualIP)
	}

	// Set new IP
	peer.VirtualIP = newIP

	// Add new IP mapping
	if newIP.IsValid() {
		r.byIP[newIP] = peer
	}
}

// UpdatePeerMAC updates the MAC index when a peer's MAC changes.
func (r *PeerRegistry) UpdatePeerMAC(peer *Peer, newMAC net.HardwareAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove old MAC mapping
	if len(peer.VirtualMAC) > 0 {
		delete(r.byMAC, peer.VirtualMAC.String())
	}

	// Set new MAC
	peer.VirtualMAC = newMAC

	// Add new MAC mapping
	if len(newMAC) > 0 {
		r.byMAC[newMAC.String()] = peer
	}
}

// Clear removes all peers.
func (r *PeerRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.peers = make(map[string]*Peer)
	r.byIP = make(map[netip.Addr]*Peer)
	r.byMAC = make(map[string]*Peer)
}
