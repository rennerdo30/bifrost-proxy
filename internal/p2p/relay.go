package p2p

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Relay errors.
var (
	ErrRelayNotAvailable  = errors.New("relay: no relay available")
	ErrRelayFailed        = errors.New("relay: relay failed")
	ErrPeerNotRelayable   = errors.New("relay: peer not relayable")
)

// RelayType represents the type of relay.
type RelayType int

const (
	// RelayTypeTURN uses a TURN server for relaying.
	RelayTypeTURN RelayType = iota

	// RelayTypePeer uses another peer for relaying.
	RelayTypePeer
)

// String returns a human-readable string for the relay type.
func (t RelayType) String() string {
	switch t {
	case RelayTypeTURN:
		return "turn"
	case RelayTypePeer:
		return "peer"
	default:
		return "unknown"
	}
}

// RelayConfig contains relay configuration.
type RelayConfig struct {
	// Enabled enables relay support.
	Enabled bool

	// TURNConfig is the TURN server configuration.
	TURNConfig *TURNConfig

	// PeerRelayEnabled allows using other peers as relays.
	PeerRelayEnabled bool

	// MaxRelayHops is the maximum number of relay hops.
	MaxRelayHops int

	// RelayTimeout is the timeout for relay operations.
	RelayTimeout time.Duration
}

// DefaultRelayConfig returns a default relay configuration.
func DefaultRelayConfig() RelayConfig {
	return RelayConfig{
		Enabled:          true,
		PeerRelayEnabled: true,
		MaxRelayHops:     3,
		RelayTimeout:     30 * time.Second,
	}
}

// Relay represents a relay node.
type Relay struct {
	// Type is the relay type.
	Type RelayType

	// Address is the relay address.
	Address netip.AddrPort

	// PeerID is the peer ID (for peer relays).
	PeerID string

	// Latency is the measured latency.
	Latency time.Duration

	// Capacity is the relay capacity (0-100).
	Capacity int

	// Available indicates if the relay is available.
	Available bool
}

// RelayManager manages relay connections.
type RelayManager struct {
	config     RelayConfig
	turnClient *TURNClient
	relays     map[string]*Relay
	peerRelays map[string]*PeerRelay

	mu sync.RWMutex
}

// NewRelayManager creates a new relay manager.
func NewRelayManager(config RelayConfig) *RelayManager {
	rm := &RelayManager{
		config:     config,
		relays:     make(map[string]*Relay),
		peerRelays: make(map[string]*PeerRelay),
	}

	if config.TURNConfig != nil {
		rm.turnClient = NewTURNClient(*config.TURNConfig)
	}

	return rm
}

// Start starts the relay manager.
func (rm *RelayManager) Start(ctx context.Context) error {
	if !rm.config.Enabled {
		return nil
	}

	// Initialize TURN relay if configured
	if rm.turnClient != nil {
		if err := rm.turnClient.Allocate(ctx); err != nil {
			slog.Warn("failed to allocate TURN relay", "error", err)
		} else {
			relayAddr, _ := rm.turnClient.RelayAddress()
			rm.mu.Lock()
			rm.relays["turn"] = &Relay{
				Type:      RelayTypeTURN,
				Address:   relayAddr,
				Available: true,
			}
			rm.mu.Unlock()

			slog.Info("TURN relay allocated", "address", relayAddr.String())
		}
	}

	return nil
}

// Stop stops the relay manager.
func (rm *RelayManager) Stop() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Close TURN client
	if rm.turnClient != nil {
		rm.turnClient.Close()
	}

	// Close peer relays
	for _, pr := range rm.peerRelays {
		pr.Close()
	}

	rm.relays = make(map[string]*Relay)
	rm.peerRelays = make(map[string]*PeerRelay)

	return nil
}

// GetRelays returns all available relays.
func (rm *RelayManager) GetRelays() []*Relay {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	relays := make([]*Relay, 0, len(rm.relays))
	for _, r := range rm.relays {
		if r.Available {
			relays = append(relays, r)
		}
	}
	return relays
}

// GetBestRelay returns the best available relay for a peer.
func (rm *RelayManager) GetBestRelay(peerID string) (*Relay, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var best *Relay

	for _, r := range rm.relays {
		if !r.Available {
			continue
		}

		if best == nil || r.Latency < best.Latency {
			best = r
		}
	}

	if best == nil {
		return nil, ErrRelayNotAvailable
	}

	return best, nil
}

// GetTURNClient returns the TURN client.
func (rm *RelayManager) GetTURNClient() *TURNClient {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.turnClient
}

// AddPeerRelay adds a peer as a potential relay.
func (rm *RelayManager) AddPeerRelay(peerID string, conn P2PConnection) error {
	if !rm.config.PeerRelayEnabled {
		return ErrPeerNotRelayable
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	pr := &PeerRelay{
		peerID: peerID,
		conn:   conn,
	}

	rm.peerRelays[peerID] = pr
	rm.relays["peer:"+peerID] = &Relay{
		Type:      RelayTypePeer,
		PeerID:    peerID,
		Address:   conn.RemoteAddr(),
		Latency:   conn.Latency(),
		Available: true,
	}

	slog.Debug("added peer relay", "peer_id", peerID)

	return nil
}

// RemovePeerRelay removes a peer relay.
func (rm *RelayManager) RemovePeerRelay(peerID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if pr, ok := rm.peerRelays[peerID]; ok {
		pr.Close()
		delete(rm.peerRelays, peerID)
	}

	delete(rm.relays, "peer:"+peerID)
}

// CreateRelayedConnection creates a relayed connection to a peer.
func (rm *RelayManager) CreateRelayedConnection(ctx context.Context, config ConnectionConfig) (P2PConnection, error) {
	relay, err := rm.GetBestRelay(config.PeerID)
	if err != nil {
		return nil, err
	}

	switch relay.Type {
	case RelayTypeTURN:
		return rm.createTURNRelayedConnection(ctx, config)
	case RelayTypePeer:
		return rm.createPeerRelayedConnection(ctx, config, relay.PeerID)
	default:
		return nil, ErrRelayFailed
	}
}

// createTURNRelayedConnection creates a TURN-relayed connection.
func (rm *RelayManager) createTURNRelayedConnection(ctx context.Context, config ConnectionConfig) (P2PConnection, error) {
	if rm.turnClient == nil {
		return nil, ErrRelayNotAvailable
	}

	conn, err := NewRelayedConnection(config, rm.turnClient)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// createPeerRelayedConnection creates a peer-relayed connection.
func (rm *RelayManager) createPeerRelayedConnection(ctx context.Context, config ConnectionConfig, relayPeerID string) (P2PConnection, error) {
	rm.mu.RLock()
	pr, ok := rm.peerRelays[relayPeerID]
	rm.mu.RUnlock()

	if !ok {
		return nil, ErrRelayNotAvailable
	}

	return pr.CreateConnection(config)
}

// PeerRelay manages relaying through another peer.
type PeerRelay struct {
	peerID string
	conn   P2PConnection

	connections map[string]*PeerRelayedConnection
	mu          sync.RWMutex
}

// CreateConnection creates a relayed connection through this peer.
func (pr *PeerRelay) CreateConnection(config ConnectionConfig) (P2PConnection, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.connections == nil {
		pr.connections = make(map[string]*PeerRelayedConnection)
	}

	conn := &PeerRelayedConnection{
		config:     config,
		relayPeer:  pr.conn,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
	}

	pr.connections[config.PeerID] = conn

	return conn, nil
}

// Close closes the peer relay.
func (pr *PeerRelay) Close() error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for _, conn := range pr.connections {
		conn.Close()
	}

	pr.connections = nil
	return nil
}

// PeerRelayedConnection represents a connection relayed through another peer.
type PeerRelayedConnection struct {
	config    ConnectionConfig
	relayPeer P2PConnection

	sendQueue chan []byte
	recvQueue chan []byte

	closed bool
	mu     sync.RWMutex
}

// PeerID returns the remote peer's ID.
func (c *PeerRelayedConnection) PeerID() string {
	return c.config.PeerID
}

// Send sends data through the relay.
func (c *PeerRelayedConnection) Send(data []byte) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrConnectionClosed
	}
	c.mu.RUnlock()

	// Wrap data with destination peer ID
	wrapped := wrapRelayMessage(c.config.PeerID, data)
	return c.relayPeer.Send(wrapped)
}

// Receive receives data from the relay.
func (c *PeerRelayedConnection) Receive() ([]byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrConnectionClosed
	}
	c.mu.RUnlock()

	select {
	case data := <-c.recvQueue:
		return data, nil
	}
}

// Latency returns the latency (relay peer latency * 2).
func (c *PeerRelayedConnection) Latency() time.Duration {
	return c.relayPeer.Latency() * 2
}

// Type returns the connection type.
func (c *PeerRelayedConnection) Type() ConnectionType {
	return ConnectionTypeMultiHop
}

// State returns the connection state.
func (c *PeerRelayedConnection) State() ConnectionState {
	if c.relayPeer.State() == ConnectionStateConnected {
		return ConnectionStateConnected
	}
	return ConnectionStateDisconnected
}

// LocalAddr returns the local address.
func (c *PeerRelayedConnection) LocalAddr() netip.AddrPort {
	return c.relayPeer.LocalAddr()
}

// RemoteAddr returns the remote address (unknown for multi-hop).
func (c *PeerRelayedConnection) RemoteAddr() netip.AddrPort {
	return netip.AddrPort{}
}

// Close closes the connection.
func (c *PeerRelayedConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	close(c.sendQueue)

	return nil
}

// RelayMessage represents a message to be relayed.
type RelayMessage struct {
	// Type is the message type.
	Type RelayMessageType

	// DestPeerID is the destination peer ID.
	DestPeerID string

	// SrcPeerID is the source peer ID.
	SrcPeerID string

	// Payload is the message payload.
	Payload []byte

	// TTL is the time-to-live (hop count).
	TTL int
}

// RelayMessageType represents the type of relay message.
type RelayMessageType byte

const (
	// RelayMessageTypeData is a data message.
	RelayMessageTypeData RelayMessageType = iota

	// RelayMessageTypeConnect is a connection request.
	RelayMessageTypeConnect

	// RelayMessageTypeDisconnect is a disconnection notification.
	RelayMessageTypeDisconnect
)

// wrapRelayMessage wraps data with relay information.
func wrapRelayMessage(destPeerID string, data []byte) []byte {
	// Format: type (1) + dest_len (1) + dest_id + payload
	destBytes := []byte(destPeerID)
	msg := make([]byte, 2+len(destBytes)+len(data))
	msg[0] = byte(RelayMessageTypeData)
	msg[1] = byte(len(destBytes))
	copy(msg[2:2+len(destBytes)], destBytes)
	copy(msg[2+len(destBytes):], data)
	return msg
}

// unwrapRelayMessage unwraps a relay message.
func unwrapRelayMessage(msg []byte) (*RelayMessage, error) {
	if len(msg) < 2 {
		return nil, errors.New("invalid relay message")
	}

	msgType := RelayMessageType(msg[0])
	destLen := int(msg[1])

	if len(msg) < 2+destLen {
		return nil, errors.New("invalid relay message")
	}

	destPeerID := string(msg[2 : 2+destLen])
	payload := msg[2+destLen:]

	return &RelayMessage{
		Type:       msgType,
		DestPeerID: destPeerID,
		Payload:    payload,
	}, nil
}

// RelayRouter routes relay messages to their destinations.
type RelayRouter struct {
	localPeerID string
	manager     *P2PManager
	maxHops     int

	mu sync.RWMutex
}

// NewRelayRouter creates a new relay router.
func NewRelayRouter(localPeerID string, manager *P2PManager, maxHops int) *RelayRouter {
	return &RelayRouter{
		localPeerID: localPeerID,
		manager:     manager,
		maxHops:     maxHops,
	}
}

// HandleRelayMessage handles an incoming relay message.
func (r *RelayRouter) HandleRelayMessage(srcPeerID string, msg *RelayMessage) error {
	// Check TTL
	if msg.TTL <= 0 {
		return errors.New("relay message TTL expired")
	}

	// Check if we're the destination
	if msg.DestPeerID == r.localPeerID {
		// Deliver locally
		return r.deliverLocally(srcPeerID, msg)
	}

	// Forward to next hop
	return r.forward(msg)
}

// deliverLocally delivers a message to a local handler.
func (r *RelayRouter) deliverLocally(srcPeerID string, msg *RelayMessage) error {
	slog.Debug("received relayed message",
		"from", srcPeerID,
		"original_src", msg.SrcPeerID,
		"type", msg.Type,
	)

	// Find the local connection for the source peer
	conn := r.manager.GetConnection(msg.SrcPeerID)
	if conn == nil {
		// No direct connection, but we received data through relay
		// Notify via callback if available
		r.mu.RLock()
		callbacks := r.manager.callbacks
		r.mu.RUnlock()

		if callbacks.OnData != nil {
			callbacks.OnData(msg.SrcPeerID, msg.Payload)
		}
		return nil
	}

	// Deliver to the connection's receive queue
	// Since we're receiving relayed data, we need to inject it into the connection
	if dc, ok := conn.(*DirectConnection); ok {
		select {
		case dc.recvQueue <- msg.Payload:
			return nil
		default:
			return errors.New("receive queue full")
		}
	}

	// For peer-relayed connections, deliver directly
	if prc, ok := conn.(*PeerRelayedConnection); ok {
		select {
		case prc.recvQueue <- msg.Payload:
			return nil
		default:
			return errors.New("receive queue full")
		}
	}

	return nil
}

// forward forwards a message to the next hop.
func (r *RelayRouter) forward(msg *RelayMessage) error {
	// Find connection to destination (or next hop)
	conn := r.manager.GetConnection(msg.DestPeerID)
	if conn == nil {
		return errors.New("no route to destination")
	}

	// Decrement TTL
	msg.TTL--

	// Re-wrap and send
	wrapped := wrapRelayMessage(msg.DestPeerID, msg.Payload)
	return conn.Send(wrapped)
}
