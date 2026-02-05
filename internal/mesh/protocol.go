package mesh

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// ProtocolMessageType represents the type of protocol message.
type ProtocolMessageType byte

const (
	// MsgTypeRouteAnnounce announces routes to neighbors.
	MsgTypeRouteAnnounce ProtocolMessageType = iota + 1

	// MsgTypeRouteRequest requests routes from neighbors.
	MsgTypeRouteRequest

	// MsgTypeRouteWithdraw withdraws a previously announced route.
	MsgTypeRouteWithdraw

	// MsgTypeHello is a periodic hello/keepalive message.
	MsgTypeHello

	// MsgTypeHelloAck acknowledges a hello message.
	MsgTypeHelloAck

	// MsgTypeLinkState announces link state updates.
	MsgTypeLinkState
)

// String returns a human-readable string for the message type.
func (t ProtocolMessageType) String() string {
	switch t {
	case MsgTypeRouteAnnounce:
		return "route_announce"
	case MsgTypeRouteRequest:
		return "route_request"
	case MsgTypeRouteWithdraw:
		return "route_withdraw"
	case MsgTypeHello:
		return "hello"
	case MsgTypeHelloAck:
		return "hello_ack"
	case MsgTypeLinkState:
		return "link_state"
	default:
		return "unknown"
	}
}

// ProtocolMessage is the base protocol message.
type ProtocolMessage struct {
	Type      ProtocolMessageType `json:"type"`
	SrcPeerID string              `json:"src_peer_id"`
	SeqNum    uint64              `json:"seq_num"`
	TTL       int                 `json:"ttl"`
	Timestamp time.Time           `json:"timestamp"`
	Payload   json.RawMessage     `json:"payload,omitempty"`
}

// RouteAnnouncement contains route information.
type RouteAnnouncement struct {
	DestPeerID string     `json:"dest_peer_id"`
	DestIP     netip.Addr `json:"dest_ip"`
	Metric     int        `json:"metric"`
	HopCount   int        `json:"hop_count"`
	Path       []string   `json:"path,omitempty"` // For loop prevention
}

// RouteWithdrawal indicates a route is no longer available.
type RouteWithdrawal struct {
	DestPeerID string `json:"dest_peer_id"`
}

// HelloMessage is a periodic keepalive.
type HelloMessage struct {
	PeerID    string     `json:"peer_id"`
	VirtualIP netip.Addr `json:"virtual_ip"`
	Timestamp time.Time  `json:"timestamp"`
	Neighbors []string   `json:"neighbors,omitempty"`
}

// HelloAckMessage acknowledges a hello.
type HelloAckMessage struct {
	PeerID       string     `json:"peer_id"`
	VirtualIP    netip.Addr `json:"virtual_ip"`
	RequestTime  time.Time  `json:"request_time"`
	ResponseTime time.Time  `json:"response_time"`
}

// LinkStateUpdate contains link state information.
type LinkStateUpdate struct {
	PeerID    string     `json:"peer_id"`
	SeqNum    uint64     `json:"seq_num"`
	Links     []LinkInfo `json:"links"`
	Timestamp time.Time  `json:"timestamp"`
}

// LinkInfo describes a link to a neighbor.
type LinkInfo struct {
	NeighborID string        `json:"neighbor_id"`
	Latency    time.Duration `json:"latency"`
	State      string        `json:"state"` // up, down, degraded
}

// RoutingProtocol manages the mesh routing protocol.
type RoutingProtocol struct {
	localPeerID string
	localIP     netip.Addr
	router      *MeshRouter

	seqNum       uint64
	receivedMsgs map[string]uint64 // peerID -> last seen seqNum

	config ProtocolConfig

	sendFunc func(peerID string, msg []byte) error

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// ProtocolConfig contains routing protocol configuration.
type ProtocolConfig struct {
	// HelloInterval is the interval between hello messages.
	HelloInterval time.Duration

	// RouteAnnounceInterval is the interval between route announcements.
	RouteAnnounceInterval time.Duration

	// RouteExpiryInterval is the route expiry check interval.
	RouteExpiryInterval time.Duration

	// DefaultTTL is the default TTL for messages.
	DefaultTTL int

	// MaxRouteAge is the maximum age of a route before expiry.
	MaxRouteAge time.Duration

	// SplitHorizon enables split horizon (don't announce routes back to source).
	SplitHorizon bool

	// PoisonReverse enables poison reverse (announce withdrawn routes with infinite metric).
	PoisonReverse bool
}

// DefaultProtocolConfig returns a default protocol configuration.
func DefaultProtocolConfig() ProtocolConfig {
	return ProtocolConfig{
		HelloInterval:         30 * time.Second,
		RouteAnnounceInterval: 60 * time.Second,
		RouteExpiryInterval:   30 * time.Second,
		DefaultTTL:            8,
		MaxRouteAge:           5 * time.Minute,
		SplitHorizon:          true,
		PoisonReverse:         false,
	}
}

// NewRoutingProtocol creates a new routing protocol handler.
func NewRoutingProtocol(localPeerID string, localIP netip.Addr, router *MeshRouter, config ProtocolConfig) *RoutingProtocol {
	ctx, cancel := context.WithCancel(context.Background())

	return &RoutingProtocol{
		localPeerID:  localPeerID,
		localIP:      localIP,
		router:       router,
		receivedMsgs: make(map[string]uint64),
		config:       config,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetSendFunc sets the function used to send messages to peers.
func (p *RoutingProtocol) SetSendFunc(sendFunc func(peerID string, msg []byte) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sendFunc = sendFunc
}

// Start starts the routing protocol.
func (p *RoutingProtocol) Start() error {
	slog.Info("starting routing protocol", "peer_id", p.localPeerID)

	// Start hello worker
	p.wg.Add(1)
	go p.helloWorker()

	// Start route announcement worker
	p.wg.Add(1)
	go p.routeAnnounceWorker()

	// Start route expiry worker
	p.wg.Add(1)
	go p.routeExpiryWorker()

	return nil
}

// Stop stops the routing protocol.
func (p *RoutingProtocol) Stop() error {
	slog.Info("stopping routing protocol")

	p.cancel()
	p.wg.Wait()

	return nil
}

// helloWorker sends periodic hello messages.
func (p *RoutingProtocol) helloWorker() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.HelloInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.sendHelloToNeighbors()
		}
	}
}

// routeAnnounceWorker sends periodic route announcements.
func (p *RoutingProtocol) routeAnnounceWorker() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.RouteAnnounceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.announceRoutes()
		}
	}
}

// routeExpiryWorker expires stale routes.
func (p *RoutingProtocol) routeExpiryWorker() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.RouteExpiryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.router.ExpireRoutes()
		}
	}
}

// sendHelloToNeighbors sends hello messages to all direct neighbors.
func (p *RoutingProtocol) sendHelloToNeighbors() {
	neighbors := p.router.GetDirectPeers()

	hello := HelloMessage{
		PeerID:    p.localPeerID,
		VirtualIP: p.localIP,
		Timestamp: time.Now(),
		Neighbors: neighbors,
	}

	payload, err := json.Marshal(hello)
	if err != nil {
		return
	}

	msg := p.createMessage(MsgTypeHello, payload)
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, peerID := range neighbors {
		if err := p.send(peerID, msgBytes); err != nil {
			slog.Debug("failed to send hello", "peer_id", peerID, "error", err)
		}
	}
}

// announceRoutes announces routes to neighbors.
func (p *RoutingProtocol) announceRoutes() {
	routes := p.router.GetBestRoutes()
	neighbors := p.router.GetDirectPeers()

	for _, neighbor := range neighbors {
		p.announceRoutesToPeer(neighbor, routes)
	}
}

// announceRoutesToPeer announces routes to a specific peer.
func (p *RoutingProtocol) announceRoutesToPeer(peerID string, routes []*Route) {
	for _, route := range routes {
		// Split horizon: don't announce routes back to their source
		if p.config.SplitHorizon && route.NextHop == peerID {
			continue
		}

		// Don't announce routes to the destination itself
		if route.DestPeerID == peerID {
			continue
		}

		announcement := RouteAnnouncement{
			DestPeerID: route.DestPeerID,
			DestIP:     route.DestIP,
			Metric:     route.Metric,
			HopCount:   route.HopCount + 1,
			Path:       append([]string{p.localPeerID}, route.DestPeerID),
		}

		payload, err := json.Marshal(announcement)
		if err != nil {
			continue
		}

		msg := p.createMessage(MsgTypeRouteAnnounce, payload)
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		if err := p.send(peerID, msgBytes); err != nil {
			slog.Debug("failed to send route announcement",
				"peer_id", peerID,
				"dest", route.DestPeerID,
				"error", err,
			)
		}
	}
}

// WithdrawRoute withdraws a route from neighbors.
func (p *RoutingProtocol) WithdrawRoute(destPeerID string) {
	neighbors := p.router.GetDirectPeers()

	withdrawal := RouteWithdrawal{
		DestPeerID: destPeerID,
	}

	payload, err := json.Marshal(withdrawal)
	if err != nil {
		return
	}

	msg := p.createMessage(MsgTypeRouteWithdraw, payload)
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, neighbor := range neighbors {
		if err := p.send(neighbor, msgBytes); err != nil {
			slog.Debug("failed to send route withdrawal",
				"peer_id", neighbor,
				"dest", destPeerID,
				"error", err,
			)
		}
	}
}

// HandleMessage handles an incoming protocol message.
func (p *RoutingProtocol) HandleMessage(fromPeerID string, data []byte) error {
	var msg ProtocolMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}

	// Check for duplicate messages
	p.mu.Lock()
	lastSeq := p.receivedMsgs[msg.SrcPeerID]
	if msg.SeqNum <= lastSeq {
		p.mu.Unlock()
		return nil // Duplicate
	}
	p.receivedMsgs[msg.SrcPeerID] = msg.SeqNum
	p.mu.Unlock()

	// Handle by message type
	switch msg.Type {
	case MsgTypeHello:
		return p.handleHello(fromPeerID, msg.Payload)
	case MsgTypeHelloAck:
		return p.handleHelloAck(fromPeerID, msg.Payload)
	case MsgTypeRouteAnnounce:
		return p.handleRouteAnnounce(fromPeerID, msg.Payload)
	case MsgTypeRouteWithdraw:
		return p.handleRouteWithdraw(fromPeerID, msg.Payload)
	case MsgTypeLinkState:
		return p.handleLinkState(fromPeerID, msg.Payload, msg.TTL)
	default:
		slog.Debug("unknown message type", "type", msg.Type)
	}

	return nil
}

// handleHello handles a hello message.
func (p *RoutingProtocol) handleHello(fromPeerID string, payload json.RawMessage) error {
	var hello HelloMessage
	if err := json.Unmarshal(payload, &hello); err != nil {
		return err
	}

	// Send hello ack
	ack := HelloAckMessage{
		PeerID:       p.localPeerID,
		VirtualIP:    p.localIP,
		RequestTime:  hello.Timestamp,
		ResponseTime: time.Now(),
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		return err
	}

	msg := p.createMessage(MsgTypeHelloAck, ackPayload)
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return p.send(fromPeerID, msgBytes)
}

// handleHelloAck handles a hello ack message.
func (p *RoutingProtocol) handleHelloAck(fromPeerID string, payload json.RawMessage) error {
	var ack HelloAckMessage
	if err := json.Unmarshal(payload, &ack); err != nil {
		return err
	}

	// Calculate RTT
	rtt := time.Since(ack.RequestTime)

	// Update route latency
	p.router.UpdateLatency(fromPeerID, rtt/2)

	slog.Debug("hello ack received",
		"from", fromPeerID,
		"rtt", rtt,
	)

	return nil
}

// handleRouteAnnounce handles a route announcement.
func (p *RoutingProtocol) handleRouteAnnounce(fromPeerID string, payload json.RawMessage) error {
	var announcement RouteAnnouncement
	if err := json.Unmarshal(payload, &announcement); err != nil {
		return err
	}

	// Check for loops (is local peer in path?)
	for _, peerID := range announcement.Path {
		if peerID == p.localPeerID {
			return nil // Loop detected
		}
	}

	// Create route
	route := &Route{
		DestPeerID:  announcement.DestPeerID,
		DestIP:      announcement.DestIP,
		NextHop:     fromPeerID,
		Type:        RouteTypeNextHop,
		Metric:      announcement.Metric,
		HopCount:    announcement.HopCount,
		LastUpdated: time.Now(),
		Active:      true,
	}

	p.router.AddRoute(route)

	slog.Debug("route received",
		"dest", announcement.DestPeerID,
		"via", fromPeerID,
		"metric", announcement.Metric,
		"hops", announcement.HopCount,
	)

	return nil
}

// handleRouteWithdraw handles a route withdrawal.
func (p *RoutingProtocol) handleRouteWithdraw(fromPeerID string, payload json.RawMessage) error {
	var withdrawal RouteWithdrawal
	if err := json.Unmarshal(payload, &withdrawal); err != nil {
		return err
	}

	// Remove routes via this peer to the destination
	// This is handled by the router when we mark routes as inactive
	slog.Debug("route withdrawn",
		"dest", withdrawal.DestPeerID,
		"via", fromPeerID,
	)

	return nil
}

// handleLinkState handles a link state update.
func (p *RoutingProtocol) handleLinkState(fromPeerID string, payload json.RawMessage, ttl int) error {
	var lsUpdate LinkStateUpdate
	if err := json.Unmarshal(payload, &lsUpdate); err != nil {
		return err
	}

	// Process link state
	for _, link := range lsUpdate.Links {
		slog.Debug("link state update",
			"peer", lsUpdate.PeerID,
			"neighbor", link.NeighborID,
			"state", link.State,
			"latency", link.Latency,
		)
	}

	// Forward to other neighbors if TTL > 1
	if ttl > 1 {
		p.forwardLinkState(fromPeerID, payload, ttl-1)
	}

	return nil
}

// forwardLinkState forwards a link state update to neighbors.
func (p *RoutingProtocol) forwardLinkState(excludePeerID string, payload json.RawMessage, ttl int) {
	neighbors := p.router.GetDirectPeers()

	msg := p.createMessage(MsgTypeLinkState, payload)
	msg.TTL = ttl

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, neighbor := range neighbors {
		if neighbor == excludePeerID {
			continue
		}
		_ = p.send(neighbor, msgBytes) //nolint:errcheck // Best effort message send
	}
}

// createMessage creates a new protocol message.
func (p *RoutingProtocol) createMessage(msgType ProtocolMessageType, payload json.RawMessage) ProtocolMessage {
	p.mu.Lock()
	p.seqNum++
	seqNum := p.seqNum
	p.mu.Unlock()

	return ProtocolMessage{
		Type:      msgType,
		SrcPeerID: p.localPeerID,
		SeqNum:    seqNum,
		TTL:       p.config.DefaultTTL,
		Timestamp: time.Now(),
		Payload:   payload,
	}
}

// send sends a message to a peer.
func (p *RoutingProtocol) send(peerID string, data []byte) error {
	p.mu.RLock()
	sendFunc := p.sendFunc
	p.mu.RUnlock()

	if sendFunc == nil {
		return nil
	}

	return sendFunc(peerID, data)
}

// NotifyPeerConnected notifies the protocol of a new peer connection.
func (p *RoutingProtocol) NotifyPeerConnected(peerID string, peerIP netip.Addr, latency time.Duration) {
	// Add direct route
	p.router.AddDirectRoute(peerID, peerIP, latency)

	// Send routes to new peer
	routes := p.router.GetBestRoutes()
	p.announceRoutesToPeer(peerID, routes)

	// Announce new peer to existing neighbors
	announcement := RouteAnnouncement{
		DestPeerID: peerID,
		DestIP:     peerIP,
		Metric:     int(latency.Milliseconds()) + 100,
		HopCount:   1,
		Path:       []string{p.localPeerID},
	}

	payload, err := json.Marshal(announcement)
	if err != nil {
		return
	}

	msg := p.createMessage(MsgTypeRouteAnnounce, payload)
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, neighbor := range p.router.GetDirectPeers() {
		if neighbor != peerID {
			_ = p.send(neighbor, msgBytes) //nolint:errcheck // Best effort message send
		}
	}
}

// NotifyPeerDisconnected notifies the protocol of a peer disconnection.
func (p *RoutingProtocol) NotifyPeerDisconnected(peerID string) {
	// Remove direct route
	p.router.RemoveDirectRoute(peerID)

	// Withdraw routes to neighbors
	p.WithdrawRoute(peerID)
}
