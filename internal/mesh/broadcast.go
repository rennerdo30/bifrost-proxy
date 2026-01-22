package mesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"sync"
	"time"
)

// BroadcastType represents the type of broadcast.
type BroadcastType int

const (
	// BroadcastTypeFlood sends to all peers.
	BroadcastTypeFlood BroadcastType = iota

	// BroadcastTypeMulticast sends to a specific group.
	BroadcastTypeMulticast

	// BroadcastTypeAnycast sends to the closest peer in a group.
	BroadcastTypeAnycast
)

// String returns a human-readable string for the broadcast type.
func (t BroadcastType) String() string {
	switch t {
	case BroadcastTypeFlood:
		return "flood"
	case BroadcastTypeMulticast:
		return "multicast"
	case BroadcastTypeAnycast:
		return "anycast"
	default:
		return "unknown"
	}
}

// BroadcastMessage represents a broadcast message.
type BroadcastMessage struct {
	// ID is a unique message identifier.
	ID string `json:"id"`

	// Type is the broadcast type.
	Type BroadcastType `json:"type"`

	// SrcPeerID is the source peer ID.
	SrcPeerID string `json:"src_peer_id"`

	// GroupID is the multicast group (for multicast/anycast).
	GroupID string `json:"group_id,omitempty"`

	// TTL is the time-to-live (hop count).
	TTL int `json:"ttl"`

	// Timestamp is when the message was created.
	Timestamp time.Time `json:"timestamp"`

	// Payload is the message data.
	Payload []byte `json:"payload"`
}

// MulticastGroup represents a multicast group.
type MulticastGroup struct {
	// ID is the group identifier.
	ID string

	// Name is the human-readable group name.
	Name string

	// Members are the peer IDs in the group.
	Members map[string]bool

	// JoinedAt is when this peer joined the group.
	JoinedAt time.Time
}

// BroadcastManager manages broadcast and multicast messaging.
type BroadcastManager struct {
	localPeerID string
	router      *MeshRouter

	groups      map[string]*MulticastGroup
	seenMsgs    map[string]time.Time // messageID -> seen time
	seenMsgsTTL time.Duration

	sendFunc func(peerID string, data []byte) error
	handlers map[BroadcastType]BroadcastHandler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// BroadcastHandler handles received broadcast messages.
type BroadcastHandler func(msg *BroadcastMessage)

// BroadcastConfig contains broadcast manager configuration.
type BroadcastConfig struct {
	// SeenMsgsTTL is how long to remember seen messages.
	SeenMsgsTTL time.Duration

	// DefaultTTL is the default TTL for broadcasts.
	DefaultTTL int

	// CleanupInterval is the interval for cleaning up seen messages.
	CleanupInterval time.Duration
}

// DefaultBroadcastConfig returns a default broadcast configuration.
func DefaultBroadcastConfig() BroadcastConfig {
	return BroadcastConfig{
		SeenMsgsTTL:     5 * time.Minute,
		DefaultTTL:      8,
		CleanupInterval: time.Minute,
	}
}

// NewBroadcastManager creates a new broadcast manager.
func NewBroadcastManager(localPeerID string, router *MeshRouter, config BroadcastConfig) *BroadcastManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &BroadcastManager{
		localPeerID: localPeerID,
		router:      router,
		groups:      make(map[string]*MulticastGroup),
		seenMsgs:    make(map[string]time.Time),
		seenMsgsTTL: config.SeenMsgsTTL,
		handlers:    make(map[BroadcastType]BroadcastHandler),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start starts the broadcast manager.
func (bm *BroadcastManager) Start() error {
	slog.Info("starting broadcast manager")

	bm.wg.Add(1)
	go bm.cleanupWorker()

	return nil
}

// Stop stops the broadcast manager.
func (bm *BroadcastManager) Stop() error {
	slog.Info("stopping broadcast manager")

	bm.cancel()
	bm.wg.Wait()

	return nil
}

// SetSendFunc sets the function used to send messages.
func (bm *BroadcastManager) SetSendFunc(sendFunc func(peerID string, data []byte) error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.sendFunc = sendFunc
}

// RegisterHandler registers a handler for a broadcast type.
func (bm *BroadcastManager) RegisterHandler(broadcastType BroadcastType, handler BroadcastHandler) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.handlers[broadcastType] = handler
}

// Broadcast sends a message to all peers in the mesh.
func (bm *BroadcastManager) Broadcast(payload []byte, ttl int) error {
	if ttl <= 0 {
		ttl = 8
	}

	msg := &BroadcastMessage{
		ID:        bm.generateMessageID(payload),
		Type:      BroadcastTypeFlood,
		SrcPeerID: bm.localPeerID,
		TTL:       ttl,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	return bm.sendBroadcast(msg)
}

// Multicast sends a message to all members of a group.
func (bm *BroadcastManager) Multicast(groupID string, payload []byte, ttl int) error {
	if ttl <= 0 {
		ttl = 8
	}

	msg := &BroadcastMessage{
		ID:        bm.generateMessageID(payload),
		Type:      BroadcastTypeMulticast,
		SrcPeerID: bm.localPeerID,
		GroupID:   groupID,
		TTL:       ttl,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	return bm.sendBroadcast(msg)
}

// Anycast sends a message to the closest member of a group.
func (bm *BroadcastManager) Anycast(groupID string, payload []byte) error {
	bm.mu.RLock()
	group := bm.groups[groupID]
	bm.mu.RUnlock()

	if group == nil {
		return nil
	}

	// Find closest member
	var closestPeer string
	var lowestLatency time.Duration = time.Hour

	for peerID := range group.Members {
		if peerID == bm.localPeerID {
			// We're a member, handle locally
			msg := &BroadcastMessage{
				ID:        bm.generateMessageID(payload),
				Type:      BroadcastTypeAnycast,
				SrcPeerID: bm.localPeerID,
				GroupID:   groupID,
				Timestamp: time.Now(),
				Payload:   payload,
			}
			bm.deliverLocally(msg)
			return nil
		}

		route := bm.router.GetRoute(peerID)
		if route != nil && route.Latency < lowestLatency {
			lowestLatency = route.Latency
			closestPeer = peerID
		}
	}

	if closestPeer == "" {
		return nil
	}

	msg := &BroadcastMessage{
		ID:        bm.generateMessageID(payload),
		Type:      BroadcastTypeAnycast,
		SrcPeerID: bm.localPeerID,
		GroupID:   groupID,
		TTL:       1,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	return bm.sendToPeer(closestPeer, msg)
}

// sendBroadcast sends a broadcast message.
func (bm *BroadcastManager) sendBroadcast(msg *BroadcastMessage) error {
	// Mark as seen
	bm.mu.Lock()
	bm.seenMsgs[msg.ID] = time.Now()
	bm.mu.Unlock()

	// Get neighbors
	neighbors := bm.router.GetDirectPeers()

	// Send to each neighbor
	for _, peerID := range neighbors {
		if err := bm.sendToPeer(peerID, msg); err != nil {
			slog.Debug("failed to send broadcast",
				"peer_id", peerID,
				"error", err,
			)
		}
	}

	return nil
}

// sendToPeer sends a message to a specific peer.
func (bm *BroadcastManager) sendToPeer(peerID string, msg *BroadcastMessage) error {
	bm.mu.RLock()
	sendFunc := bm.sendFunc
	bm.mu.RUnlock()

	if sendFunc == nil {
		return nil
	}

	// Serialize message
	data := serializeBroadcastMessage(msg)

	return sendFunc(peerID, data)
}

// HandleMessage handles an incoming broadcast message.
func (bm *BroadcastManager) HandleMessage(fromPeerID string, data []byte) error {
	msg, err := deserializeBroadcastMessage(data)
	if err != nil {
		return err
	}

	// Check if we've seen this message
	bm.mu.Lock()
	if _, seen := bm.seenMsgs[msg.ID]; seen {
		bm.mu.Unlock()
		return nil // Already processed
	}
	bm.seenMsgs[msg.ID] = time.Now()
	bm.mu.Unlock()

	// Deliver locally
	bm.deliverLocally(msg)

	// Forward if TTL > 0
	if msg.TTL > 1 {
		bm.forward(fromPeerID, msg)
	}

	return nil
}

// deliverLocally delivers a message to local handlers.
func (bm *BroadcastManager) deliverLocally(msg *BroadcastMessage) {
	// Check if we should receive this message
	switch msg.Type {
	case BroadcastTypeMulticast, BroadcastTypeAnycast:
		bm.mu.RLock()
		group := bm.groups[msg.GroupID]
		bm.mu.RUnlock()

		if group == nil || !group.Members[bm.localPeerID] {
			return // Not a member
		}
	}

	bm.mu.RLock()
	handler := bm.handlers[msg.Type]
	bm.mu.RUnlock()

	if handler != nil {
		handler(msg)
	}
}

// forward forwards a message to neighbors.
func (bm *BroadcastManager) forward(excludePeerID string, msg *BroadcastMessage) {
	// Decrement TTL
	forwardMsg := *msg
	forwardMsg.TTL--

	neighbors := bm.router.GetDirectPeers()

	for _, peerID := range neighbors {
		// Don't send back to sender
		if peerID == excludePeerID {
			continue
		}

		// Don't send back to original source
		if peerID == msg.SrcPeerID {
			continue
		}

		if err := bm.sendToPeer(peerID, &forwardMsg); err != nil {
			slog.Debug("failed to forward broadcast",
				"peer_id", peerID,
				"error", err,
			)
		}
	}
}

// JoinGroup joins a multicast group.
func (bm *BroadcastManager) JoinGroup(groupID, groupName string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if _, exists := bm.groups[groupID]; exists {
		return
	}

	bm.groups[groupID] = &MulticastGroup{
		ID:       groupID,
		Name:     groupName,
		Members:  map[string]bool{bm.localPeerID: true},
		JoinedAt: time.Now(),
	}

	slog.Debug("joined multicast group", "group_id", groupID, "name", groupName)
}

// LeaveGroup leaves a multicast group.
func (bm *BroadcastManager) LeaveGroup(groupID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	delete(bm.groups, groupID)

	slog.Debug("left multicast group", "group_id", groupID)
}

// AddGroupMember adds a member to a group.
func (bm *BroadcastManager) AddGroupMember(groupID, peerID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	group := bm.groups[groupID]
	if group == nil {
		group = &MulticastGroup{
			ID:       groupID,
			Members:  make(map[string]bool),
			JoinedAt: time.Now(),
		}
		bm.groups[groupID] = group
	}

	group.Members[peerID] = true
}

// RemoveGroupMember removes a member from a group.
func (bm *BroadcastManager) RemoveGroupMember(groupID, peerID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	group := bm.groups[groupID]
	if group != nil {
		delete(group.Members, peerID)
	}
}

// GetGroups returns all joined groups.
func (bm *BroadcastManager) GetGroups() []*MulticastGroup {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	groups := make([]*MulticastGroup, 0, len(bm.groups))
	for _, group := range bm.groups {
		groups = append(groups, group)
	}

	return groups
}

// GetGroupMembers returns members of a group.
func (bm *BroadcastManager) GetGroupMembers(groupID string) []string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	group := bm.groups[groupID]
	if group == nil {
		return nil
	}

	members := make([]string, 0, len(group.Members))
	for peerID := range group.Members {
		members = append(members, peerID)
	}

	return members
}

// IsGroupMember checks if a peer is a member of a group.
func (bm *BroadcastManager) IsGroupMember(groupID, peerID string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	group := bm.groups[groupID]
	if group == nil {
		return false
	}

	return group.Members[peerID]
}

// cleanupWorker cleans up expired seen messages.
func (bm *BroadcastManager) cleanupWorker() {
	defer bm.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-bm.ctx.Done():
			return
		case <-ticker.C:
			bm.cleanupSeenMsgs()
		}
	}
}

// cleanupSeenMsgs removes expired seen message IDs.
func (bm *BroadcastManager) cleanupSeenMsgs() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	for id, seen := range bm.seenMsgs {
		if now.Sub(seen) > bm.seenMsgsTTL {
			delete(bm.seenMsgs, id)
		}
	}
}

// generateMessageID generates a unique message ID.
func (bm *BroadcastManager) generateMessageID(payload []byte) string {
	hash := sha256.New()
	hash.Write([]byte(bm.localPeerID))
	hash.Write([]byte(time.Now().String()))
	hash.Write(payload)
	return hex.EncodeToString(hash.Sum(nil))[:16]
}

// serializeBroadcastMessage serializes a broadcast message.
func serializeBroadcastMessage(msg *BroadcastMessage) []byte {
	// Simple serialization format:
	// [type:1][ttl:1][id_len:1][id][src_len:1][src][group_len:1][group][timestamp:8][payload]
	idBytes := []byte(msg.ID)
	srcBytes := []byte(msg.SrcPeerID)
	groupBytes := []byte(msg.GroupID)

	data := make([]byte, 0, 3+len(idBytes)+1+len(srcBytes)+1+len(groupBytes)+8+len(msg.Payload))

	data = append(data, byte(msg.Type))
	data = append(data, byte(msg.TTL))
	data = append(data, byte(len(idBytes)))
	data = append(data, idBytes...)
	data = append(data, byte(len(srcBytes)))
	data = append(data, srcBytes...)
	data = append(data, byte(len(groupBytes)))
	data = append(data, groupBytes...)

	// Timestamp as unix nano
	ts := msg.Timestamp.UnixNano()
	tsBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		tsBytes[i] = byte(ts >> (56 - i*8))
	}
	data = append(data, tsBytes...)

	data = append(data, msg.Payload...)

	return data
}

// deserializeBroadcastMessage deserializes a broadcast message.
func deserializeBroadcastMessage(data []byte) (*BroadcastMessage, error) {
	if len(data) < 3 {
		return nil, net.ErrClosed
	}

	offset := 0

	msgType := BroadcastType(data[offset])
	offset++

	ttl := int(data[offset])
	offset++

	idLen := int(data[offset])
	offset++

	if len(data) < offset+idLen {
		return nil, net.ErrClosed
	}
	id := string(data[offset : offset+idLen])
	offset += idLen

	if len(data) < offset+1 {
		return nil, net.ErrClosed
	}
	srcLen := int(data[offset])
	offset++

	if len(data) < offset+srcLen {
		return nil, net.ErrClosed
	}
	srcPeerID := string(data[offset : offset+srcLen])
	offset += srcLen

	if len(data) < offset+1 {
		return nil, net.ErrClosed
	}
	groupLen := int(data[offset])
	offset++

	if len(data) < offset+groupLen {
		return nil, net.ErrClosed
	}
	groupID := string(data[offset : offset+groupLen])
	offset += groupLen

	if len(data) < offset+8 {
		return nil, net.ErrClosed
	}

	var ts int64
	for i := 0; i < 8; i++ {
		ts |= int64(data[offset+i]) << (56 - i*8)
	}
	offset += 8

	payload := data[offset:]

	return &BroadcastMessage{
		ID:        id,
		Type:      msgType,
		SrcPeerID: srcPeerID,
		GroupID:   groupID,
		TTL:       ttl,
		Timestamp: time.Unix(0, ts),
		Payload:   payload,
	}, nil
}

// EthernetBroadcastHandler handles Ethernet broadcast frames for TAP devices.
type EthernetBroadcastHandler struct {
	manager *BroadcastManager
}

// NewEthernetBroadcastHandler creates a new Ethernet broadcast handler.
func NewEthernetBroadcastHandler(manager *BroadcastManager) *EthernetBroadcastHandler {
	return &EthernetBroadcastHandler{
		manager: manager,
	}
}

// HandleFrame handles an Ethernet broadcast/multicast frame.
func (h *EthernetBroadcastHandler) HandleFrame(dstMAC net.HardwareAddr, frame []byte) error {
	if isBroadcastMAC(dstMAC) {
		// Ethernet broadcast - flood to all peers
		return h.manager.Broadcast(frame, 8)
	}

	if isMulticastMAC(dstMAC) {
		// Ethernet multicast - send to multicast group based on MAC
		groupID := macToGroupID(dstMAC)
		return h.manager.Multicast(groupID, frame, 8)
	}

	return nil
}

// isBroadcastMAC checks if a MAC address is broadcast.
func isBroadcastMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0xFF {
			return false
		}
	}
	return true
}

// isMulticastMAC checks if a MAC address is multicast.
func isMulticastMAC(mac net.HardwareAddr) bool {
	return len(mac) > 0 && (mac[0]&0x01) != 0
}

// macToGroupID converts a multicast MAC to a group ID.
func macToGroupID(mac net.HardwareAddr) string {
	return hex.EncodeToString(mac)
}
