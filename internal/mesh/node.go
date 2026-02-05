package mesh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/device"
	"github.com/rennerdo30/bifrost-proxy/internal/frame"
	"github.com/rennerdo30/bifrost-proxy/internal/p2p"
)

// MeshNode errors.
var (
	ErrNodeNotStarted      = errors.New("mesh: node not started")
	ErrNodeAlreadyRunning  = errors.New("mesh: node already running")
	ErrNoPeerConnection    = errors.New("mesh: no connection to peer")
	ErrDeviceNotConfigured = errors.New("mesh: device not configured")
)

// NodeStatus represents the current status of the mesh node.
type NodeStatus string

const (
	NodeStatusStopped  NodeStatus = "stopped"
	NodeStatusStarting NodeStatus = "starting"
	NodeStatusRunning  NodeStatus = "running"
	NodeStatusStopping NodeStatus = "stopping"
	NodeStatusError    NodeStatus = "error"
)

// NodeStats contains mesh node statistics.
type NodeStats struct {
	Status             NodeStatus    `json:"status"`
	PeerCount          int           `json:"peer_count"`
	ConnectedPeers     int           `json:"connected_peers"`
	DirectConnections  int           `json:"direct_connections"`
	RelayedConnections int           `json:"relayed_connections"`
	BytesSent          int64         `json:"bytes_sent"`
	BytesReceived      int64         `json:"bytes_received"`
	PacketsSent        int64         `json:"packets_sent"`
	PacketsReceived    int64         `json:"packets_received"`
	Uptime             time.Duration `json:"uptime"`
}

// MeshNode is the central orchestrator that ties all mesh networking components together.
type MeshNode struct {
	config Config

	// Core identifiers
	localPeerID string
	localIP     netip.Addr
	localMAC    net.HardwareAddr

	// Sub-components
	device       device.NetworkDevice
	p2pManager   *p2p.P2PManager
	discovery    *DiscoveryClient
	router       *MeshRouter
	protocol     *RoutingProtocol
	broadcast    *BroadcastManager
	peerRegistry *PeerRegistry
	macTable     *frame.MACTable
	arpHandler   *frame.ARPInterceptor

	// State
	status    NodeStatus
	startTime time.Time

	// Statistics
	bytesSent       int64
	bytesReceived   int64
	packetsSent     int64
	packetsReceived int64

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// NewMeshNode creates a new mesh node with the given configuration.
func NewMeshNode(config Config) (*MeshNode, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Generate or load peer ID
	localPeerID := generatePeerID(config.PeerName)

	node := &MeshNode{
		config:       config,
		localPeerID:  localPeerID,
		status:       NodeStatusStopped,
		peerRegistry: NewPeerRegistry(),
		macTable:     frame.NewMACTable(frame.MACTableConfig{MaxAge: 5 * time.Minute}),
	}

	return node, nil
}

// Start starts the mesh node and all its components.
func (n *MeshNode) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.status == NodeStatusRunning || n.status == NodeStatusStarting {
		n.mu.Unlock()
		return ErrNodeAlreadyRunning
	}
	n.status = NodeStatusStarting
	n.mu.Unlock()

	slog.Info("starting mesh node",
		"peer_id", n.localPeerID,
		"network_id", n.config.NetworkID,
	)

	n.ctx, n.cancel = context.WithCancel(ctx)
	n.startTime = time.Now()

	// Initialize components in order
	if err := n.initializeDevice(); err != nil {
		n.setStatus(NodeStatusError)
		return fmt.Errorf("failed to initialize device: %w", err)
	}

	if err := n.initializeP2PManager(); err != nil {
		n.cleanup()
		n.setStatus(NodeStatusError)
		return fmt.Errorf("failed to initialize P2P manager: %w", err)
	}

	n.initializeRouter()
	n.initializeBroadcast()
	n.initializeDiscovery()

	// Wire up callbacks between components
	n.wireCallbacks()

	// Start all components
	if err := n.startComponents(); err != nil {
		n.cleanup()
		n.setStatus(NodeStatusError)
		return fmt.Errorf("failed to start components: %w", err)
	}

	// Start packet processing loop
	n.wg.Add(1)
	go n.packetLoop()

	// Start discovery event processing
	n.wg.Add(1)
	go n.discoveryEventLoop()

	// Start periodic maintenance
	n.wg.Add(1)
	go n.maintenanceLoop()

	n.setStatus(NodeStatusRunning)

	slog.Info("mesh node started successfully",
		"peer_id", n.localPeerID,
		"virtual_ip", n.localIP.String(),
	)

	return nil
}

// Stop stops the mesh node and all its components.
func (n *MeshNode) Stop() error {
	n.mu.Lock()
	if n.status != NodeStatusRunning {
		n.mu.Unlock()
		return nil
	}
	n.status = NodeStatusStopping
	n.mu.Unlock()

	slog.Info("stopping mesh node", "peer_id", n.localPeerID)

	// Signal all goroutines to stop
	if n.cancel != nil {
		n.cancel()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		slog.Warn("timeout waiting for mesh node goroutines to stop")
	}

	// Cleanup in reverse order
	n.cleanup()

	n.setStatus(NodeStatusStopped)
	slog.Info("mesh node stopped")

	return nil
}

// Status returns the current node status.
func (n *MeshNode) Status() NodeStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.status
}

// Stats returns current node statistics.
func (n *MeshNode) Stats() NodeStats {
	n.mu.RLock()
	defer n.mu.RUnlock()

	stats := NodeStats{
		Status:          n.status,
		BytesSent:       n.bytesSent,
		BytesReceived:   n.bytesReceived,
		PacketsSent:     n.packetsSent,
		PacketsReceived: n.packetsReceived,
	}

	if n.status == NodeStatusRunning {
		stats.Uptime = time.Since(n.startTime)
	}

	if n.peerRegistry != nil {
		stats.PeerCount = n.peerRegistry.Count()
		stats.ConnectedPeers = len(n.peerRegistry.Connected())
	}

	if n.p2pManager != nil {
		p2pStats := n.p2pManager.GetStats()
		stats.DirectConnections = p2pStats.DirectConnections
		stats.RelayedConnections = p2pStats.RelayedConnections
	}

	return stats
}

// LocalPeerID returns the local peer ID.
func (n *MeshNode) LocalPeerID() string {
	return n.localPeerID
}

// LocalIP returns the local virtual IP.
func (n *MeshNode) LocalIP() netip.Addr {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.localIP
}

// GetPeers returns all known peers.
func (n *MeshNode) GetPeers() []*Peer {
	if n.peerRegistry == nil {
		return nil
	}
	return n.peerRegistry.All()
}

// GetConnectedPeers returns all connected peers.
func (n *MeshNode) GetConnectedPeers() []*Peer {
	if n.peerRegistry == nil {
		return nil
	}
	return n.peerRegistry.Connected()
}

// GetPeer returns a peer by ID.
func (n *MeshNode) GetPeer(peerID string) (*Peer, bool) {
	if n.peerRegistry == nil {
		return nil, false
	}
	return n.peerRegistry.Get(peerID)
}

// GetRoutes returns the routing table.
func (n *MeshNode) GetRoutes() []*Route {
	if n.router == nil {
		return nil
	}
	return n.router.GetBestRoutes()
}

// initializeDevice creates and configures the network device.
func (n *MeshNode) initializeDevice() error {
	// Parse network prefix to get our address
	prefix, err := n.config.NetworkPrefix()
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}

	// We'll get our IP from the discovery server, but for now use a temporary one
	// This will be updated when we register
	tempIP := prefix.Addr().Next()
	n.localIP = tempIP

	// Create device config
	deviceCfg := n.config.Device.ToDeviceConfig(fmt.Sprintf("%s/%d", tempIP.String(), prefix.Bits()))

	// Create the device
	dev, err := device.Create(deviceCfg)
	if err != nil {
		return fmt.Errorf("failed to create device: %w", err)
	}

	n.device = dev

	// If TAP device, get/set MAC address
	if n.config.Device.Type == "tap" {
		if tapDev, ok := dev.(device.TAPDevice); ok {
			n.localMAC = tapDev.MACAddress()
			slog.Debug("TAP device created", "mac", n.localMAC.String())
		}
	}

	// Initialize ARP handler for TAP mode
	if n.config.Device.Type == "tap" && n.localMAC != nil {
		n.arpHandler = frame.NewARPInterceptor(n.localMAC, n.localIP, n.macTable)
	}

	slog.Info("device initialized",
		"name", dev.Name(),
		"type", dev.Type().String(),
		"mtu", dev.MTU(),
	)

	return nil
}

// initializeP2PManager creates and configures the P2P manager.
func (n *MeshNode) initializeP2PManager() error {
	// Load or generate key pair
	var privateKey []byte
	if n.config.Security.PrivateKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(n.config.Security.PrivateKey)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		privateKey = decoded
	}

	// Build TURN config if configured
	var turnConfig *p2p.TURNConfig
	if n.config.TURN.Enabled && len(n.config.TURN.Servers) > 0 {
		server := n.config.TURN.Servers[0]
		turnConfig = &p2p.TURNConfig{
			Server:   server.URL,
			Username: server.Username,
			Password: server.Password,
			Timeout:  30 * time.Second,
		}
	}

	pmConfig := p2p.ManagerConfig{
		LocalPeerID:          n.localPeerID,
		LocalPrivateKey:      privateKey,
		STUNServers:          n.config.STUN.Servers,
		TURNConfig:           turnConfig,
		ConnectTimeout:       n.config.Connection.ConnectTimeout,
		KeepAliveInterval:    n.config.Connection.KeepAliveInterval,
		DirectConnectEnabled: n.config.Connection.DirectConnect,
		RelayEnabled:         n.config.Connection.RelayEnabled,
		PeerRelayEnabled:     n.config.Connection.RelayViaPeers,
	}

	pm, err := p2p.NewP2PManager(pmConfig)
	if err != nil {
		return fmt.Errorf("failed to create P2P manager: %w", err)
	}

	n.p2pManager = pm
	return nil
}

// initializeRouter creates and configures the mesh router.
func (n *MeshNode) initializeRouter() {
	routerConfig := RouterConfig{
		LocalPeerID:  n.localPeerID,
		LocalIP:      n.localIP,
		MaxHops:      8,
		RouteTimeout: 5 * time.Minute,
	}

	n.router = NewMeshRouter(routerConfig)

	// Initialize routing protocol
	protocolConfig := DefaultProtocolConfig()
	n.protocol = NewRoutingProtocol(n.localPeerID, n.localIP, n.router, protocolConfig)
}

// initializeBroadcast creates and configures the broadcast manager.
func (n *MeshNode) initializeBroadcast() {
	broadcastConfig := DefaultBroadcastConfig()
	n.broadcast = NewBroadcastManager(n.localPeerID, n.router, broadcastConfig)
}

// initializeDiscovery creates and configures the discovery client.
func (n *MeshNode) initializeDiscovery() {
	// Create local peer representation
	localPeer := NewPeer(n.localPeerID, n.config.PeerName)
	localPeer.SetVirtualIP(n.localIP)
	if n.localMAC != nil {
		localPeer.SetVirtualMAC(n.localMAC)
	}

	// Get local public key
	if n.p2pManager != nil {
		pubKey := n.p2pManager.LocalPublicKey()
		localPeer.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
	}

	// Add local endpoints
	if n.p2pManager != nil {
		for _, ep := range n.p2pManager.LocalEndpoints() {
			localPeer.AddEndpoint(Endpoint{
				Address:  ep.Addr().String(),
				Port:     ep.Port(),
				Type:     "local",
				Priority: 100,
			})
		}
	}

	n.discovery = NewDiscoveryClient(
		n.config.Discovery,
		n.config.NetworkID,
		localPeer,
		n.peerRegistry,
	)
}

// wireCallbacks connects all component callbacks.
func (n *MeshNode) wireCallbacks() {
	// P2P Manager callbacks
	n.p2pManager.SetCallbacks(p2p.ManagerCallbacks{
		OnPeerConnected:    n.onPeerConnected,
		OnPeerDisconnected: n.onPeerDisconnected,
		OnData:             n.onP2PData,
		OnError:            n.onP2PError,
	})

	// Routing protocol send function
	n.protocol.SetSendFunc(n.sendToP2P)

	// Broadcast manager send function
	n.broadcast.SetSendFunc(n.sendToP2P)

	// Register broadcast handlers
	n.broadcast.RegisterHandler(BroadcastTypeFlood, n.handleFloodBroadcast)
	n.broadcast.RegisterHandler(BroadcastTypeMulticast, n.handleMulticastBroadcast)

	// Router callbacks
	n.router.OnRouteChanged(n.onRouteChanged)
}

// startComponents starts all sub-components.
func (n *MeshNode) startComponents() error {
	// Start P2P manager
	if err := n.p2pManager.Start(n.ctx); err != nil {
		return fmt.Errorf("failed to start P2P manager: %w", err)
	}

	// Start routing protocol
	if err := n.protocol.Start(); err != nil {
		return fmt.Errorf("failed to start routing protocol: %w", err)
	}

	// Start broadcast manager
	if err := n.broadcast.Start(); err != nil {
		return fmt.Errorf("failed to start broadcast manager: %w", err)
	}

	// Start discovery client
	if err := n.discovery.Start(n.ctx); err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}

	return nil
}

// cleanup stops and cleans up all components.
func (n *MeshNode) cleanup() {
	// Stop discovery
	if n.discovery != nil {
		_ = n.discovery.Stop() //nolint:errcheck // Best effort cleanup
	}

	// Stop broadcast
	if n.broadcast != nil {
		_ = n.broadcast.Stop() //nolint:errcheck // Best effort cleanup
	}

	// Stop routing protocol
	if n.protocol != nil {
		_ = n.protocol.Stop() //nolint:errcheck // Best effort cleanup
	}

	// Stop P2P manager
	if n.p2pManager != nil {
		_ = n.p2pManager.Stop() //nolint:errcheck // Best effort cleanup
	}

	// Close device
	if n.device != nil {
		n.device.Close()
	}
}

// packetLoop reads packets from the device and forwards them.
func (n *MeshNode) packetLoop() {
	defer n.wg.Done()

	buf := make([]byte, 65536)

	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		// Read packet/frame from device
		nr, err := n.device.Read(buf)
		if err != nil {
			if n.ctx.Err() != nil {
				return
			}
			slog.Debug("device read error", "error", err)
			continue
		}

		if nr == 0 {
			continue
		}

		packet := make([]byte, nr)
		copy(packet, buf[:nr])

		n.mu.Lock()
		n.packetsReceived++
		n.bytesReceived += int64(nr)
		n.mu.Unlock()

		// Process based on device type
		if n.device.Type() == device.DeviceTAP {
			n.handleTAPFrame(packet)
		} else {
			n.handleTUNPacket(packet)
		}
	}
}

// handleTUNPacket processes an IP packet from the TUN device.
func (n *MeshNode) handleTUNPacket(packet []byte) {
	if len(packet) < 20 {
		return // Too short for IP header
	}

	// Parse destination IP from IP header
	version := packet[0] >> 4
	var destIP netip.Addr

	if version == 4 {
		// IPv4: destination is at bytes 16-19
		destIP = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	} else if version == 6 {
		// IPv6: destination is at bytes 24-39
		if len(packet) < 40 {
			return
		}
		var addr [16]byte
		copy(addr[:], packet[24:40])
		destIP = netip.AddrFrom16(addr)
	} else {
		return // Unknown IP version
	}

	// Find next hop for this destination
	nextHop := n.router.GetNextHopByIP(destIP)
	if nextHop == "" {
		slog.Debug("no route to destination", "dest_ip", destIP.String())
		return
	}

	// Send to peer
	if err := n.sendToP2P(nextHop, packet); err != nil {
		slog.Debug("failed to send packet to peer",
			"peer_id", nextHop,
			"error", err,
		)
	}
}

// handleTAPFrame processes an Ethernet frame from the TAP device.
func (n *MeshNode) handleTAPFrame(frameData []byte) {
	ethFrame, err := frame.ParseEthernetFrame(frameData)
	if err != nil {
		slog.Debug("failed to parse ethernet frame", "error", err)
		return
	}

	// Learn source MAC
	n.macTable.Learn(ethFrame.Header.SrcMAC, n.localPeerID)

	// Handle ARP
	if ethFrame.Header.EtherType == frame.EtherTypeARP && n.arpHandler != nil {
		response := n.arpHandler.HandleFrame(frameData)
		if response != nil {
			// Write ARP response back to device
			if _, err := n.device.Write(response); err != nil {
				slog.Debug("failed to write ARP response", "error", err)
			}
		}
		return
	}

	// Check if broadcast/multicast
	if frame.IsBroadcast(ethFrame.Header.DstMAC) {
		// Flood to all peers
		if err := n.broadcast.Broadcast(frameData, 8); err != nil {
			slog.Debug("failed to broadcast frame", "error", err)
		}
		return
	}

	if frame.IsMulticast(ethFrame.Header.DstMAC) {
		// Multicast handling
		groupID := macToGroupID(ethFrame.Header.DstMAC)
		if err := n.broadcast.Multicast(groupID, frameData, 8); err != nil {
			slog.Debug("failed to multicast frame", "error", err)
		}
		return
	}

	// Unicast - look up peer by MAC
	entry, found := n.macTable.LookupEntry(ethFrame.Header.DstMAC)
	if !found {
		// Unknown destination - flood
		if err := n.broadcast.Broadcast(frameData, 8); err != nil {
			slog.Debug("failed to flood unknown frame", "error", err)
		}
		return
	}

	// Send directly to peer
	if err := n.sendToP2P(entry.PeerID, frameData); err != nil {
		slog.Debug("failed to send frame to peer",
			"peer_id", entry.PeerID,
			"error", err,
		)
	}
}

// sendToP2P sends data to a peer via the P2P manager.
func (n *MeshNode) sendToP2P(peerID string, data []byte) error {
	if n.p2pManager == nil {
		return ErrNodeNotStarted
	}

	// Check if we have a direct connection
	conn := n.p2pManager.GetConnection(peerID)
	if conn != nil {
		n.mu.Lock()
		n.packetsSent++
		n.bytesSent += int64(len(data))
		n.mu.Unlock()

		return conn.Send(data)
	}

	// Check for multi-hop route
	nextHop := n.router.GetNextHop(peerID)
	if nextHop == "" || nextHop == peerID {
		return ErrNoPeerConnection
	}

	// Forward via next hop
	return n.sendToP2P(nextHop, data)
}

// writeToDevice writes data to the network device.
func (n *MeshNode) writeToDevice(data []byte) error {
	if n.device == nil {
		return ErrDeviceNotConfigured
	}

	_, err := n.device.Write(data)
	return err
}

// discoveryEventLoop processes discovery events.
func (n *MeshNode) discoveryEventLoop() {
	defer n.wg.Done()

	events := n.discovery.Events()

	for {
		select {
		case <-n.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			n.handleDiscoveryEvent(event)
		}
	}
}

// handleDiscoveryEvent processes a peer discovery event.
func (n *MeshNode) handleDiscoveryEvent(event PeerEvent) {
	switch event.Type {
	case "join":
		n.onPeerDiscovered(event.Peer)
	case "leave":
		n.onPeerLeft(event.Peer.ID)
	case "update":
		n.onPeerUpdated(event.Peer)
	}
}

// onPeerDiscovered is called when a new peer is discovered.
func (n *MeshNode) onPeerDiscovered(info PeerInfo) {
	slog.Info("peer discovered", "peer_id", info.ID, "name", info.Name)

	// Get peer from registry
	peer, exists := n.peerRegistry.Get(info.ID)
	if !exists {
		return
	}

	// Decode public key
	pubKey, err := base64.StdEncoding.DecodeString(info.PublicKey)
	if err != nil {
		slog.Warn("invalid peer public key", "peer_id", info.ID, "error", err)
		return
	}

	// Convert endpoints to netip.AddrPort
	endpoints := make([]netip.AddrPort, 0, len(info.Endpoints))
	for _, ep := range info.Endpoints {
		addr, err := netip.ParseAddr(ep.Address)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, netip.AddrPortFrom(addr, ep.Port))
	}

	if len(endpoints) == 0 {
		slog.Debug("peer has no valid endpoints", "peer_id", info.ID)
		return
	}

	// Attempt to connect
	peer.SetStatus(PeerStatusConnecting)

	go func() {
		ctx, cancel := context.WithTimeout(n.ctx, n.config.Connection.ConnectTimeout)
		defer cancel()

		conn, err := n.p2pManager.Connect(ctx, info.ID, pubKey, endpoints)
		if err != nil {
			slog.Warn("failed to connect to peer",
				"peer_id", info.ID,
				"error", err,
			)
			peer.SetStatus(PeerStatusUnreachable)
			return
		}

		slog.Info("connected to peer",
			"peer_id", info.ID,
			"connection_type", conn.Type().String(),
		)
	}()
}

// onPeerLeft is called when a peer leaves the network.
func (n *MeshNode) onPeerLeft(peerID string) {
	slog.Info("peer left", "peer_id", peerID)

	// Disconnect if connected
	_ = n.p2pManager.Disconnect(peerID) //nolint:errcheck // Best effort disconnect

	// Remove routes
	n.protocol.NotifyPeerDisconnected(peerID)

	// Clean up MAC table entries
	n.macTable.RemovePeer(peerID)
}

// onPeerUpdated is called when a peer's information is updated.
func (n *MeshNode) onPeerUpdated(info PeerInfo) {
	slog.Debug("peer updated", "peer_id", info.ID)
}

// onPeerConnected is called when a P2P connection is established.
func (n *MeshNode) onPeerConnected(peerID string, conn p2p.P2PConnection) {
	slog.Info("P2P connection established",
		"peer_id", peerID,
		"type", conn.Type().String(),
		"latency", conn.Latency(),
	)

	// Update peer status
	peer, exists := n.peerRegistry.Get(peerID)
	if exists {
		if conn.Type() == p2p.ConnectionTypeDirect {
			peer.SetStatus(PeerStatusConnected)
			peer.SetConnectionType(ConnectionTypeDirect)
		} else {
			peer.SetStatus(PeerStatusRelayed)
			peer.SetConnectionType(ConnectionTypeRelayed)
		}
		peer.SetLatency(conn.Latency())
	}

	// Notify routing protocol
	if peer != nil && peer.VirtualIP.IsValid() {
		n.protocol.NotifyPeerConnected(peerID, peer.VirtualIP, conn.Latency())
	}

	// Add as potential relay (feature planned for future release)
	// When RelayViaPeers is enabled, connected peers can act as relays
	// for other peers that cannot establish direct connections.
	if n.config.Connection.RelayViaPeers {
		// Currently logs relay capability; full relay implementation
		// will be added in a future version
		slog.Debug("Peer relay enabled, peer available as relay candidate",
			"peer", peerID,
			"stats", n.p2pManager.GetStats())
	}
}

// onPeerDisconnected is called when a P2P connection is lost.
func (n *MeshNode) onPeerDisconnected(peerID string) {
	slog.Info("P2P connection lost", "peer_id", peerID)

	// Update peer status
	peer, exists := n.peerRegistry.Get(peerID)
	if exists {
		peer.SetStatus(PeerStatusDiscovered)
	}

	// Notify routing protocol
	n.protocol.NotifyPeerDisconnected(peerID)

	// Clean up MAC table
	n.macTable.RemovePeer(peerID)
}

// onP2PData is called when data is received from a peer.
func (n *MeshNode) onP2PData(peerID string, data []byte) {
	n.mu.Lock()
	n.packetsReceived++
	n.bytesReceived += int64(len(data))
	n.mu.Unlock()

	// Update peer stats
	peer, exists := n.peerRegistry.Get(peerID)
	if exists {
		peer.AddBytesReceived(int64(len(data)))
		peer.UpdateLastSeen()
	}

	// Check if this is a protocol message
	if len(data) > 0 && isProtocolMessage(data) {
		n.handleProtocolMessage(peerID, data)
		return
	}

	// Check if this is a broadcast message
	if len(data) > 0 && isBroadcastMessage(data) {
		_ = n.broadcast.HandleMessage(peerID, data) //nolint:errcheck // Best effort broadcast
		return
	}

	// Regular data - write to device
	if n.device.Type() == device.DeviceTAP {
		// For TAP, learn the source MAC
		if len(data) >= 14 {
			srcMAC := net.HardwareAddr(data[6:12])
			n.macTable.Learn(srcMAC, peerID)
		}
	}

	if err := n.writeToDevice(data); err != nil {
		slog.Debug("failed to write to device", "error", err)
	}
}

// onP2PError is called when a P2P error occurs.
func (n *MeshNode) onP2PError(peerID string, err error) {
	slog.Warn("P2P error", "peer_id", peerID, "error", err)
}

// handleProtocolMessage processes an incoming routing protocol message.
func (n *MeshNode) handleProtocolMessage(peerID string, data []byte) {
	// Strip message type marker
	if len(data) < 2 {
		return
	}
	msgData := data[1:]

	if err := n.protocol.HandleMessage(peerID, msgData); err != nil {
		slog.Debug("failed to handle protocol message",
			"peer_id", peerID,
			"error", err,
		)
	}
}

// handleFloodBroadcast handles a flood broadcast message.
func (n *MeshNode) handleFloodBroadcast(msg *BroadcastMessage) {
	// Write payload to device
	if err := n.writeToDevice(msg.Payload); err != nil {
		slog.Debug("failed to write broadcast to device", "error", err)
	}
}

// handleMulticastBroadcast handles a multicast broadcast message.
func (n *MeshNode) handleMulticastBroadcast(msg *BroadcastMessage) {
	// Write payload to device
	if err := n.writeToDevice(msg.Payload); err != nil {
		slog.Debug("failed to write multicast to device", "error", err)
	}
}

// onRouteChanged is called when a route is added or changed.
func (n *MeshNode) onRouteChanged(route *Route) {
	slog.Debug("route changed",
		"dest", route.DestPeerID,
		"type", route.Type.String(),
		"metric", route.Metric,
	)
}

// maintenanceLoop performs periodic maintenance tasks.
func (n *MeshNode) maintenanceLoop() {
	defer n.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.performMaintenance()
		}
	}
}

// performMaintenance performs periodic maintenance.
func (n *MeshNode) performMaintenance() {
	// Clean up expired MAC table entries
	if n.macTable != nil {
		n.macTable.Expire()
	}

	// Update local endpoints if they changed
	if n.p2pManager != nil && n.discovery != nil {
		endpoints := n.p2pManager.LocalEndpoints()
		meshEndpoints := make([]Endpoint, 0, len(endpoints))
		for _, ep := range endpoints {
			meshEndpoints = append(meshEndpoints, Endpoint{
				Address:  ep.Addr().String(),
				Port:     ep.Port(),
				Type:     "reflexive",
				Priority: 50,
			})
		}
		_ = n.discovery.UpdateEndpoints(meshEndpoints) //nolint:errcheck // Best effort endpoint update
	}
}

// setStatus sets the node status.
func (n *MeshNode) setStatus(status NodeStatus) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.status = status
}

// Helper functions

// generatePeerID generates a unique peer ID.
func generatePeerID(peerName string) string {
	if peerName != "" {
		return peerName
	}
	// Generate a random ID
	mac, err := device.GenerateRandomMAC()
	if err != nil {
		return fmt.Sprintf("peer-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("peer-%s", base64.RawURLEncoding.EncodeToString(mac))
}

// isProtocolMessage checks if data is a routing protocol message.
func isProtocolMessage(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	// Protocol messages start with 0x01 marker
	return data[0] == 0x01
}

// isBroadcastMessage checks if data is a broadcast message.
func isBroadcastMessage(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	// Broadcast messages start with 0x02 marker
	return data[0] == 0x02
}
