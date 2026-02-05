package p2p

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Manager errors.
var (
	ErrManagerClosed      = errors.New("p2p: manager closed")
	ErrPeerNotFound       = errors.New("p2p: peer not found")
	ErrConnectionExists   = errors.New("p2p: connection already exists")
	ErrNoEndpoints        = errors.New("p2p: no endpoints available")
)

// P2PManager manages all P2P connections.
type P2PManager struct {
	config       ManagerConfig
	localPeerID  string
	localKeyPair *KeyPair

	iceAgent     *ICEAgent
	natDetector  *NATDetector
	relayManager *RelayManager

	connections map[string]P2PConnection
	endpoints   map[string][]netip.AddrPort
	callbacks   ManagerCallbacks

	conn   net.PacketConn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// ManagerConfig contains P2P manager configuration.
type ManagerConfig struct {
	// LocalPeerID is the local peer identifier.
	LocalPeerID string

	// LocalPrivateKey is the local private key.
	LocalPrivateKey []byte

	// STUNServers is a list of STUN servers.
	STUNServers []string

	// TURNConfig is the TURN server configuration.
	TURNConfig *TURNConfig

	// RelayConfig is the relay configuration.
	RelayConfig RelayConfig

	// ConnectTimeout is the connection timeout.
	ConnectTimeout time.Duration

	// KeepAliveInterval is the keep-alive interval.
	KeepAliveInterval time.Duration

	// DirectConnectEnabled enables direct connections.
	DirectConnectEnabled bool

	// RelayEnabled enables relay connections.
	RelayEnabled bool

	// PeerRelayEnabled enables peer relaying.
	PeerRelayEnabled bool
}

// DefaultManagerConfig returns a default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		STUNServers:          DefaultSTUNServers(),
		RelayConfig:          DefaultRelayConfig(),
		ConnectTimeout:       30 * time.Second,
		KeepAliveInterval:    25 * time.Second,
		DirectConnectEnabled: true,
		RelayEnabled:         true,
		PeerRelayEnabled:     true,
	}
}

// ManagerCallbacks contains callbacks for P2P events.
type ManagerCallbacks struct {
	// OnPeerConnected is called when a peer connects.
	OnPeerConnected func(peerID string, conn P2PConnection)

	// OnPeerDisconnected is called when a peer disconnects.
	OnPeerDisconnected func(peerID string)

	// OnData is called when data is received from a peer.
	OnData func(peerID string, data []byte)

	// OnError is called when an error occurs.
	OnError func(peerID string, err error)
}

// NewP2PManager creates a new P2P manager.
func NewP2PManager(config ManagerConfig) (*P2PManager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Generate or use provided key pair
	var keyPair *KeyPair
	var err error

	if len(config.LocalPrivateKey) > 0 {
		keyPair = &KeyPair{}
		copy(keyPair.PrivateKey[:], config.LocalPrivateKey)
		pubKey, err := PublicKeyFromPrivate(config.LocalPrivateKey)
		if err != nil {
			cancel()
			return nil, err
		}
		copy(keyPair.PublicKey[:], pubKey)
	} else {
		keyPair, err = GenerateKeyPair()
		if err != nil {
			cancel()
			return nil, err
		}
	}

	pm := &P2PManager{
		config:       config,
		localPeerID:  config.LocalPeerID,
		localKeyPair: keyPair,
		connections:  make(map[string]P2PConnection),
		endpoints:    make(map[string][]netip.AddrPort),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize NAT detector
	pm.natDetector = NewNATDetector(config.STUNServers, config.ConnectTimeout)

	// Initialize relay manager
	pm.relayManager = NewRelayManager(config.RelayConfig)

	return pm, nil
}

// Start starts the P2P manager.
func (pm *P2PManager) Start(ctx context.Context) error {
	slog.Info("starting P2P manager", "peer_id", pm.localPeerID)

	// Create UDP socket
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	pm.conn = conn

	// Detect NAT type
	natInfo, err := pm.natDetector.Detect(ctx)
	if err != nil {
		slog.Warn("failed to detect NAT type", "error", err)
	} else {
		slog.Info("NAT detected",
			"type", natInfo.Type.String(),
			"mapped_address", natInfo.MappedAddress.String(),
		)
	}

	// Start relay manager
	if err := pm.relayManager.Start(ctx); err != nil {
		slog.Warn("failed to start relay manager", "error", err)
	}

	// Start receive worker
	pm.wg.Add(1)
	go pm.receiveWorker()

	// Start connection monitor
	pm.wg.Add(1)
	go pm.connectionMonitor()

	return nil
}

// Stop stops the P2P manager.
func (pm *P2PManager) Stop() error {
	slog.Info("stopping P2P manager")

	pm.cancel()

	// Close all connections
	pm.mu.Lock()
	for _, conn := range pm.connections {
		conn.Close()
	}
	pm.connections = make(map[string]P2PConnection)
	pm.mu.Unlock()

	// Stop relay manager
	pm.relayManager.Stop()

	// Close NAT detector
	pm.natDetector.Close()

	// Close socket
	if pm.conn != nil {
		pm.conn.Close()
	}

	pm.wg.Wait()

	return nil
}

// Connect initiates a connection to a peer.
func (pm *P2PManager) Connect(ctx context.Context, peerID string, remotePublicKey []byte, endpoints []netip.AddrPort) (P2PConnection, error) {
	pm.mu.Lock()
	if _, exists := pm.connections[peerID]; exists {
		pm.mu.Unlock()
		return nil, ErrConnectionExists
	}
	pm.mu.Unlock()

	slog.Debug("connecting to peer", "peer_id", peerID, "endpoints", len(endpoints))

	// Store endpoints
	pm.mu.Lock()
	pm.endpoints[peerID] = endpoints
	pm.mu.Unlock()

	// Try direct connection first
	if pm.config.DirectConnectEnabled && len(endpoints) > 0 {
		conn, err := pm.tryDirectConnect(ctx, peerID, remotePublicKey, endpoints)
		if err == nil {
			pm.mu.Lock()
			pm.connections[peerID] = conn
			pm.mu.Unlock()

			if pm.callbacks.OnPeerConnected != nil {
				pm.callbacks.OnPeerConnected(peerID, conn)
			}

			slog.Info("direct connection established", "peer_id", peerID)
			return conn, nil
		}
		slog.Debug("direct connection failed", "peer_id", peerID, "error", err)
	}

	// Try relay connection
	if pm.config.RelayEnabled {
		conn, err := pm.tryRelayConnect(ctx, peerID, remotePublicKey)
		if err == nil {
			pm.mu.Lock()
			pm.connections[peerID] = conn
			pm.mu.Unlock()

			if pm.callbacks.OnPeerConnected != nil {
				pm.callbacks.OnPeerConnected(peerID, conn)
			}

			slog.Info("relay connection established", "peer_id", peerID)
			return conn, nil
		}
		slog.Debug("relay connection failed", "peer_id", peerID, "error", err)
	}

	return nil, ErrConnectionFailed
}

// tryDirectConnect attempts a direct connection.
func (pm *P2PManager) tryDirectConnect(ctx context.Context, peerID string, remotePublicKey []byte, endpoints []netip.AddrPort) (P2PConnection, error) {
	config := ConnectionConfig{
		PeerID:            peerID,
		LocalPrivateKey:   pm.localKeyPair.PrivateKey[:],
		RemotePublicKey:   remotePublicKey,
		ConnectTimeout:    pm.config.ConnectTimeout,
		KeepAliveInterval: pm.config.KeepAliveInterval,
	}

	// Try each endpoint
	for _, endpoint := range endpoints {
		conn, err := NewDirectConnection(config, pm.conn, endpoint)
		if err != nil {
			continue
		}

		connectCtx, cancel := context.WithTimeout(ctx, pm.config.ConnectTimeout)
		err = conn.Connect(connectCtx)
		cancel()

		if err == nil {
			return conn, nil
		}

		conn.Close()
	}

	return nil, ErrNoEndpoints
}

// tryRelayConnect attempts a relayed connection.
func (pm *P2PManager) tryRelayConnect(ctx context.Context, peerID string, remotePublicKey []byte) (P2PConnection, error) {
	config := ConnectionConfig{
		PeerID:            peerID,
		LocalPrivateKey:   pm.localKeyPair.PrivateKey[:],
		RemotePublicKey:   remotePublicKey,
		ConnectTimeout:    pm.config.ConnectTimeout,
		KeepAliveInterval: pm.config.KeepAliveInterval,
	}

	return pm.relayManager.CreateRelayedConnection(ctx, config)
}

// Disconnect disconnects from a peer.
func (pm *P2PManager) Disconnect(peerID string) error {
	pm.mu.Lock()
	conn, exists := pm.connections[peerID]
	if !exists {
		pm.mu.Unlock()
		return ErrPeerNotFound
	}
	delete(pm.connections, peerID)
	delete(pm.endpoints, peerID)
	pm.mu.Unlock()

	if pm.callbacks.OnPeerDisconnected != nil {
		pm.callbacks.OnPeerDisconnected(peerID)
	}

	slog.Debug("disconnected from peer", "peer_id", peerID)

	return conn.Close()
}

// Send sends data to a peer.
func (pm *P2PManager) Send(peerID string, data []byte) error {
	pm.mu.RLock()
	conn, exists := pm.connections[peerID]
	pm.mu.RUnlock()

	if !exists {
		return ErrPeerNotFound
	}

	return conn.Send(data)
}

// GetConnection returns the connection for a peer.
func (pm *P2PManager) GetConnection(peerID string) P2PConnection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.connections[peerID]
}

// GetConnections returns all connections.
func (pm *P2PManager) GetConnections() map[string]P2PConnection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	conns := make(map[string]P2PConnection, len(pm.connections))
	for k, v := range pm.connections {
		conns[k] = v
	}
	return conns
}

// LocalPublicKey returns the local public key.
func (pm *P2PManager) LocalPublicKey() []byte {
	return pm.localKeyPair.PublicKey[:]
}

// LocalEndpoints returns the local endpoints.
func (pm *P2PManager) LocalEndpoints() []netip.AddrPort {
	endpoints := make([]netip.AddrPort, 0)

	// Add local address
	if pm.conn != nil {
		localAddr := pm.conn.LocalAddr().(*net.UDPAddr)
		endpoints = append(endpoints, netip.AddrPortFrom(
			netip.MustParseAddr(localAddr.IP.String()),
			uint16(localAddr.Port),
		))
	}

	// Add NAT mapped address
	if addr, ok := pm.natDetector.GetMappedAddress(); ok {
		endpoints = append(endpoints, addr)
	}

	// Add relay address
	if pm.relayManager.turnClient != nil {
		if addr, err := pm.relayManager.turnClient.RelayAddress(); err == nil {
			endpoints = append(endpoints, addr)
		}
	}

	return endpoints
}

// GetNATInfo returns the detected NAT info.
func (pm *P2PManager) GetNATInfo() *NATInfo {
	return pm.natDetector.GetCachedInfo()
}

// SetCallbacks sets the manager callbacks.
func (pm *P2PManager) SetCallbacks(callbacks ManagerCallbacks) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.callbacks = callbacks
}

// receiveWorker handles incoming packets.
func (pm *P2PManager) receiveWorker() {
	defer pm.wg.Done()

	buf := make([]byte, 65536)

	for {
		select {
		case <-pm.ctx.Done():
			return
		default:
		}

		if err := pm.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("failed to set read deadline in receive worker", "error", err)
			} else {
				slog.Warn("failed to set read deadline in receive worker", "error", err)
			}
		}
		n, from, err := pm.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		// Find connection for this source
		fromUDP := from.(*net.UDPAddr)
		fromAddr := netip.AddrPortFrom(
			netip.MustParseAddr(fromUDP.IP.String()),
			uint16(fromUDP.Port),
		)

		pm.mu.RLock()
		var foundPeerID string
		for peerID, endpoints := range pm.endpoints {
			for _, ep := range endpoints {
				if ep == fromAddr {
					foundPeerID = peerID
					break
				}
			}
			if foundPeerID != "" {
				break
			}
		}
		pm.mu.RUnlock()

		if foundPeerID == "" {
			// Unknown source, could be a new connection request
			pm.handleNewConnection(fromAddr, buf[:n])
			continue
		}

		// Dispatch to connection handler
		pm.handleData(foundPeerID, buf[:n])
	}
}

// handleNewConnection handles a potential new connection.
func (pm *P2PManager) handleNewConnection(from netip.AddrPort, data []byte) {
	// Check if this is a handshake initiation
	if len(data) < 1 || data[0] != msgTypeHandshakeInit {
		return
	}

	// Handshake init message format: type (1) + public key (32) + random (32)
	if len(data) < 1+32+32 {
		slog.Debug("invalid handshake init: too short", "from", from.String())
		return
	}

	slog.Debug("received connection request", "from", from.String())

	// Extract remote public key from handshake init
	remotePublicKey := data[1:33]

	// Look up peer by public key or address
	peerID := pm.lookupPeerByKey(remotePublicKey)
	if peerID == "" {
		// Unknown peer - could accept or reject based on config
		// For now, generate a temporary peer ID
		peerID = fmt.Sprintf("incoming-%s", from.String())
		slog.Debug("unknown peer connecting", "peer_id", peerID, "from", from.String())
	}

	// Check if we already have a connection to this peer
	pm.mu.RLock()
	_, exists := pm.connections[peerID]
	pm.mu.RUnlock()

	if exists {
		slog.Debug("already connected to peer", "peer_id", peerID)
		return
	}

	// Create crypto session for the responder
	crypto, err := NewCryptoSession(pm.localKeyPair.PrivateKey[:])
	if err != nil {
		slog.Debug("failed to create crypto session", "error", err)
		return
	}

	// Process the handshake init and create response
	response, err := crypto.ProcessHandshakeInit(data)
	if err != nil {
		slog.Debug("failed to process handshake init", "error", err)
		return
	}

	// Send response
	remoteAddr := net.UDPAddrFromAddrPort(from)
	if _, err := pm.conn.WriteTo(response, remoteAddr); err != nil {
		slog.Debug("failed to send handshake response", "error", err)
		return
	}

	// Create connection config
	config := ConnectionConfig{
		PeerID:            peerID,
		LocalPrivateKey:   pm.localKeyPair.PrivateKey[:],
		RemotePublicKey:   remotePublicKey,
		ConnectTimeout:    pm.config.ConnectTimeout,
		KeepAliveInterval: pm.config.KeepAliveInterval,
	}

	// Create incoming connection
	conn, err := newIncomingConnection(config, pm.conn, from, crypto)
	if err != nil {
		slog.Debug("failed to create incoming connection", "error", err)
		return
	}

	// Store connection
	pm.mu.Lock()
	pm.connections[peerID] = conn
	pm.endpoints[peerID] = []netip.AddrPort{from}
	pm.mu.Unlock()

	// Notify callback
	if pm.callbacks.OnPeerConnected != nil {
		pm.callbacks.OnPeerConnected(peerID, conn)
	}

	slog.Info("incoming connection established", "peer_id", peerID, "from", from.String())
}

// lookupPeerByKey looks up a peer ID by their public key.
func (pm *P2PManager) lookupPeerByKey(publicKey []byte) string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Check known endpoints to find matching peer
	// This would typically involve a separate registry mapping public keys to peer IDs
	// For now, we rely on the connection being pre-registered
	return ""
}

// newIncomingConnection creates a connection for an incoming request.
func newIncomingConnection(config ConnectionConfig, conn net.PacketConn, remoteAddr netip.AddrPort, crypto *CryptoSession) (*DirectConnection, error) {
	ctx, cancel := context.WithCancel(context.Background())

	localUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	localAddr := netip.AddrPortFrom(
		netip.MustParseAddr(localUDPAddr.IP.String()),
		uint16(localUDPAddr.Port),
	)

	dc := &DirectConnection{
		config:     config,
		conn:       conn,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		crypto:     crypto,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		ctx:        ctx,
		cancel:     cancel,
	}

	dc.state.Store(int32(ConnectionStateConnected))

	// Start workers
	dc.wg.Add(3)
	go dc.sendWorker()
	go dc.recvWorker()
	go dc.keepAliveWorker()

	return dc, nil
}

// handleData handles incoming data for a peer.
func (pm *P2PManager) handleData(peerID string, data []byte) {
	if pm.callbacks.OnData != nil {
		pm.callbacks.OnData(peerID, data)
	}
}

// connectionMonitor monitors connection health.
func (pm *P2PManager) connectionMonitor() {
	defer pm.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.checkConnections()
		}
	}
}

// checkConnections checks the health of all connections.
func (pm *P2PManager) checkConnections() {
	pm.mu.RLock()
	peers := make([]string, 0, len(pm.connections))
	for peerID := range pm.connections {
		peers = append(peers, peerID)
	}
	pm.mu.RUnlock()

	for _, peerID := range peers {
		pm.mu.RLock()
		conn := pm.connections[peerID]
		pm.mu.RUnlock()

		if conn == nil {
			continue
		}

		// Check connection state
		if conn.State() == ConnectionStateFailed || conn.State() == ConnectionStateDisconnected {
			slog.Warn("connection unhealthy, disconnecting", "peer_id", peerID, "state", conn.State().String())
			pm.Disconnect(peerID)
		}
	}
}

// PeerInfo contains information about a connected peer.
type PeerInfo struct {
	PeerID         string
	ConnectionType ConnectionType
	State          ConnectionState
	LocalAddr      netip.AddrPort
	RemoteAddr     netip.AddrPort
	Latency        time.Duration
}

// GetPeerInfo returns information about a connected peer.
func (pm *P2PManager) GetPeerInfo(peerID string) (*PeerInfo, error) {
	pm.mu.RLock()
	conn := pm.connections[peerID]
	pm.mu.RUnlock()

	if conn == nil {
		return nil, ErrPeerNotFound
	}

	return &PeerInfo{
		PeerID:         peerID,
		ConnectionType: conn.Type(),
		State:          conn.State(),
		LocalAddr:      conn.LocalAddr(),
		RemoteAddr:     conn.RemoteAddr(),
		Latency:        conn.Latency(),
	}, nil
}

// GetAllPeerInfo returns information about all connected peers.
func (pm *P2PManager) GetAllPeerInfo() []*PeerInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	infos := make([]*PeerInfo, 0, len(pm.connections))
	for peerID, conn := range pm.connections {
		infos = append(infos, &PeerInfo{
			PeerID:         peerID,
			ConnectionType: conn.Type(),
			State:          conn.State(),
			LocalAddr:      conn.LocalAddr(),
			RemoteAddr:     conn.RemoteAddr(),
			Latency:        conn.Latency(),
		})
	}

	return infos
}

// Stats returns P2P manager statistics.
type Stats struct {
	ActiveConnections  int
	DirectConnections  int
	RelayedConnections int
	NATType            NATType
	LocalEndpoints     []netip.AddrPort
}

// GetStats returns manager statistics.
func (pm *P2PManager) GetStats() Stats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := Stats{
		ActiveConnections: len(pm.connections),
		LocalEndpoints:    pm.LocalEndpoints(),
	}

	for _, conn := range pm.connections {
		switch conn.Type() {
		case ConnectionTypeDirect:
			stats.DirectConnections++
		case ConnectionTypeRelayed, ConnectionTypeMultiHop:
			stats.RelayedConnections++
		}
	}

	if info := pm.natDetector.GetCachedInfo(); info != nil {
		stats.NATType = info.Type
	}

	return stats
}
