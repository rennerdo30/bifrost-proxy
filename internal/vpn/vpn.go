// Package vpn provides TUN-based VPN functionality with split tunneling support.
package vpn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Status represents the current VPN status.
type Status string

const (
	StatusDisabled     Status = "disabled"
	StatusConnecting   Status = "connecting"
	StatusConnected    Status = "connected"
	StatusDisconnected Status = "disconnected"
	StatusError        Status = "error"
)

// VPNStats contains VPN connection statistics.
type VPNStats struct {
	Status            Status        `json:"status"`
	Uptime            time.Duration `json:"uptime"`
	BytesSent         int64         `json:"bytes_sent"`
	BytesReceived     int64         `json:"bytes_received"`
	PacketsSent       int64         `json:"packets_sent"`
	PacketsReceived   int64         `json:"packets_received"`
	ActiveConnections int64         `json:"active_connections"`
	TunneledConns     int64         `json:"tunneled_connections"`
	BypassedConns     int64         `json:"bypassed_connections"`
	DNSQueries        int64         `json:"dns_queries"`
	DNSCacheHits      int64         `json:"dns_cache_hits"`
	LastError         string        `json:"last_error,omitempty"`
	LastErrorTime     time.Time     `json:"last_error_time,omitempty"`
}

// ConnectionInfo contains information about an active VPN connection.
type ConnectionInfo struct {
	ID            string         `json:"id"`
	Protocol      string         `json:"protocol"` // "tcp" or "udp"
	LocalAddr     netip.AddrPort `json:"local_addr"`
	RemoteAddr    netip.AddrPort `json:"remote_addr"`
	RemoteHost    string         `json:"remote_host,omitempty"` // Resolved hostname
	Action        Action         `json:"action"`
	MatchedBy     string         `json:"matched_by"`
	ProcessInfo   *ProcessInfo   `json:"process_info,omitempty"`
	StartTime     time.Time      `json:"start_time"`
	BytesSent     int64          `json:"bytes_sent"`
	BytesReceived int64          `json:"bytes_received"`
}

// ServerConnector defines the interface for tunneling traffic through the proxy server.
type ServerConnector interface {
	// Connect establishes a connection to the target through the proxy server.
	// The target is in the format "host:port".
	Connect(ctx context.Context, target string) (net.Conn, error)
}

// Manager manages the VPN lifecycle and packet routing.
type Manager struct {
	config        Config
	tun           TUNDevice
	connTracker   *ConnTracker
	splitEngine   *SplitTunnelEngine
	dnsServer     *DNSServer
	dnsCache      *DNSCache
	routeManager  RouteManager
	processLookup ProcessLookup
	serverConn    ServerConnector
	udpRelay      *UDPRelay

	status    atomic.Value // Status
	startTime time.Time

	// Statistics
	bytesSent       atomic.Int64
	bytesReceived   atomic.Int64
	packetsSent     atomic.Int64
	packetsReceived atomic.Int64
	tunneledConns   atomic.Int64
	bypassedConns   atomic.Int64
	lastError       atomic.Value // string
	lastErrorTime   atomic.Value // time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// ManagerOption configures the VPN manager.
type ManagerOption func(*Manager)

// WithServerConnector sets the server connector for tunneling traffic.
func WithServerConnector(sc ServerConnector) ManagerOption {
	return func(m *Manager) {
		m.serverConn = sc
	}
}

// WithLogger sets a custom logger (not used currently, uses slog).
func WithLogger(logger *slog.Logger) ManagerOption {
	return func(m *Manager) {
		// Reserved for future use
	}
}

// New creates a new VPN manager.
func New(cfg Config) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid VPN config: %w", err)
	}

	m := &Manager{
		config: cfg,
	}
	m.status.Store(StatusDisabled)

	return m, nil
}

// Configure applies options to the manager.
func (m *Manager) Configure(opts ...ManagerOption) {
	for _, opt := range opts {
		opt(m)
	}
}

// Start initializes and starts the VPN.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.Load().(Status) == StatusConnected {
		return errors.New("VPN already running")
	}

	m.status.Store(StatusConnecting)

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Initialize DNS cache
	m.dnsCache = NewDNSCache(m.config.DNS.CacheTTL)

	// Initialize split tunnel engine
	var err error
	m.splitEngine, err = NewSplitTunnelEngine(m.config.SplitTunnel, m.dnsCache)
	if err != nil {
		m.status.Store(StatusError)
		m.setError(err)
		return fmt.Errorf("failed to create split tunnel engine: %w", err)
	}

	// Initialize process lookup
	m.processLookup = NewProcessLookup()

	// Initialize connection tracker
	m.connTracker = NewConnTracker()

	// Create TUN device
	m.tun, err = CreateTUN(m.config.TUN)
	if err != nil {
		m.status.Store(StatusError)
		m.setError(err)
		return fmt.Errorf("failed to create TUN device: %w", err)
	}

	slog.Info("TUN device created",
		"name", m.tun.Name(),
		"mtu", m.tun.MTU(),
	)

	// Initialize UDP relay for UDP packet forwarding
	tunAddr, err := netip.ParsePrefix(m.config.TUN.Address)
	if err == nil {
		udpCfg := UDPRelayConfig{
			TUNAddr:     tunAddr.Addr(),
			IdleTimeout: 30 * time.Second,
		}
		m.udpRelay, err = NewUDPRelay(udpCfg, m.tun)
		if err != nil {
			slog.Warn("failed to create UDP relay, UDP tunneling disabled", "error", err)
		} else {
			m.udpRelay.Start()
			slog.Info("UDP relay started")
		}
	}

	// Initialize route manager and set up routes
	m.routeManager = NewRouteManager()
	if err := m.routeManager.Setup(ctx, m.tun.Name(), m.config); err != nil {
		m.cleanup()
		m.status.Store(StatusError)
		m.setError(err)
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	// Start DNS server if enabled
	if m.config.DNS.Enabled {
		m.dnsServer = NewDNSServer(m.config.DNS, m.dnsCache, m.splitEngine)
		if err := m.dnsServer.Start(m.ctx); err != nil {
			m.cleanup()
			m.status.Store(StatusError)
			m.setError(err)
			return fmt.Errorf("failed to start DNS server: %w", err)
		}
		slog.Info("DNS server started", "listen", m.config.DNS.Listen)
	}

	// Start packet processing
	m.wg.Add(1)
	go m.processPackets()

	m.startTime = time.Now()
	m.status.Store(StatusConnected)

	slog.Info("VPN started",
		"tun", m.tun.Name(),
		"address", m.config.TUN.Address,
	)

	return nil
}

// Stop shuts down the VPN.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.Load().(Status) != StatusConnected {
		return nil
	}

	slog.Info("stopping VPN")

	// Signal shutdown
	if m.cancel != nil {
		m.cancel()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("VPN shutdown timeout, forcing cleanup")
	}

	m.cleanup()
	m.status.Store(StatusDisconnected)

	slog.Info("VPN stopped")
	return nil
}

// cleanup releases all resources.
func (m *Manager) cleanup() {
	// Stop UDP relay
	if m.udpRelay != nil {
		m.udpRelay.Stop()
		m.udpRelay = nil
	}

	// Stop DNS server
	if m.dnsServer != nil {
		if err := m.dnsServer.Stop(); err != nil {
			slog.Error("failed to stop DNS server", "error", err)
		}
		m.dnsServer = nil
	}

	// Close DNS cache
	if m.dnsCache != nil {
		m.dnsCache.Close()
		m.dnsCache = nil
	}

	// Restore routes
	if m.routeManager != nil {
		if err := m.routeManager.Cleanup(context.Background()); err != nil {
			slog.Error("failed to cleanup routes", "error", err)
		}
		m.routeManager = nil
	}

	// Close TUN device
	if m.tun != nil {
		if err := m.tun.Close(); err != nil {
			slog.Error("failed to close TUN device", "error", err)
		}
		m.tun = nil
	}

	// Close connection tracker
	if m.connTracker != nil {
		m.connTracker.Close()
		m.connTracker = nil
	}
}

// processPackets reads packets from TUN and processes them.
func (m *Manager) processPackets() {
	defer m.wg.Done()

	buf := make([]byte, m.config.TUN.MTU+100) // Extra space for headers

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		n, err := m.tun.Read(buf)
		if err != nil {
			if m.ctx.Err() != nil {
				return // Context cancelled
			}
			slog.Error("failed to read from TUN", "error", err)
			m.setError(err)
			continue
		}

		m.packetsReceived.Add(1)
		m.bytesReceived.Add(int64(n))

		packet, err := ParseIPPacket(buf[:n])
		if err != nil {
			slog.Debug("failed to parse IP packet", "error", err)
			continue
		}

		m.handlePacket(packet)
	}
}

// handlePacket processes a single IP packet.
func (m *Manager) handlePacket(packet *IPPacket) {
	// Look up process info for the connection
	var procInfo *ProcessInfo
	if m.processLookup != nil && (packet.Protocol == ProtocolTCP || packet.Protocol == ProtocolUDP) {
		local := netip.AddrPortFrom(packet.SrcIP, packet.SrcPort)
		remote := netip.AddrPortFrom(packet.DstIP, packet.DstPort)
		proto := "tcp"
		if packet.Protocol == ProtocolUDP {
			proto = "udp"
		}
		procInfo, _ = m.processLookup.LookupBySocket(local, remote, proto)
	}

	// Make split tunnel decision
	decision := m.splitEngine.Decide(packet, procInfo)

	switch decision.Action {
	case ActionBypass:
		m.bypassedConns.Add(1)
		m.handleBypassPacket(packet, decision)
	case ActionTunnel:
		m.tunneledConns.Add(1)
		m.handleTunnelPacket(packet, decision)
	}
}

// handleBypassPacket handles packets that should bypass the VPN.
func (m *Manager) handleBypassPacket(packet *IPPacket, decision Decision) {
	// For bypass, we inject the packet directly to the network stack
	// This requires sending through the original interface, not TUN
	slog.Debug("bypassing packet",
		"dst", packet.DstIP,
		"port", packet.DstPort,
		"reason", decision.Reason,
		"matched_by", decision.MatchedBy,
	)

	// The actual bypass is handled by not routing this packet through the tunnel
	// On most systems, we need to use policy-based routing or mark packets
	// For now, we'll rely on the route manager to set up proper bypass routes
}

// handleTunnelPacket handles packets that should go through the VPN tunnel.
func (m *Manager) handleTunnelPacket(packet *IPPacket, decision Decision) {
	if m.serverConn == nil {
		slog.Debug("no server connector configured, dropping packet")
		return
	}

	slog.Debug("tunneling packet",
		"dst", packet.DstIP,
		"port", packet.DstPort,
		"proto", packet.Protocol,
	)

	// For TCP connections, we need to establish a connection through the proxy
	// For UDP, we need different handling
	switch packet.Protocol {
	case ProtocolTCP:
		m.handleTCPPacket(packet)
	case ProtocolUDP:
		m.handleUDPPacket(packet)
	default:
		// Drop other protocols
		slog.Debug("dropping unsupported protocol", "protocol", packet.Protocol)
	}
}

// handleTCPPacket handles TCP packets by establishing proxy connections.
func (m *Manager) handleTCPPacket(packet *IPPacket) {
	// Check if this is part of an existing connection
	connKey := ConnKey{
		SrcIP:    packet.SrcIP,
		DstIP:    packet.DstIP,
		SrcPort:  packet.SrcPort,
		DstPort:  packet.DstPort,
		Protocol: packet.Protocol,
	}

	conn := m.connTracker.Get(connKey)
	if conn != nil {
		// If this is a retransmitted SYN, re-send SYN-ACK
		if packet.IsSYN() {
			m.sendTCPSynAck(conn, packet)
			return
		}

		// Forward packet on existing connection
		m.forwardOnConnection(conn, packet)
		return
	}

	// Check if this is a SYN packet (new connection)
	if !packet.IsSYN() {
		// Not a SYN packet, ignore
		return
	}

	// Create new connection through proxy
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.establishProxyConnection(packet)
	}()
}

// establishProxyConnection establishes a TCP connection through the proxy.
func (m *Manager) establishProxyConnection(packet *IPPacket) {
	target := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	proxyConn, err := m.serverConn.Connect(ctx, target)
	if err != nil {
		slog.Error("failed to connect through proxy",
			"target", target,
			"error", err,
		)
		m.setError(err)
		return
	}

	// Create tracked connection
	serverISN := randomISN()
	clientNext := advanceTCPSeq(packet.SeqNum, len(packet.Payload), packet.TCPFlags)
	tcpState := &TCPState{
		ClientISN:  packet.SeqNum,
		ServerISN:  serverISN,
		ClientNext: clientNext,
		ServerNext: serverISN + 1,
	}

	trackedConn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    packet.SrcIP,
			DstIP:    packet.DstIP,
			SrcPort:  packet.SrcPort,
			DstPort:  packet.DstPort,
			Protocol: ProtocolTCP,
		},
		ProxyConn: proxyConn,
		Created:   time.Now(),
		TCP:       tcpState,
	}

	m.connTracker.Add(trackedConn)

	slog.Debug("established proxy connection",
		"target", target,
		"local", fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort),
	)

	// Send SYN-ACK back to the client to complete handshake
	m.sendTCPSynAck(trackedConn, packet)

	// Handle bidirectional data flow
	m.handleConnectionData(trackedConn)
}

// handleConnectionData handles bidirectional data flow for a tracked connection.
func (m *Manager) handleConnectionData(conn *TrackedConnection) {
	// This is a simplified implementation
	// In a full implementation, we would:
	// 1. Reassemble TCP segments from TUN
	// 2. Forward data to proxy connection
	// 3. Read responses from proxy
	// 4. Create response packets and write to TUN

	// Cleanup function to remove connection from tracker
	cleanup := func() {
		if conn.ProxyConn != nil {
			conn.ProxyConn.Close()
		}
		m.connTracker.Remove(conn.Key)
	}

	// Set connection timeout to prevent indefinite blocking
	if conn.ProxyConn != nil {
		conn.ProxyConn.SetDeadline(time.Now().Add(5 * time.Minute))
	}

	// Monitor context for shutdown
	go func() {
		<-m.ctx.Done()
		cleanup()
	}()

	// Also start a goroutine to read from the proxy connection
	// and handle errors (connection closed, timeouts, etc.)
	go func() {
		if conn.ProxyConn == nil {
			return
		}

		buf := make([]byte, 4096)
		for {
			// Check if context is done
			select {
			case <-m.ctx.Done():
				return
			default:
			}

			// Set read deadline for each read to allow checking context
			conn.ProxyConn.SetReadDeadline(time.Now().Add(30 * time.Second))

			n, err := conn.ProxyConn.Read(buf)
			if n > 0 {
				// Update activity and bytes received
				conn.LastActivity = time.Now()
				conn.BytesReceived.Add(int64(n))

				if writeErr := m.sendTCPData(conn, buf[:n]); writeErr != nil {
					slog.Debug("failed to write TCP response to TUN",
						"key", conn.Key,
						"error", writeErr,
					)
					cleanup()
					return
				}
			}

			if err != nil {
				// Connection closed or error - clean up
				if m.ctx.Err() == nil {
					// Only log if not shutting down
					slog.Debug("proxy connection read error, cleaning up",
						"key", conn.Key,
						"error", err,
					)
				}

				if errors.Is(err, io.EOF) {
					m.sendTCPFin(conn)
				} else {
					m.sendTCPRst(conn)
				}
				cleanup()
				return
			}
		}
	}()
}

// handleUDPPacket handles UDP packets.
func (m *Manager) handleUDPPacket(packet *IPPacket) {
	// Check if UDP relay is available
	if m.udpRelay == nil {
		slog.Debug("UDP relay not initialized, dropping packet",
			"dst", packet.DstIP,
			"port", packet.DstPort,
		)
		return
	}

	// Forward the UDP packet through the relay
	if err := m.udpRelay.HandlePacket(packet); err != nil {
		slog.Debug("failed to handle UDP packet",
			"dst", packet.DstIP,
			"port", packet.DstPort,
			"error", err,
		)
	}
}

// forwardOnConnection forwards a packet on an existing connection.
func (m *Manager) forwardOnConnection(conn *TrackedConnection, packet *IPPacket) {
	if conn == nil || conn.ProxyConn == nil {
		return
	}

	if packet.IsRST() {
		m.connTracker.Remove(conn.Key)
		conn.ProxyConn.Close()
		return
	}

	m.updateTCPClientState(conn, packet)

	if packet.IsFIN() {
		m.sendTCPFin(conn)
		m.connTracker.Remove(conn.Key)
		conn.ProxyConn.Close()
		return
	}

	if len(packet.Payload) == 0 {
		return
	}

	n, err := conn.ProxyConn.Write(packet.Payload)
	if err != nil {
		slog.Error("failed to forward on connection", "error", err)
		m.connTracker.Remove(conn.Key)
		conn.ProxyConn.Close()
		m.sendTCPRst(conn)
		return
	}

	conn.BytesSent.Add(int64(n))
	conn.LastActivity = time.Now()
	m.sendTCPAck(conn)
}

func (m *Manager) updateTCPClientState(conn *TrackedConnection, packet *IPPacket) {
	if conn == nil || conn.TCP == nil {
		return
	}

	state := conn.TCP
	state.mu.Lock()
	defer state.mu.Unlock()

	next := advanceTCPSeq(packet.SeqNum, len(packet.Payload), packet.TCPFlags)
	if state.ClientNext == 0 || tcpSeqAfter(next, state.ClientNext) {
		state.ClientNext = next
	}

	if !state.Established && (packet.TCPFlags&TCPFlagACK != 0) {
		if packet.AckNum == state.ServerISN+1 || packet.AckNum == state.ServerNext {
			state.Established = true
			conn.State = ConnStateEstablished
		}
	}
}

func (m *Manager) sendTCPSynAck(conn *TrackedConnection, packet *IPPacket) {
	if conn == nil || conn.TCP == nil {
		return
	}

	state := conn.TCP
	state.mu.Lock()
	next := advanceTCPSeq(packet.SeqNum, len(packet.Payload), packet.TCPFlags)
	if state.ClientNext == 0 || tcpSeqAfter(next, state.ClientNext) {
		state.ClientNext = next
	}
	seq := state.ServerISN
	ack := state.ClientNext
	state.mu.Unlock()

	if err := m.writeTCPPacket(conn, seq, ack, TCPFlagSYN|TCPFlagACK, nil); err != nil {
		slog.Debug("failed to send SYN-ACK", "error", err)
	}
}

func (m *Manager) sendTCPAck(conn *TrackedConnection) {
	if conn == nil || conn.TCP == nil {
		return
	}

	state := conn.TCP
	state.mu.Lock()
	seq := state.ServerNext
	ack := state.ClientNext
	state.mu.Unlock()

	if err := m.writeTCPPacket(conn, seq, ack, TCPFlagACK, nil); err != nil {
		slog.Debug("failed to send TCP ACK", "error", err)
	}
}

func (m *Manager) sendTCPFin(conn *TrackedConnection) {
	if conn == nil || conn.TCP == nil {
		return
	}

	state := conn.TCP
	state.mu.Lock()
	seq := state.ServerNext
	ack := state.ClientNext
	state.ServerNext++
	state.mu.Unlock()

	if err := m.writeTCPPacket(conn, seq, ack, TCPFlagFIN|TCPFlagACK, nil); err != nil {
		slog.Debug("failed to send TCP FIN", "error", err)
	}
}

func (m *Manager) sendTCPRst(conn *TrackedConnection) {
	if conn == nil || conn.TCP == nil {
		return
	}

	state := conn.TCP
	state.mu.Lock()
	seq := state.ServerNext
	ack := state.ClientNext
	state.mu.Unlock()

	if err := m.writeTCPPacket(conn, seq, ack, TCPFlagRST|TCPFlagACK, nil); err != nil {
		slog.Debug("failed to send TCP RST", "error", err)
	}
}

func (m *Manager) sendTCPData(conn *TrackedConnection, payload []byte) error {
	if conn == nil || conn.TCP == nil {
		return nil
	}
	if len(payload) == 0 {
		return nil
	}

	maxPayload := m.tcpMaxPayload(conn.Key.DstIP)
	if maxPayload <= 0 {
		maxPayload = len(payload)
	}

	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxPayload {
			chunk = payload[:maxPayload]
		}

		state := conn.TCP
		state.mu.Lock()
		seq := state.ServerNext
		ack := state.ClientNext
		state.ServerNext += uint32(len(chunk))
		state.mu.Unlock()

		flags := uint8(TCPFlagACK | TCPFlagPSH)
		if err := m.writeTCPPacket(conn, seq, ack, flags, chunk); err != nil {
			return err
		}

		payload = payload[len(chunk):]
	}

	return nil
}

func (m *Manager) tcpMaxPayload(dstIP netip.Addr) int {
	mtu := 1400
	if m.tun != nil && m.tun.MTU() > 0 {
		mtu = m.tun.MTU()
	}

	headerLen := 20 + 20
	if !dstIP.Is4() {
		headerLen = 40 + 20
	}

	maxPayload := mtu - headerLen
	if maxPayload < 1 {
		return 1
	}
	return maxPayload
}

func (m *Manager) writeTCPPacket(conn *TrackedConnection, seq, ack uint32, flags uint8, payload []byte) error {
	if m.tun == nil {
		return errors.New("TUN device not initialized")
	}

	srcIP := conn.Key.DstIP
	dstIP := conn.Key.SrcIP
	srcPort := conn.Key.DstPort
	dstPort := conn.Key.SrcPort

	packet := BuildTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, 65535, payload)
	n, err := m.tun.Write(packet)
	if err != nil {
		return err
	}

	m.packetsSent.Add(1)
	m.bytesSent.Add(int64(n))
	return nil
}

func advanceTCPSeq(seq uint32, payloadLen int, flags uint8) uint32 {
	next := seq + uint32(payloadLen)
	if flags&TCPFlagSYN != 0 {
		next++
	}
	if flags&TCPFlagFIN != 0 {
		next++
	}
	return next
}

func tcpSeqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

func randomISN() uint32 {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return binary.BigEndian.Uint32(buf[:])
	}
	return uint32(time.Now().UnixNano())
}

// Status returns the current VPN status and statistics.
func (m *Manager) Status() VPNStats {
	if m == nil {
		return VPNStats{Status: StatusDisabled}
	}
	status := m.status.Load().(Status)

	var uptime time.Duration
	if status == StatusConnected {
		uptime = time.Since(m.startTime)
	}

	var lastErr string
	if e := m.lastError.Load(); e != nil {
		lastErr = e.(string)
	}

	var lastErrTime time.Time
	if t := m.lastErrorTime.Load(); t != nil {
		lastErrTime = t.(time.Time)
	}

	var activeConns int64
	if m.connTracker != nil {
		activeConns = int64(m.connTracker.Count())
	}

	var dnsQueries, dnsCacheHits int64
	if m.dnsServer != nil {
		stats := m.dnsServer.Stats()
		dnsQueries = stats.TotalQueries
		dnsCacheHits = stats.CacheHits
	}

	return VPNStats{
		Status:            status,
		Uptime:            uptime,
		BytesSent:         m.bytesSent.Load(),
		BytesReceived:     m.bytesReceived.Load(),
		PacketsSent:       m.packetsSent.Load(),
		PacketsReceived:   m.packetsReceived.Load(),
		ActiveConnections: activeConns,
		TunneledConns:     m.tunneledConns.Load(),
		BypassedConns:     m.bypassedConns.Load(),
		DNSQueries:        dnsQueries,
		DNSCacheHits:      dnsCacheHits,
		LastError:         lastErr,
		LastErrorTime:     lastErrTime,
	}
}

// Connections returns information about active VPN connections.
func (m *Manager) Connections() []ConnectionInfo {
	if m == nil || m.connTracker == nil {
		return nil
	}

	tracked := m.connTracker.All()
	result := make([]ConnectionInfo, 0, len(tracked))

	for _, conn := range tracked {
		proto := "tcp"
		if conn.Key.Protocol == ProtocolUDP {
			proto = "udp"
		}

		result = append(result, ConnectionInfo{
			ID:            fmt.Sprintf("%s-%d-%s-%d", conn.Key.SrcIP, conn.Key.SrcPort, conn.Key.DstIP, conn.Key.DstPort),
			Protocol:      proto,
			LocalAddr:     netip.AddrPortFrom(conn.Key.SrcIP, conn.Key.SrcPort),
			RemoteAddr:    netip.AddrPortFrom(conn.Key.DstIP, conn.Key.DstPort),
			StartTime:     conn.Created,
			BytesSent:     conn.BytesSent.Load(),
			BytesReceived: conn.BytesReceived.Load(),
		})
	}

	return result
}

// Enabled returns whether VPN is enabled in configuration.
func (m *Manager) Enabled() bool {
	return m.config.Enabled
}

// SplitTunnelRules returns the current split tunnel rules.
func (m *Manager) SplitTunnelRules() SplitTunnelConfig {
	if m == nil {
		return SplitTunnelConfig{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.SplitTunnel
}

// AddSplitTunnelApp adds an app to the split tunnel rules.
func (m *Manager) AddSplitTunnelApp(app AppRule) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicates
	for _, existing := range m.config.SplitTunnel.Apps {
		if existing.Name == app.Name {
			return fmt.Errorf("app %q already exists in split tunnel rules", app.Name)
		}
	}

	m.config.SplitTunnel.Apps = append(m.config.SplitTunnel.Apps, app)

	if m.splitEngine != nil {
		m.splitEngine.AddApp(app)
	}

	return nil
}

// RemoveSplitTunnelApp removes an app from the split tunnel rules.
func (m *Manager) RemoveSplitTunnelApp(name string) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false
	apps := make([]AppRule, 0, len(m.config.SplitTunnel.Apps))
	for _, app := range m.config.SplitTunnel.Apps {
		if app.Name == name {
			found = true
			continue
		}
		apps = append(apps, app)
	}

	if !found {
		return fmt.Errorf("app %q not found in split tunnel rules", name)
	}

	m.config.SplitTunnel.Apps = apps

	if m.splitEngine != nil {
		m.splitEngine.RemoveApp(name)
	}

	return nil
}

// AddSplitTunnelDomain adds a domain pattern to the split tunnel rules.
func (m *Manager) AddSplitTunnelDomain(pattern string) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicates
	for _, existing := range m.config.SplitTunnel.Domains {
		if existing == pattern {
			return fmt.Errorf("domain pattern %q already exists in split tunnel rules", pattern)
		}
	}

	m.config.SplitTunnel.Domains = append(m.config.SplitTunnel.Domains, pattern)

	if m.splitEngine != nil {
		m.splitEngine.AddDomain(pattern)
	}

	return nil
}

// AddSplitTunnelIP adds an IP/CIDR to the split tunnel rules.
func (m *Manager) AddSplitTunnelIP(cidr string) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP or CIDR: %s", cidr)
		}
	}

	// Check for duplicates
	for _, existing := range m.config.SplitTunnel.IPs {
		if existing == cidr {
			return fmt.Errorf("IP/CIDR %q already exists in split tunnel rules", cidr)
		}
	}

	m.config.SplitTunnel.IPs = append(m.config.SplitTunnel.IPs, cidr)

	if m.splitEngine != nil {
		m.splitEngine.AddIP(cidr)
	}

	return nil
}

// RemoveSplitTunnelDomain removes a domain pattern from the split tunnel rules.
func (m *Manager) RemoveSplitTunnelDomain(pattern string) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false
	domains := make([]string, 0, len(m.config.SplitTunnel.Domains))
	for _, domain := range m.config.SplitTunnel.Domains {
		if domain == pattern {
			found = true
			continue
		}
		domains = append(domains, domain)
	}

	if !found {
		return fmt.Errorf("domain pattern %q not found in split tunnel rules", pattern)
	}

	m.config.SplitTunnel.Domains = domains

	if m.splitEngine != nil {
		m.splitEngine.RemoveDomain(pattern)
	}

	return nil
}

// RemoveSplitTunnelIP removes an IP/CIDR from the split tunnel rules.
func (m *Manager) RemoveSplitTunnelIP(cidr string) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false
	ips := make([]string, 0, len(m.config.SplitTunnel.IPs))
	for _, ip := range m.config.SplitTunnel.IPs {
		if ip == cidr {
			found = true
			continue
		}
		ips = append(ips, ip)
	}

	if !found {
		return fmt.Errorf("IP/CIDR %q not found in split tunnel rules", cidr)
	}

	m.config.SplitTunnel.IPs = ips

	if m.splitEngine != nil {
		m.splitEngine.RemoveIP(cidr)
	}

	return nil
}

// SetSplitTunnelMode sets the split tunnel mode ("exclude" or "include").
func (m *Manager) SetSplitTunnelMode(mode string) error {
	if m == nil {
		return errors.New("VPN manager not initialized")
	}

	if mode != "exclude" && mode != "include" {
		return fmt.Errorf("invalid mode %q: must be 'exclude' or 'include'", mode)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.SplitTunnel.Mode = mode

	if m.splitEngine != nil {
		m.splitEngine.SetMode(mode)
	}

	return nil
}

// setError records an error.
func (m *Manager) setError(err error) {
	m.lastError.Store(err.Error())
	m.lastErrorTime.Store(time.Now())
}
