package vpn

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// UDPRelay handles UDP packet forwarding through the VPN.
type UDPRelay struct {
	// UDP socket for sending/receiving packets
	conn *net.UDPConn

	// Mapping of local port to remote destination
	sessions   map[uint16]*UDPSession
	sessionsMu sync.RWMutex

	// NAT table for port mapping
	nat *NATTable

	// TUN device for writing response packets
	tun TUNDevice

	// Local TUN address
	tunAddr netip.Addr

	// Configuration
	idleTimeout time.Duration

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// UDPSession represents an active UDP session.
type UDPSession struct {
	// Original source from the TUN
	OriginalSrc netip.AddrPort
	// Remote destination
	Destination netip.AddrPort
	// Local port used for this session
	LocalPort uint16
	// Creation time
	Created time.Time
	// Last activity
	LastActivity time.Time
	// Bytes sent/received
	BytesSent     int64
	BytesReceived int64
}

// UDPRelayConfig holds configuration for the UDP relay.
type UDPRelayConfig struct {
	// ListenAddr is the address to listen on for UDP relay
	// Default: "0.0.0.0:0" (random port)
	ListenAddr string
	// IdleTimeout is how long to keep idle sessions
	// Default: 30 seconds
	IdleTimeout time.Duration
	// TUNAddr is the TUN interface address
	TUNAddr netip.Addr
}

// DefaultUDPRelayConfig returns the default configuration.
func DefaultUDPRelayConfig() UDPRelayConfig {
	return UDPRelayConfig{
		ListenAddr:  "0.0.0.0:0",
		IdleTimeout: 30 * time.Second,
	}
}

// NewUDPRelay creates a new UDP relay.
func NewUDPRelay(cfg UDPRelayConfig, tun TUNDevice) (*UDPRelay, error) {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:0"
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	relay := &UDPRelay{
		conn:        conn,
		sessions:    make(map[uint16]*UDPSession),
		nat:         NewNATTable(cfg.TUNAddr, 10000, 60000),
		tun:         tun,
		tunAddr:     cfg.TUNAddr,
		idleTimeout: cfg.IdleTimeout,
		ctx:         ctx,
		cancel:      cancel,
	}

	return relay, nil
}

// Start starts the UDP relay.
func (r *UDPRelay) Start() {
	r.wg.Add(2)
	go r.readLoop()
	go r.cleanupLoop()
}

// Stop stops the UDP relay.
func (r *UDPRelay) Stop() {
	r.cancel()
	r.conn.Close()
	r.wg.Wait()
}

// HandlePacket handles an outgoing UDP packet from the TUN.
func (r *UDPRelay) HandlePacket(packet *IPPacket) error {
	if packet.Protocol != ProtocolUDP {
		return nil
	}

	src := netip.AddrPortFrom(packet.SrcIP, packet.SrcPort)
	dst := netip.AddrPortFrom(packet.DstIP, packet.DstPort)

	// Get or create session
	session := r.getOrCreateSession(src, dst)
	if session == nil {
		slog.Debug("failed to create UDP session",
			"src", src,
			"dst", dst,
		)
		return nil
	}

	// Forward the packet
	destAddr := net.UDPAddrFromAddrPort(dst)
	n, err := r.conn.WriteToUDP(packet.Payload, destAddr)
	if err != nil {
		slog.Debug("failed to forward UDP packet",
			"dst", dst,
			"error", err,
		)
		return err
	}

	session.BytesSent += int64(n)
	session.LastActivity = time.Now()

	slog.Debug("forwarded UDP packet",
		"src", src,
		"dst", dst,
		"bytes", n,
	)

	return nil
}

// getOrCreateSession gets an existing session or creates a new one.
func (r *UDPRelay) getOrCreateSession(src, dst netip.AddrPort) *UDPSession {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	// Look for existing session by source
	for _, session := range r.sessions {
		if session.OriginalSrc == src && session.Destination == dst {
			return session
		}
	}

	// Allocate NAT entry for the new session
	entry, err := r.nat.Allocate(src, dst, ProtocolUDP)
	if err != nil {
		slog.Error("failed to allocate NAT entry for UDP", "error", err)
		return nil
	}

	session := &UDPSession{
		OriginalSrc:  src,
		Destination:  dst,
		LocalPort:    entry.MappedSrc.Port(),
		Created:      time.Now(),
		LastActivity: time.Now(),
	}

	r.sessions[session.LocalPort] = session
	return session
}

// readLoop reads responses from the UDP socket and writes them back to the TUN.
func (r *UDPRelay) readLoop() {
	defer r.wg.Done()

	buf := make([]byte, 65535)

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		// Set read deadline to allow checking context
		r.conn.SetReadDeadline(time.Now().Add(time.Second))

		n, remoteAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if r.ctx.Err() != nil {
				return
			}
			slog.Debug("UDP read error", "error", err)
			continue
		}

		// Find the session for this response
		session := r.findSessionByRemote(remoteAddr)
		if session == nil {
			slog.Debug("received UDP packet for unknown session",
				"remote", remoteAddr,
			)
			continue
		}

		session.BytesReceived += int64(n)
		session.LastActivity = time.Now()

		// Build response packet and write to TUN
		responsePacket := r.buildResponsePacket(session, buf[:n])
		if responsePacket != nil {
			if _, err := r.tun.Write(responsePacket); err != nil {
				slog.Debug("failed to write UDP response to TUN", "error", err)
			}
		}
	}
}

// findSessionByRemote finds a session by the remote address.
func (r *UDPRelay) findSessionByRemote(remote *net.UDPAddr) *UDPSession {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()

	remoteAddrPort := remote.AddrPort()
	// Unmap IPv4-mapped IPv6 addresses for comparison
	remoteAddr := remoteAddrPort.Addr().Unmap()
	remotePort := remoteAddrPort.Port()

	for _, session := range r.sessions {
		sessionAddr := session.Destination.Addr().Unmap()
		if sessionAddr == remoteAddr && session.Destination.Port() == remotePort {
			return session
		}
	}
	return nil
}

// buildResponsePacket builds an IP packet for the response.
func (r *UDPRelay) buildResponsePacket(session *UDPSession, payload []byte) []byte {
	srcIP := session.Destination.Addr()
	dstIP := session.OriginalSrc.Addr()
	srcPort := session.Destination.Port()
	dstPort := session.OriginalSrc.Port()

	if srcIP.Is4() {
		return buildIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, payload)
	}
	return buildIPv6UDPPacket(srcIP, dstIP, srcPort, dstPort, payload)
}

// buildIPv4UDPPacket builds an IPv4 UDP packet.
func buildIPv4UDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	// IPv4 header (20 bytes) + UDP header (8 bytes) + payload
	totalLen := 20 + 8 + len(payload)
	packet := make([]byte, totalLen)

	// IPv4 header
	packet[0] = 0x45                              // Version (4) + IHL (5)
	packet[1] = 0                                 // DSCP + ECN
	packet[2] = byte(totalLen >> 8)               // Total length
	packet[3] = byte(totalLen)
	packet[4] = 0                                 // Identification
	packet[5] = 0
	packet[6] = 0x40                              // Flags (Don't Fragment) + Fragment offset
	packet[7] = 0
	packet[8] = 64                                // TTL
	packet[9] = ProtocolUDP                       // Protocol
	packet[10] = 0                                // Header checksum (calculated below)
	packet[11] = 0

	src4 := srcIP.As4()
	dst4 := dstIP.As4()
	copy(packet[12:16], src4[:])                  // Source IP
	copy(packet[16:20], dst4[:])                  // Destination IP

	// Calculate IP header checksum
	checksum := ipChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)

	// UDP header
	udpOffset := 20
	packet[udpOffset] = byte(srcPort >> 8)        // Source port
	packet[udpOffset+1] = byte(srcPort)
	packet[udpOffset+2] = byte(dstPort >> 8)      // Destination port
	packet[udpOffset+3] = byte(dstPort)
	udpLen := 8 + len(payload)
	packet[udpOffset+4] = byte(udpLen >> 8)       // UDP length
	packet[udpOffset+5] = byte(udpLen)
	packet[udpOffset+6] = 0                       // Checksum (optional for IPv4)
	packet[udpOffset+7] = 0

	// Payload
	copy(packet[28:], payload)

	return packet
}

// buildIPv6UDPPacket builds an IPv6 UDP packet.
func buildIPv6UDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	// IPv6 header (40 bytes) + UDP header (8 bytes) + payload
	totalLen := 40 + 8 + len(payload)
	packet := make([]byte, totalLen)

	// IPv6 header
	packet[0] = 0x60                              // Version (6) + Traffic class
	packet[1] = 0
	packet[2] = 0
	packet[3] = 0                                 // Flow label
	payloadLen := 8 + len(payload)
	packet[4] = byte(payloadLen >> 8)             // Payload length
	packet[5] = byte(payloadLen)
	packet[6] = ProtocolUDP                       // Next header (UDP)
	packet[7] = 64                                // Hop limit

	src6 := srcIP.As16()
	dst6 := dstIP.As16()
	copy(packet[8:24], src6[:])                   // Source IP
	copy(packet[24:40], dst6[:])                  // Destination IP

	// UDP header
	udpOffset := 40
	packet[udpOffset] = byte(srcPort >> 8)        // Source port
	packet[udpOffset+1] = byte(srcPort)
	packet[udpOffset+2] = byte(dstPort >> 8)      // Destination port
	packet[udpOffset+3] = byte(dstPort)
	udpLen := 8 + len(payload)
	packet[udpOffset+4] = byte(udpLen >> 8)       // UDP length
	packet[udpOffset+5] = byte(udpLen)

	// Calculate UDP checksum (required for IPv6)
	udpChecksum := udpIPv6Checksum(src6[:], dst6[:], packet[udpOffset:udpOffset+8], payload)
	packet[udpOffset+6] = byte(udpChecksum >> 8)
	packet[udpOffset+7] = byte(udpChecksum)

	// Payload
	copy(packet[48:], payload)

	return packet
}

// ipChecksum calculates the IP header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32

	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}

	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// udpIPv6Checksum calculates UDP checksum for IPv6.
func udpIPv6Checksum(srcIP, dstIP, udpHeader, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}

	// UDP length
	udpLen := len(udpHeader) + len(payload)
	sum += uint32(udpLen)

	// Next header (UDP = 17)
	sum += uint32(ProtocolUDP)

	// UDP header (skip checksum field)
	sum += uint32(udpHeader[0])<<8 | uint32(udpHeader[1]) // src port
	sum += uint32(udpHeader[2])<<8 | uint32(udpHeader[3]) // dst port
	sum += uint32(udpHeader[4])<<8 | uint32(udpHeader[5]) // length

	// Payload
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	// Fold to 16 bits
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xffff
	}

	return checksum
}

// cleanupLoop periodically removes idle sessions.
func (r *UDPRelay) cleanupLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.cleanupIdleSessions()
		}
	}
}

// cleanupIdleSessions removes sessions that have been idle too long.
func (r *UDPRelay) cleanupIdleSessions() {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	now := time.Now()
	for port, session := range r.sessions {
		if now.Sub(session.LastActivity) > r.idleTimeout {
			// Release NAT entry
			r.nat.Release(session.OriginalSrc, session.Destination, ProtocolUDP)
			delete(r.sessions, port)

			slog.Debug("cleaned up idle UDP session",
				"src", session.OriginalSrc,
				"dst", session.Destination,
			)
		}
	}
}

// Stats returns UDP relay statistics.
func (r *UDPRelay) Stats() UDPRelayStats {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()

	stats := UDPRelayStats{
		ActiveSessions: len(r.sessions),
	}

	for _, session := range r.sessions {
		stats.TotalBytesSent += session.BytesSent
		stats.TotalBytesReceived += session.BytesReceived
	}

	return stats
}

// UDPRelayStats contains UDP relay statistics.
type UDPRelayStats struct {
	ActiveSessions     int   `json:"active_sessions"`
	TotalBytesSent     int64 `json:"total_bytes_sent"`
	TotalBytesReceived int64 `json:"total_bytes_received"`
}
