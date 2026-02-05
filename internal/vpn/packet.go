package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// IP protocol numbers.
const (
	ProtocolICMP   uint8 = 1
	ProtocolTCP    uint8 = 6
	ProtocolUDP    uint8 = 17
	ProtocolICMPv6 uint8 = 58
)

// TCP flags.
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// IPPacket represents a parsed IP packet.
type IPPacket struct {
	Version   int        // IP version (4 or 6)
	Protocol  uint8      // Transport protocol (TCP, UDP, ICMP)
	SrcIP     netip.Addr // Source IP address
	DstIP     netip.Addr // Destination IP address
	SrcPort   uint16     // Source port (for TCP/UDP)
	DstPort   uint16     // Destination port (for TCP/UDP)
	SeqNum    uint32     // TCP sequence number
	AckNum    uint32     // TCP acknowledgment number
	Window    uint16     // TCP window size
	TCPFlags  uint8      // TCP flags (for TCP)
	Payload   []byte     // Payload after transport header
	Raw       []byte     // Original raw packet
	HeaderLen int        // IP header length
}

// ParseIPPacket parses a raw IP packet.
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 1 {
		return nil, errors.New("packet too short")
	}

	version := data[0] >> 4

	switch version {
	case 4:
		return parseIPv4Packet(data)
	case 6:
		return parseIPv6Packet(data)
	default:
		return nil, fmt.Errorf("unknown IP version: %d", version)
	}
}

// parseIPv4Packet parses an IPv4 packet.
func parseIPv4Packet(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, errors.New("IPv4 packet too short")
	}

	// IP header length (IHL) is in 32-bit words
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, fmt.Errorf("invalid IPv4 header length: %d", ihl)
	}

	// Total length
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen > len(data) {
		totalLen = len(data) // Truncated packet
	}

	protocol := data[9]

	// Parse addresses
	srcIP, ok := netip.AddrFromSlice(data[12:16])
	if !ok {
		return nil, errors.New("invalid source IP")
	}
	dstIP, ok := netip.AddrFromSlice(data[16:20])
	if !ok {
		return nil, errors.New("invalid destination IP")
	}

	pkt := &IPPacket{
		Version:   4,
		Protocol:  protocol,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Raw:       data[:totalLen],
		HeaderLen: ihl,
	}

	// Parse transport layer header
	transportData := data[ihl:]
	if err := pkt.parseTransportHeader(transportData); err != nil {
		// Non-fatal, we can still use the packet
		pkt.Payload = transportData
	}

	return pkt, nil
}

// parseIPv6Packet parses an IPv6 packet.
func parseIPv6Packet(data []byte) (*IPPacket, error) {
	if len(data) < 40 {
		return nil, errors.New("IPv6 packet too short")
	}

	// IPv6 has a fixed 40-byte header
	nextHeader := data[6]
	payloadLen := int(binary.BigEndian.Uint16(data[4:6]))

	// Parse addresses
	srcIP, ok := netip.AddrFromSlice(data[8:24])
	if !ok {
		return nil, errors.New("invalid source IPv6")
	}
	dstIP, ok := netip.AddrFromSlice(data[24:40])
	if !ok {
		return nil, errors.New("invalid destination IPv6")
	}

	// Handle extension headers
	protocol, headerLen, err := parseIPv6ExtensionHeaders(data[40:], nextHeader)
	if err != nil {
		// Use next header as protocol if extension parsing fails
		protocol = nextHeader
		headerLen = 0
	}

	totalLen := 40 + payloadLen
	if totalLen > len(data) {
		totalLen = len(data)
	}

	pkt := &IPPacket{
		Version:   6,
		Protocol:  protocol,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Raw:       data[:totalLen],
		HeaderLen: 40 + headerLen,
	}

	// Parse transport layer header
	transportData := data[40+headerLen:]
	if err := pkt.parseTransportHeader(transportData); err != nil {
		pkt.Payload = transportData
	}

	return pkt, nil
}

// parseIPv6ExtensionHeaders parses IPv6 extension headers.
func parseIPv6ExtensionHeaders(data []byte, nextHeader uint8) (protocol uint8, headerLen int, err error) {
	offset := 0

	for {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if offset+2 > len(data) {
				return nextHeader, offset, nil
			}
			nextHeader = data[offset]
			extLen := int(data[offset+1]+1) * 8
			offset += extLen
		case 44: // Fragment
			if offset+8 > len(data) {
				return nextHeader, offset, nil
			}
			nextHeader = data[offset]
			offset += 8
		case ProtocolTCP, ProtocolUDP, ProtocolICMPv6, ProtocolICMP:
			return nextHeader, offset, nil
		default:
			return nextHeader, offset, nil
		}

		if offset > len(data) {
			return nextHeader, offset, errors.New("extension header exceeds packet length")
		}
	}
}

// parseTransportHeader parses the transport layer header.
func (p *IPPacket) parseTransportHeader(data []byte) error {
	switch p.Protocol {
	case ProtocolTCP:
		return p.parseTCPHeader(data)
	case ProtocolUDP:
		return p.parseUDPHeader(data)
	default:
		p.Payload = data
		return nil
	}
}

// parseTCPHeader parses a TCP header.
func (p *IPPacket) parseTCPHeader(data []byte) error {
	if len(data) < 20 {
		return errors.New("TCP header too short")
	}

	p.SrcPort = binary.BigEndian.Uint16(data[0:2])
	p.DstPort = binary.BigEndian.Uint16(data[2:4])
	p.SeqNum = binary.BigEndian.Uint32(data[4:8])
	p.AckNum = binary.BigEndian.Uint32(data[8:12])

	// Data offset (header length) is in 32-bit words
	dataOffset := int((data[12] >> 4)) * 4
	if dataOffset < 20 || dataOffset > len(data) {
		dataOffset = 20
	}

	p.TCPFlags = data[13]
	p.Window = binary.BigEndian.Uint16(data[14:16])

	if dataOffset <= len(data) {
		p.Payload = data[dataOffset:]
	}

	return nil
}

// parseUDPHeader parses a UDP header.
func (p *IPPacket) parseUDPHeader(data []byte) error {
	if len(data) < 8 {
		return errors.New("UDP header too short")
	}

	p.SrcPort = binary.BigEndian.Uint16(data[0:2])
	p.DstPort = binary.BigEndian.Uint16(data[2:4])

	p.Payload = data[8:]

	return nil
}

// IsTCP returns true if this is a TCP packet.
func (p *IPPacket) IsTCP() bool {
	return p.Protocol == ProtocolTCP
}

// IsUDP returns true if this is a UDP packet.
func (p *IPPacket) IsUDP() bool {
	return p.Protocol == ProtocolUDP
}

// IsICMP returns true if this is an ICMP packet.
func (p *IPPacket) IsICMP() bool {
	return p.Protocol == ProtocolICMP || p.Protocol == ProtocolICMPv6
}

// IsSYN returns true if this is a TCP SYN packet (new connection).
func (p *IPPacket) IsSYN() bool {
	return p.IsTCP() && (p.TCPFlags&TCPFlagSYN != 0) && (p.TCPFlags&TCPFlagACK == 0)
}

// IsFIN returns true if this is a TCP FIN packet.
func (p *IPPacket) IsFIN() bool {
	return p.IsTCP() && (p.TCPFlags&TCPFlagFIN != 0)
}

// IsRST returns true if this is a TCP RST packet.
func (p *IPPacket) IsRST() bool {
	return p.IsTCP() && (p.TCPFlags&TCPFlagRST != 0)
}

// String returns a string representation of the packet.
func (p *IPPacket) String() string {
	protoName := "unknown"
	switch p.Protocol {
	case ProtocolTCP:
		protoName = "TCP"
	case ProtocolUDP:
		protoName = "UDP"
	case ProtocolICMP:
		protoName = "ICMP"
	case ProtocolICMPv6:
		protoName = "ICMPv6"
	}

	if p.SrcPort != 0 || p.DstPort != 0 {
		return fmt.Sprintf("IPv%d %s %s:%d -> %s:%d",
			p.Version, protoName, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
	}
	return fmt.Sprintf("IPv%d %s %s -> %s",
		p.Version, protoName, p.SrcIP, p.DstIP)
}

// BuildTCPPacket creates a TCP packet with optional payload.
func BuildTCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum, ackNum uint32, flags uint8, window uint16, payload []byte) []byte {
	if srcIP.Is4() {
		return buildIPv4TCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, ackNum, flags, window, payload)
	}
	return buildIPv6TCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, ackNum, flags, window, payload)
}

// buildIPv4TCPPacket builds an IPv4 TCP packet with payload.
func buildIPv4TCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum, ackNum uint32, flags uint8, window uint16, payload []byte) []byte {
	// IPv4 header (20 bytes) + TCP header (20 bytes) + payload
	totalLen := 20 + 20 + len(payload)
	packet := make([]byte, totalLen)

	// IPv4 header
	packet[0] = 0x45 // Version (4) + IHL (5)
	packet[1] = 0    // DSCP + ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)      // ID
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags (Don't Fragment) + Fragment offset
	packet[8] = 64                                  // TTL
	packet[9] = ProtocolTCP                         // Protocol
	// Checksum (10-11) will be calculated later
	copy(packet[12:16], srcIP.AsSlice())
	copy(packet[16:20], dstIP.AsSlice())

	// TCP header
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	binary.BigEndian.PutUint32(packet[24:28], seqNum)
	binary.BigEndian.PutUint32(packet[28:32], ackNum)
	packet[32] = 0x50 // Data offset (5) + reserved
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], window)
	// Checksum (36-37) will be calculated later
	binary.BigEndian.PutUint16(packet[38:40], 0) // Urgent pointer

	// Payload
	copy(packet[40:], payload)

	// Calculate IP checksum
	ipChecksum := calculateChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	// Calculate TCP checksum (with pseudo header + payload)
	tcpChecksum := calculateTCPChecksum(srcIP, dstIP, packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], tcpChecksum)

	return packet
}

// buildIPv6TCPPacket builds an IPv6 TCP packet with payload.
func buildIPv6TCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum, ackNum uint32, flags uint8, window uint16, payload []byte) []byte {
	// IPv6 header (40 bytes) + TCP header (20 bytes) + payload
	totalLen := 40 + 20 + len(payload)
	packet := make([]byte, totalLen)

	// IPv6 header
	packet[0] = 0x60 // Version (6) + Traffic class
	// Flow label (1-3) = 0
	binary.BigEndian.PutUint16(packet[4:6], uint16(20+len(payload))) // Payload length (TCP header + payload)
	packet[6] = ProtocolTCP
	packet[7] = 64 // Hop limit
	copy(packet[8:24], srcIP.AsSlice())
	copy(packet[24:40], dstIP.AsSlice())

	// TCP header
	binary.BigEndian.PutUint16(packet[40:42], srcPort)
	binary.BigEndian.PutUint16(packet[42:44], dstPort)
	binary.BigEndian.PutUint32(packet[44:48], seqNum)
	binary.BigEndian.PutUint32(packet[48:52], ackNum)
	packet[52] = 0x50 // Data offset (5) + reserved
	packet[53] = flags
	binary.BigEndian.PutUint16(packet[54:56], window)
	// Checksum (56-57) will be calculated later
	binary.BigEndian.PutUint16(packet[58:60], 0) // Urgent pointer

	// Payload
	copy(packet[60:], payload)

	// Calculate TCP checksum (with pseudo header + payload)
	tcpChecksum := calculateTCPv6Checksum(srcIP, dstIP, packet[40:])
	binary.BigEndian.PutUint16(packet[56:58], tcpChecksum)

	return packet
}

// BuildTCPRSTPacket creates a TCP RST packet to terminate a connection.
func BuildTCPRSTPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum uint32) []byte {
	if srcIP.Is4() {
		return buildIPv4TCPRSTPacket(srcIP, dstIP, srcPort, dstPort, seqNum)
	}
	return buildIPv6TCPRSTPacket(srcIP, dstIP, srcPort, dstPort, seqNum)
}

// buildIPv4TCPRSTPacket builds an IPv4 TCP RST packet.
func buildIPv4TCPRSTPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum uint32) []byte {
	// IPv4 header (20 bytes) + TCP header (20 bytes)
	packet := make([]byte, 40)

	// IPv4 header
	packet[0] = 0x45                            // Version (4) + IHL (5)
	packet[1] = 0                               // DSCP + ECN
	binary.BigEndian.PutUint16(packet[2:4], 40) // Total length
	binary.BigEndian.PutUint16(packet[4:6], 0)  // ID
	binary.BigEndian.PutUint16(packet[6:8], 0)  // Flags + Fragment offset
	packet[8] = 64                              // TTL
	packet[9] = ProtocolTCP                     // Protocol
	// Checksum (10-11) will be calculated later
	copy(packet[12:16], srcIP.AsSlice())
	copy(packet[16:20], dstIP.AsSlice())

	// TCP header
	binary.BigEndian.PutUint16(packet[20:22], srcPort) // Source port
	binary.BigEndian.PutUint16(packet[22:24], dstPort) // Dest port
	binary.BigEndian.PutUint32(packet[24:28], seqNum)  // Sequence number
	binary.BigEndian.PutUint32(packet[28:32], 0)       // ACK number
	packet[32] = 0x50                                  // Data offset (5) + reserved
	packet[33] = TCPFlagRST                            // Flags (RST)
	binary.BigEndian.PutUint16(packet[34:36], 0)       // Window
	// Checksum (36-37) will be calculated later
	binary.BigEndian.PutUint16(packet[38:40], 0) // Urgent pointer

	// Calculate IP checksum
	ipChecksum := calculateChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	// Calculate TCP checksum (with pseudo header)
	tcpChecksum := calculateTCPChecksum(srcIP, dstIP, packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], tcpChecksum)

	return packet
}

// buildIPv6TCPRSTPacket builds an IPv6 TCP RST packet.
func buildIPv6TCPRSTPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum uint32) []byte {
	// IPv6 header (40 bytes) + TCP header (20 bytes)
	packet := make([]byte, 60)

	// IPv6 header
	packet[0] = 0x60 // Version (6) + Traffic class
	// Flow label (1-3) = 0
	binary.BigEndian.PutUint16(packet[4:6], 20) // Payload length (TCP header)
	packet[6] = ProtocolTCP                     // Next header
	packet[7] = 64                              // Hop limit
	copy(packet[8:24], srcIP.AsSlice())
	copy(packet[24:40], dstIP.AsSlice())

	// TCP header
	binary.BigEndian.PutUint16(packet[40:42], srcPort) // Source port
	binary.BigEndian.PutUint16(packet[42:44], dstPort) // Dest port
	binary.BigEndian.PutUint32(packet[44:48], seqNum)  // Sequence number
	binary.BigEndian.PutUint32(packet[48:52], 0)       // ACK number
	packet[52] = 0x50                                  // Data offset (5) + reserved
	packet[53] = TCPFlagRST                            // Flags (RST)
	binary.BigEndian.PutUint16(packet[54:56], 0)       // Window
	// Checksum (56-57) will be calculated later
	binary.BigEndian.PutUint16(packet[58:60], 0) // Urgent pointer

	// Calculate TCP checksum (with pseudo header)
	tcpChecksum := calculateTCPv6Checksum(srcIP, dstIP, packet[40:])
	binary.BigEndian.PutUint16(packet[56:58], tcpChecksum)

	return packet
}

// calculateChecksum calculates the Internet checksum.
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateTCPChecksum calculates TCP checksum with IPv4 pseudo header.
func calculateTCPChecksum(srcIP, dstIP netip.Addr, tcpData []byte) uint16 {
	// Pseudo header: src IP + dst IP + zero + protocol + TCP length
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.AsSlice())
	copy(pseudoHeader[4:8], dstIP.AsSlice())
	pseudoHeader[8] = 0
	pseudoHeader[9] = ProtocolTCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpData)))

	var sum uint32

	// Sum pseudo header
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}

	// Sum TCP data
	for i := 0; i+1 < len(tcpData); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateTCPv6Checksum calculates TCP checksum with IPv6 pseudo header.
func calculateTCPv6Checksum(srcIP, dstIP netip.Addr, tcpData []byte) uint16 {
	// Pseudo header: src IP + dst IP + TCP length + zeros + next header
	pseudoHeader := make([]byte, 40)
	copy(pseudoHeader[0:16], srcIP.AsSlice())
	copy(pseudoHeader[16:32], dstIP.AsSlice())
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(tcpData)))
	pseudoHeader[39] = ProtocolTCP

	var sum uint32

	// Sum pseudo header
	for i := 0; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}

	// Sum TCP data
	for i := 0; i+1 < len(tcpData); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}
