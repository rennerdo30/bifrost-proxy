package vpn

import (
	"net/netip"
	"testing"
)

func TestParseIPv4Packet(t *testing.T) {
	// Build a simple TCP SYN packet
	// IPv4 header (20 bytes) + TCP header (20 bytes minimum)
	packet := []byte{
		// IPv4 header
		0x45,             // Version (4) + IHL (5)
		0x00,             // DSCP + ECN
		0x00, 0x28,       // Total length (40 bytes)
		0x00, 0x00,       // Identification
		0x40, 0x00,       // Flags (Don't Fragment) + Fragment Offset
		0x40,             // TTL (64)
		0x06,             // Protocol (TCP = 6)
		0x00, 0x00,       // Header checksum (not validated in this test)
		192, 168, 1, 100, // Source IP: 192.168.1.100
		93, 184, 216, 34, // Destination IP: 93.184.216.34

		// TCP header
		0x00, 0x50, // Source port: 80
		0x01, 0xBB, // Destination port: 443
		0x00, 0x00, 0x00, 0x01, // Sequence number
		0x00, 0x00, 0x00, 0x00, // Acknowledgment number
		0x50, // Data offset (5 = 20 bytes) + reserved
		0x02, // Flags (SYN)
		0x00, 0x00, // Window
		0x00, 0x00, // Checksum
		0x00, 0x00, // Urgent pointer
	}

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	// Verify parsed values
	if pkt.Version != 4 {
		t.Errorf("expected version 4, got %d", pkt.Version)
	}
	if pkt.Protocol != ProtocolTCP {
		t.Errorf("expected protocol TCP (6), got %d", pkt.Protocol)
	}

	expectedSrc := netip.MustParseAddr("192.168.1.100")
	if pkt.SrcIP != expectedSrc {
		t.Errorf("expected src IP %v, got %v", expectedSrc, pkt.SrcIP)
	}

	expectedDst := netip.MustParseAddr("93.184.216.34")
	if pkt.DstIP != expectedDst {
		t.Errorf("expected dst IP %v, got %v", expectedDst, pkt.DstIP)
	}

	if pkt.SrcPort != 80 {
		t.Errorf("expected src port 80, got %d", pkt.SrcPort)
	}
	if pkt.DstPort != 443 {
		t.Errorf("expected dst port 443, got %d", pkt.DstPort)
	}

	if !pkt.IsTCP() {
		t.Error("expected IsTCP() to return true")
	}
	if !pkt.IsSYN() {
		t.Error("expected IsSYN() to return true")
	}
}

func TestParseUDPPacket(t *testing.T) {
	// Build a simple UDP packet
	packet := []byte{
		// IPv4 header
		0x45,             // Version (4) + IHL (5)
		0x00,             // DSCP + ECN
		0x00, 0x1C,       // Total length (28 bytes)
		0x00, 0x00,       // Identification
		0x00, 0x00,       // Flags + Fragment Offset
		0x40,             // TTL (64)
		0x11,             // Protocol (UDP = 17)
		0x00, 0x00,       // Header checksum
		10, 0, 0, 1,      // Source IP: 10.0.0.1
		8, 8, 8, 8,       // Destination IP: 8.8.8.8

		// UDP header
		0x30, 0x39, // Source port: 12345
		0x00, 0x35, // Destination port: 53 (DNS)
		0x00, 0x08, // Length
		0x00, 0x00, // Checksum
	}

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if pkt.Protocol != ProtocolUDP {
		t.Errorf("expected protocol UDP (17), got %d", pkt.Protocol)
	}

	if !pkt.IsUDP() {
		t.Error("expected IsUDP() to return true")
	}

	if pkt.SrcPort != 12345 {
		t.Errorf("expected src port 12345, got %d", pkt.SrcPort)
	}
	if pkt.DstPort != 53 {
		t.Errorf("expected dst port 53, got %d", pkt.DstPort)
	}
}

func TestPacketString(t *testing.T) {
	pkt := &IPPacket{
		Version:  4,
		Protocol: ProtocolTCP,
		SrcIP:    netip.MustParseAddr("192.168.1.1"),
		DstIP:    netip.MustParseAddr("10.0.0.1"),
		SrcPort:  12345,
		DstPort:  80,
	}

	s := pkt.String()
	if s == "" {
		t.Error("expected non-empty string")
	}

	// Should contain basic info
	expected := "IPv4 TCP 192.168.1.1:12345 -> 10.0.0.1:80"
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

func TestCalculateChecksum(t *testing.T) {
	// Test data from RFC 1071
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	checksum := calculateChecksum(data)

	// The checksum should be non-zero
	if checksum == 0 {
		t.Error("expected non-zero checksum")
	}

	// Verify checksum is correct by adding it back
	data = append(data, byte(checksum>>8), byte(checksum))
	result := calculateChecksum(data)
	// Result should be 0xFFFF (or 0 after complement)
	if result != 0xFFFF && result != 0 {
		t.Errorf("checksum verification failed, got 0x%04X", result)
	}
}

func TestParseIPv6Packet(t *testing.T) {
	// Build a simple IPv6 TCP packet
	// IPv6 header (40 bytes) + TCP header (20 bytes)
	packet := make([]byte, 60)

	// IPv6 header
	packet[0] = 0x60                           // Version (6) + Traffic class
	packet[1] = 0x00                           // Traffic class + Flow label
	packet[2] = 0x00                           // Flow label
	packet[3] = 0x00                           // Flow label
	packet[4] = 0x00                           // Payload length (high byte)
	packet[5] = 0x14                           // Payload length (20 bytes for TCP header)
	packet[6] = ProtocolTCP                    // Next header (TCP)
	packet[7] = 0x40                           // Hop limit (64)

	// Source IPv6 address: 2001:db8::1
	packet[8] = 0x20
	packet[9] = 0x01
	packet[10] = 0x0d
	packet[11] = 0xb8
	// bytes 12-22 are zero
	packet[23] = 0x01

	// Destination IPv6 address: 2001:db8::2
	packet[24] = 0x20
	packet[25] = 0x01
	packet[26] = 0x0d
	packet[27] = 0xb8
	// bytes 28-38 are zero
	packet[39] = 0x02

	// TCP header
	packet[40] = 0x00 // Source port (high)
	packet[41] = 0x50 // Source port (low) = 80
	packet[42] = 0x01 // Dest port (high)
	packet[43] = 0xBB // Dest port (low) = 443
	// Sequence number (44-47)
	packet[44] = 0x00
	packet[45] = 0x00
	packet[46] = 0x00
	packet[47] = 0x01
	// ACK number (48-51)
	packet[52] = 0x50 // Data offset (5) + reserved
	packet[53] = 0x02 // Flags (SYN)
	// Window, checksum, urgent (54-59)

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if pkt.Version != 6 {
		t.Errorf("expected version 6, got %d", pkt.Version)
	}
	if pkt.Protocol != ProtocolTCP {
		t.Errorf("expected protocol TCP (6), got %d", pkt.Protocol)
	}

	expectedSrc := netip.MustParseAddr("2001:db8::1")
	if pkt.SrcIP != expectedSrc {
		t.Errorf("expected src IP %v, got %v", expectedSrc, pkt.SrcIP)
	}

	expectedDst := netip.MustParseAddr("2001:db8::2")
	if pkt.DstIP != expectedDst {
		t.Errorf("expected dst IP %v, got %v", expectedDst, pkt.DstIP)
	}

	if pkt.SrcPort != 80 {
		t.Errorf("expected src port 80, got %d", pkt.SrcPort)
	}
	if pkt.DstPort != 443 {
		t.Errorf("expected dst port 443, got %d", pkt.DstPort)
	}

	if !pkt.IsSYN() {
		t.Error("expected IsSYN() to return true")
	}
}

func TestParseIPv6PacketWithExtensionHeaders(t *testing.T) {
	// Build an IPv6 packet with a Hop-by-Hop extension header
	// IPv6 header (40 bytes) + Hop-by-Hop header (8 bytes) + TCP header (20 bytes)
	packet := make([]byte, 68)

	// IPv6 header
	packet[0] = 0x60                // Version (6)
	packet[4] = 0x00                // Payload length (high)
	packet[5] = 0x1C                // Payload length (28 bytes = 8 + 20)
	packet[6] = 0x00                // Next header: Hop-by-Hop Options
	packet[7] = 0x40                // Hop limit

	// Source IPv6: ::1
	packet[23] = 0x01

	// Destination IPv6: ::2
	packet[39] = 0x02

	// Hop-by-Hop extension header (8 bytes)
	packet[40] = ProtocolTCP // Next header: TCP
	packet[41] = 0x00        // Header Ext Len (0 = 8 bytes total)
	// Options (padding) in bytes 42-47

	// TCP header at offset 48
	packet[48] = 0x1F // Source port high = 8080
	packet[49] = 0x90 // Source port low
	packet[50] = 0x00 // Dest port high
	packet[51] = 0x50 // Dest port low = 80
	// Sequence number (52-55)
	// ACK number (56-59)
	packet[60] = 0x50 // Data offset
	packet[61] = 0x10 // Flags (ACK)

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if pkt.Version != 6 {
		t.Errorf("expected version 6, got %d", pkt.Version)
	}
	if pkt.Protocol != ProtocolTCP {
		t.Errorf("expected protocol TCP, got %d", pkt.Protocol)
	}
	if pkt.SrcPort != 8080 {
		t.Errorf("expected src port 8080, got %d", pkt.SrcPort)
	}
	if pkt.DstPort != 80 {
		t.Errorf("expected dst port 80, got %d", pkt.DstPort)
	}
}

func TestParseIPv6PacketShort(t *testing.T) {
	// Packet too short for IPv6
	packet := make([]byte, 30)
	packet[0] = 0x60 // IPv6 version

	_, err := ParseIPPacket(packet)
	if err == nil {
		t.Error("expected error for short IPv6 packet")
	}
}

func TestParseIPv6ExtensionHeaders(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		nextHeader     uint8
		expectProtocol uint8
		expectOffset   int
	}{
		{
			name:           "no extension headers - TCP",
			data:           []byte{0x00}, // Just some data
			nextHeader:     ProtocolTCP,
			expectProtocol: ProtocolTCP,
			expectOffset:   0,
		},
		{
			name:           "no extension headers - UDP",
			data:           []byte{0x00},
			nextHeader:     ProtocolUDP,
			expectProtocol: ProtocolUDP,
			expectOffset:   0,
		},
		{
			name:           "no extension headers - ICMPv6",
			data:           []byte{0x00},
			nextHeader:     ProtocolICMPv6,
			expectProtocol: ProtocolICMPv6,
			expectOffset:   0,
		},
		{
			name: "hop-by-hop header",
			data: []byte{
				ProtocolTCP, // Next header
				0x00,        // Length (0 = 8 bytes)
				0, 0, 0, 0, 0, 0, // Options
			},
			nextHeader:     0, // Hop-by-Hop
			expectProtocol: ProtocolTCP,
			expectOffset:   8,
		},
		{
			name: "routing header",
			data: []byte{
				ProtocolUDP, // Next header
				0x00,        // Length
				0, 0, 0, 0, 0, 0,
			},
			nextHeader:     43, // Routing
			expectProtocol: ProtocolUDP,
			expectOffset:   8,
		},
		{
			name: "destination options header",
			data: []byte{
				ProtocolTCP, // Next header
				0x00,        // Length
				0, 0, 0, 0, 0, 0,
			},
			nextHeader:     60, // Destination Options
			expectProtocol: ProtocolTCP,
			expectOffset:   8,
		},
		{
			name: "fragment header",
			data: []byte{
				ProtocolTCP, // Next header
				0x00,        // Reserved
				0, 0, // Fragment offset + flags
				0, 0, 0, 0, // Identification
			},
			nextHeader:     44, // Fragment
			expectProtocol: ProtocolTCP,
			expectOffset:   8,
		},
		{
			name:           "unknown header - returns as-is",
			data:           []byte{0x00},
			nextHeader:     99, // Unknown
			expectProtocol: 99,
			expectOffset:   0,
		},
		{
			name:           "short hop-by-hop - returns current",
			data:           []byte{0x06}, // Only 1 byte, need at least 2
			nextHeader:     0,            // Hop-by-Hop
			expectProtocol: 0,
			expectOffset:   0,
		},
		{
			name:           "short fragment - returns current",
			data:           []byte{0x06, 0x00, 0x00}, // Only 3 bytes, need 8
			nextHeader:     44,                       // Fragment
			expectProtocol: 44,
			expectOffset:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocol, offset, _ := parseIPv6ExtensionHeaders(tt.data, tt.nextHeader)
			if protocol != tt.expectProtocol {
				t.Errorf("expected protocol %d, got %d", tt.expectProtocol, protocol)
			}
			if offset != tt.expectOffset {
				t.Errorf("expected offset %d, got %d", tt.expectOffset, offset)
			}
		})
	}
}

func TestIsICMP(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint8
		expected bool
	}{
		{"ICMP", ProtocolICMP, true},
		{"ICMPv6", ProtocolICMPv6, true},
		{"TCP", ProtocolTCP, false},
		{"UDP", ProtocolUDP, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &IPPacket{Protocol: tt.protocol}
			if pkt.IsICMP() != tt.expected {
				t.Errorf("expected IsICMP() to return %v for protocol %d", tt.expected, tt.protocol)
			}
		})
	}
}

func TestIsFIN(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint8
		flags    uint8
		expected bool
	}{
		{"TCP FIN", ProtocolTCP, TCPFlagFIN, true},
		{"TCP FIN+ACK", ProtocolTCP, TCPFlagFIN | TCPFlagACK, true},
		{"TCP ACK only", ProtocolTCP, TCPFlagACK, false},
		{"TCP SYN", ProtocolTCP, TCPFlagSYN, false},
		{"UDP - not TCP", ProtocolUDP, TCPFlagFIN, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &IPPacket{Protocol: tt.protocol, TCPFlags: tt.flags}
			if pkt.IsFIN() != tt.expected {
				t.Errorf("expected IsFIN() to return %v", tt.expected)
			}
		})
	}
}

func TestIsRST(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint8
		flags    uint8
		expected bool
	}{
		{"TCP RST", ProtocolTCP, TCPFlagRST, true},
		{"TCP RST+ACK", ProtocolTCP, TCPFlagRST | TCPFlagACK, true},
		{"TCP ACK only", ProtocolTCP, TCPFlagACK, false},
		{"TCP SYN", ProtocolTCP, TCPFlagSYN, false},
		{"UDP - not TCP", ProtocolUDP, TCPFlagRST, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &IPPacket{Protocol: tt.protocol, TCPFlags: tt.flags}
			if pkt.IsRST() != tt.expected {
				t.Errorf("expected IsRST() to return %v", tt.expected)
			}
		})
	}
}

func TestBuildTCPRSTPacket_IPv4(t *testing.T) {
	srcIP := netip.MustParseAddr("192.168.1.100")
	dstIP := netip.MustParseAddr("10.0.0.1")
	srcPort := uint16(8080)
	dstPort := uint16(443)
	seqNum := uint32(12345)

	packet := BuildTCPRSTPacket(srcIP, dstIP, srcPort, dstPort, seqNum)

	// IPv4 header (20 bytes) + TCP header (20 bytes)
	if len(packet) != 40 {
		t.Errorf("expected packet length 40, got %d", len(packet))
	}

	// Parse the packet we just built
	parsed, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("failed to parse built packet: %v", err)
	}

	if parsed.Version != 4 {
		t.Errorf("expected version 4, got %d", parsed.Version)
	}
	if parsed.SrcIP != srcIP {
		t.Errorf("expected src IP %v, got %v", srcIP, parsed.SrcIP)
	}
	if parsed.DstIP != dstIP {
		t.Errorf("expected dst IP %v, got %v", dstIP, parsed.DstIP)
	}
	if parsed.SrcPort != srcPort {
		t.Errorf("expected src port %d, got %d", srcPort, parsed.SrcPort)
	}
	if parsed.DstPort != dstPort {
		t.Errorf("expected dst port %d, got %d", dstPort, parsed.DstPort)
	}
	if !parsed.IsRST() {
		t.Error("expected IsRST() to return true")
	}

	// Verify IP header fields
	if packet[0] != 0x45 {
		t.Errorf("expected IP version/IHL 0x45, got 0x%02x", packet[0])
	}
	if packet[8] != 64 {
		t.Errorf("expected TTL 64, got %d", packet[8])
	}
	if packet[9] != ProtocolTCP {
		t.Errorf("expected protocol TCP, got %d", packet[9])
	}
}

func TestBuildTCPRSTPacket_IPv6(t *testing.T) {
	srcIP := netip.MustParseAddr("2001:db8::1")
	dstIP := netip.MustParseAddr("2001:db8::2")
	srcPort := uint16(8080)
	dstPort := uint16(443)
	seqNum := uint32(67890)

	packet := BuildTCPRSTPacket(srcIP, dstIP, srcPort, dstPort, seqNum)

	// IPv6 header (40 bytes) + TCP header (20 bytes)
	if len(packet) != 60 {
		t.Errorf("expected packet length 60, got %d", len(packet))
	}

	// Parse the packet we just built
	parsed, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("failed to parse built packet: %v", err)
	}

	if parsed.Version != 6 {
		t.Errorf("expected version 6, got %d", parsed.Version)
	}
	if parsed.SrcIP != srcIP {
		t.Errorf("expected src IP %v, got %v", srcIP, parsed.SrcIP)
	}
	if parsed.DstIP != dstIP {
		t.Errorf("expected dst IP %v, got %v", dstIP, parsed.DstIP)
	}
	if parsed.SrcPort != srcPort {
		t.Errorf("expected src port %d, got %d", srcPort, parsed.SrcPort)
	}
	if parsed.DstPort != dstPort {
		t.Errorf("expected dst port %d, got %d", dstPort, parsed.DstPort)
	}
	if !parsed.IsRST() {
		t.Error("expected IsRST() to return true")
	}

	// Verify IPv6 header fields
	if packet[0]>>4 != 6 {
		t.Errorf("expected IP version 6, got %d", packet[0]>>4)
	}
	if packet[6] != ProtocolTCP {
		t.Errorf("expected next header TCP, got %d", packet[6])
	}
	if packet[7] != 64 {
		t.Errorf("expected hop limit 64, got %d", packet[7])
	}
}

func TestCalculateTCPChecksum(t *testing.T) {
	srcIP := netip.MustParseAddr("192.168.1.1")
	dstIP := netip.MustParseAddr("192.168.1.2")

	// Simple TCP header with RST flag
	tcpData := make([]byte, 20)
	tcpData[0] = 0x00  // Source port high
	tcpData[1] = 0x50  // Source port low = 80
	tcpData[2] = 0x01  // Dest port high
	tcpData[3] = 0xBB  // Dest port low = 443
	tcpData[12] = 0x50 // Data offset
	tcpData[13] = TCPFlagRST

	checksum := calculateTCPChecksum(srcIP, dstIP, tcpData)

	// Checksum should be non-zero
	if checksum == 0 {
		t.Error("expected non-zero checksum")
	}

	// Verify determinism
	checksum2 := calculateTCPChecksum(srcIP, dstIP, tcpData)
	if checksum != checksum2 {
		t.Error("checksum not deterministic")
	}

	// Different IPs should produce different checksum
	dstIP2 := netip.MustParseAddr("192.168.1.3")
	checksum3 := calculateTCPChecksum(srcIP, dstIP2, tcpData)
	if checksum == checksum3 {
		t.Error("expected different checksum for different IPs")
	}
}

func TestCalculateTCPv6Checksum(t *testing.T) {
	srcIP := netip.MustParseAddr("2001:db8::1")
	dstIP := netip.MustParseAddr("2001:db8::2")

	// Simple TCP header
	tcpData := make([]byte, 20)
	tcpData[0] = 0x1F  // Source port high = 8080
	tcpData[1] = 0x90  // Source port low
	tcpData[2] = 0x00  // Dest port high
	tcpData[3] = 0x50  // Dest port low = 80
	tcpData[12] = 0x50 // Data offset
	tcpData[13] = TCPFlagSYN

	checksum := calculateTCPv6Checksum(srcIP, dstIP, tcpData)

	// Checksum should be non-zero
	if checksum == 0 {
		t.Error("expected non-zero checksum")
	}

	// Verify determinism
	checksum2 := calculateTCPv6Checksum(srcIP, dstIP, tcpData)
	if checksum != checksum2 {
		t.Error("checksum not deterministic")
	}

	// Different IPs should produce different checksum
	dstIP2 := netip.MustParseAddr("2001:db8::3")
	checksum3 := calculateTCPv6Checksum(srcIP, dstIP2, tcpData)
	if checksum == checksum3 {
		t.Error("expected different checksum for different IPs")
	}
}

func TestCalculateChecksumOddLength(t *testing.T) {
	// Test with odd-length data
	data := []byte{0x01, 0x02, 0x03}
	checksum := calculateChecksum(data)

	if checksum == 0 {
		t.Error("expected non-zero checksum for odd-length data")
	}
}

func TestParseIPPacketErrors(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{"empty packet", []byte{}},
		{"unknown version", []byte{0x30}}, // Version 3
		{"short IPv4", []byte{0x45, 0x00, 0x00}},
		{"invalid IPv4 IHL too small", []byte{
			0x41, // Version 4, IHL 1 (invalid, must be >= 5)
			0x00,
			0x00, 0x14, // Total length
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00,
			192, 168, 1, 1,
			192, 168, 1, 2,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIPPacket(tt.packet)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestPacketStringVariants(t *testing.T) {
	tests := []struct {
		name     string
		pkt      *IPPacket
		expected string
	}{
		{
			name: "TCP with ports",
			pkt: &IPPacket{
				Version:  4,
				Protocol: ProtocolTCP,
				SrcIP:    netip.MustParseAddr("192.168.1.1"),
				DstIP:    netip.MustParseAddr("10.0.0.1"),
				SrcPort:  80,
				DstPort:  443,
			},
			expected: "IPv4 TCP 192.168.1.1:80 -> 10.0.0.1:443",
		},
		{
			name: "UDP with ports",
			pkt: &IPPacket{
				Version:  4,
				Protocol: ProtocolUDP,
				SrcIP:    netip.MustParseAddr("10.0.0.1"),
				DstIP:    netip.MustParseAddr("8.8.8.8"),
				SrcPort:  12345,
				DstPort:  53,
			},
			expected: "IPv4 UDP 10.0.0.1:12345 -> 8.8.8.8:53",
		},
		{
			name: "ICMP no ports",
			pkt: &IPPacket{
				Version:  4,
				Protocol: ProtocolICMP,
				SrcIP:    netip.MustParseAddr("192.168.1.1"),
				DstIP:    netip.MustParseAddr("8.8.8.8"),
			},
			expected: "IPv4 ICMP 192.168.1.1 -> 8.8.8.8",
		},
		{
			name: "ICMPv6",
			pkt: &IPPacket{
				Version:  6,
				Protocol: ProtocolICMPv6,
				SrcIP:    netip.MustParseAddr("::1"),
				DstIP:    netip.MustParseAddr("::2"),
			},
			expected: "IPv6 ICMPv6 ::1 -> ::2",
		},
		{
			name: "Unknown protocol",
			pkt: &IPPacket{
				Version:  4,
				Protocol: 99,
				SrcIP:    netip.MustParseAddr("1.2.3.4"),
				DstIP:    netip.MustParseAddr("5.6.7.8"),
			},
			expected: "IPv4 unknown 1.2.3.4 -> 5.6.7.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pkt.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestParseTCPHeaderShort(t *testing.T) {
	// Create an IPv4 packet with truncated TCP header
	packet := []byte{
		// IPv4 header
		0x45,             // Version (4) + IHL (5)
		0x00,             // DSCP + ECN
		0x00, 0x18,       // Total length (24 bytes = 20 IP + 4 TCP)
		0x00, 0x00,       // Identification
		0x00, 0x00,       // Flags + Fragment Offset
		0x40,             // TTL
		0x06,             // Protocol (TCP)
		0x00, 0x00,       // Header checksum
		192, 168, 1, 100, // Source IP
		192, 168, 1, 200, // Destination IP
		// Truncated TCP header (only 4 bytes)
		0x00, 0x50, // Source port
		0x01, 0xBB, // Dest port
	}

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	// Packet should parse but TCP header won't be fully parsed
	if pkt.Protocol != ProtocolTCP {
		t.Errorf("expected protocol TCP, got %d", pkt.Protocol)
	}
}

func TestParseUDPHeaderShort(t *testing.T) {
	// Create an IPv4 packet with truncated UDP header
	packet := []byte{
		// IPv4 header
		0x45,             // Version (4) + IHL (5)
		0x00,             // DSCP + ECN
		0x00, 0x18,       // Total length (24 bytes = 20 IP + 4 UDP)
		0x00, 0x00,       // Identification
		0x00, 0x00,       // Flags + Fragment Offset
		0x40,             // TTL
		0x11,             // Protocol (UDP)
		0x00, 0x00,       // Header checksum
		10, 0, 0, 1,      // Source IP
		8, 8, 8, 8,       // Destination IP
		// Truncated UDP header (only 4 bytes)
		0x30, 0x39, // Source port
		0x00, 0x35, // Dest port
	}

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	// Packet should parse but UDP header won't be fully parsed
	if pkt.Protocol != ProtocolUDP {
		t.Errorf("expected protocol UDP, got %d", pkt.Protocol)
	}
}

func TestParseICMPPacket(t *testing.T) {
	// Build an ICMP echo request packet
	packet := []byte{
		// IPv4 header
		0x45,             // Version (4) + IHL (5)
		0x00,             // DSCP + ECN
		0x00, 0x1C,       // Total length (28 bytes)
		0x00, 0x00,       // Identification
		0x00, 0x00,       // Flags + Fragment Offset
		0x40,             // TTL (64)
		0x01,             // Protocol (ICMP = 1)
		0x00, 0x00,       // Header checksum
		192, 168, 1, 1,   // Source IP
		8, 8, 8, 8,       // Destination IP

		// ICMP header
		0x08,       // Type: Echo Request
		0x00,       // Code
		0x00, 0x00, // Checksum
		0x00, 0x01, // Identifier
		0x00, 0x01, // Sequence number
	}

	pkt, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("ParseIPPacket failed: %v", err)
	}

	if pkt.Protocol != ProtocolICMP {
		t.Errorf("expected protocol ICMP (1), got %d", pkt.Protocol)
	}
	if !pkt.IsICMP() {
		t.Error("expected IsICMP() to return true")
	}
	if pkt.IsTCP() {
		t.Error("expected IsTCP() to return false")
	}
	if pkt.IsUDP() {
		t.Error("expected IsUDP() to return false")
	}
}
