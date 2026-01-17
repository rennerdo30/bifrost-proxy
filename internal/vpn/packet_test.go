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
