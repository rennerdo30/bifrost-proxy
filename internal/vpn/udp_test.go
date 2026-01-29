package vpn

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUDPRelayConfig(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		cfg := DefaultUDPRelayConfig()
		assert.Equal(t, "0.0.0.0:0", cfg.ListenAddr)
		assert.Equal(t, 30*time.Second, cfg.IdleTimeout)
	})
}

func TestBuildIPv4UDPPacket(t *testing.T) {
	srcIP := netip.MustParseAddr("8.8.8.8")
	dstIP := netip.MustParseAddr("192.168.1.100")
	srcPort := uint16(53)
	dstPort := uint16(12345)
	payload := []byte("test payload data")

	packet := buildIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, payload)

	// Verify total length
	expectedLen := 20 + 8 + len(payload)
	assert.Equal(t, expectedLen, len(packet))

	// Verify IP version and header length
	assert.Equal(t, byte(0x45), packet[0])

	// Verify total length field
	totalLen := int(packet[2])<<8 | int(packet[3])
	assert.Equal(t, expectedLen, totalLen)

	// Verify protocol (UDP = 17)
	assert.Equal(t, byte(ProtocolUDP), packet[9])

	// Verify source IP
	src4 := srcIP.As4()
	assert.Equal(t, src4[:], packet[12:16])

	// Verify destination IP
	dst4 := dstIP.As4()
	assert.Equal(t, dst4[:], packet[16:20])

	// Verify UDP source port
	udpSrcPort := uint16(packet[20])<<8 | uint16(packet[21])
	assert.Equal(t, srcPort, udpSrcPort)

	// Verify UDP destination port
	udpDstPort := uint16(packet[22])<<8 | uint16(packet[23])
	assert.Equal(t, dstPort, udpDstPort)

	// Verify UDP length
	udpLen := int(packet[24])<<8 | int(packet[25])
	assert.Equal(t, 8+len(payload), udpLen)

	// Verify payload
	assert.Equal(t, payload, packet[28:])
}

func TestBuildIPv6UDPPacket(t *testing.T) {
	srcIP := netip.MustParseAddr("2001:4860:4860::8888")
	dstIP := netip.MustParseAddr("fd00::100")
	srcPort := uint16(53)
	dstPort := uint16(12345)
	payload := []byte("test payload")

	packet := buildIPv6UDPPacket(srcIP, dstIP, srcPort, dstPort, payload)

	// Verify total length
	expectedLen := 40 + 8 + len(payload)
	assert.Equal(t, expectedLen, len(packet))

	// Verify IP version
	assert.Equal(t, byte(0x60), packet[0]&0xf0)

	// Verify payload length
	payloadLen := int(packet[4])<<8 | int(packet[5])
	assert.Equal(t, 8+len(payload), payloadLen)

	// Verify next header (UDP = 17)
	assert.Equal(t, byte(ProtocolUDP), packet[6])

	// Verify source IP
	src16 := srcIP.As16()
	assert.Equal(t, src16[:], packet[8:24])

	// Verify destination IP
	dst16 := dstIP.As16()
	assert.Equal(t, dst16[:], packet[24:40])

	// Verify UDP source port
	udpSrcPort := uint16(packet[40])<<8 | uint16(packet[41])
	assert.Equal(t, srcPort, udpSrcPort)

	// Verify UDP destination port
	udpDstPort := uint16(packet[42])<<8 | uint16(packet[43])
	assert.Equal(t, dstPort, udpDstPort)

	// Verify UDP length
	udpLen := int(packet[44])<<8 | int(packet[45])
	assert.Equal(t, 8+len(payload), udpLen)

	// Verify payload
	assert.Equal(t, payload, packet[48:])
}

func TestIPChecksum(t *testing.T) {
	// Test with a known good header
	header := []byte{
		0x45, 0x00, 0x00, 0x1d, // Version, IHL, TOS, Total Length
		0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment Offset
		0x40, 0x11, 0x00, 0x00, // TTL, Protocol, Checksum (zeroed)
		0xc0, 0xa8, 0x01, 0x64, // Source IP (192.168.1.100)
		0x08, 0x08, 0x08, 0x08, // Destination IP (8.8.8.8)
	}

	checksum := ipChecksum(header)

	// Checksum should be non-zero
	assert.NotEqual(t, uint16(0), checksum)

	// Put checksum in header and verify it equals 0xFFFF complement
	header[10] = byte(checksum >> 8)
	header[11] = byte(checksum)

	// Verify checksum (recalculating should give 0)
	verifySum := ipChecksum(header)
	assert.Equal(t, uint16(0), verifySum)
}

func TestUDPSession(t *testing.T) {
	session := &UDPSession{
		OriginalSrc:  netip.MustParseAddrPort("192.168.1.100:12345"),
		Destination:  netip.MustParseAddrPort("8.8.8.8:53"),
		LocalPort:    10001,
		Created:      time.Now(),
		LastActivity: time.Now(),
	}

	assert.Equal(t, netip.MustParseAddrPort("192.168.1.100:12345"), session.OriginalSrc)
	assert.Equal(t, netip.MustParseAddrPort("8.8.8.8:53"), session.Destination)
	assert.Equal(t, uint16(10001), session.LocalPort)
}

func TestUDPRelayStats(t *testing.T) {
	stats := UDPRelayStats{
		ActiveSessions:     5,
		TotalBytesSent:     1024,
		TotalBytesReceived: 2048,
	}

	assert.Equal(t, 5, stats.ActiveSessions)
	assert.Equal(t, int64(1024), stats.TotalBytesSent)
	assert.Equal(t, int64(2048), stats.TotalBytesReceived)
}

// mockTUNDevice is defined in vpn_test.go and shared across test files

func TestNewUDPRelay(t *testing.T) {
	mockTUN := &mockTUNDevice{
		name: "test0",
		mtu:  1400,
	}

	cfg := UDPRelayConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 10 * time.Second,
		TUNAddr:     netip.MustParseAddr("10.0.0.1"),
	}

	relay, err := NewUDPRelay(cfg, mockTUN)
	require.NoError(t, err)
	require.NotNil(t, relay)

	// Verify configuration
	assert.Equal(t, 10*time.Second, relay.idleTimeout)
	assert.NotNil(t, relay.conn)
	assert.NotNil(t, relay.nat)

	// Clean up
	relay.Stop()
}

func TestUDPRelayHandlePacket(t *testing.T) {
	mockTUN := &mockTUNDevice{
		name: "test0",
		mtu:  1400,
	}

	cfg := UDPRelayConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 10 * time.Second,
		TUNAddr:     netip.MustParseAddr("10.0.0.1"),
	}

	relay, err := NewUDPRelay(cfg, mockTUN)
	require.NoError(t, err)
	relay.Start()
	defer relay.Stop()

	// Create a UDP packet
	packet := &IPPacket{
		Version:  4,
		Protocol: ProtocolUDP,
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		SrcPort:  12345,
		DstPort:  53,
		Payload:  []byte("test DNS query"),
	}

	// Handle the packet - this creates a session
	err = relay.HandlePacket(packet)
	// May fail because 8.8.8.8 isn't reachable in tests, but session should be created
	_ = err

	// Check that a session was created
	stats := relay.Stats()
	assert.Equal(t, 1, stats.ActiveSessions)
}

func TestUDPRelaySessionCleanup(t *testing.T) {
	mockTUN := &mockTUNDevice{
		name: "test0",
		mtu:  1400,
	}

	cfg := UDPRelayConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 100 * time.Millisecond, // Short timeout for testing
		TUNAddr:     netip.MustParseAddr("10.0.0.1"),
	}

	relay, err := NewUDPRelay(cfg, mockTUN)
	require.NoError(t, err)
	relay.Start()
	defer relay.Stop()

	// Create a session manually
	relay.sessionsMu.Lock()
	relay.sessions[10001] = &UDPSession{
		OriginalSrc:  netip.MustParseAddrPort("10.0.0.1:12345"),
		Destination:  netip.MustParseAddrPort("8.8.8.8:53"),
		LocalPort:    10001,
		Created:      time.Now().Add(-time.Second),
		LastActivity: time.Now().Add(-time.Second), // Already idle
	}
	relay.sessionsMu.Unlock()

	// Manually trigger cleanup
	relay.cleanupIdleSessions()

	// Session should be removed
	stats := relay.Stats()
	assert.Equal(t, 0, stats.ActiveSessions)
}

func TestUDPRelayBuildResponsePacket(t *testing.T) {
	mockTUN := &mockTUNDevice{
		name: "test0",
		mtu:  1400,
	}

	cfg := UDPRelayConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 10 * time.Second,
		TUNAddr:     netip.MustParseAddr("10.0.0.1"),
	}

	relay, err := NewUDPRelay(cfg, mockTUN)
	require.NoError(t, err)
	defer relay.Stop()

	t.Run("IPv4 response", func(t *testing.T) {
		session := &UDPSession{
			OriginalSrc: netip.MustParseAddrPort("10.0.0.1:12345"),
			Destination: netip.MustParseAddrPort("8.8.8.8:53"),
		}

		payload := []byte("response data")
		packet := relay.buildResponsePacket(session, payload)

		require.NotNil(t, packet)

		// Should be IPv4
		assert.Equal(t, byte(0x45), packet[0])

		// Verify addresses are swapped (response goes back to original source)
		srcIP := net.IP(packet[12:16])
		dstIP := net.IP(packet[16:20])
		assert.Equal(t, "8.8.8.8", srcIP.String())
		assert.Equal(t, "10.0.0.1", dstIP.String())
	})

	t.Run("IPv6 response", func(t *testing.T) {
		session := &UDPSession{
			OriginalSrc: netip.MustParseAddrPort("[fd00::1]:12345"),
			Destination: netip.MustParseAddrPort("[2001:4860:4860::8888]:53"),
		}

		payload := []byte("response data")
		packet := relay.buildResponsePacket(session, payload)

		require.NotNil(t, packet)

		// Should be IPv6
		assert.Equal(t, byte(0x60), packet[0]&0xf0)
	})
}

func TestFindSessionByRemote(t *testing.T) {
	mockTUN := &mockTUNDevice{
		name: "test0",
		mtu:  1400,
	}

	cfg := UDPRelayConfig{
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 10 * time.Second,
		TUNAddr:     netip.MustParseAddr("10.0.0.1"),
	}

	relay, err := NewUDPRelay(cfg, mockTUN)
	require.NoError(t, err)
	defer relay.Stop()

	// Create a session
	relay.sessionsMu.Lock()
	relay.sessions[10001] = &UDPSession{
		OriginalSrc:  netip.MustParseAddrPort("10.0.0.1:12345"),
		Destination:  netip.MustParseAddrPort("8.8.8.8:53"),
		LocalPort:    10001,
		Created:      time.Now(),
		LastActivity: time.Now(),
	}
	relay.sessionsMu.Unlock()

	t.Run("find existing session", func(t *testing.T) {
		remote := &net.UDPAddr{
			IP:   net.ParseIP("8.8.8.8"),
			Port: 53,
		}
		session := relay.findSessionByRemote(remote)
		require.NotNil(t, session)
		assert.Equal(t, uint16(10001), session.LocalPort)
	})

	t.Run("no session found", func(t *testing.T) {
		remote := &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 53,
		}
		session := relay.findSessionByRemote(remote)
		assert.Nil(t, session)
	})
}
