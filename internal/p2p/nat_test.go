package p2p

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNATTypeString(t *testing.T) {
	tests := []struct {
		natType  NATType
		expected string
	}{
		{NATTypeUnknown, "unknown"},
		{NATTypeNone, "none"},
		{NATTypeFullCone, "full_cone"},
		{NATTypeRestrictedCone, "restricted_cone"},
		{NATTypePortRestricted, "port_restricted"},
		{NATTypeSymmetric, "symmetric"},
		{NATType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.natType.String())
		})
	}
}

func TestNATTypeIsFriendly(t *testing.T) {
	t.Run("friendly types", func(t *testing.T) {
		assert.True(t, NATTypeNone.IsFriendly())
		assert.True(t, NATTypeFullCone.IsFriendly())
		assert.True(t, NATTypeRestrictedCone.IsFriendly())
		assert.True(t, NATTypePortRestricted.IsFriendly())
	})

	t.Run("unfriendly types", func(t *testing.T) {
		assert.False(t, NATTypeUnknown.IsFriendly())
		assert.False(t, NATTypeSymmetric.IsFriendly())
	})
}

func TestNewNATDetector(t *testing.T) {
	t.Run("with servers and timeout", func(t *testing.T) {
		servers := []string{"stun:stun.example.com:3478"}
		detector := NewNATDetector(servers, 10*time.Second)

		assert.NotNil(t, detector)
		assert.Equal(t, servers, detector.servers)
		assert.Equal(t, 10*time.Second, detector.timeout)
		assert.NotNil(t, detector.stunClient)
	})

	t.Run("with default servers", func(t *testing.T) {
		detector := NewNATDetector(nil, 10*time.Second)

		assert.NotNil(t, detector)
		assert.Equal(t, DefaultSTUNServers(), detector.servers)
	})

	t.Run("with default timeout", func(t *testing.T) {
		detector := NewNATDetector([]string{"stun:stun.example.com"}, 0)

		assert.NotNil(t, detector)
		assert.Equal(t, 10*time.Second, detector.timeout)
	})
}

func TestNATDetectorGetCachedInfo(t *testing.T) {
	detector := NewNATDetector([]string{}, 5*time.Second)

	// Initially nil
	info := detector.GetCachedInfo()
	assert.Nil(t, info)

	// Set cached info manually
	detector.mu.Lock()
	detector.cachedInfo = &NATInfo{
		Type:        NATTypeFullCone,
		IsBehindNAT: true,
	}
	detector.mu.Unlock()

	info = detector.GetCachedInfo()
	assert.NotNil(t, info)
	assert.Equal(t, NATTypeFullCone, info.Type)
	assert.True(t, info.IsBehindNAT)
}

func TestNATDetectorGetMappedAddress(t *testing.T) {
	detector := NewNATDetector([]string{}, 5*time.Second)

	t.Run("no cached info", func(t *testing.T) {
		addr, ok := detector.GetMappedAddress()
		assert.False(t, ok)
		assert.False(t, addr.IsValid())
	})

	t.Run("with cached info", func(t *testing.T) {
		mappedAddr := netip.MustParseAddrPort("203.0.113.50:12345")
		detector.mu.Lock()
		detector.cachedInfo = &NATInfo{
			MappedAddress: mappedAddr,
		}
		detector.mu.Unlock()

		addr, ok := detector.GetMappedAddress()
		assert.True(t, ok)
		assert.Equal(t, mappedAddr, addr)
	})
}

func TestNATDetectorClose(t *testing.T) {
	detector := NewNATDetector([]string{}, 5*time.Second)

	err := detector.Close()
	assert.NoError(t, err)
}

func TestCanTraverse(t *testing.T) {
	tests := []struct {
		name     string
		nat1     NATType
		nat2     NATType
		expected bool
	}{
		// Both friendly
		{"none-none", NATTypeNone, NATTypeNone, true},
		{"fullcone-fullcone", NATTypeFullCone, NATTypeFullCone, true},
		{"restricted-restricted", NATTypeRestrictedCone, NATTypeRestrictedCone, true},
		{"portrestricted-portrestricted", NATTypePortRestricted, NATTypePortRestricted, true},
		{"none-fullcone", NATTypeNone, NATTypeFullCone, true},

		// One symmetric with full cone
		{"symmetric-fullcone", NATTypeSymmetric, NATTypeFullCone, true},
		{"fullcone-symmetric", NATTypeFullCone, NATTypeSymmetric, true},

		// One symmetric with non-full-cone - fails
		{"symmetric-restricted", NATTypeSymmetric, NATTypeRestrictedCone, false},
		{"symmetric-portrestricted", NATTypeSymmetric, NATTypePortRestricted, false},
		{"symmetric-symmetric", NATTypeSymmetric, NATTypeSymmetric, false},
		{"symmetric-none", NATTypeSymmetric, NATTypeNone, false}, // none is not full cone

		// Mixed friendly types
		{"none-restricted", NATTypeNone, NATTypeRestrictedCone, true},
		{"fullcone-portrestricted", NATTypeFullCone, NATTypePortRestricted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanTraverse(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRecommendedTraversalStrategy(t *testing.T) {
	tests := []struct {
		name     string
		nat1     NATType
		nat2     NATType
		expected string
	}{
		// Can't traverse - relay
		{"symmetric-symmetric", NATTypeSymmetric, NATTypeSymmetric, "relay"},
		{"symmetric-portrestricted", NATTypeSymmetric, NATTypePortRestricted, "relay"},

		// One is none - direct
		{"none-none", NATTypeNone, NATTypeNone, "direct"},
		{"none-fullcone", NATTypeNone, NATTypeFullCone, "direct"},
		{"none-symmetric", NATTypeNone, NATTypeSymmetric, "direct"},
		{"portrestricted-none", NATTypePortRestricted, NATTypeNone, "direct"},

		// Both full cone - direct
		{"fullcone-fullcone", NATTypeFullCone, NATTypeFullCone, "direct"},

		// Symmetric with full cone
		{"symmetric-fullcone", NATTypeSymmetric, NATTypeFullCone, "direct_to_full_cone"},
		{"fullcone-symmetric", NATTypeFullCone, NATTypeSymmetric, "direct_to_full_cone"},

		// Restricted types - hole punch
		{"restricted-restricted", NATTypeRestrictedCone, NATTypeRestrictedCone, "hole_punch"},
		{"portrestricted-portrestricted", NATTypePortRestricted, NATTypePortRestricted, "hole_punch"},
		{"fullcone-restricted", NATTypeFullCone, NATTypeRestrictedCone, "hole_punch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RecommendedTraversalStrategy(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNATDetectorDetect(t *testing.T) {
	t.Run("with mock STUN server", func(t *testing.T) {
		// Create mock STUN server
		serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer serverConn.Close()

		serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

		// Start mock server
		go handleMockSTUNRequests(serverConn)

		detector := NewNATDetector([]string{serverAddr.String()}, 5*time.Second)
		defer detector.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		info, err := detector.Detect(ctx)
		require.NoError(t, err)
		assert.NotNil(t, info)
		assert.True(t, info.IsBehindNAT)
		assert.NotZero(t, info.DetectedAt)
	})

	t.Run("with two mock servers for NAT type detection", func(t *testing.T) {
		// Create two mock STUN servers
		server1Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer server1Conn.Close()

		server2Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer server2Conn.Close()

		server1Addr := server1Conn.LocalAddr().(*net.UDPAddr)
		server2Addr := server2Conn.LocalAddr().(*net.UDPAddr)

		// Start mock servers - same mapped address means not symmetric
		go handleMockSTUNRequestsWithAddress(server1Conn, "198.51.100.1", 12345)
		go handleMockSTUNRequestsWithAddress(server2Conn, "198.51.100.1", 12345)

		detector := NewNATDetector([]string{
			server1Addr.String(),
			server2Addr.String(),
		}, 5*time.Second)
		defer detector.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		info, err := detector.Detect(ctx)
		require.NoError(t, err)
		assert.NotNil(t, info)
		// Same address from both servers means port restricted (not symmetric)
		assert.Equal(t, NATTypePortRestricted, info.Type)
	})

	t.Run("symmetric NAT detection", func(t *testing.T) {
		// Create two mock STUN servers
		server1Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer server1Conn.Close()

		server2Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer server2Conn.Close()

		server1Addr := server1Conn.LocalAddr().(*net.UDPAddr)
		server2Addr := server2Conn.LocalAddr().(*net.UDPAddr)

		// Start mock servers - different mapped addresses means symmetric
		go handleMockSTUNRequestsWithAddress(server1Conn, "198.51.100.1", 12345)
		go handleMockSTUNRequestsWithAddress(server2Conn, "198.51.100.1", 54321) // Different port

		detector := NewNATDetector([]string{
			server1Addr.String(),
			server2Addr.String(),
		}, 5*time.Second)
		defer detector.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		info, err := detector.Detect(ctx)
		require.NoError(t, err)
		assert.NotNil(t, info)
		// Different port from different servers means symmetric
		assert.Equal(t, NATTypeSymmetric, info.Type)
	})

	t.Run("timeout on STUN", func(t *testing.T) {
		detector := NewNATDetector([]string{"192.0.2.1:3478"}, 100*time.Millisecond)
		defer detector.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		_, err := detector.Detect(ctx)
		assert.Error(t, err)
	})
}

func TestNATInfo(t *testing.T) {
	info := NATInfo{
		Type:          NATTypeFullCone,
		MappedAddress: netip.MustParseAddrPort("203.0.113.50:12345"),
		LocalAddress:  netip.MustParseAddrPort("192.168.1.100:54321"),
		IsBehindNAT:   true,
		Hairpin:       false,
		DetectedAt:    time.Now(),
	}

	assert.Equal(t, NATTypeFullCone, info.Type)
	assert.Equal(t, netip.MustParseAddrPort("203.0.113.50:12345"), info.MappedAddress)
	assert.Equal(t, netip.MustParseAddrPort("192.168.1.100:54321"), info.LocalAddress)
	assert.True(t, info.IsBehindNAT)
	assert.False(t, info.Hairpin)
}

// Helper function to handle STUN requests
func handleMockSTUNRequests(conn net.PacketConn) {
	handleMockSTUNRequestsWithAddress(conn, "198.51.100.1", 12345)
}

func handleMockSTUNRequestsWithAddress(conn net.PacketConn, ip string, port int) {
	buf := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < stunHeaderSize {
			continue
		}

		transactionID := buf[8:20]
		response := buildMockSTUNResponseWithIP(transactionID, ip, port)
		conn.WriteTo(response, clientAddr)
	}
}

func buildMockSTUNResponseWithIP(transactionID []byte, ipStr string, port int) []byte {
	// Build XOR-MAPPED-ADDRESS attribute
	attrData := make([]byte, 8)
	attrData[1] = 0x01 // IPv4

	// Port XORed
	xorPort := uint16(port) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(attrData[2:4], xorPort)

	// IP XORed
	ip := netip.MustParseAddr(ipStr)
	ipBytes := ip.As4()
	ipUint := binary.BigEndian.Uint32(ipBytes[:])
	xorIP := ipUint ^ stunMagicCookie
	binary.BigEndian.PutUint32(attrData[4:8], xorIP)

	// Build response
	response := make([]byte, stunHeaderSize+4+8)
	binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint16(response[2:4], 12)
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)

	binary.BigEndian.PutUint16(response[20:22], stunAttrXORMappedAddress)
	binary.BigEndian.PutUint16(response[22:24], 8)
	copy(response[24:32], attrData)

	return response
}
