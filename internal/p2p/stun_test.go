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

func TestNewSTUNClient(t *testing.T) {
	t.Run("with servers and timeout", func(t *testing.T) {
		servers := []string{"stun:stun.example.com:3478"}
		client := NewSTUNClient(servers, 10*time.Second)

		assert.NotNil(t, client)
		assert.Equal(t, servers, client.servers)
		assert.Equal(t, 10*time.Second, client.timeout)
	})

	t.Run("with zero timeout uses default", func(t *testing.T) {
		client := NewSTUNClient([]string{"stun:stun.example.com"}, 0)

		assert.NotNil(t, client)
		assert.Equal(t, 5*time.Second, client.timeout)
	})

	t.Run("empty servers", func(t *testing.T) {
		client := NewSTUNClient(nil, 0)

		assert.NotNil(t, client)
		assert.Empty(t, client.servers)
	})
}

func TestDefaultSTUNServers(t *testing.T) {
	servers := DefaultSTUNServers()

	assert.NotEmpty(t, servers)
	assert.Contains(t, servers[0], "google")
	assert.Equal(t, 5, len(servers))

	// All should have stun: prefix
	for _, server := range servers {
		assert.True(t, len(server) > 5 && server[:5] == "stun:")
	}
}

func TestSTUNClientGetLocalPort(t *testing.T) {
	t.Run("before connection returns 0", func(t *testing.T) {
		client := NewSTUNClient([]string{}, 5*time.Second)

		port := client.GetLocalPort()
		assert.Equal(t, 0, port)
	})
}

func TestSTUNClientClose(t *testing.T) {
	t.Run("close without connection", func(t *testing.T) {
		client := NewSTUNClient([]string{}, 5*time.Second)

		err := client.Close()
		assert.NoError(t, err)
	})

	t.Run("close with connection", func(t *testing.T) {
		client := NewSTUNClient([]string{}, 5*time.Second)

		// Create a connection manually
		conn, err := net.ListenPacket("udp", ":0")
		require.NoError(t, err)

		client.mu.Lock()
		client.conn = conn
		client.mu.Unlock()

		err = client.Close()
		assert.NoError(t, err)

		client.mu.Lock()
		assert.Nil(t, client.conn)
		client.mu.Unlock()
	})
}

func TestResolveSTUNServer(t *testing.T) {
	t.Run("with stun: prefix", func(t *testing.T) {
		addr, err := resolveSTUNServer("stun:127.0.0.1:19302")
		require.NoError(t, err)
		assert.Equal(t, 19302, addr.Port)
		assert.Equal(t, "127.0.0.1", addr.IP.String())
	})

	t.Run("without port uses default 3478", func(t *testing.T) {
		addr, err := resolveSTUNServer("127.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, 3478, addr.Port)
	})

	t.Run("with host and port", func(t *testing.T) {
		addr, err := resolveSTUNServer("127.0.0.1:5000")
		require.NoError(t, err)
		assert.Equal(t, 5000, addr.Port)
	})

	t.Run("invalid hostname", func(t *testing.T) {
		_, err := resolveSTUNServer("nonexistent.invalid.hostname.xyz")
		assert.Error(t, err)
	})

	t.Run("invalid port", func(t *testing.T) {
		_, err := resolveSTUNServer("127.0.0.1:invalid")
		assert.Error(t, err)
	})
}

func TestBuildSTUNBindingRequest(t *testing.T) {
	transactionID := make([]byte, 12)
	for i := range transactionID {
		transactionID[i] = byte(i + 1)
	}

	request := buildSTUNBindingRequest(transactionID)

	// Check header size
	assert.Len(t, request, stunHeaderSize)

	// Check message type (Binding Request)
	msgType := binary.BigEndian.Uint16(request[0:2])
	assert.Equal(t, stunMsgTypeBindingRequest, msgType)

	// Check message length (0 for simple binding request)
	msgLen := binary.BigEndian.Uint16(request[2:4])
	assert.Equal(t, uint16(0), msgLen)

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(request[4:8])
	assert.Equal(t, stunMagicCookie, cookie)

	// Check transaction ID
	assert.Equal(t, transactionID, request[8:20])
}

func TestParseSTUNBindingResponse(t *testing.T) {
	transactionID := make([]byte, 12)
	for i := range transactionID {
		transactionID[i] = byte(i)
	}

	t.Run("valid response with XOR-MAPPED-ADDRESS", func(t *testing.T) {
		// Build a mock response
		response := buildMockSTUNResponse(transactionID, true)

		addr, err := parseSTUNBindingResponse(response, transactionID)
		require.NoError(t, err)
		assert.True(t, addr.IsValid())
	})

	t.Run("valid response with MAPPED-ADDRESS", func(t *testing.T) {
		// Build a mock response with MAPPED-ADDRESS
		response := buildMockSTUNResponseMapped(transactionID)

		addr, err := parseSTUNBindingResponse(response, transactionID)
		require.NoError(t, err)
		assert.True(t, addr.IsValid())
	})

	t.Run("too short", func(t *testing.T) {
		_, err := parseSTUNBindingResponse([]byte{0, 1, 2}, transactionID)
		assert.Equal(t, ErrSTUNInvalidResponse, err)
	})

	t.Run("wrong message type", func(t *testing.T) {
		response := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingError)
		binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
		copy(response[8:20], transactionID)

		_, err := parseSTUNBindingResponse(response, transactionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected message type")
	})

	t.Run("wrong magic cookie", func(t *testing.T) {
		response := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
		binary.BigEndian.PutUint32(response[4:8], 0x12345678) // Wrong cookie
		copy(response[8:20], transactionID)

		_, err := parseSTUNBindingResponse(response, transactionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid magic cookie")
	})

	t.Run("wrong transaction ID", func(t *testing.T) {
		response := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
		binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
		wrongTxID := make([]byte, 12)
		copy(wrongTxID, transactionID)
		wrongTxID[0] = 0xFF // Change one byte
		copy(response[8:20], wrongTxID)

		_, err := parseSTUNBindingResponse(response, transactionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction ID mismatch")
	})

	t.Run("message length mismatch", func(t *testing.T) {
		response := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
		binary.BigEndian.PutUint16(response[2:4], 100) // Claim 100 bytes but only have header
		binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
		copy(response[8:20], transactionID)

		_, err := parseSTUNBindingResponse(response, transactionID)
		assert.Equal(t, ErrSTUNInvalidResponse, err)
	})

	t.Run("no mapped address", func(t *testing.T) {
		// Build response without any address attributes
		response := make([]byte, stunHeaderSize+8)
		binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
		binary.BigEndian.PutUint16(response[2:4], 8) // Has attributes but not address
		binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
		copy(response[8:20], transactionID)

		// Add SOFTWARE attribute instead of address
		binary.BigEndian.PutUint16(response[20:22], stunAttrSoftware)
		binary.BigEndian.PutUint16(response[22:24], 4)
		copy(response[24:28], []byte("test"))

		_, err := parseSTUNBindingResponse(response, transactionID)
		assert.Equal(t, ErrSTUNNoMappedAddress, err)
	})
}

func TestParseMappedAddress(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		// Format: reserved (1) + family (1) + port (2) + ip (4)
		data := []byte{0, 0x01, 0x04, 0x00, 192, 168, 1, 1}

		addr, err := parseMappedAddress(data)
		require.NoError(t, err)
		assert.Equal(t, netip.MustParseAddr("192.168.1.1"), addr.Addr())
		assert.Equal(t, uint16(1024), addr.Port())
	})

	t.Run("IPv6", func(t *testing.T) {
		// Format: reserved (1) + family (1) + port (2) + ip (16)
		data := make([]byte, 20)
		data[1] = 0x02 // IPv6 family
		binary.BigEndian.PutUint16(data[2:4], 8080)
		// Set IPv6 address (::1)
		data[19] = 1

		addr, err := parseMappedAddress(data)
		require.NoError(t, err)
		assert.True(t, addr.Addr().Is6())
		assert.Equal(t, uint16(8080), addr.Port())
	})

	t.Run("too short for header", func(t *testing.T) {
		_, err := parseMappedAddress([]byte{0, 1, 2})
		assert.Equal(t, ErrSTUNInvalidResponse, err)
	})

	t.Run("too short for IPv4", func(t *testing.T) {
		data := []byte{0, 0x01, 0x04, 0x00, 192, 168, 1} // Missing last byte
		_, err := parseMappedAddress(data)
		assert.Equal(t, ErrSTUNInvalidResponse, err)
	})

	t.Run("too short for IPv6", func(t *testing.T) {
		data := make([]byte, 10) // Not enough for IPv6
		data[1] = 0x02           // IPv6 family
		_, err := parseMappedAddress(data)
		assert.Equal(t, ErrSTUNInvalidResponse, err)
	})

	t.Run("unknown address family", func(t *testing.T) {
		data := []byte{0, 0x99, 0x04, 0x00, 192, 168, 1, 1}
		_, err := parseMappedAddress(data)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown address family")
	})
}

func TestParseXORMappedAddress(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		// Build XOR-MAPPED-ADDRESS
		// The actual IP and port are XORed with magic cookie
		data := make([]byte, 8)
		data[1] = 0x01 // IPv4 family

		// Port XOR with high 16 bits of magic cookie
		port := uint16(1234)
		xorPort := port ^ uint16(stunMagicCookie>>16)
		binary.BigEndian.PutUint16(data[2:4], xorPort)

		// IP XOR with magic cookie
		ip := netip.MustParseAddr("203.0.113.50")
		ipBytes := ip.As4()
		ipUint := binary.BigEndian.Uint32(ipBytes[:])
		xorIP := ipUint ^ stunMagicCookie
		binary.BigEndian.PutUint32(data[4:8], xorIP)

		addr, err := parseXORMappedAddress(data)
		require.NoError(t, err)
		assert.Equal(t, ip, addr.Addr())
		assert.Equal(t, port, addr.Port())
	})

	t.Run("IPv6", func(t *testing.T) {
		// For IPv6, the implementation is simplified (doesn't fully XOR)
		data := make([]byte, 20)
		data[1] = 0x02 // IPv6 family
		binary.BigEndian.PutUint16(data[2:4], 8080^uint16(stunMagicCookie>>16))
		data[19] = 1

		addr, err := parseXORMappedAddress(data)
		require.NoError(t, err)
		assert.True(t, addr.Addr().Is6())
	})

	t.Run("too short", func(t *testing.T) {
		_, err := parseXORMappedAddress([]byte{0, 1, 2})
		assert.Equal(t, ErrSTUNInvalidResponse, err)
	})

	t.Run("unknown family", func(t *testing.T) {
		data := make([]byte, 8)
		data[1] = 0x99
		_, err := parseXORMappedAddress(data)
		assert.Error(t, err)
	})
}

func TestSTUNErrors(t *testing.T) {
	assert.Equal(t, "stun: request timed out", ErrSTUNTimeout.Error())
	assert.Equal(t, "stun: invalid response", ErrSTUNInvalidResponse.Error())
	assert.Equal(t, "stun: no mapped address in response", ErrSTUNNoMappedAddress.Error())
}

func TestSTUNClientBind(t *testing.T) {
	t.Run("no servers returns timeout", func(t *testing.T) {
		client := NewSTUNClient(nil, 100*time.Millisecond)

		ctx := context.Background()
		_, err := client.Bind(ctx)
		assert.Equal(t, ErrSTUNTimeout, err)
	})

	t.Run("with mock server", func(t *testing.T) {
		// Create a mock STUN server
		serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer serverConn.Close()

		serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

		// Start mock server
		go func() {
			buf := make([]byte, 1024)
			n, clientAddr, readErr := serverConn.ReadFrom(buf)
			if readErr != nil {
				return
			}

			// Parse request to get transaction ID
			if n < stunHeaderSize {
				return
			}
			transactionID := buf[8:20]

			// Build response
			response := buildMockSTUNResponse(transactionID, true)
			serverConn.WriteTo(response, clientAddr)
		}()

		client := NewSTUNClient([]string{serverAddr.String()}, 5*time.Second)
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := client.Bind(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.MappedAddress.IsValid())
		assert.Equal(t, serverAddr.String(), result.Server)
		assert.True(t, result.RTT > 0)
	})

	t.Run("context canceled", func(t *testing.T) {
		client := NewSTUNClient([]string{"192.0.2.1:3478"}, 10*time.Second)
		defer client.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.Bind(ctx)
		assert.Error(t, err)
	})
}

// Helper function to build a mock STUN response
func buildMockSTUNResponse(transactionID []byte, useXOR bool) []byte {
	// Build XOR-MAPPED-ADDRESS attribute
	attrData := make([]byte, 8)
	attrData[1] = 0x01 // IPv4

	// Port 12345 XORed
	port := uint16(12345)
	xorPort := port ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(attrData[2:4], xorPort)

	// IP 198.51.100.1 XORed
	ip := netip.MustParseAddr("198.51.100.1")
	ipBytes := ip.As4()
	ipUint := binary.BigEndian.Uint32(ipBytes[:])
	xorIP := ipUint ^ stunMagicCookie
	binary.BigEndian.PutUint32(attrData[4:8], xorIP)

	// Build response
	attrType := stunAttrXORMappedAddress
	if !useXOR {
		attrType = stunAttrMappedAddress
	}

	response := make([]byte, stunHeaderSize+4+8) // header + attr header + attr data
	binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint16(response[2:4], 12) // attribute length
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)

	// Attribute
	binary.BigEndian.PutUint16(response[20:22], attrType)
	binary.BigEndian.PutUint16(response[22:24], 8)
	copy(response[24:32], attrData)

	return response
}

// Helper function to build a mock STUN response with MAPPED-ADDRESS
func buildMockSTUNResponseMapped(transactionID []byte) []byte {
	// Build MAPPED-ADDRESS attribute (not XORed)
	attrData := make([]byte, 8)
	attrData[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(attrData[2:4], 12345)
	copy(attrData[4:8], []byte{198, 51, 100, 1})

	response := make([]byte, stunHeaderSize+4+8)
	binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint16(response[2:4], 12)
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)

	binary.BigEndian.PutUint16(response[20:22], stunAttrMappedAddress)
	binary.BigEndian.PutUint16(response[22:24], 8)
	copy(response[24:32], attrData)

	return response
}

func TestSTUNBindWithDeadline(t *testing.T) {
	// Create a mock STUN server that delays response
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Start mock server that delays
	go func() {
		buf := make([]byte, 1024)
		n, clientAddr, readErr := serverConn.ReadFrom(buf)
		if readErr != nil {
			return
		}

		// Delay before responding
		time.Sleep(200 * time.Millisecond)

		if n >= stunHeaderSize {
			transactionID := buf[8:20]
			response := buildMockSTUNResponse(transactionID, true)
			serverConn.WriteTo(response, clientAddr)
		}
	}()

	client := NewSTUNClient([]string{serverAddr.String()}, 50*time.Millisecond)
	defer client.Close()

	ctx := context.Background()
	_, err = client.Bind(ctx)
	assert.Equal(t, ErrSTUNTimeout, err)
}

func TestSTUNParseResponseWithPadding(t *testing.T) {
	transactionID := make([]byte, 12)

	// Build response with attribute that needs padding
	response := make([]byte, stunHeaderSize+4+5+3) // header + attr header + 5 bytes data + 3 padding
	binary.BigEndian.PutUint16(response[0:2], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint16(response[2:4], 8) // 4 + 5 rounded to 8
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)

	// Add SOFTWARE attribute with 5 bytes (needs padding to 8)
	binary.BigEndian.PutUint16(response[20:22], stunAttrSoftware)
	binary.BigEndian.PutUint16(response[22:24], 5)
	copy(response[24:29], []byte("test!"))

	// This should parse without error but return no mapped address
	_, err := parseSTUNBindingResponse(response, transactionID)
	assert.Equal(t, ErrSTUNNoMappedAddress, err)
}
