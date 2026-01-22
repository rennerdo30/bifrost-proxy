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

func TestNewTURNClient(t *testing.T) {
	t.Run("with all options", func(t *testing.T) {
		config := TURNConfig{
			Server:   "turn:turn.example.com:3478",
			Username: "user",
			Password: "pass",
			Timeout:  10 * time.Second,
		}

		client := NewTURNClient(config)

		assert.NotNil(t, client)
		assert.Equal(t, config.Server, client.server)
		assert.Equal(t, config.Username, client.username)
		assert.Equal(t, config.Password, client.password)
		assert.Equal(t, 10*time.Second, client.timeout)
		assert.NotNil(t, client.channels)
		assert.NotNil(t, client.permissions)
		assert.Equal(t, uint16(0x4000), client.nextChannel)
	})

	t.Run("with default timeout", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:turn.example.com",
		}

		client := NewTURNClient(config)

		assert.Equal(t, 10*time.Second, client.timeout)
	})
}

func TestTURNErrors(t *testing.T) {
	assert.Equal(t, "turn: allocation failed", ErrTURNAllocationFailed.Error())
	assert.Equal(t, "turn: request timed out", ErrTURNTimeout.Error())
	assert.Equal(t, "turn: unauthorized", ErrTURNUnauthorized.Error())
	assert.Equal(t, "turn: no relay address allocated", ErrTURNNoRelayAddress.Error())
}

func TestTURNClientRelayAddressNotAllocated(t *testing.T) {
	config := TURNConfig{
		Server: "turn:turn.example.com",
	}
	client := NewTURNClient(config)

	_, err := client.RelayAddress()
	assert.Equal(t, ErrTURNNoRelayAddress, err)
}

func TestTURNClientClose(t *testing.T) {
	t.Run("close without allocation", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:turn.example.com",
		}
		client := NewTURNClient(config)

		err := client.Close()
		assert.NoError(t, err)
	})
}

func TestResolveTURNServer(t *testing.T) {
	t.Run("with turn: prefix", func(t *testing.T) {
		addr, err := resolveTURNServer("turn:127.0.0.1:3478")
		require.NoError(t, err)
		assert.Equal(t, 3478, addr.Port)
		assert.Equal(t, "127.0.0.1", addr.IP.String())
	})

	t.Run("without port uses default", func(t *testing.T) {
		addr, err := resolveTURNServer("127.0.0.1")
		require.NoError(t, err)
		assert.Equal(t, 3478, addr.Port)
	})

	t.Run("with host and port", func(t *testing.T) {
		addr, err := resolveTURNServer("127.0.0.1:5000")
		require.NoError(t, err)
		assert.Equal(t, 5000, addr.Port)
	})

	t.Run("invalid hostname", func(t *testing.T) {
		_, err := resolveTURNServer("nonexistent.invalid.hostname.xyz")
		assert.Error(t, err)
	})
}

func TestGenerateTransactionID(t *testing.T) {
	id1 := generateTransactionID()
	assert.Len(t, id1, 12)

	// Wait a tiny bit and generate another
	time.Sleep(time.Nanosecond)
	id2 := generateTransactionID()
	assert.Len(t, id2, 12)

	// Should be different (time-based)
	assert.NotEqual(t, id1, id2)
}

func TestBuildXORPeerAddress(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.100")

	data := buildXORPeerAddress(ip)

	assert.Len(t, data, 8)
	assert.Equal(t, byte(0x01), data[1]) // IPv4

	// Verify XORed IP
	xorAddr := binary.BigEndian.Uint32(data[4:8])
	ipBytes := ip.As4()
	originalIP := binary.BigEndian.Uint32(ipBytes[:])
	assert.Equal(t, originalIP^stunMagicCookie, xorAddr)
}

func TestBuildXORPeerAddressPort(t *testing.T) {
	addrPort := netip.MustParseAddrPort("192.168.1.100:12345")

	data := buildXORPeerAddressPort(addrPort)

	assert.Len(t, data, 8)
	assert.Equal(t, byte(0x01), data[1]) // IPv4

	// Verify XORed port
	xorPort := binary.BigEndian.Uint16(data[2:4])
	assert.Equal(t, uint16(12345)^uint16(stunMagicCookie>>16), xorPort)

	// Verify XORed IP
	xorAddr := binary.BigEndian.Uint32(data[4:8])
	ip := addrPort.Addr()
	ipBytes := ip.As4()
	originalIP := binary.BigEndian.Uint32(ipBytes[:])
	assert.Equal(t, originalIP^stunMagicCookie, xorAddr)
}

func TestParseSTUNMessage(t *testing.T) {
	transactionID := make([]byte, 12)
	for i := range transactionID {
		transactionID[i] = byte(i)
	}

	t.Run("valid message", func(t *testing.T) {
		msg := make([]byte, stunHeaderSize+8)
		binary.BigEndian.PutUint16(msg[0:2], turnMsgTypeAllocateSuccess)
		binary.BigEndian.PutUint16(msg[2:4], 8) // attributes length
		binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
		copy(msg[8:20], transactionID)

		// Add an attribute
		binary.BigEndian.PutUint16(msg[20:22], turnAttrLifetime)
		binary.BigEndian.PutUint16(msg[22:24], 4)
		binary.BigEndian.PutUint32(msg[24:28], 600)

		msgType, txID, attrs, err := parseSTUNMessage(msg, transactionID)
		require.NoError(t, err)
		assert.Equal(t, turnMsgTypeAllocateSuccess, msgType)
		assert.Equal(t, transactionID, txID)
		assert.Contains(t, attrs, turnAttrLifetime)
	})

	t.Run("too short", func(t *testing.T) {
		_, _, _, err := parseSTUNMessage([]byte{0, 1, 2}, nil)
		assert.Error(t, err)
	})

	t.Run("transaction ID mismatch", func(t *testing.T) {
		msg := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(msg[0:2], turnMsgTypeAllocateSuccess)
		binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
		copy(msg[8:20], transactionID)

		wrongTxID := make([]byte, 12)
		wrongTxID[0] = 0xFF

		_, _, _, err := parseSTUNMessage(msg, wrongTxID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction ID mismatch")
	})

	t.Run("nil expected transaction ID", func(t *testing.T) {
		msg := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(msg[0:2], turnMsgTypeAllocateSuccess)
		binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
		copy(msg[8:20], transactionID)

		_, _, _, err := parseSTUNMessage(msg, nil)
		assert.NoError(t, err)
	})

	t.Run("with padding", func(t *testing.T) {
		msg := make([]byte, stunHeaderSize+12) // 4 byte header + 5 bytes data + 3 padding
		binary.BigEndian.PutUint16(msg[0:2], turnMsgTypeAllocateSuccess)
		binary.BigEndian.PutUint16(msg[2:4], 12)
		binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
		copy(msg[8:20], transactionID)

		// Add attribute with 5 bytes (needs padding)
		binary.BigEndian.PutUint16(msg[20:22], turnAttrRealm)
		binary.BigEndian.PutUint16(msg[22:24], 5)
		copy(msg[24:29], []byte("realm"))

		_, _, attrs, err := parseSTUNMessage(msg, nil)
		require.NoError(t, err)
		assert.Equal(t, "realm", string(attrs[turnAttrRealm]))
	})
}

func TestBuildSTUNMessage(t *testing.T) {
	transactionID := make([]byte, 12)

	t.Run("without authentication", func(t *testing.T) {
		attrs := []struct {
			typ  uint16
			data []byte
		}{
			{turnAttrRequestedTransport, []byte{17, 0, 0, 0}},
		}

		msg := buildSTUNMessage(turnMsgTypeAllocate, transactionID, attrs, "", "", "", false)

		assert.NotNil(t, msg)
		// Check header
		msgType := binary.BigEndian.Uint16(msg[0:2])
		assert.Equal(t, turnMsgTypeAllocate, msgType)

		cookie := binary.BigEndian.Uint32(msg[4:8])
		assert.Equal(t, stunMagicCookie, cookie)
	})

	t.Run("with authentication", func(t *testing.T) {
		attrs := []struct {
			typ  uint16
			data []byte
		}{
			{turnAttrRequestedTransport, []byte{17, 0, 0, 0}},
		}

		msg := buildSTUNMessage(turnMsgTypeAllocate, transactionID, attrs, "user", "pass", "realm", true)

		assert.NotNil(t, msg)
		// Should include MESSAGE-INTEGRITY
		msgLen := binary.BigEndian.Uint16(msg[2:4])
		assert.Greater(t, msgLen, uint16(4)) // At least attribute + integrity
	})
}

func TestComputeLongTermKey(t *testing.T) {
	key := computeLongTermKey("user", "realm", "password")

	assert.Len(t, key, 16)
	assert.NotZero(t, key)

	// Same inputs should produce same output
	key2 := computeLongTermKey("user", "realm", "password")
	assert.Equal(t, key, key2)

	// Different inputs should produce different output
	key3 := computeLongTermKey("user2", "realm", "password")
	assert.NotEqual(t, key, key3)
}

func TestTURNClientCreatePermission(t *testing.T) {
	t.Run("not allocated", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:127.0.0.1:3478",
		}
		client := NewTURNClient(config)

		ctx := context.Background()
		err := client.CreatePermission(ctx, netip.MustParseAddr("192.168.1.100"))
		assert.Equal(t, ErrTURNNoRelayAddress, err)
	})
}

func TestTURNClientBindChannel(t *testing.T) {
	t.Run("not allocated", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:127.0.0.1:3478",
		}
		client := NewTURNClient(config)

		ctx := context.Background()
		_, err := client.BindChannel(ctx, netip.MustParseAddrPort("192.168.1.100:12345"))
		assert.Equal(t, ErrTURNNoRelayAddress, err)
	})
}

func TestTURNClientSend(t *testing.T) {
	t.Run("not allocated", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:127.0.0.1:3478",
		}
		client := NewTURNClient(config)

		err := client.Send(netip.MustParseAddrPort("192.168.1.100:12345"), []byte("test"))
		assert.Equal(t, ErrTURNNoRelayAddress, err)
	})
}

func TestTURNClientReceive(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:127.0.0.1:3478",
		}
		client := NewTURNClient(config)

		buf := make([]byte, 1024)
		_, _, err := client.Receive(buf)
		assert.Error(t, err)
	})
}

func TestTURNClientRefresh(t *testing.T) {
	t.Run("not allocated", func(t *testing.T) {
		config := TURNConfig{
			Server: "turn:127.0.0.1:3478",
		}
		client := NewTURNClient(config)

		ctx := context.Background()
		err := client.Refresh(ctx)
		assert.NoError(t, err) // No error when not allocated
	})
}

func TestTURNClientBuildAllocateRequest(t *testing.T) {
	config := TURNConfig{
		Server:   "turn:127.0.0.1:3478",
		Username: "user",
		Password: "pass",
	}
	client := NewTURNClient(config)
	client.realm = "testrealm"
	client.nonce = "testnonce"

	transactionID := make([]byte, 12)

	t.Run("unauthenticated", func(t *testing.T) {
		request := client.buildAllocateRequest(transactionID, false)
		assert.NotNil(t, request)
		assert.GreaterOrEqual(t, len(request), stunHeaderSize)
	})

	t.Run("authenticated", func(t *testing.T) {
		request := client.buildAllocateRequest(transactionID, true)
		assert.NotNil(t, request)
		assert.Greater(t, len(request), stunHeaderSize) // Should include auth attrs
	})
}

func TestTURNClientBuildCreatePermissionRequest(t *testing.T) {
	config := TURNConfig{
		Server:   "turn:127.0.0.1:3478",
		Username: "user",
		Password: "pass",
	}
	client := NewTURNClient(config)
	client.realm = "testrealm"

	transactionID := make([]byte, 12)
	peerIP := netip.MustParseAddr("192.168.1.100")

	request := client.buildCreatePermissionRequest(transactionID, peerIP)
	assert.NotNil(t, request)
	assert.GreaterOrEqual(t, len(request), stunHeaderSize)
}

func TestTURNClientBuildChannelBindRequest(t *testing.T) {
	config := TURNConfig{
		Server:   "turn:127.0.0.1:3478",
		Username: "user",
		Password: "pass",
	}
	client := NewTURNClient(config)
	client.realm = "testrealm"

	transactionID := make([]byte, 12)
	peerAddr := netip.MustParseAddrPort("192.168.1.100:12345")

	request := client.buildChannelBindRequest(transactionID, 0x4000, peerAddr)
	assert.NotNil(t, request)
	assert.GreaterOrEqual(t, len(request), stunHeaderSize)
}

func TestTURNClientBuildSendIndication(t *testing.T) {
	config := TURNConfig{
		Server: "turn:127.0.0.1:3478",
	}
	client := NewTURNClient(config)

	transactionID := make([]byte, 12)
	peerAddr := netip.MustParseAddrPort("192.168.1.100:12345")
	data := []byte("test data")

	request := client.buildSendIndication(transactionID, peerAddr, data)
	assert.NotNil(t, request)
	assert.GreaterOrEqual(t, len(request), stunHeaderSize)
}

func TestTURNClientBuildRefreshRequest(t *testing.T) {
	config := TURNConfig{
		Server:   "turn:127.0.0.1:3478",
		Username: "user",
		Password: "pass",
	}
	client := NewTURNClient(config)
	client.realm = "testrealm"

	transactionID := make([]byte, 12)

	request := client.buildRefreshRequest(transactionID)
	assert.NotNil(t, request)
	assert.GreaterOrEqual(t, len(request), stunHeaderSize)
}

func TestTURNClientAllocateWithMockServer(t *testing.T) {
	// Create mock TURN server
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Start mock server
	go handleMockTURNServer(serverConn)

	config := TURNConfig{
		Server:   serverAddr.String(),
		Username: "testuser",
		Password: "testpass",
		Timeout:  5 * time.Second,
	}
	client := NewTURNClient(config)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Allocate(ctx)
	require.NoError(t, err)
	assert.True(t, client.allocated)

	// Get relay address
	addr, err := client.RelayAddress()
	require.NoError(t, err)
	assert.True(t, addr.IsValid())

	// Allocate again should be no-op
	err = client.Allocate(ctx)
	assert.NoError(t, err)
}

func TestTURNClientWithChannelBinding(t *testing.T) {
	// Create mock TURN server
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Start mock server
	go handleMockTURNServerWithChannelBind(serverConn)

	config := TURNConfig{
		Server:   serverAddr.String(),
		Username: "testuser",
		Password: "testpass",
		Timeout:  5 * time.Second,
	}
	client := NewTURNClient(config)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Allocate(ctx)
	require.NoError(t, err)

	peerAddr := netip.MustParseAddrPort("192.168.1.100:12345")

	// Create permission first
	err = client.CreatePermission(ctx, peerAddr.Addr())
	require.NoError(t, err)

	// Bind channel
	channel, err := client.BindChannel(ctx, peerAddr)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, channel, uint16(0x4000))

	// Bind same channel again should return cached
	channel2, err := client.BindChannel(ctx, peerAddr)
	require.NoError(t, err)
	assert.Equal(t, channel, channel2)
}

func TestTURNClientSendWithChannel(t *testing.T) {
	// Create mock TURN server
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Start mock server
	go handleMockTURNServerWithChannelBind(serverConn)

	config := TURNConfig{
		Server:   serverAddr.String(),
		Username: "testuser",
		Password: "testpass",
		Timeout:  5 * time.Second,
	}
	client := NewTURNClient(config)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Allocate(ctx)
	require.NoError(t, err)

	peerAddr := netip.MustParseAddrPort("192.168.1.100:12345")

	// Create permission and bind channel
	client.CreatePermission(ctx, peerAddr.Addr())
	_, err = client.BindChannel(ctx, peerAddr)
	require.NoError(t, err)

	// Send via channel
	err = client.Send(peerAddr, []byte("test data"))
	assert.NoError(t, err)
}

func TestTURNClientSendWithIndication(t *testing.T) {
	// Create mock TURN server
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Start mock server
	go handleMockTURNServer(serverConn)

	config := TURNConfig{
		Server:   serverAddr.String(),
		Username: "testuser",
		Password: "testpass",
		Timeout:  5 * time.Second,
	}
	client := NewTURNClient(config)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Allocate(ctx)
	require.NoError(t, err)

	// Send without channel binding - uses Send indication
	peerAddr := netip.MustParseAddrPort("192.168.1.100:12345")
	err = client.Send(peerAddr, []byte("test data"))
	assert.NoError(t, err)
}

// Mock TURN server handlers
func handleMockTURNServer(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < stunHeaderSize {
			continue
		}

		msgType := binary.BigEndian.Uint16(buf[0:2])
		transactionID := buf[8:20]

		switch msgType {
		case turnMsgTypeAllocate:
			// Check if this is the first request (401 response) or authenticated
			response := buildTURNAllocateSuccess(transactionID)
			conn.WriteTo(response, clientAddr)

		case turnMsgTypeRefresh:
			response := buildTURNRefreshSuccess(transactionID)
			conn.WriteTo(response, clientAddr)

		case turnMsgTypeCreatePermission:
			response := buildTURNCreatePermissionSuccess(transactionID)
			conn.WriteTo(response, clientAddr)
		}
	}
}

func handleMockTURNServerWithChannelBind(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < 4 {
			continue
		}

		// Check if it's a channel data message
		if buf[0]&0xC0 == 0x40 {
			continue // Channel data, ignore
		}

		if n < stunHeaderSize {
			continue
		}

		msgType := binary.BigEndian.Uint16(buf[0:2])
		transactionID := buf[8:20]

		switch msgType {
		case turnMsgTypeAllocate:
			response := buildTURNAllocateSuccess(transactionID)
			conn.WriteTo(response, clientAddr)

		case turnMsgTypeRefresh:
			response := buildTURNRefreshSuccess(transactionID)
			conn.WriteTo(response, clientAddr)

		case turnMsgTypeCreatePermission:
			response := buildTURNCreatePermissionSuccess(transactionID)
			conn.WriteTo(response, clientAddr)

		case turnMsgTypeChannelBind:
			response := buildTURNChannelBindSuccess(transactionID)
			conn.WriteTo(response, clientAddr)
		}
	}
}

func buildTURNAllocateSuccess(transactionID []byte) []byte {
	// Build XOR-RELAYED-ADDRESS attribute
	relayAttr := make([]byte, 8)
	relayAttr[1] = 0x01 // IPv4
	xorPort := uint16(54321) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(relayAttr[2:4], xorPort)
	ip := netip.MustParseAddr("198.51.100.50")
	ipBytes := ip.As4()
	ipUint := binary.BigEndian.Uint32(ipBytes[:])
	xorIP := ipUint ^ stunMagicCookie
	binary.BigEndian.PutUint32(relayAttr[4:8], xorIP)

	// Build LIFETIME attribute
	lifetimeAttr := make([]byte, 4)
	binary.BigEndian.PutUint32(lifetimeAttr, 600) // 10 minutes

	// Build response
	response := make([]byte, stunHeaderSize+4+8+4+4)
	binary.BigEndian.PutUint16(response[0:2], turnMsgTypeAllocateSuccess)
	binary.BigEndian.PutUint16(response[2:4], 20) // attributes length
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)

	// XOR-RELAYED-ADDRESS
	binary.BigEndian.PutUint16(response[20:22], turnAttrXORRelayedAddress)
	binary.BigEndian.PutUint16(response[22:24], 8)
	copy(response[24:32], relayAttr)

	// LIFETIME
	binary.BigEndian.PutUint16(response[32:34], turnAttrLifetime)
	binary.BigEndian.PutUint16(response[34:36], 4)
	copy(response[36:40], lifetimeAttr)

	return response
}

func buildTURNRefreshSuccess(transactionID []byte) []byte {
	response := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(response[0:2], turnMsgTypeRefreshSuccess)
	binary.BigEndian.PutUint16(response[2:4], 0)
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)
	return response
}

func buildTURNCreatePermissionSuccess(transactionID []byte) []byte {
	response := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(response[0:2], 0x0108) // CreatePermission success
	binary.BigEndian.PutUint16(response[2:4], 0)
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)
	return response
}

func buildTURNChannelBindSuccess(transactionID []byte) []byte {
	response := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(response[0:2], 0x0109) // ChannelBind success
	binary.BigEndian.PutUint16(response[2:4], 0)
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], transactionID)
	return response
}
