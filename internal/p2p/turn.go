package p2p

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// TURN message types and attributes (RFC 5766).
const (
	turnMsgTypeAllocate        uint16 = 0x0003
	turnMsgTypeAllocateSuccess uint16 = 0x0103
	turnMsgTypeAllocateError   uint16 = 0x0113
	turnMsgTypeRefresh         uint16 = 0x0004
	turnMsgTypeRefreshSuccess  uint16 = 0x0104
	turnMsgTypeSend            uint16 = 0x0006
	turnMsgTypeData            uint16 = 0x0007
	turnMsgTypeCreatePermission uint16 = 0x0008
	turnMsgTypeChannelBind     uint16 = 0x0009
	turnMsgTypeChannelData     uint16 = 0x0040

	turnAttrChannelNumber      uint16 = 0x000C
	turnAttrLifetime           uint16 = 0x000D
	turnAttrXORPeerAddress     uint16 = 0x0012
	turnAttrData               uint16 = 0x0013
	turnAttrXORRelayedAddress  uint16 = 0x0016
	turnAttrRequestedTransport uint16 = 0x0019
	turnAttrDontFragment       uint16 = 0x001A
	turnAttrRealm              uint16 = 0x0014
	turnAttrNonce              uint16 = 0x0015
	turnAttrUsername           uint16 = 0x0006
	turnAttrMessageIntegrity   uint16 = 0x0008
	turnAttrErrorCode          uint16 = 0x0009

	// Transport protocol constants
	transportUDP = 17
)

// Common TURN errors.
var (
	ErrTURNAllocationFailed = errors.New("turn: allocation failed")
	ErrTURNTimeout          = errors.New("turn: request timed out")
	ErrTURNUnauthorized     = errors.New("turn: unauthorized")
	ErrTURNNoRelayAddress   = errors.New("turn: no relay address allocated")
)

// TURNClient handles TURN protocol operations for relay.
type TURNClient struct {
	server   string
	username string
	password string
	timeout  time.Duration

	conn          net.PacketConn
	relayAddr     netip.AddrPort
	lifetime      time.Duration
	realm         string
	nonce         string
	channels      map[netip.AddrPort]uint16 // Peer -> Channel number
	nextChannel   uint16
	permissions   map[netip.Addr]time.Time // Peer IP -> Expiry
	allocated     bool
	allocatedAt   time.Time

	mu sync.Mutex
}

// TURNConfig contains TURN server configuration.
type TURNConfig struct {
	Server   string
	Username string
	Password string
	Timeout  time.Duration
}

// NewTURNClient creates a new TURN client.
func NewTURNClient(config TURNConfig) *TURNClient {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	return &TURNClient{
		server:      config.Server,
		username:    config.Username,
		password:    config.Password,
		timeout:     config.Timeout,
		channels:    make(map[netip.AddrPort]uint16),
		nextChannel: 0x4000, // Channels start at 0x4000
		permissions: make(map[netip.Addr]time.Time),
	}
}

// Allocate requests a relay allocation from the TURN server.
func (c *TURNClient) Allocate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.allocated {
		return nil // Already allocated
	}

	// Parse server address
	addr, err := resolveTURNServer(c.server)
	if err != nil {
		return err
	}

	// Create UDP connection
	c.conn, err = net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// Set deadline
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			slog.Debug("failed to set deadline on TURN connection", "error", err)
		} else {
			slog.Warn("failed to set deadline on TURN connection", "error", err)
		}
	}

	// First request (unauthenticated)
	transactionID := generateTransactionID()
	request := c.buildAllocateRequest(transactionID, false)

	if _, err := c.conn.WriteTo(request, addr); err != nil {
		return fmt.Errorf("failed to send allocate request: %w", err)
	}

	buf := make([]byte, 4096)
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return ErrTURNTimeout
	}

	// Parse response - expect 401 Unauthorized with realm and nonce
	msgType, _, attrs, err := parseSTUNMessage(buf[:n], transactionID)
	if err != nil {
		return err
	}

	if msgType == turnMsgTypeAllocateError {
		// Extract realm and nonce for authentication
		if realm, ok := attrs[turnAttrRealm]; ok {
			c.realm = string(realm)
		}
		if nonce, ok := attrs[turnAttrNonce]; ok {
			c.nonce = string(nonce)
		}

		// Retry with authentication
		transactionID = generateTransactionID()
		request = c.buildAllocateRequest(transactionID, true)

		if _, err := c.conn.WriteTo(request, addr); err != nil {
			return fmt.Errorf("failed to send authenticated allocate request: %w", err)
		}

		if err := c.conn.SetDeadline(deadline); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("failed to set deadline for authenticated request", "error", err)
			} else {
				slog.Warn("failed to set deadline for authenticated request", "error", err)
			}
		}
		n, _, err = c.conn.ReadFrom(buf)
		if err != nil {
			return ErrTURNTimeout
		}

		msgType, _, attrs, err = parseSTUNMessage(buf[:n], transactionID)
		if err != nil {
			return err
		}
	}

	if msgType != turnMsgTypeAllocateSuccess {
		return ErrTURNAllocationFailed
	}

	// Parse relay address
	if relayData, ok := attrs[turnAttrXORRelayedAddress]; ok {
		c.relayAddr, _ = parseXORMappedAddress(relayData)
	} else {
		return ErrTURNNoRelayAddress
	}

	// Parse lifetime
	if lifetimeData, ok := attrs[turnAttrLifetime]; ok && len(lifetimeData) >= 4 {
		c.lifetime = time.Duration(binary.BigEndian.Uint32(lifetimeData)) * time.Second
	} else {
		c.lifetime = 10 * time.Minute // Default
	}

	c.allocated = true
	c.allocatedAt = time.Now()

	return nil
}

// RelayAddress returns the allocated relay address.
func (c *TURNClient) RelayAddress() (netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.allocated {
		return netip.AddrPort{}, ErrTURNNoRelayAddress
	}
	return c.relayAddr, nil
}

// CreatePermission creates a permission for a peer IP address.
func (c *TURNClient) CreatePermission(ctx context.Context, peerIP netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.allocated {
		return ErrTURNNoRelayAddress
	}

	addr, _ := resolveTURNServer(c.server)

	transactionID := generateTransactionID()
	request := c.buildCreatePermissionRequest(transactionID, peerIP)

	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			slog.Debug("failed to set deadline for create permission", "error", err)
		} else {
			slog.Warn("failed to set deadline for create permission", "error", err)
		}
	}
	if _, err := c.conn.WriteTo(request, addr); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return ErrTURNTimeout
	}

	msgType, _, _, err := parseSTUNMessage(buf[:n], transactionID)
	if err != nil {
		return err
	}

	if msgType != 0x0108 { // CreatePermission success
		return errors.New("turn: create permission failed")
	}

	c.permissions[peerIP] = time.Now().Add(5 * time.Minute)
	return nil
}

// BindChannel binds a channel number to a peer address for efficient data transfer.
func (c *TURNClient) BindChannel(ctx context.Context, peerAddr netip.AddrPort) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.allocated {
		return 0, ErrTURNNoRelayAddress
	}

	// Check if already bound
	if channel, exists := c.channels[peerAddr]; exists {
		return channel, nil
	}

	channel := c.nextChannel
	c.nextChannel++

	addr, _ := resolveTURNServer(c.server)

	transactionID := generateTransactionID()
	request := c.buildChannelBindRequest(transactionID, channel, peerAddr)

	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			slog.Debug("failed to set deadline for channel bind", "error", err)
		} else {
			slog.Warn("failed to set deadline for channel bind", "error", err)
		}
	}
	if _, err := c.conn.WriteTo(request, addr); err != nil {
		return 0, err
	}

	buf := make([]byte, 4096)
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return 0, ErrTURNTimeout
	}

	msgType, _, _, err := parseSTUNMessage(buf[:n], transactionID)
	if err != nil {
		return 0, err
	}

	if msgType != 0x0109 { // ChannelBind success
		return 0, errors.New("turn: channel bind failed")
	}

	c.channels[peerAddr] = channel
	return channel, nil
}

// Send sends data through the relay to a peer.
func (c *TURNClient) Send(peerAddr netip.AddrPort, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.allocated {
		return ErrTURNNoRelayAddress
	}

	addr, _ := resolveTURNServer(c.server)

	// Use channel data if bound
	if channel, exists := c.channels[peerAddr]; exists {
		packet := make([]byte, 4+len(data))
		binary.BigEndian.PutUint16(packet[0:2], channel)
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(data)))
		copy(packet[4:], data)

		_, err := c.conn.WriteTo(packet, addr)
		return err
	}

	// Use Send indication
	transactionID := generateTransactionID()
	request := c.buildSendIndication(transactionID, peerAddr, data)

	_, err := c.conn.WriteTo(request, addr)
	return err
}

// Receive receives data from the relay.
func (c *TURNClient) Receive(buf []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return 0, netip.AddrPort{}, errors.New("turn: not connected")
	}

	tempBuf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(tempBuf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Check if it's a channel data message
	if n >= 4 && tempBuf[0]&0xC0 == 0x40 {
		channel := binary.BigEndian.Uint16(tempBuf[0:2])
		dataLen := int(binary.BigEndian.Uint16(tempBuf[2:4]))

		if n >= 4+dataLen {
			// Find peer for this channel
			var peerAddr netip.AddrPort
			c.mu.Lock()
			for addr, ch := range c.channels {
				if ch == channel {
					peerAddr = addr
					break
				}
			}
			c.mu.Unlock()

			copied := copy(buf, tempBuf[4:4+dataLen])
			return copied, peerAddr, nil
		}
	}

	// Parse as Data indication
	_, _, attrs, err := parseSTUNMessage(tempBuf[:n], nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if peerData, ok := attrs[turnAttrXORPeerAddress]; ok {
		peerAddr, _ := parseXORMappedAddress(peerData)
		if data, ok := attrs[turnAttrData]; ok {
			copied := copy(buf, data)
			return copied, peerAddr, nil
		}
	}

	return 0, netip.AddrPort{}, errors.New("turn: no data in message")
}

// Refresh refreshes the allocation.
func (c *TURNClient) Refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.allocated {
		return nil
	}

	addr, _ := resolveTURNServer(c.server)

	transactionID := generateTransactionID()
	request := c.buildRefreshRequest(transactionID)

	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			slog.Debug("failed to set deadline for refresh", "error", err)
		} else {
			slog.Warn("failed to set deadline for refresh", "error", err)
		}
	}
	if _, err := c.conn.WriteTo(request, addr); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return ErrTURNTimeout
	}

	msgType, _, _, err := parseSTUNMessage(buf[:n], transactionID)
	if err != nil {
		return err
	}

	if msgType != turnMsgTypeRefreshSuccess {
		return errors.New("turn: refresh failed")
	}

	return nil
}

// Close releases the allocation and closes the connection.
func (c *TURNClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Send refresh with lifetime=0 to release allocation
		addr, _ := resolveTURNServer(c.server)
		transactionID := generateTransactionID()
		request := c.buildRefreshRequest(transactionID)

		if err := c.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("failed to set deadline for close", "error", err)
			} else {
				slog.Warn("failed to set deadline for close", "error", err)
			}
		}
		if _, err := c.conn.WriteTo(request, addr); err != nil {
			slog.Debug("failed to send close request", "error", err)
		}

		err := c.conn.Close()
		c.conn = nil
		c.allocated = false
		return err
	}
	return nil
}

// buildAllocateRequest builds a TURN Allocate request.
func (c *TURNClient) buildAllocateRequest(transactionID []byte, authenticated bool) []byte {
	attrs := []struct {
		typ  uint16
		data []byte
	}{
		{turnAttrRequestedTransport, []byte{transportUDP, 0, 0, 0}},
	}

	if authenticated && c.username != "" {
		attrs = append(attrs, struct {
			typ  uint16
			data []byte
		}{turnAttrUsername, []byte(c.username)})
		attrs = append(attrs, struct {
			typ  uint16
			data []byte
		}{turnAttrRealm, []byte(c.realm)})
		attrs = append(attrs, struct {
			typ  uint16
			data []byte
		}{turnAttrNonce, []byte(c.nonce)})
	}

	return buildSTUNMessage(turnMsgTypeAllocate, transactionID, attrs, c.username, c.password, c.realm, authenticated)
}

// buildCreatePermissionRequest builds a CreatePermission request.
func (c *TURNClient) buildCreatePermissionRequest(transactionID []byte, peerIP netip.Addr) []byte {
	peerAddr := buildXORPeerAddress(peerIP)

	attrs := []struct {
		typ  uint16
		data []byte
	}{
		{turnAttrXORPeerAddress, peerAddr},
	}

	return buildSTUNMessage(turnMsgTypeCreatePermission, transactionID, attrs, c.username, c.password, c.realm, true)
}

// buildChannelBindRequest builds a ChannelBind request.
func (c *TURNClient) buildChannelBindRequest(transactionID []byte, channel uint16, peerAddr netip.AddrPort) []byte {
	channelData := make([]byte, 4)
	binary.BigEndian.PutUint16(channelData[0:2], channel)

	peerAddrData := buildXORPeerAddressPort(peerAddr)

	attrs := []struct {
		typ  uint16
		data []byte
	}{
		{turnAttrChannelNumber, channelData},
		{turnAttrXORPeerAddress, peerAddrData},
	}

	return buildSTUNMessage(turnMsgTypeChannelBind, transactionID, attrs, c.username, c.password, c.realm, true)
}

// buildSendIndication builds a Send indication.
func (c *TURNClient) buildSendIndication(transactionID []byte, peerAddr netip.AddrPort, data []byte) []byte {
	peerAddrData := buildXORPeerAddressPort(peerAddr)

	attrs := []struct {
		typ  uint16
		data []byte
	}{
		{turnAttrXORPeerAddress, peerAddrData},
		{turnAttrData, data},
	}

	return buildSTUNMessage(turnMsgTypeSend, transactionID, attrs, "", "", "", false)
}

// buildRefreshRequest builds a Refresh request.
func (c *TURNClient) buildRefreshRequest(transactionID []byte) []byte {
	lifetime := make([]byte, 4)
	binary.BigEndian.PutUint32(lifetime, 600) // 10 minutes

	attrs := []struct {
		typ  uint16
		data []byte
	}{
		{turnAttrLifetime, lifetime},
	}

	return buildSTUNMessage(turnMsgTypeRefresh, transactionID, attrs, c.username, c.password, c.realm, true)
}

// Helper functions

func resolveTURNServer(server string) (*net.UDPAddr, error) {
	// Handle turn: URI scheme
	if len(server) > 5 && server[:5] == "turn:" {
		server = server[5:]
	}

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		port = "3478"
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for TURN server %q", host)
	}

	portNum := 3478
	fmt.Sscanf(port, "%d", &portNum)

	return &net.UDPAddr{IP: ips[0], Port: portNum}, nil
}

func generateTransactionID() []byte {
	id := make([]byte, 12)
	for i := 0; i < 12; i++ {
		id[i] = byte(time.Now().UnixNano() >> (i * 8))
	}
	return id
}

func buildSTUNMessage(msgType uint16, transactionID []byte, attrs []struct {
	typ  uint16
	data []byte
}, username, password, realm string, authenticated bool) []byte {
	// Calculate attributes length
	attrsLen := 0
	for _, attr := range attrs {
		attrsLen += 4 + len(attr.data)
		if len(attr.data)%4 != 0 {
			attrsLen += 4 - (len(attr.data) % 4)
		}
	}

	if authenticated && username != "" {
		attrsLen += 24 // MESSAGE-INTEGRITY (20 bytes + 4 header)
	}

	msg := make([]byte, stunHeaderSize+attrsLen)

	// Header
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(attrsLen))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], transactionID)

	// Attributes
	offset := stunHeaderSize
	for _, attr := range attrs {
		binary.BigEndian.PutUint16(msg[offset:offset+2], attr.typ)
		binary.BigEndian.PutUint16(msg[offset+2:offset+4], uint16(len(attr.data)))
		copy(msg[offset+4:], attr.data)
		offset += 4 + len(attr.data)
		if len(attr.data)%4 != 0 {
			offset += 4 - (len(attr.data) % 4)
		}
	}

	// MESSAGE-INTEGRITY
	if authenticated && username != "" {
		key := computeLongTermKey(username, realm, password)
		binary.BigEndian.PutUint16(msg[2:4], uint16(offset-stunHeaderSize+24))
		mac := hmac.New(sha1.New, key)
		mac.Write(msg[:offset])
		integrity := mac.Sum(nil)

		binary.BigEndian.PutUint16(msg[offset:offset+2], turnAttrMessageIntegrity)
		binary.BigEndian.PutUint16(msg[offset+2:offset+4], 20)
		copy(msg[offset+4:], integrity)
	}

	return msg
}

func computeLongTermKey(username, realm, password string) []byte {
	h := sha1.New()
	h.Write([]byte(username + ":" + realm + ":" + password))
	return h.Sum(nil)[:16] // Use first 16 bytes
}

func parseSTUNMessage(data []byte, expectedTransactionID []byte) (uint16, []byte, map[uint16][]byte, error) {
	if len(data) < stunHeaderSize {
		return 0, nil, nil, errors.New("message too short")
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	transactionID := data[8:20]

	if expectedTransactionID != nil {
		for i := 0; i < 12; i++ {
			if transactionID[i] != expectedTransactionID[i] {
				return 0, nil, nil, errors.New("transaction ID mismatch")
			}
		}
	}

	attrs := make(map[uint16][]byte)
	offset := stunHeaderSize
	for offset < stunHeaderSize+msgLen && offset+4 <= len(data) {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+attrLen > len(data) {
			break
		}

		attrs[attrType] = data[offset : offset+attrLen]
		offset += attrLen
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}

	return msgType, transactionID, attrs, nil
}

func buildXORPeerAddress(ip netip.Addr) []byte {
	data := make([]byte, 8)
	data[1] = 0x01 // IPv4

	addr := ip.As4()
	xorAddr := binary.BigEndian.Uint32(addr[:]) ^ stunMagicCookie
	binary.BigEndian.PutUint32(data[4:8], xorAddr)

	return data
}

func buildXORPeerAddressPort(addrPort netip.AddrPort) []byte {
	data := make([]byte, 8)
	data[1] = 0x01 // IPv4

	port := addrPort.Port() ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(data[2:4], port)

	addr := addrPort.Addr().As4()
	xorAddr := binary.BigEndian.Uint32(addr[:]) ^ stunMagicCookie
	binary.BigEndian.PutUint32(data[4:8], xorAddr)

	return data
}
