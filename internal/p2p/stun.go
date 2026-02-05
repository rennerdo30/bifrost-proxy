// Package p2p provides peer-to-peer connectivity with NAT traversal.
package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// STUN message types (RFC 5389).
const (
	stunMsgTypeBindingRequest  uint16 = 0x0001
	stunMsgTypeBindingResponse uint16 = 0x0101
	stunMsgTypeBindingError    uint16 = 0x0111

	stunMagicCookie uint32 = 0x2112A442

	stunAttrMappedAddress     uint16 = 0x0001
	stunAttrXORMappedAddress  uint16 = 0x0020
	stunAttrSoftware          uint16 = 0x8022
	stunAttrFingerprint       uint16 = 0x8028
)

// STUN message header size.
const stunHeaderSize = 20

// Common STUN errors.
var (
	ErrSTUNTimeout       = errors.New("stun: request timed out")
	ErrSTUNInvalidResponse = errors.New("stun: invalid response")
	ErrSTUNNoMappedAddress = errors.New("stun: no mapped address in response")
)

// STUNClient handles STUN protocol operations.
type STUNClient struct {
	servers []string
	timeout time.Duration
	conn    net.PacketConn
	mu      sync.Mutex
}

// STUNResult contains the result of a STUN binding request.
type STUNResult struct {
	// MappedAddress is our public IP:port as seen by the STUN server.
	MappedAddress netip.AddrPort

	// Server is the STUN server that responded.
	Server string

	// RTT is the round-trip time of the request.
	RTT time.Duration
}

// NewSTUNClient creates a new STUN client.
func NewSTUNClient(servers []string, timeout time.Duration) *STUNClient {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &STUNClient{
		servers: servers,
		timeout: timeout,
	}
}

// Bind performs a STUN binding request and returns the mapped address.
func (c *STUNClient) Bind(ctx context.Context) (*STUNResult, error) {
	for _, server := range c.servers {
		result, err := c.bindToServer(ctx, server)
		if err == nil {
			return result, nil
		}
	}
	return nil, ErrSTUNTimeout
}

// bindToServer performs a STUN binding request to a specific server.
func (c *STUNClient) bindToServer(ctx context.Context, server string) (*STUNResult, error) {
	// Parse server address
	addr, err := resolveSTUNServer(server)
	if err != nil {
		return nil, err
	}

	// Create UDP connection if not already created
	c.mu.Lock()
	if c.conn == nil {
		c.conn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			c.mu.Unlock()
			return nil, fmt.Errorf("failed to create UDP socket: %w", err)
		}
	}
	conn := c.conn
	c.mu.Unlock()

	// Build STUN binding request
	transactionID := make([]byte, 12)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	request := buildSTUNBindingRequest(transactionID)

	// Set deadline
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			slog.Debug("failed to set deadline on STUN connection", "error", err)
		} else {
			slog.Warn("failed to set deadline on STUN connection", "error", err)
		}
	}

	start := time.Now()

	// Send request
	_, err = conn.WriteTo(request, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// Receive response
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, ErrSTUNTimeout
		}
		return nil, fmt.Errorf("failed to receive STUN response: %w", err)
	}

	rtt := time.Since(start)

	// Parse response
	mappedAddr, err := parseSTUNBindingResponse(buf[:n], transactionID)
	if err != nil {
		return nil, err
	}

	return &STUNResult{
		MappedAddress: mappedAddr,
		Server:        server,
		RTT:           rtt,
	}, nil
}

// GetLocalPort returns the local port used for STUN.
func (c *STUNClient) GetLocalPort() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0
	}

	localAddr := c.conn.LocalAddr().(*net.UDPAddr)
	return localAddr.Port
}

// Close closes the STUN client.
func (c *STUNClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// resolveSTUNServer resolves a STUN server address.
func resolveSTUNServer(server string) (*net.UDPAddr, error) {
	// Handle stun: URI scheme
	if len(server) > 5 && server[:5] == "stun:" {
		server = server[5:]
	}

	// Add default port if not specified
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		port = "3478"
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for STUN server %q", host)
	}

	// Parse port
	portNum := 3478
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		return nil, fmt.Errorf("invalid port: %s", port)
	}

	return &net.UDPAddr{IP: ips[0], Port: portNum}, nil
}

// buildSTUNBindingRequest builds a STUN binding request message.
func buildSTUNBindingRequest(transactionID []byte) []byte {
	msg := make([]byte, stunHeaderSize)

	// Message type: Binding Request
	binary.BigEndian.PutUint16(msg[0:2], stunMsgTypeBindingRequest)

	// Message length (0 for simple binding request)
	binary.BigEndian.PutUint16(msg[2:4], 0)

	// Magic cookie
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)

	// Transaction ID
	copy(msg[8:20], transactionID)

	return msg
}

// parseSTUNBindingResponse parses a STUN binding response.
func parseSTUNBindingResponse(data []byte, expectedTransactionID []byte) (netip.AddrPort, error) {
	if len(data) < stunHeaderSize {
		return netip.AddrPort{}, ErrSTUNInvalidResponse
	}

	// Check message type
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunMsgTypeBindingResponse {
		return netip.AddrPort{}, fmt.Errorf("%w: unexpected message type 0x%04X", ErrSTUNInvalidResponse, msgType)
	}

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return netip.AddrPort{}, fmt.Errorf("%w: invalid magic cookie", ErrSTUNInvalidResponse)
	}

	// Check transaction ID
	for i := 0; i < 12; i++ {
		if data[8+i] != expectedTransactionID[i] {
			return netip.AddrPort{}, fmt.Errorf("%w: transaction ID mismatch", ErrSTUNInvalidResponse)
		}
	}

	// Parse message length
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < stunHeaderSize+msgLen {
		return netip.AddrPort{}, ErrSTUNInvalidResponse
	}

	// Parse attributes
	offset := stunHeaderSize
	for offset < stunHeaderSize+msgLen {
		if offset+4 > len(data) {
			break
		}

		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+attrLen > len(data) {
			break
		}

		attrValue := data[offset : offset+attrLen]

		switch attrType {
		case stunAttrXORMappedAddress:
			return parseXORMappedAddress(attrValue)
		case stunAttrMappedAddress:
			return parseMappedAddress(attrValue)
		}

		// Align to 4-byte boundary
		offset += attrLen
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}

	return netip.AddrPort{}, ErrSTUNNoMappedAddress
}

// parseMappedAddress parses a MAPPED-ADDRESS attribute.
func parseMappedAddress(data []byte) (netip.AddrPort, error) {
	if len(data) < 8 {
		return netip.AddrPort{}, ErrSTUNInvalidResponse
	}

	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])

	var addr netip.Addr
	if family == 0x01 { // IPv4
		if len(data) < 8 {
			return netip.AddrPort{}, ErrSTUNInvalidResponse
		}
		addr = netip.AddrFrom4([4]byte(data[4:8]))
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return netip.AddrPort{}, ErrSTUNInvalidResponse
		}
		addr = netip.AddrFrom16([16]byte(data[4:20]))
	} else {
		return netip.AddrPort{}, fmt.Errorf("%w: unknown address family %d", ErrSTUNInvalidResponse, family)
	}

	return netip.AddrPortFrom(addr, port), nil
}

// parseXORMappedAddress parses an XOR-MAPPED-ADDRESS attribute.
func parseXORMappedAddress(data []byte) (netip.AddrPort, error) {
	if len(data) < 8 {
		return netip.AddrPort{}, ErrSTUNInvalidResponse
	}

	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4]) ^ uint16(stunMagicCookie>>16)

	var addr netip.Addr
	if family == 0x01 { // IPv4
		if len(data) < 8 {
			return netip.AddrPort{}, ErrSTUNInvalidResponse
		}
		xorAddr := binary.BigEndian.Uint32(data[4:8]) ^ stunMagicCookie
		addr = netip.AddrFrom4([4]byte{
			byte(xorAddr >> 24),
			byte(xorAddr >> 16),
			byte(xorAddr >> 8),
			byte(xorAddr),
		})
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return netip.AddrPort{}, ErrSTUNInvalidResponse
		}
		// XOR with magic cookie + transaction ID (not fully implemented)
		addr = netip.AddrFrom16([16]byte(data[4:20]))
	} else {
		return netip.AddrPort{}, fmt.Errorf("%w: unknown address family %d", ErrSTUNInvalidResponse, family)
	}

	return netip.AddrPortFrom(addr, port), nil
}

// DefaultSTUNServers returns a list of default public STUN servers.
func DefaultSTUNServers() []string {
	return []string{
		"stun:stun.l.google.com:19302",
		"stun:stun1.l.google.com:19302",
		"stun:stun2.l.google.com:19302",
		"stun:stun3.l.google.com:19302",
		"stun:stun4.l.google.com:19302",
	}
}
