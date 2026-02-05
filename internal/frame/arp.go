package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ARP operation codes.
const (
	ARPRequest uint16 = 1
	ARPReply   uint16 = 2
)

// ARP hardware types.
const (
	ARPHardwareEthernet uint16 = 1
)

// ARP protocol types.
const (
	ARPProtocolIPv4 uint16 = 0x0800
)

// ARPPacket represents an ARP packet.
type ARPPacket struct {
	HardwareType       uint16           // Hardware type (Ethernet = 1)
	ProtocolType       uint16           // Protocol type (IPv4 = 0x0800)
	HardwareAddrLen    uint8            // Hardware address length (6 for Ethernet)
	ProtocolAddrLen    uint8            // Protocol address length (4 for IPv4)
	Operation          uint16           // Operation (1 = request, 2 = reply)
	SenderHardwareAddr net.HardwareAddr // Sender MAC address
	SenderProtocolAddr netip.Addr       // Sender IP address
	TargetHardwareAddr net.HardwareAddr // Target MAC address
	TargetProtocolAddr netip.Addr       // Target IP address
}

// ARP packet size constants.
const (
	ARPHeaderSize      = 8  // HW type + Proto type + HW len + Proto len + Operation
	ARPEthernetIPv4Len = 28 // Full ARP packet for Ethernet/IPv4
)

// Common ARP errors.
var (
	ErrARPTooShort      = errors.New("ARP packet too short")
	ErrARPInvalidType   = errors.New("invalid ARP hardware or protocol type")
	ErrARPInvalidLength = errors.New("invalid ARP address length")
)

// ParseARPPacket parses an ARP packet from raw bytes.
func ParseARPPacket(data []byte) (*ARPPacket, error) {
	if len(data) < ARPHeaderSize {
		return nil, ErrARPTooShort
	}

	hwType := binary.BigEndian.Uint16(data[0:2])
	protoType := binary.BigEndian.Uint16(data[2:4])
	hwAddrLen := data[4]
	protoAddrLen := data[5]
	operation := binary.BigEndian.Uint16(data[6:8])

	// Validate Ethernet/IPv4
	if hwType != ARPHardwareEthernet {
		return nil, fmt.Errorf("%w: hardware type %d", ErrARPInvalidType, hwType)
	}
	if protoType != ARPProtocolIPv4 {
		return nil, fmt.Errorf("%w: protocol type 0x%04X", ErrARPInvalidType, protoType)
	}
	if hwAddrLen != 6 {
		return nil, fmt.Errorf("%w: hardware address length %d", ErrARPInvalidLength, hwAddrLen)
	}
	if protoAddrLen != 4 {
		return nil, fmt.Errorf("%w: protocol address length %d", ErrARPInvalidLength, protoAddrLen)
	}

	// Calculate total packet size
	totalLen := ARPHeaderSize + 2*int(hwAddrLen) + 2*int(protoAddrLen)
	if len(data) < totalLen {
		return nil, ErrARPTooShort
	}

	offset := ARPHeaderSize

	senderHWAddr := make(net.HardwareAddr, hwAddrLen)
	copy(senderHWAddr, data[offset:offset+int(hwAddrLen)])
	offset += int(hwAddrLen)

	senderIPBytes := data[offset : offset+int(protoAddrLen)]
	senderIP, ok := netip.AddrFromSlice(senderIPBytes)
	if !ok {
		return nil, errors.New("invalid sender IP address")
	}
	offset += int(protoAddrLen)

	targetHWAddr := make(net.HardwareAddr, hwAddrLen)
	copy(targetHWAddr, data[offset:offset+int(hwAddrLen)])
	offset += int(hwAddrLen)

	targetIPBytes := data[offset : offset+int(protoAddrLen)]
	targetIP, ok := netip.AddrFromSlice(targetIPBytes)
	if !ok {
		return nil, errors.New("invalid target IP address")
	}

	return &ARPPacket{
		HardwareType:       hwType,
		ProtocolType:       protoType,
		HardwareAddrLen:    hwAddrLen,
		ProtocolAddrLen:    protoAddrLen,
		Operation:          operation,
		SenderHardwareAddr: senderHWAddr,
		SenderProtocolAddr: senderIP,
		TargetHardwareAddr: targetHWAddr,
		TargetProtocolAddr: targetIP,
	}, nil
}

// BuildARPPacket builds an ARP packet from components.
func BuildARPPacket(operation uint16, senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr) ([]byte, error) {
	if len(senderMAC) != 6 || len(targetMAC) != 6 {
		return nil, ErrInvalidMAC
	}
	if !senderIP.Is4() || !targetIP.Is4() {
		return nil, errors.New("only IPv4 addresses supported")
	}

	packet := make([]byte, ARPEthernetIPv4Len)

	binary.BigEndian.PutUint16(packet[0:2], ARPHardwareEthernet)
	binary.BigEndian.PutUint16(packet[2:4], ARPProtocolIPv4)
	packet[4] = 6 // Hardware address length
	packet[5] = 4 // Protocol address length
	binary.BigEndian.PutUint16(packet[6:8], operation)

	copy(packet[8:14], senderMAC)
	copy(packet[14:18], senderIP.AsSlice())
	copy(packet[18:24], targetMAC)
	copy(packet[24:28], targetIP.AsSlice())

	return packet, nil
}

// BuildARPRequest builds an ARP request packet.
func BuildARPRequest(senderMAC net.HardwareAddr, senderIP, targetIP netip.Addr) ([]byte, error) {
	// Target MAC is zero for requests
	targetMAC := make(net.HardwareAddr, 6)
	return BuildARPPacket(ARPRequest, senderMAC, senderIP, targetMAC, targetIP)
}

// BuildARPReply builds an ARP reply packet.
func BuildARPReply(senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr) ([]byte, error) {
	return BuildARPPacket(ARPReply, senderMAC, senderIP, targetMAC, targetIP)
}

// BuildARPFrame builds a complete Ethernet frame containing an ARP packet.
func BuildARPFrame(dstMAC, srcMAC net.HardwareAddr, arpPacket []byte) ([]byte, error) {
	return BuildEthernetFrame(dstMAC, srcMAC, EtherTypeARP, arpPacket)
}

// BuildARPRequestFrame builds a complete Ethernet ARP request frame.
func BuildARPRequestFrame(senderMAC net.HardwareAddr, senderIP, targetIP netip.Addr) ([]byte, error) {
	arp, err := BuildARPRequest(senderMAC, senderIP, targetIP)
	if err != nil {
		return nil, err
	}
	return BuildARPFrame(BroadcastMAC, senderMAC, arp)
}

// BuildARPReplyFrame builds a complete Ethernet ARP reply frame.
func BuildARPReplyFrame(senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr) ([]byte, error) {
	arp, err := BuildARPReply(senderMAC, senderIP, targetMAC, targetIP)
	if err != nil {
		return nil, err
	}
	return BuildARPFrame(targetMAC, senderMAC, arp)
}

// IsRequest returns true if this is an ARP request.
func (a *ARPPacket) IsRequest() bool {
	return a.Operation == ARPRequest
}

// IsReply returns true if this is an ARP reply.
func (a *ARPPacket) IsReply() bool {
	return a.Operation == ARPReply
}

// String returns a string representation of the ARP packet.
func (a *ARPPacket) String() string {
	opStr := "unknown"
	switch a.Operation {
	case ARPRequest:
		opStr = "request"
	case ARPReply:
		opStr = "reply"
	}
	return fmt.Sprintf("ARP %s: %s (%s) -> %s (%s)",
		opStr,
		a.SenderProtocolAddr, a.SenderHardwareAddr,
		a.TargetProtocolAddr, a.TargetHardwareAddr)
}

// MarshalBinary returns the binary representation of the ARP packet.
func (a *ARPPacket) MarshalBinary() ([]byte, error) {
	return BuildARPPacket(a.Operation, a.SenderHardwareAddr, a.SenderProtocolAddr, a.TargetHardwareAddr, a.TargetProtocolAddr)
}

// ARPInterceptor handles ARP requests and responses for a virtual network interface.
// It responds to ARP requests for the local IP and learns MAC addresses from ARP traffic.
type ARPInterceptor struct {
	localMAC net.HardwareAddr
	localIP  netip.Addr
	macTable *MACTable
}

// NewARPInterceptor creates a new ARP interceptor.
func NewARPInterceptor(localMAC net.HardwareAddr, localIP netip.Addr, macTable *MACTable) *ARPInterceptor {
	return &ARPInterceptor{
		localMAC: localMAC,
		localIP:  localIP,
		macTable: macTable,
	}
}

// HandleFrame processes an Ethernet frame containing an ARP packet.
// Returns an ARP response frame if this is a request for our IP, nil otherwise.
func (ai *ARPInterceptor) HandleFrame(frameData []byte) []byte {
	// Parse Ethernet frame
	ethFrame, err := ParseEthernetFrame(frameData)
	if err != nil {
		return nil
	}

	// Only handle ARP frames
	if ethFrame.Header.EtherType != EtherTypeARP {
		return nil
	}

	// Parse ARP packet
	arp, err := ParseARPPacket(ethFrame.Payload)
	if err != nil {
		return nil
	}

	// Learn sender's MAC address from any ARP packet
	if ai.macTable != nil && arp.SenderProtocolAddr.IsValid() {
		ai.macTable.LearnWithIP(arp.SenderHardwareAddr, "", arp.SenderProtocolAddr)
	}

	// Only respond to ARP requests for our IP
	if !arp.IsRequest() {
		return nil
	}

	// Check if this ARP request is for our IP
	if arp.TargetProtocolAddr != ai.localIP {
		return nil
	}

	// Build ARP reply
	response, err := BuildARPReplyFrame(ai.localMAC, ai.localIP, arp.SenderHardwareAddr, arp.SenderProtocolAddr)
	if err != nil {
		return nil
	}

	return response
}

// HandlePacket processes a raw ARP packet (without Ethernet header).
// Returns an ARP reply packet if this is a request for our IP, nil otherwise.
func (ai *ARPInterceptor) HandlePacket(arpData []byte) ([]byte, error) {
	arp, err := ParseARPPacket(arpData)
	if err != nil {
		return nil, err
	}

	// Learn sender's MAC address
	if ai.macTable != nil && arp.SenderProtocolAddr.IsValid() {
		ai.macTable.LearnWithIP(arp.SenderHardwareAddr, "", arp.SenderProtocolAddr)
	}

	// Only respond to requests for our IP
	if !arp.IsRequest() || arp.TargetProtocolAddr != ai.localIP {
		return nil, nil
	}

	// Build reply
	return BuildARPReply(ai.localMAC, ai.localIP, arp.SenderHardwareAddr, arp.SenderProtocolAddr)
}

// LocalMAC returns the local MAC address.
func (ai *ARPInterceptor) LocalMAC() net.HardwareAddr {
	return ai.localMAC
}

// LocalIP returns the local IP address.
func (ai *ARPInterceptor) LocalIP() netip.Addr {
	return ai.localIP
}
