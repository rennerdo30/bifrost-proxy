// Package frame provides Ethernet frame parsing and building for TAP devices.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// EtherType represents the EtherType field in Ethernet frames.
type EtherType uint16

// Common EtherTypes.
const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86DD
	EtherTypeVLAN EtherType = 0x8100
)

// String returns the string representation of the EtherType.
func (t EtherType) String() string {
	switch t {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6"
	case EtherTypeVLAN:
		return "VLAN"
	default:
		return fmt.Sprintf("0x%04X", uint16(t))
	}
}

// EthernetHeader represents an Ethernet frame header.
type EthernetHeader struct {
	DstMAC    net.HardwareAddr // Destination MAC address (6 bytes)
	SrcMAC    net.HardwareAddr // Source MAC address (6 bytes)
	EtherType EtherType        // EtherType (2 bytes)
}

// EthernetFrame represents a complete Ethernet frame.
type EthernetFrame struct {
	Header  EthernetHeader
	Payload []byte
	Raw     []byte // Original raw frame (for forwarding)
}

// Minimum Ethernet frame size (without FCS).
const (
	EthernetHeaderSize = 14
	MinEthernetFrame   = 60
	MaxEthernetFrame   = 1522 // With VLAN tag
	MaxPayload         = 1500 // Standard MTU
)

// Common errors.
var (
	ErrFrameTooShort   = errors.New("ethernet frame too short")
	ErrFrameTooLong    = errors.New("ethernet frame too long")
	ErrInvalidMAC      = errors.New("invalid MAC address")
	ErrPayloadTooLarge = errors.New("payload too large for Ethernet frame")
)

// BroadcastMAC is the broadcast MAC address.
var BroadcastMAC = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// ParseEthernetFrame parses a raw Ethernet frame.
func ParseEthernetFrame(data []byte) (*EthernetFrame, error) {
	if len(data) < EthernetHeaderSize {
		return nil, ErrFrameTooShort
	}

	frame := &EthernetFrame{
		Header: EthernetHeader{
			DstMAC:    net.HardwareAddr(data[0:6]),
			SrcMAC:    net.HardwareAddr(data[6:12]),
			EtherType: EtherType(binary.BigEndian.Uint16(data[12:14])),
		},
		Payload: data[EthernetHeaderSize:],
		Raw:     data,
	}

	// Handle VLAN-tagged frames
	if frame.Header.EtherType == EtherTypeVLAN {
		if len(data) < EthernetHeaderSize+4 {
			return nil, ErrFrameTooShort
		}
		// Real EtherType is 4 bytes further
		frame.Header.EtherType = EtherType(binary.BigEndian.Uint16(data[16:18]))
		frame.Payload = data[18:]
	}

	return frame, nil
}

// BuildEthernetFrame builds an Ethernet frame from components.
func BuildEthernetFrame(dstMAC, srcMAC net.HardwareAddr, etherType EtherType, payload []byte) ([]byte, error) {
	if len(dstMAC) != 6 || len(srcMAC) != 6 {
		return nil, ErrInvalidMAC
	}
	if len(payload) > MaxPayload {
		return nil, ErrPayloadTooLarge
	}

	frameSize := EthernetHeaderSize + len(payload)
	if frameSize < MinEthernetFrame {
		frameSize = MinEthernetFrame // Pad to minimum size
	}

	frame := make([]byte, frameSize)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], uint16(etherType))
	copy(frame[14:], payload)
	// Remaining bytes are zero-padded

	return frame, nil
}

// IsBroadcast returns true if the destination MAC is the broadcast address.
func (f *EthernetFrame) IsBroadcast() bool {
	return f.Header.DstMAC[0]&0x01 != 0 && // Multicast/broadcast bit
		f.Header.DstMAC[0] == 0xFF &&
		f.Header.DstMAC[1] == 0xFF &&
		f.Header.DstMAC[2] == 0xFF &&
		f.Header.DstMAC[3] == 0xFF &&
		f.Header.DstMAC[4] == 0xFF &&
		f.Header.DstMAC[5] == 0xFF
}

// IsMulticast returns true if the destination MAC is a multicast address.
func (f *EthernetFrame) IsMulticast() bool {
	return f.Header.DstMAC[0]&0x01 != 0
}

// IsUnicast returns true if the destination MAC is a unicast address.
func (f *EthernetFrame) IsUnicast() bool {
	return f.Header.DstMAC[0]&0x01 == 0
}

// IsIPv4 returns true if this frame contains an IPv4 packet.
func (f *EthernetFrame) IsIPv4() bool {
	return f.Header.EtherType == EtherTypeIPv4
}

// IsIPv6 returns true if this frame contains an IPv6 packet.
func (f *EthernetFrame) IsIPv6() bool {
	return f.Header.EtherType == EtherTypeIPv6
}

// IsARP returns true if this frame contains an ARP packet.
func (f *EthernetFrame) IsARP() bool {
	return f.Header.EtherType == EtherTypeARP
}

// IsIP returns true if this frame contains an IP packet (v4 or v6).
func (f *EthernetFrame) IsIP() bool {
	return f.IsIPv4() || f.IsIPv6()
}

// String returns a string representation of the frame.
func (f *EthernetFrame) String() string {
	return fmt.Sprintf("Ethernet %s -> %s [%s] %d bytes",
		f.Header.SrcMAC, f.Header.DstMAC, f.Header.EtherType, len(f.Payload))
}

// Clone creates a copy of the frame.
func (f *EthernetFrame) Clone() *EthernetFrame {
	clone := &EthernetFrame{
		Header: EthernetHeader{
			DstMAC:    make(net.HardwareAddr, 6),
			SrcMAC:    make(net.HardwareAddr, 6),
			EtherType: f.Header.EtherType,
		},
		Payload: make([]byte, len(f.Payload)),
		Raw:     make([]byte, len(f.Raw)),
	}
	copy(clone.Header.DstMAC, f.Header.DstMAC)
	copy(clone.Header.SrcMAC, f.Header.SrcMAC)
	copy(clone.Payload, f.Payload)
	copy(clone.Raw, f.Raw)
	return clone
}

// MarshalBinary returns the binary representation of the frame.
func (f *EthernetFrame) MarshalBinary() ([]byte, error) {
	return BuildEthernetFrame(f.Header.DstMAC, f.Header.SrcMAC, f.Header.EtherType, f.Payload)
}

// ExtractIPAddresses extracts source and destination IP addresses from the payload.
// Returns nil for non-IP frames.
func (f *EthernetFrame) ExtractIPAddresses() (src, dst net.IP, err error) {
	if len(f.Payload) < 1 {
		return nil, nil, errors.New("empty payload")
	}

	switch f.Header.EtherType {
	case EtherTypeIPv4:
		if len(f.Payload) < 20 {
			return nil, nil, errors.New("IPv4 header too short")
		}
		src = net.IP(f.Payload[12:16])
		dst = net.IP(f.Payload[16:20])
		return src, dst, nil

	case EtherTypeIPv6:
		if len(f.Payload) < 40 {
			return nil, nil, errors.New("IPv6 header too short")
		}
		src = net.IP(f.Payload[8:24])
		dst = net.IP(f.Payload[24:40])
		return src, dst, nil

	default:
		return nil, nil, fmt.Errorf("not an IP frame: %s", f.Header.EtherType)
	}
}

// MACEqual compares two MAC addresses for equality.
func MACEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// IsLocallyAdministered returns true if the MAC address is locally administered.
func IsLocallyAdministered(mac net.HardwareAddr) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&0x02 != 0
}

// IsGloballyUnique returns true if the MAC address is globally unique (OUI-based).
func IsGloballyUnique(mac net.HardwareAddr) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&0x02 == 0
}

// IsBroadcast returns true if the MAC address is the broadcast address (ff:ff:ff:ff:ff:ff).
func IsBroadcast(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	return mac[0] == 0xFF &&
		mac[1] == 0xFF &&
		mac[2] == 0xFF &&
		mac[3] == 0xFF &&
		mac[4] == 0xFF &&
		mac[5] == 0xFF
}

// IsMulticast returns true if the MAC address is a multicast address.
// Multicast addresses have the least significant bit of the first byte set.
func IsMulticast(mac net.HardwareAddr) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&0x01 != 0
}

// IsUnicast returns true if the MAC address is a unicast address.
func IsUnicast(mac net.HardwareAddr) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&0x01 == 0
}
