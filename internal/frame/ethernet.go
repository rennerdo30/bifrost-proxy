// Package frame provides Ethernet frame parsing and building for TAP devices.
package frame

import (
	"encoding/binary"
	"errors"
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
