package frame

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEtherTypeString(t *testing.T) {
	tests := []struct {
		etherType EtherType
		expected  string
	}{
		{EtherTypeIPv4, "IPv4"},
		{EtherTypeARP, "ARP"},
		{EtherTypeIPv6, "IPv6"},
		{EtherTypeVLAN, "VLAN"},
		{EtherType(0x1234), "0x1234"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.etherType.String())
		})
	}
}

func TestParseEthernetFrame(t *testing.T) {
	t.Run("valid IPv4 frame", func(t *testing.T) {
		// Build a minimal Ethernet frame with IPv4
		frame := make([]byte, EthernetHeaderSize+20)
		copy(frame[0:6], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})  // dst
		copy(frame[6:12], []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}) // src
		frame[12] = 0x08                                              // EtherType IPv4 (0x0800)
		frame[13] = 0x00

		parsed, err := ParseEthernetFrame(frame)
		require.NoError(t, err)
		assert.Equal(t, EtherTypeIPv4, parsed.Header.EtherType)
		assert.Equal(t, net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, parsed.Header.DstMAC)
		assert.Equal(t, net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, parsed.Header.SrcMAC)
		assert.Len(t, parsed.Payload, 20)
	})

	t.Run("valid ARP frame", func(t *testing.T) {
		frame := make([]byte, EthernetHeaderSize+28)
		copy(frame[0:6], BroadcastMAC)
		copy(frame[6:12], []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F})
		frame[12] = 0x08 // EtherType ARP (0x0806)
		frame[13] = 0x06

		parsed, err := ParseEthernetFrame(frame)
		require.NoError(t, err)
		assert.Equal(t, EtherTypeARP, parsed.Header.EtherType)
		assert.True(t, parsed.IsBroadcast())
		assert.True(t, parsed.IsARP())
	})

	t.Run("valid IPv6 frame", func(t *testing.T) {
		frame := make([]byte, EthernetHeaderSize+40)
		copy(frame[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}) // IPv6 multicast
		copy(frame[6:12], []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F})
		frame[12] = 0x86 // EtherType IPv6 (0x86DD)
		frame[13] = 0xDD

		parsed, err := ParseEthernetFrame(frame)
		require.NoError(t, err)
		assert.Equal(t, EtherTypeIPv6, parsed.Header.EtherType)
		assert.True(t, parsed.IsMulticast())
		assert.True(t, parsed.IsIPv6())
	})

	t.Run("VLAN-tagged frame", func(t *testing.T) {
		// VLAN-tagged frame: 14 byte header + 4 byte VLAN tag + payload
		frame := make([]byte, EthernetHeaderSize+4+20)
		copy(frame[0:6], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		copy(frame[6:12], []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F})
		frame[12] = 0x81 // EtherType VLAN (0x8100)
		frame[13] = 0x00
		frame[14] = 0x00 // VLAN ID
		frame[15] = 0x01
		frame[16] = 0x08 // Real EtherType IPv4
		frame[17] = 0x00

		parsed, err := ParseEthernetFrame(frame)
		require.NoError(t, err)
		assert.Equal(t, EtherTypeIPv4, parsed.Header.EtherType)
		assert.Len(t, parsed.Payload, 20)
	})

	t.Run("frame too short", func(t *testing.T) {
		_, err := ParseEthernetFrame([]byte{0x01, 0x02, 0x03})
		assert.Equal(t, ErrFrameTooShort, err)
	})

	t.Run("VLAN frame too short", func(t *testing.T) {
		frame := make([]byte, EthernetHeaderSize+2) // Not enough for VLAN tag
		frame[12] = 0x81                            // VLAN EtherType
		frame[13] = 0x00

		_, err := ParseEthernetFrame(frame)
		assert.Equal(t, ErrFrameTooShort, err)
	})
}

func TestBuildEthernetFrame(t *testing.T) {
	t.Run("valid frame", func(t *testing.T) {
		dst := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		src := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		payload := []byte("Hello, World!")

		frame, err := BuildEthernetFrame(dst, src, EtherTypeIPv4, payload)
		require.NoError(t, err)

		// Should be padded to minimum size
		assert.GreaterOrEqual(t, len(frame), MinEthernetFrame)

		// Parse it back
		parsed, err := ParseEthernetFrame(frame)
		require.NoError(t, err)
		assert.Equal(t, dst, parsed.Header.DstMAC)
		assert.Equal(t, src, parsed.Header.SrcMAC)
		assert.Equal(t, EtherTypeIPv4, parsed.Header.EtherType)
	})

	t.Run("invalid dst MAC", func(t *testing.T) {
		_, err := BuildEthernetFrame([]byte{1, 2, 3}, []byte{1, 2, 3, 4, 5, 6}, EtherTypeIPv4, nil)
		assert.Equal(t, ErrInvalidMAC, err)
	})

	t.Run("invalid src MAC", func(t *testing.T) {
		_, err := BuildEthernetFrame([]byte{1, 2, 3, 4, 5, 6}, []byte{1, 2, 3}, EtherTypeIPv4, nil)
		assert.Equal(t, ErrInvalidMAC, err)
	})

	t.Run("payload too large", func(t *testing.T) {
		dst := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		src := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		payload := make([]byte, MaxPayload+1)

		_, err := BuildEthernetFrame(dst, src, EtherTypeIPv4, payload)
		assert.Equal(t, ErrPayloadTooLarge, err)
	})
}

func TestEthernetFrameMethods(t *testing.T) {
	t.Run("IsBroadcast", func(t *testing.T) {
		frame := &EthernetFrame{
			Header: EthernetHeader{DstMAC: BroadcastMAC},
		}
		assert.True(t, frame.IsBroadcast())

		frame.Header.DstMAC = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		assert.False(t, frame.IsBroadcast())
	})

	t.Run("IsMulticast", func(t *testing.T) {
		// Multicast addresses have least significant bit of first octet set
		frame := &EthernetFrame{
			Header: EthernetHeader{DstMAC: net.HardwareAddr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}},
		}
		assert.True(t, frame.IsMulticast())

		frame.Header.DstMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		assert.False(t, frame.IsMulticast())
	})

	t.Run("IsUnicast", func(t *testing.T) {
		frame := &EthernetFrame{
			Header: EthernetHeader{DstMAC: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
		}
		assert.True(t, frame.IsUnicast())

		frame.Header.DstMAC = net.HardwareAddr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
		assert.False(t, frame.IsUnicast())
	})

	t.Run("IsIPv4", func(t *testing.T) {
		frame := &EthernetFrame{Header: EthernetHeader{EtherType: EtherTypeIPv4}}
		assert.True(t, frame.IsIPv4())
		assert.False(t, frame.IsIPv6())
		assert.True(t, frame.IsIP())
	})

	t.Run("IsIPv6", func(t *testing.T) {
		frame := &EthernetFrame{Header: EthernetHeader{EtherType: EtherTypeIPv6}}
		assert.True(t, frame.IsIPv6())
		assert.False(t, frame.IsIPv4())
		assert.True(t, frame.IsIP())
	})

	t.Run("IsARP", func(t *testing.T) {
		frame := &EthernetFrame{Header: EthernetHeader{EtherType: EtherTypeARP}}
		assert.True(t, frame.IsARP())
		assert.False(t, frame.IsIP())
	})
}

func TestEthernetFrameString(t *testing.T) {
	frame := &EthernetFrame{
		Header: EthernetHeader{
			DstMAC:    net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			SrcMAC:    net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
			EtherType: EtherTypeIPv4,
		},
		Payload: make([]byte, 100),
	}

	str := frame.String()
	assert.Contains(t, str, "0a:0b:0c:0d:0e:0f")
	assert.Contains(t, str, "01:02:03:04:05:06")
	assert.Contains(t, str, "IPv4")
	assert.Contains(t, str, "100 bytes")
}

func TestEthernetFrameClone(t *testing.T) {
	original := &EthernetFrame{
		Header: EthernetHeader{
			DstMAC:    net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			SrcMAC:    net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
			EtherType: EtherTypeIPv4,
		},
		Payload: []byte{1, 2, 3, 4, 5},
		Raw:     []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	}

	clone := original.Clone()

	// Verify clone has same values
	assert.Equal(t, original.Header.EtherType, clone.Header.EtherType)
	assert.Equal(t, original.Header.DstMAC, clone.Header.DstMAC)
	assert.Equal(t, original.Header.SrcMAC, clone.Header.SrcMAC)
	assert.Equal(t, original.Payload, clone.Payload)
	assert.Equal(t, original.Raw, clone.Raw)

	// Verify it's a deep copy
	clone.Header.DstMAC[0] = 0xFF
	clone.Payload[0] = 0xFF
	assert.NotEqual(t, original.Header.DstMAC[0], clone.Header.DstMAC[0])
	assert.NotEqual(t, original.Payload[0], clone.Payload[0])
}

func TestEthernetFrameMarshalBinary(t *testing.T) {
	frame := &EthernetFrame{
		Header: EthernetHeader{
			DstMAC:    net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			SrcMAC:    net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
			EtherType: EtherTypeIPv4,
		},
		Payload: []byte("test payload"),
	}

	data, err := frame.MarshalBinary()
	require.NoError(t, err)

	// Parse it back
	parsed, err := ParseEthernetFrame(data)
	require.NoError(t, err)
	assert.Equal(t, frame.Header.EtherType, parsed.Header.EtherType)
}

func TestExtractIPAddresses(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		// Create a minimal IPv4 header
		payload := make([]byte, 20)
		// Source IP: 192.168.1.1
		payload[12] = 192
		payload[13] = 168
		payload[14] = 1
		payload[15] = 1
		// Dest IP: 10.0.0.1
		payload[16] = 10
		payload[17] = 0
		payload[18] = 0
		payload[19] = 1

		frame := &EthernetFrame{
			Header:  EthernetHeader{EtherType: EtherTypeIPv4},
			Payload: payload,
		}

		src, dst, err := frame.ExtractIPAddresses()
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", src.String())
		assert.Equal(t, "10.0.0.1", dst.String())
	})

	t.Run("IPv6", func(t *testing.T) {
		// Create a minimal IPv6 header
		payload := make([]byte, 40)
		// Source IP (bytes 8-23)
		payload[8] = 0x20
		payload[9] = 0x01
		// ... rest zeros = 2001::
		// Dest IP (bytes 24-39)
		payload[24] = 0xfe
		payload[25] = 0x80
		// ... rest zeros = fe80::

		frame := &EthernetFrame{
			Header:  EthernetHeader{EtherType: EtherTypeIPv6},
			Payload: payload,
		}

		src, dst, err := frame.ExtractIPAddresses()
		require.NoError(t, err)
		assert.NotNil(t, src)
		assert.NotNil(t, dst)
	})

	t.Run("empty payload", func(t *testing.T) {
		frame := &EthernetFrame{
			Header:  EthernetHeader{EtherType: EtherTypeIPv4},
			Payload: []byte{},
		}
		_, _, err := frame.ExtractIPAddresses()
		assert.Error(t, err)
	})

	t.Run("IPv4 too short", func(t *testing.T) {
		frame := &EthernetFrame{
			Header:  EthernetHeader{EtherType: EtherTypeIPv4},
			Payload: make([]byte, 10),
		}
		_, _, err := frame.ExtractIPAddresses()
		assert.Error(t, err)
	})

	t.Run("IPv6 too short", func(t *testing.T) {
		frame := &EthernetFrame{
			Header:  EthernetHeader{EtherType: EtherTypeIPv6},
			Payload: make([]byte, 20),
		}
		_, _, err := frame.ExtractIPAddresses()
		assert.Error(t, err)
	})

	t.Run("non-IP frame", func(t *testing.T) {
		frame := &EthernetFrame{
			Header:  EthernetHeader{EtherType: EtherTypeARP},
			Payload: make([]byte, 28),
		}
		_, _, err := frame.ExtractIPAddresses()
		assert.Error(t, err)
	})
}

func TestMACEqual(t *testing.T) {
	mac1 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac2 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	mac3 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}
	mac4 := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05}

	assert.True(t, MACEqual(mac1, mac2))
	assert.False(t, MACEqual(mac1, mac3))
	assert.False(t, MACEqual(mac1, mac4))
}

func TestIsLocallyAdministered(t *testing.T) {
	// Locally administered: bit 1 of first octet is set
	local := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	global := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	assert.True(t, IsLocallyAdministered(local))
	assert.False(t, IsLocallyAdministered(global))
	assert.False(t, IsLocallyAdministered(nil))
}

func TestIsGloballyUnique(t *testing.T) {
	global := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	local := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

	assert.True(t, IsGloballyUnique(global))
	assert.False(t, IsGloballyUnique(local))
	assert.False(t, IsGloballyUnique(nil))
}

func TestStandaloneIsBroadcast(t *testing.T) {
	broadcast := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	unicast := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	assert.True(t, IsBroadcast(broadcast))
	assert.False(t, IsBroadcast(unicast))
	assert.False(t, IsBroadcast(net.HardwareAddr{0xFF, 0xFF, 0xFF})) // Wrong length
}

func TestStandaloneIsMulticast(t *testing.T) {
	multicast := net.HardwareAddr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	unicast := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	assert.True(t, IsMulticast(multicast))
	assert.False(t, IsMulticast(unicast))
	assert.False(t, IsMulticast(nil))
}

func TestStandaloneIsUnicast(t *testing.T) {
	unicast := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	multicast := net.HardwareAddr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

	assert.True(t, IsUnicast(unicast))
	assert.False(t, IsUnicast(multicast))
	assert.False(t, IsUnicast(nil))
}
