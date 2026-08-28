package frame

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		assert.True(t, IsBroadcast(parsed.Header.DstMAC))
		assert.Equal(t, EtherTypeARP, parsed.Header.EtherType)
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
		assert.True(t, IsMulticast(parsed.Header.DstMAC))
		assert.Equal(t, EtherTypeIPv6, parsed.Header.EtherType)
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
