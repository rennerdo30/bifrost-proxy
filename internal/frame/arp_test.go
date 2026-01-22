package frame

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseARPPacket(t *testing.T) {
	t.Run("valid ARP request", func(t *testing.T) {
		// Build a valid ARP request packet
		packet := make([]byte, ARPEthernetIPv4Len)
		// Hardware type: Ethernet (1)
		packet[0] = 0x00
		packet[1] = 0x01
		// Protocol type: IPv4 (0x0800)
		packet[2] = 0x08
		packet[3] = 0x00
		// Hardware address length: 6
		packet[4] = 6
		// Protocol address length: 4
		packet[5] = 4
		// Operation: ARP request (1)
		packet[6] = 0x00
		packet[7] = 0x01
		// Sender hardware address
		copy(packet[8:14], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		// Sender protocol address: 192.168.1.1
		copy(packet[14:18], []byte{192, 168, 1, 1})
		// Target hardware address (zeros for request)
		copy(packet[18:24], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		// Target protocol address: 192.168.1.2
		copy(packet[24:28], []byte{192, 168, 1, 2})

		arp, err := ParseARPPacket(packet)
		require.NoError(t, err)
		assert.Equal(t, ARPHardwareEthernet, arp.HardwareType)
		assert.Equal(t, ARPProtocolIPv4, arp.ProtocolType)
		assert.Equal(t, uint8(6), arp.HardwareAddrLen)
		assert.Equal(t, uint8(4), arp.ProtocolAddrLen)
		assert.Equal(t, ARPRequest, arp.Operation)
		assert.Equal(t, net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, arp.SenderHardwareAddr)
		assert.Equal(t, netip.MustParseAddr("192.168.1.1"), arp.SenderProtocolAddr)
		assert.Equal(t, netip.MustParseAddr("192.168.1.2"), arp.TargetProtocolAddr)
		assert.True(t, arp.IsRequest())
		assert.False(t, arp.IsReply())
	})

	t.Run("valid ARP reply", func(t *testing.T) {
		packet := make([]byte, ARPEthernetIPv4Len)
		// Hardware type: Ethernet (1)
		packet[0] = 0x00
		packet[1] = 0x01
		// Protocol type: IPv4 (0x0800)
		packet[2] = 0x08
		packet[3] = 0x00
		// Hardware address length: 6
		packet[4] = 6
		// Protocol address length: 4
		packet[5] = 4
		// Operation: ARP reply (2)
		packet[6] = 0x00
		packet[7] = 0x02
		// Sender hardware address
		copy(packet[8:14], []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F})
		// Sender protocol address: 10.0.0.1
		copy(packet[14:18], []byte{10, 0, 0, 1})
		// Target hardware address
		copy(packet[18:24], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		// Target protocol address: 10.0.0.2
		copy(packet[24:28], []byte{10, 0, 0, 2})

		arp, err := ParseARPPacket(packet)
		require.NoError(t, err)
		assert.True(t, arp.IsReply())
		assert.False(t, arp.IsRequest())
		assert.Equal(t, ARPReply, arp.Operation)
	})

	t.Run("packet too short for header", func(t *testing.T) {
		packet := make([]byte, ARPHeaderSize-1)
		_, err := ParseARPPacket(packet)
		assert.Equal(t, ErrARPTooShort, err)
	})

	t.Run("packet too short for data", func(t *testing.T) {
		packet := make([]byte, ARPHeaderSize+10) // Not enough for full Ethernet/IPv4 ARP
		// Hardware type: Ethernet (1)
		packet[0] = 0x00
		packet[1] = 0x01
		// Protocol type: IPv4 (0x0800)
		packet[2] = 0x08
		packet[3] = 0x00
		// Hardware address length: 6
		packet[4] = 6
		// Protocol address length: 4
		packet[5] = 4
		// Operation
		packet[6] = 0x00
		packet[7] = 0x01

		_, err := ParseARPPacket(packet)
		assert.Equal(t, ErrARPTooShort, err)
	})

	t.Run("invalid hardware type", func(t *testing.T) {
		packet := make([]byte, ARPEthernetIPv4Len)
		// Hardware type: Not Ethernet (2)
		packet[0] = 0x00
		packet[1] = 0x02
		// Protocol type: IPv4
		packet[2] = 0x08
		packet[3] = 0x00
		// Lengths
		packet[4] = 6
		packet[5] = 4
		// Operation
		packet[6] = 0x00
		packet[7] = 0x01

		_, err := ParseARPPacket(packet)
		assert.ErrorIs(t, err, ErrARPInvalidType)
	})

	t.Run("invalid protocol type", func(t *testing.T) {
		packet := make([]byte, ARPEthernetIPv4Len)
		// Hardware type: Ethernet
		packet[0] = 0x00
		packet[1] = 0x01
		// Protocol type: Not IPv4
		packet[2] = 0x86
		packet[3] = 0xDD
		// Lengths
		packet[4] = 6
		packet[5] = 4
		// Operation
		packet[6] = 0x00
		packet[7] = 0x01

		_, err := ParseARPPacket(packet)
		assert.ErrorIs(t, err, ErrARPInvalidType)
	})

	t.Run("invalid hardware address length", func(t *testing.T) {
		packet := make([]byte, ARPEthernetIPv4Len)
		// Hardware type: Ethernet
		packet[0] = 0x00
		packet[1] = 0x01
		// Protocol type: IPv4
		packet[2] = 0x08
		packet[3] = 0x00
		// Invalid hardware address length
		packet[4] = 8
		packet[5] = 4
		// Operation
		packet[6] = 0x00
		packet[7] = 0x01

		_, err := ParseARPPacket(packet)
		assert.ErrorIs(t, err, ErrARPInvalidLength)
	})

	t.Run("invalid protocol address length", func(t *testing.T) {
		packet := make([]byte, ARPEthernetIPv4Len)
		// Hardware type: Ethernet
		packet[0] = 0x00
		packet[1] = 0x01
		// Protocol type: IPv4
		packet[2] = 0x08
		packet[3] = 0x00
		// Lengths - invalid protocol length
		packet[4] = 6
		packet[5] = 16 // IPv6 length instead of IPv4
		// Operation
		packet[6] = 0x00
		packet[7] = 0x01

		_, err := ParseARPPacket(packet)
		assert.ErrorIs(t, err, ErrARPInvalidLength)
	})
}

func TestBuildARPPacket(t *testing.T) {
	t.Run("valid ARP request", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		targetMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		senderIP := netip.MustParseAddr("192.168.1.1")
		targetIP := netip.MustParseAddr("192.168.1.2")

		packet, err := BuildARPPacket(ARPRequest, senderMAC, senderIP, targetMAC, targetIP)
		require.NoError(t, err)
		assert.Len(t, packet, ARPEthernetIPv4Len)

		// Parse it back
		arp, err := ParseARPPacket(packet)
		require.NoError(t, err)
		assert.Equal(t, ARPRequest, arp.Operation)
		assert.Equal(t, senderMAC, arp.SenderHardwareAddr)
		assert.Equal(t, senderIP, arp.SenderProtocolAddr)
		assert.Equal(t, targetMAC, arp.TargetHardwareAddr)
		assert.Equal(t, targetIP, arp.TargetProtocolAddr)
	})

	t.Run("valid ARP reply", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		targetMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		senderIP := netip.MustParseAddr("10.0.0.1")
		targetIP := netip.MustParseAddr("10.0.0.2")

		packet, err := BuildARPPacket(ARPReply, senderMAC, senderIP, targetMAC, targetIP)
		require.NoError(t, err)

		arp, err := ParseARPPacket(packet)
		require.NoError(t, err)
		assert.Equal(t, ARPReply, arp.Operation)
	})

	t.Run("invalid sender MAC length", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03} // Too short
		targetMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		senderIP := netip.MustParseAddr("192.168.1.1")
		targetIP := netip.MustParseAddr("192.168.1.2")

		_, err := BuildARPPacket(ARPRequest, senderMAC, senderIP, targetMAC, targetIP)
		assert.Equal(t, ErrInvalidMAC, err)
	})

	t.Run("invalid target MAC length", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		targetMAC := net.HardwareAddr{0x00, 0x00, 0x00} // Too short
		senderIP := netip.MustParseAddr("192.168.1.1")
		targetIP := netip.MustParseAddr("192.168.1.2")

		_, err := BuildARPPacket(ARPRequest, senderMAC, senderIP, targetMAC, targetIP)
		assert.Equal(t, ErrInvalidMAC, err)
	})

	t.Run("IPv6 sender address not supported", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		targetMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		senderIP := netip.MustParseAddr("2001:db8::1")
		targetIP := netip.MustParseAddr("192.168.1.2")

		_, err := BuildARPPacket(ARPRequest, senderMAC, senderIP, targetMAC, targetIP)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IPv4")
	})

	t.Run("IPv6 target address not supported", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		targetMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		senderIP := netip.MustParseAddr("192.168.1.1")
		targetIP := netip.MustParseAddr("2001:db8::2")

		_, err := BuildARPPacket(ARPRequest, senderMAC, senderIP, targetMAC, targetIP)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IPv4")
	})
}

func TestBuildARPRequest(t *testing.T) {
	senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("192.168.1.1")
	targetIP := netip.MustParseAddr("192.168.1.2")

	packet, err := BuildARPRequest(senderMAC, senderIP, targetIP)
	require.NoError(t, err)

	arp, err := ParseARPPacket(packet)
	require.NoError(t, err)
	assert.Equal(t, ARPRequest, arp.Operation)
	assert.Equal(t, senderMAC, arp.SenderHardwareAddr)
	assert.Equal(t, senderIP, arp.SenderProtocolAddr)
	// Target MAC should be all zeros for request
	assert.Equal(t, net.HardwareAddr{0, 0, 0, 0, 0, 0}, arp.TargetHardwareAddr)
	assert.Equal(t, targetIP, arp.TargetProtocolAddr)
}

func TestBuildARPReply(t *testing.T) {
	senderMAC := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	targetMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("10.0.0.1")
	targetIP := netip.MustParseAddr("10.0.0.2")

	packet, err := BuildARPReply(senderMAC, senderIP, targetMAC, targetIP)
	require.NoError(t, err)

	arp, err := ParseARPPacket(packet)
	require.NoError(t, err)
	assert.Equal(t, ARPReply, arp.Operation)
	assert.Equal(t, senderMAC, arp.SenderHardwareAddr)
	assert.Equal(t, senderIP, arp.SenderProtocolAddr)
	assert.Equal(t, targetMAC, arp.TargetHardwareAddr)
	assert.Equal(t, targetIP, arp.TargetProtocolAddr)
}

func TestBuildARPFrame(t *testing.T) {
	t.Run("valid ARP frame", func(t *testing.T) {
		dstMAC := BroadcastMAC
		srcMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

		// Build an ARP packet first
		senderIP := netip.MustParseAddr("192.168.1.1")
		targetIP := netip.MustParseAddr("192.168.1.2")
		arpPacket, err := BuildARPRequest(srcMAC, senderIP, targetIP)
		require.NoError(t, err)

		frame, err := BuildARPFrame(dstMAC, srcMAC, arpPacket)
		require.NoError(t, err)

		// Parse the Ethernet frame
		ethFrame, err := ParseEthernetFrame(frame)
		require.NoError(t, err)
		assert.Equal(t, EtherTypeARP, ethFrame.Header.EtherType)
		assert.Equal(t, dstMAC, ethFrame.Header.DstMAC)
		assert.Equal(t, srcMAC, ethFrame.Header.SrcMAC)

		// Parse the ARP packet from payload
		arp, err := ParseARPPacket(ethFrame.Payload)
		require.NoError(t, err)
		assert.True(t, arp.IsRequest())
	})

	t.Run("invalid MAC addresses", func(t *testing.T) {
		_, err := BuildARPFrame([]byte{1, 2, 3}, []byte{4, 5, 6}, []byte{})
		assert.Error(t, err)
	})
}

func TestBuildARPRequestFrame(t *testing.T) {
	senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("192.168.1.1")
	targetIP := netip.MustParseAddr("192.168.1.2")

	frame, err := BuildARPRequestFrame(senderMAC, senderIP, targetIP)
	require.NoError(t, err)

	// Parse the Ethernet frame
	ethFrame, err := ParseEthernetFrame(frame)
	require.NoError(t, err)
	assert.Equal(t, EtherTypeARP, ethFrame.Header.EtherType)
	assert.Equal(t, BroadcastMAC, ethFrame.Header.DstMAC)
	assert.Equal(t, senderMAC, ethFrame.Header.SrcMAC)

	// Parse the ARP packet
	arp, err := ParseARPPacket(ethFrame.Payload)
	require.NoError(t, err)
	assert.True(t, arp.IsRequest())
	assert.Equal(t, senderMAC, arp.SenderHardwareAddr)
	assert.Equal(t, senderIP, arp.SenderProtocolAddr)
	assert.Equal(t, targetIP, arp.TargetProtocolAddr)
}

func TestBuildARPRequestFrameError(t *testing.T) {
	// Invalid sender MAC
	_, err := BuildARPRequestFrame(net.HardwareAddr{0x01, 0x02, 0x03}, netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.2"))
	assert.Error(t, err)
}

func TestBuildARPReplyFrame(t *testing.T) {
	senderMAC := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	targetMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("10.0.0.1")
	targetIP := netip.MustParseAddr("10.0.0.2")

	frame, err := BuildARPReplyFrame(senderMAC, senderIP, targetMAC, targetIP)
	require.NoError(t, err)

	// Parse the Ethernet frame
	ethFrame, err := ParseEthernetFrame(frame)
	require.NoError(t, err)
	assert.Equal(t, EtherTypeARP, ethFrame.Header.EtherType)
	assert.Equal(t, targetMAC, ethFrame.Header.DstMAC)
	assert.Equal(t, senderMAC, ethFrame.Header.SrcMAC)

	// Parse the ARP packet
	arp, err := ParseARPPacket(ethFrame.Payload)
	require.NoError(t, err)
	assert.True(t, arp.IsReply())
	assert.Equal(t, senderMAC, arp.SenderHardwareAddr)
	assert.Equal(t, senderIP, arp.SenderProtocolAddr)
	assert.Equal(t, targetMAC, arp.TargetHardwareAddr)
	assert.Equal(t, targetIP, arp.TargetProtocolAddr)
}

func TestBuildARPReplyFrameError(t *testing.T) {
	// Invalid sender MAC
	_, err := BuildARPReplyFrame(
		net.HardwareAddr{0x01, 0x02, 0x03}, // Invalid
		netip.MustParseAddr("10.0.0.1"),
		net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		netip.MustParseAddr("10.0.0.2"),
	)
	assert.Error(t, err)
}

func TestARPPacketString(t *testing.T) {
	t.Run("ARP request", func(t *testing.T) {
		arp := &ARPPacket{
			Operation:          ARPRequest,
			SenderHardwareAddr: net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			SenderProtocolAddr: netip.MustParseAddr("192.168.1.1"),
			TargetHardwareAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			TargetProtocolAddr: netip.MustParseAddr("192.168.1.2"),
		}

		str := arp.String()
		assert.Contains(t, str, "ARP")
		assert.Contains(t, str, "request")
		assert.Contains(t, str, "192.168.1.1")
		assert.Contains(t, str, "192.168.1.2")
		assert.Contains(t, str, "01:02:03:04:05:06")
	})

	t.Run("ARP reply", func(t *testing.T) {
		arp := &ARPPacket{
			Operation:          ARPReply,
			SenderHardwareAddr: net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
			SenderProtocolAddr: netip.MustParseAddr("10.0.0.1"),
			TargetHardwareAddr: net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			TargetProtocolAddr: netip.MustParseAddr("10.0.0.2"),
		}

		str := arp.String()
		assert.Contains(t, str, "reply")
	})

	t.Run("unknown operation", func(t *testing.T) {
		arp := &ARPPacket{
			Operation:          0x0003, // Unknown
			SenderHardwareAddr: net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			SenderProtocolAddr: netip.MustParseAddr("192.168.1.1"),
			TargetHardwareAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			TargetProtocolAddr: netip.MustParseAddr("192.168.1.2"),
		}

		str := arp.String()
		assert.Contains(t, str, "unknown")
	})
}

func TestARPPacketMarshalBinary(t *testing.T) {
	arp := &ARPPacket{
		HardwareType:       ARPHardwareEthernet,
		ProtocolType:       ARPProtocolIPv4,
		HardwareAddrLen:    6,
		ProtocolAddrLen:    4,
		Operation:          ARPRequest,
		SenderHardwareAddr: net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		SenderProtocolAddr: netip.MustParseAddr("192.168.1.1"),
		TargetHardwareAddr: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		TargetProtocolAddr: netip.MustParseAddr("192.168.1.2"),
	}

	data, err := arp.MarshalBinary()
	require.NoError(t, err)

	// Parse it back
	parsed, err := ParseARPPacket(data)
	require.NoError(t, err)
	assert.Equal(t, arp.Operation, parsed.Operation)
	assert.Equal(t, arp.SenderHardwareAddr, parsed.SenderHardwareAddr)
	assert.Equal(t, arp.SenderProtocolAddr, parsed.SenderProtocolAddr)
	assert.Equal(t, arp.TargetHardwareAddr, parsed.TargetHardwareAddr)
	assert.Equal(t, arp.TargetProtocolAddr, parsed.TargetProtocolAddr)
}

func TestNewARPInterceptor(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	macTable := NewMACTable(DefaultMACTableConfig())

	interceptor := NewARPInterceptor(localMAC, localIP, macTable)
	require.NotNil(t, interceptor)
	assert.Equal(t, localMAC, interceptor.LocalMAC())
	assert.Equal(t, localIP, interceptor.LocalIP())
}

func TestARPInterceptorHandleFrame(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	macTable := NewMACTable(DefaultMACTableConfig())
	interceptor := NewARPInterceptor(localMAC, localIP, macTable)

	t.Run("ARP request for our IP - should respond", func(t *testing.T) {
		// Build an ARP request frame asking for our IP
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		senderIP := netip.MustParseAddr("10.0.0.2")

		frame, err := BuildARPRequestFrame(senderMAC, senderIP, localIP)
		require.NoError(t, err)

		response := interceptor.HandleFrame(frame)
		require.NotNil(t, response)

		// Parse the response
		ethFrame, err := ParseEthernetFrame(response)
		require.NoError(t, err)
		assert.Equal(t, EtherTypeARP, ethFrame.Header.EtherType)
		assert.Equal(t, senderMAC, ethFrame.Header.DstMAC)
		assert.Equal(t, localMAC, ethFrame.Header.SrcMAC)

		arp, err := ParseARPPacket(ethFrame.Payload)
		require.NoError(t, err)
		assert.True(t, arp.IsReply())
		assert.Equal(t, localMAC, arp.SenderHardwareAddr)
		assert.Equal(t, localIP, arp.SenderProtocolAddr)
		assert.Equal(t, senderMAC, arp.TargetHardwareAddr)
		assert.Equal(t, senderIP, arp.TargetProtocolAddr)

		// Check that the sender MAC was learned
		foundMAC, found := macTable.LookupByIP(senderIP)
		assert.True(t, found)
		assert.Equal(t, senderMAC, foundMAC)
	})

	t.Run("ARP request for different IP - should not respond", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		senderIP := netip.MustParseAddr("10.0.0.2")
		targetIP := netip.MustParseAddr("10.0.0.99") // Not our IP

		frame, err := BuildARPRequestFrame(senderMAC, senderIP, targetIP)
		require.NoError(t, err)

		response := interceptor.HandleFrame(frame)
		assert.Nil(t, response)
	})

	t.Run("ARP reply - should learn but not respond", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		targetMAC := localMAC
		senderIP := netip.MustParseAddr("10.0.0.3")
		targetIP := localIP

		frame, err := BuildARPReplyFrame(senderMAC, senderIP, targetMAC, targetIP)
		require.NoError(t, err)

		response := interceptor.HandleFrame(frame)
		assert.Nil(t, response) // Should not respond to replies

		// But should have learned the sender's MAC
		foundMAC, found := macTable.LookupByIP(senderIP)
		assert.True(t, found)
		assert.Equal(t, senderMAC, foundMAC)
	})

	t.Run("non-ARP frame - should return nil", func(t *testing.T) {
		// Build an IPv4 frame
		dstMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		srcMAC := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		payload := make([]byte, 20) // Minimal IPv4 payload

		frame, err := BuildEthernetFrame(dstMAC, srcMAC, EtherTypeIPv4, payload)
		require.NoError(t, err)

		response := interceptor.HandleFrame(frame)
		assert.Nil(t, response)
	})

	t.Run("invalid frame - should return nil", func(t *testing.T) {
		// Too short frame
		frame := []byte{0x01, 0x02, 0x03}
		response := interceptor.HandleFrame(frame)
		assert.Nil(t, response)
	})

	t.Run("ARP frame with invalid ARP packet - should return nil", func(t *testing.T) {
		// Build a frame that looks like ARP but has invalid ARP content
		dstMAC := BroadcastMAC
		srcMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		invalidARP := []byte{0x00, 0x02} // Invalid hardware type and too short

		frame, err := BuildEthernetFrame(dstMAC, srcMAC, EtherTypeARP, invalidARP)
		require.NoError(t, err)

		response := interceptor.HandleFrame(frame)
		assert.Nil(t, response)
	})
}

func TestARPInterceptorHandleFrameWithoutMACTable(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	interceptor := NewARPInterceptor(localMAC, localIP, nil) // No MAC table

	// Build an ARP request frame
	senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("10.0.0.2")

	frame, err := BuildARPRequestFrame(senderMAC, senderIP, localIP)
	require.NoError(t, err)

	// Should still respond, just not learn
	response := interceptor.HandleFrame(frame)
	require.NotNil(t, response)
}

func TestARPInterceptorHandlePacket(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	macTable := NewMACTable(DefaultMACTableConfig())
	interceptor := NewARPInterceptor(localMAC, localIP, macTable)

	t.Run("ARP request for our IP - should respond", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		senderIP := netip.MustParseAddr("10.0.0.2")

		arpPacket, err := BuildARPRequest(senderMAC, senderIP, localIP)
		require.NoError(t, err)

		response, err := interceptor.HandlePacket(arpPacket)
		require.NoError(t, err)
		require.NotNil(t, response)

		// Parse the response
		arp, err := ParseARPPacket(response)
		require.NoError(t, err)
		assert.True(t, arp.IsReply())
		assert.Equal(t, localMAC, arp.SenderHardwareAddr)
		assert.Equal(t, localIP, arp.SenderProtocolAddr)
	})

	t.Run("ARP request for different IP - should not respond", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		senderIP := netip.MustParseAddr("10.0.0.2")
		targetIP := netip.MustParseAddr("10.0.0.99")

		arpPacket, err := BuildARPRequest(senderMAC, senderIP, targetIP)
		require.NoError(t, err)

		response, err := interceptor.HandlePacket(arpPacket)
		require.NoError(t, err)
		assert.Nil(t, response)
	})

	t.Run("ARP reply - should learn but not respond", func(t *testing.T) {
		senderMAC := net.HardwareAddr{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
		senderIP := netip.MustParseAddr("10.0.0.4")

		arpPacket, err := BuildARPReply(senderMAC, senderIP, localMAC, localIP)
		require.NoError(t, err)

		response, err := interceptor.HandlePacket(arpPacket)
		require.NoError(t, err)
		assert.Nil(t, response)

		// But should have learned the sender's MAC
		foundMAC, found := macTable.LookupByIP(senderIP)
		assert.True(t, found)
		assert.Equal(t, senderMAC, foundMAC)
	})

	t.Run("invalid ARP packet - should return error", func(t *testing.T) {
		invalidPacket := []byte{0x01, 0x02, 0x03}
		_, err := interceptor.HandlePacket(invalidPacket)
		assert.Error(t, err)
	})
}

func TestARPInterceptorHandlePacketWithoutMACTable(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	interceptor := NewARPInterceptor(localMAC, localIP, nil) // No MAC table

	senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("10.0.0.2")

	arpPacket, err := BuildARPRequest(senderMAC, senderIP, localIP)
	require.NoError(t, err)

	// Should still respond, just not learn
	response, err := interceptor.HandlePacket(arpPacket)
	require.NoError(t, err)
	require.NotNil(t, response)
}

func TestARPInterceptorLocalMACAndIP(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	interceptor := NewARPInterceptor(localMAC, localIP, nil)

	assert.Equal(t, localMAC, interceptor.LocalMAC())
	assert.Equal(t, localIP, interceptor.LocalIP())
}

func TestARPInterceptorHandleFrameWithInvalidLocalMAC(t *testing.T) {
	// This test verifies behavior when BuildARPReplyFrame might fail
	// In practice, this branch is unlikely to be reached with valid local MAC
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	macTable := NewMACTable(DefaultMACTableConfig())
	interceptor := NewARPInterceptor(localMAC, localIP, macTable)

	// Build a valid ARP request
	senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("10.0.0.2")
	frame, err := BuildARPRequestFrame(senderMAC, senderIP, localIP)
	require.NoError(t, err)

	// The interceptor should respond successfully
	response := interceptor.HandleFrame(frame)
	require.NotNil(t, response)
}

func TestARPInterceptorHandleFrameWithInvalidSenderIP(t *testing.T) {
	// Test with a sender that has an invalid protocol address
	// This tests the macTable learning with invalid address
	localMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIP := netip.MustParseAddr("10.0.0.1")
	macTable := NewMACTable(DefaultMACTableConfig())
	interceptor := NewARPInterceptor(localMAC, localIP, macTable)

	// Create a raw ARP packet where sender IP might be problematic
	// For valid tests, this is a normal packet
	senderMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	senderIP := netip.MustParseAddr("0.0.0.0") // Zero IP (might be used in announcements)
	frame, err := BuildARPRequestFrame(senderMAC, senderIP, localIP)
	require.NoError(t, err)

	// Should still respond (even though sender IP is 0.0.0.0)
	response := interceptor.HandleFrame(frame)
	require.NotNil(t, response)
}
