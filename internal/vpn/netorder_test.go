package vpn

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The byte swap must happen in 16-bit arithmetic: the previous widened form
// (`uint32(port)<<8 | uint32(port)>>8`) pushed the high byte into bits 16–23,
// so no Windows MIB-table port ever matched and per-app split tunneling never
// classified a single connection.
func TestPortToNetworkOrder(t *testing.T) {
	cases := []struct {
		port uint16
		want uint32
	}{
		{0, 0x0000},
		{1, 0x0100},
		{80, 0x5000},
		{255, 0xFF00},
		{256, 0x0001},
		{443, 0xBB01},
		{7080, 0xA81B},
		{8080, 0x901F},
		{32768, 0x0080},
		{65535, 0xFFFF},
	}
	for _, tc := range cases {
		got := portToNetworkOrder(tc.port)
		assert.Equal(t, tc.want, got, "port %d", tc.port)

		// Cross-check against the definitionally correct encoding: the low
		// 16 bits hold the port in big-endian (network) byte order.
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], tc.port)
		ref := uint32(binary.LittleEndian.Uint16(b[:]))
		assert.Equal(t, ref, got, "port %d disagrees with the reference encoding", tc.port)

		// And it must fit in 16 bits — the widened bug produced values with
		// bits above 15 set, which is exactly why nothing ever matched.
		assert.Zero(t, got&0xFFFF0000, "port %d leaked into the high word", tc.port)
	}
}

// The buggy form, preserved here as a proof: for any port with a non-zero high
// byte it disagrees with the correct conversion.
func TestPortToNetworkOrder_WidenedFormWasWrong(t *testing.T) {
	buggy := func(port uint16) uint32 { return uint32(port)<<8 | uint32(port)>>8 }
	assert.NotEqual(t, portToNetworkOrder(443), buggy(443))
	assert.NotEqual(t, portToNetworkOrder(7080), buggy(7080))
	// Ports that fit in one byte happened to work, which is how the bug could
	// pass a casual test with a small port number.
	assert.Equal(t, portToNetworkOrder(80), buggy(80))
}
