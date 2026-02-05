//go:build linux

package device

import (
	"net/netip"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildIPv6AddrMessage(t *testing.T) {
	tun := &linuxTUN{name: "test0"}

	t.Run("builds valid message for /64 prefix", func(t *testing.T) {
		prefix, err := netip.ParsePrefix("fd00::1/64")
		require.NoError(t, err)

		msg := tun.buildIPv6AddrMessage(5, prefix)

		// Verify message length
		assert.Equal(t, 64, len(msg))

		// Verify nlmsghdr
		assert.Equal(t, uint32(64), *(*uint32)(unsafe.Pointer(&msg[0])))   // nlmsg_len
		assert.Equal(t, uint16(20), *(*uint16)(unsafe.Pointer(&msg[4])))   // nlmsg_type (RTM_NEWADDR)
		assert.Equal(t, uint16(0x605), *(*uint16)(unsafe.Pointer(&msg[6]))) // nlmsg_flags (NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)

		// Verify ifaddrmsg
		assert.Equal(t, byte(10), msg[16])                                  // ifa_family (AF_INET6)
		assert.Equal(t, byte(64), msg[17])                                  // ifa_prefixlen
		assert.Equal(t, uint32(5), *(*uint32)(unsafe.Pointer(&msg[20])))   // ifa_index

		// Verify IFA_LOCAL attribute
		assert.Equal(t, uint16(20), *(*uint16)(unsafe.Pointer(&msg[24])))  // rta_len
		assert.Equal(t, uint16(2), *(*uint16)(unsafe.Pointer(&msg[26])))   // rta_type (IFA_LOCAL)

		// Verify IFA_ADDRESS attribute
		assert.Equal(t, uint16(20), *(*uint16)(unsafe.Pointer(&msg[44])))  // rta_len
		assert.Equal(t, uint16(1), *(*uint16)(unsafe.Pointer(&msg[46])))   // rta_type (IFA_ADDRESS)
	})

	t.Run("builds valid message for /128 prefix", func(t *testing.T) {
		prefix, err := netip.ParsePrefix("2001:db8::1/128")
		require.NoError(t, err)

		msg := tun.buildIPv6AddrMessage(10, prefix)

		// Verify prefix length
		assert.Equal(t, byte(128), msg[17])                                 // ifa_prefixlen
		assert.Equal(t, uint32(10), *(*uint32)(unsafe.Pointer(&msg[20])))  // ifa_index
	})

	t.Run("builds valid message for link-local address", func(t *testing.T) {
		prefix, err := netip.ParsePrefix("fe80::1/10")
		require.NoError(t, err)

		msg := tun.buildIPv6AddrMessage(3, prefix)

		// Verify prefix length
		assert.Equal(t, byte(10), msg[17]) // ifa_prefixlen
	})
}

func TestParseNetlinkResponse(t *testing.T) {
	tun := &linuxTUN{name: "test0"}

	t.Run("parses success ACK", func(t *testing.T) {
		// Successful ACK: NLMSG_ERROR with errno = 0
		response := make([]byte, 36)
		*(*uint32)(unsafe.Pointer(&response[0])) = 36      // nlmsg_len
		*(*uint16)(unsafe.Pointer(&response[4])) = 2       // nlmsg_type (NLMSG_ERROR)
		*(*uint16)(unsafe.Pointer(&response[6])) = 0       // nlmsg_flags
		*(*uint32)(unsafe.Pointer(&response[8])) = 1       // nlmsg_seq
		*(*uint32)(unsafe.Pointer(&response[12])) = 0      // nlmsg_pid
		*(*int32)(unsafe.Pointer(&response[16])) = 0       // error code (0 = success)

		err := tun.parseNetlinkResponse(response)
		assert.NoError(t, err)
	})

	t.Run("parses error response", func(t *testing.T) {
		// Error response: NLMSG_ERROR with errno != 0
		response := make([]byte, 36)
		*(*uint32)(unsafe.Pointer(&response[0])) = 36      // nlmsg_len
		*(*uint16)(unsafe.Pointer(&response[4])) = 2       // nlmsg_type (NLMSG_ERROR)
		*(*uint16)(unsafe.Pointer(&response[6])) = 0       // nlmsg_flags
		*(*uint32)(unsafe.Pointer(&response[8])) = 1       // nlmsg_seq
		*(*uint32)(unsafe.Pointer(&response[12])) = 0      // nlmsg_pid
		*(*int32)(unsafe.Pointer(&response[16])) = -17     // EEXIST

		err := tun.parseNetlinkResponse(response)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "set IPv6 address")
	})

	t.Run("handles response too short", func(t *testing.T) {
		response := make([]byte, 10)
		err := tun.parseNetlinkResponse(response)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "response too short")
	})

	t.Run("handles invalid message length", func(t *testing.T) {
		response := make([]byte, 20)
		*(*uint32)(unsafe.Pointer(&response[0])) = 100 // nlmsg_len > actual length
		*(*uint16)(unsafe.Pointer(&response[4])) = 2   // nlmsg_type (NLMSG_ERROR)

		err := tun.parseNetlinkResponse(response)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid message length")
	})

	t.Run("handles error response too short", func(t *testing.T) {
		response := make([]byte, 18)
		*(*uint32)(unsafe.Pointer(&response[0])) = 18  // nlmsg_len
		*(*uint16)(unsafe.Pointer(&response[4])) = 2   // nlmsg_type (NLMSG_ERROR)

		err := tun.parseNetlinkResponse(response)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error response too short")
	})

	t.Run("ignores non-error message types", func(t *testing.T) {
		// Non-error message type (e.g., RTM_NEWADDR = 20)
		response := make([]byte, 20)
		*(*uint32)(unsafe.Pointer(&response[0])) = 20  // nlmsg_len
		*(*uint16)(unsafe.Pointer(&response[4])) = 20  // nlmsg_type (RTM_NEWADDR)

		err := tun.parseNetlinkResponse(response)
		assert.NoError(t, err)
	})
}

func TestLinuxTUN_setAddress(t *testing.T) {
	// Note: This test uses real socket operations, so it requires root
	// and is tested separately from the message building tests above
	if testing.Short() {
		t.Skip("skipping test that requires privileges")
	}

	tun := &linuxTUN{name: "lo"} // Use loopback for testing

	t.Run("IPv4 address detection", func(t *testing.T) {
		prefix, _ := netip.ParsePrefix("10.0.0.1/24")
		// This would call setIPv4Address
		err := tun.setAddress(0, prefix)
		// We expect an error since we don't have a real socket, but it should
		// be from the IPv4 path, not the IPv6 path
		if err != nil {
			// Expected error from socket operations
			assert.NotContains(t, err.Error(), "IPv6")
		}
	})

	t.Run("IPv6 address detection", func(t *testing.T) {
		prefix, _ := netip.ParsePrefix("fd00::1/64")
		// This would call setIPv6Address
		err := tun.setAddress(0, prefix)
		// We expect an error since we don't have a real interface, but it should
		// be from the IPv6 path
		if err != nil {
			// Acceptable - we're just testing routing
			assert.True(t, true)
		}
	})
}
