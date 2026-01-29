//go:build linux

package device

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunCloneDevice = "/dev/net/tun"
	ifnamsiz       = 16
	tunSetIff      = 0x400454ca
	tunSetPersist  = 0x400454cb
	tunSetOwner    = 0x400454cc
	iffTun         = 0x0001
	iffTap         = 0x0002
	iffNoPi        = 0x1000
	iffMultiQueue  = 0x0100
)

// linuxTUN implements NetworkDevice for Linux TUN.
type linuxTUN struct {
	name   string
	mtu    int
	fd     *os.File
	closed bool
	mu     sync.Mutex
}

// createPlatformTUN creates a TUN device on Linux.
func createPlatformTUN(cfg Config) (NetworkDevice, error) {
	// Open the TUN clone device
	fd, err := os.OpenFile(tunCloneDevice, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, &DeviceError{Op: "open", Err: err}
	}

	// Configure the TUN interface
	var ifr [ifnamsiz + 2]byte
	copy(ifr[:], cfg.Name)

	// Set flags: TUN mode, no packet info header
	flags := uint16(iffTun | iffNoPi)
	ifr[ifnamsiz] = byte(flags)
	ifr[ifnamsiz+1] = byte(flags >> 8)

	// Create the interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), tunSetIff, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		fd.Close()
		return nil, &DeviceError{Op: "ioctl TUNSETIFF", Err: errno}
	}

	// Get the actual interface name (kernel might modify it)
	name := string(ifr[:])
	for i, c := range name {
		if c == 0 {
			name = name[:i]
			break
		}
	}

	tun := &linuxTUN{
		name: name,
		mtu:  cfg.MTU,
		fd:   fd,
	}

	// Configure the interface (IP address, MTU, bring up)
	if err := tun.configure(cfg); err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

// configure sets up the TUN interface with IP address and MTU.
func (t *linuxTUN) configure(cfg Config) error {
	// Parse the address
	prefix, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Get a socket for ioctl operations
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sock)

	// Set MTU
	if err := t.setMTU(sock, cfg.MTU); err != nil {
		return err
	}

	// Set IP address
	if err := t.setAddress(sock, prefix); err != nil {
		return err
	}

	// Bring interface up
	if err := t.setUp(sock); err != nil {
		return err
	}

	return nil
}

// setMTU sets the interface MTU.
func (t *linuxTUN) setMTU(sock int, mtu int) error {
	var ifr [40]byte
	copy(ifr[:], t.name)

	// Put MTU in the ifr structure
	*(*int32)(unsafe.Pointer(&ifr[16])) = int32(mtu)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &DeviceError{Op: "set MTU", Err: errno}
	}

	return nil
}

// setAddress sets the interface IP address and netmask.
func (t *linuxTUN) setAddress(sock int, prefix netip.Prefix) error {
	addr := prefix.Addr()

	if addr.Is4() {
		return t.setIPv4Address(sock, prefix)
	}
	return t.setIPv6Address(prefix)
}

// setIPv4Address sets an IPv4 address on the interface.
func (t *linuxTUN) setIPv4Address(sock int, prefix netip.Prefix) error {
	addr := prefix.Addr().As4()

	// Set IP address
	var ifrAddr [40]byte
	copy(ifrAddr[:], t.name)

	// sockaddr_in structure at offset 16
	ifrAddr[16] = syscall.AF_INET // sin_family
	ifrAddr[17] = 0
	copy(ifrAddr[20:24], addr[:]) // sin_addr

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifrAddr[0])))
	if errno != 0 {
		return &DeviceError{Op: "set address", Err: errno}
	}

	// Set netmask
	var ifrMask [40]byte
	copy(ifrMask[:], t.name)
	ifrMask[16] = syscall.AF_INET
	ifrMask[17] = 0

	// Calculate netmask from prefix length
	mask := net.CIDRMask(prefix.Bits(), 32)
	copy(ifrMask[20:24], mask)

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifrMask[0])))
	if errno != 0 {
		return &DeviceError{Op: "set netmask", Err: errno}
	}

	return nil
}

// setIPv6Address sets an IPv6 address on the interface using netlink.
func (t *linuxTUN) setIPv6Address(prefix netip.Prefix) error {
	// Get interface index
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return &DeviceError{Op: "get interface", Err: err}
	}

	// Create netlink socket for address configuration
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_ROUTE)
	if err != nil {
		return &DeviceError{Op: "create netlink socket", Err: err}
	}
	defer unix.Close(sock)

	// Bind the socket
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Pid:    0, // Let kernel assign
	}
	if err := unix.Bind(sock, addr); err != nil {
		return &DeviceError{Op: "bind netlink socket", Err: err}
	}

	// Build the netlink message to add IPv6 address
	msg := t.buildIPv6AddrMessage(iface.Index, prefix)

	// Send the message
	if err := unix.Sendto(sock, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return &DeviceError{Op: "send netlink message", Err: err}
	}

	// Receive acknowledgment
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return &DeviceError{Op: "receive netlink response", Err: err}
	}

	// Parse response for errors
	if err := t.parseNetlinkResponse(buf[:n]); err != nil {
		return err
	}

	return nil
}

// buildIPv6AddrMessage constructs a netlink RTM_NEWADDR message for IPv6.
func (t *linuxTUN) buildIPv6AddrMessage(ifIndex int, prefix netip.Prefix) []byte {
	addr := prefix.Addr().As16()
	prefixLen := uint8(prefix.Bits())

	// Netlink message header (16 bytes)
	// struct nlmsghdr {
	//     __u32 nlmsg_len;    // Length of message including header
	//     __u16 nlmsg_type;   // Message type (RTM_NEWADDR = 20)
	//     __u16 nlmsg_flags;  // Additional flags
	//     __u32 nlmsg_seq;    // Sequence number
	//     __u32 nlmsg_pid;    // Sending process port ID
	// }

	// Interface address message (8 bytes)
	// struct ifaddrmsg {
	//     __u8  ifa_family;   // Address family (AF_INET6)
	//     __u8  ifa_prefixlen; // Prefix length
	//     __u8  ifa_flags;    // Address flags
	//     __u8  ifa_scope;    // Address scope
	//     __u32 ifa_index;    // Interface index
	// }

	// Attribute for address (4 byte header + 16 byte IPv6 address)
	// struct rtattr {
	//     unsigned short rta_len;
	//     unsigned short rta_type;
	// }

	// Calculate total message length
	// nlmsghdr (16) + ifaddrmsg (8) + rtattr for IFA_LOCAL (4 + 16) + rtattr for IFA_ADDRESS (4 + 16) = 64
	msgLen := 16 + 8 + (4 + 16) + (4 + 16)
	msg := make([]byte, msgLen)

	// nlmsghdr
	*(*uint32)(unsafe.Pointer(&msg[0])) = uint32(msgLen)          // nlmsg_len
	*(*uint16)(unsafe.Pointer(&msg[4])) = unix.RTM_NEWADDR        // nlmsg_type
	*(*uint16)(unsafe.Pointer(&msg[6])) = unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK // nlmsg_flags
	*(*uint32)(unsafe.Pointer(&msg[8])) = 1                       // nlmsg_seq
	*(*uint32)(unsafe.Pointer(&msg[12])) = 0                      // nlmsg_pid (0 = kernel)

	// ifaddrmsg
	msg[16] = unix.AF_INET6                                       // ifa_family
	msg[17] = prefixLen                                           // ifa_prefixlen
	msg[18] = 0                                                   // ifa_flags
	msg[19] = unix.RT_SCOPE_UNIVERSE                              // ifa_scope (global)
	*(*uint32)(unsafe.Pointer(&msg[20])) = uint32(ifIndex)        // ifa_index

	// rtattr for IFA_LOCAL (local address)
	offset := 24
	*(*uint16)(unsafe.Pointer(&msg[offset])) = 20                 // rta_len (4 + 16)
	*(*uint16)(unsafe.Pointer(&msg[offset+2])) = unix.IFA_LOCAL   // rta_type
	copy(msg[offset+4:offset+20], addr[:])                        // IPv6 address

	// rtattr for IFA_ADDRESS (peer/broadcast address, same as local for point-to-point)
	offset = 44
	*(*uint16)(unsafe.Pointer(&msg[offset])) = 20                 // rta_len (4 + 16)
	*(*uint16)(unsafe.Pointer(&msg[offset+2])) = unix.IFA_ADDRESS // rta_type
	copy(msg[offset+4:offset+20], addr[:])                        // IPv6 address

	return msg
}

// parseNetlinkResponse checks for errors in the netlink response.
func (t *linuxTUN) parseNetlinkResponse(data []byte) error {
	if len(data) < 16 {
		return &DeviceError{Op: "parse netlink response", Err: errors.New("response too short")}
	}

	// Parse nlmsghdr
	msgLen := *(*uint32)(unsafe.Pointer(&data[0]))
	msgType := *(*uint16)(unsafe.Pointer(&data[4]))

	if msgLen > uint32(len(data)) {
		return &DeviceError{Op: "parse netlink response", Err: errors.New("invalid message length")}
	}

	// Check for error response (NLMSG_ERROR = 2)
	if msgType == unix.NLMSG_ERROR {
		if len(data) < 20 {
			return &DeviceError{Op: "parse netlink response", Err: errors.New("error response too short")}
		}
		// Error code is at offset 16 (after nlmsghdr)
		errno := *(*int32)(unsafe.Pointer(&data[16]))
		if errno < 0 {
			return &DeviceError{Op: "set IPv6 address", Err: syscall.Errno(-errno)}
		}
		// errno == 0 means ACK (success)
	}

	return nil
}

// setUp brings the interface up.
func (t *linuxTUN) setUp(sock int) error {
	var ifr [40]byte
	copy(ifr[:], t.name)

	// Get current flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &DeviceError{Op: "get flags", Err: errno}
	}

	// Add IFF_UP flag
	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &DeviceError{Op: "set flags", Err: errno}
	}

	return nil
}

// Name returns the interface name.
func (t *linuxTUN) Name() string {
	return t.name
}

// Type returns the device type.
func (t *linuxTUN) Type() DeviceType {
	return DeviceTUN
}

// Read reads a packet from the TUN device.
func (t *linuxTUN) Read(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	fd := t.fd
	t.mu.Unlock()

	n, err := fd.Read(buf)
	if err != nil {
		return 0, &DeviceError{Op: "read", Err: err}
	}
	return n, nil
}

// Write writes a packet to the TUN device.
func (t *linuxTUN) Write(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	fd := t.fd
	t.mu.Unlock()

	n, err := fd.Write(buf)
	if err != nil {
		return 0, &DeviceError{Op: "write", Err: err}
	}
	return n, nil
}

// Close closes the TUN device.
func (t *linuxTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	if t.fd != nil {
		return t.fd.Close()
	}
	return nil
}

// MTU returns the MTU of the interface.
func (t *linuxTUN) MTU() int {
	return t.mtu
}
