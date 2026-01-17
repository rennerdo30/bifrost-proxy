//go:build linux

package vpn

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
	tunDevice      = "/dev/net/tun"
	ifnamsiz       = 16
	tunSetIff      = 0x400454ca
	tunSetPersist  = 0x400454cb
	tunSetOwner    = 0x400454cc
	iffTun         = 0x0001
	iffNoPi        = 0x1000
	iffMultiQueue  = 0x0100
)

// linuxTUN implements TUNDevice for Linux.
type linuxTUN struct {
	name   string
	mtu    int
	fd     *os.File
	closed bool
	mu     sync.Mutex
}

// createPlatformTUN creates a TUN device on Linux.
func createPlatformTUN(cfg TUNConfig) (TUNDevice, error) {
	// Open the TUN clone device
	fd, err := os.OpenFile(tunDevice, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsPermission(err) {
			return nil, ErrTUNPermissionDenied
		}
		return nil, &TUNError{Op: "open", Err: err}
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
		return nil, &TUNError{Op: "ioctl TUNSETIFF", Err: errno}
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
func (t *linuxTUN) configure(cfg TUNConfig) error {
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
		return &TUNError{Op: "set MTU", Err: errno}
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
		return &TUNError{Op: "set address", Err: errno}
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
		return &TUNError{Op: "set netmask", Err: errno}
	}

	return nil
}

// setIPv6Address sets an IPv6 address on the interface.
func (t *linuxTUN) setIPv6Address(prefix netip.Prefix) error {
	// IPv6 address configuration requires netlink or ip command
	// For simplicity, we'll use the ip command
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return &TUNError{Op: "get interface", Err: err}
	}

	addr := &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), 128),
	}

	// Use netlink to add address
	// This is a simplified version - full implementation would use netlink directly
	_ = iface
	_ = addr

	return errors.New("IPv6 address configuration not yet implemented")
}

// setUp brings the interface up.
func (t *linuxTUN) setUp(sock int) error {
	var ifr [40]byte
	copy(ifr[:], t.name)

	// Get current flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &TUNError{Op: "get flags", Err: errno}
	}

	// Add IFF_UP flag
	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &TUNError{Op: "set flags", Err: errno}
	}

	return nil
}

// Name returns the interface name.
func (t *linuxTUN) Name() string {
	return t.name
}

// Read reads a packet from the TUN device.
func (t *linuxTUN) Read(packet []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrTUNClosed
	}
	fd := t.fd
	t.mu.Unlock()

	n, err := fd.Read(packet)
	if err != nil {
		return 0, &TUNError{Op: "read", Err: err}
	}
	return n, nil
}

// Write writes a packet to the TUN device.
func (t *linuxTUN) Write(packet []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrTUNClosed
	}
	fd := t.fd
	t.mu.Unlock()

	n, err := fd.Write(packet)
	if err != nil {
		return 0, &TUNError{Op: "write", Err: err}
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
