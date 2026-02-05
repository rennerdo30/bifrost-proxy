//go:build linux

package device

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxTAP implements TAPDevice for Linux.
type linuxTAP struct {
	name   string
	mtu    int
	fd     *os.File
	mac    net.HardwareAddr
	closed bool
	mu     sync.Mutex
}

// createPlatformTAP creates a TAP device on Linux.
func createPlatformTAP(cfg Config) (NetworkDevice, error) {
	// Open the TUN clone device
	fd, err := os.OpenFile(tunCloneDevice, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, &DeviceError{Op: "open", Err: err}
	}

	// Configure the TAP interface
	var ifr [ifnamsiz + 2]byte
	copy(ifr[:], cfg.Name)

	// Set flags: TAP mode, no packet info header
	flags := uint16(iffTap | iffNoPi)
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

	// Parse or generate MAC address
	var mac net.HardwareAddr
	if cfg.TAP.MACAddress != "" {
		var err error
		mac, err = net.ParseMAC(cfg.TAP.MACAddress)
		if err != nil {
			fd.Close()
			return nil, &DeviceError{Op: "parse MAC", Err: err}
		}
	} else {
		var err error
		mac, err = GenerateRandomMAC()
		if err != nil {
			fd.Close()
			return nil, err
		}
	}

	tap := &linuxTAP{
		name: name,
		mtu:  cfg.MTU,
		fd:   fd,
		mac:  mac,
	}

	// Configure the interface
	if err := tap.configure(cfg); err != nil {
		tap.Close()
		return nil, err
	}

	return tap, nil
}

// configure sets up the TAP interface with IP address, MAC, and MTU.
func (t *linuxTAP) configure(cfg Config) error {
	// Get a socket for ioctl operations
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sock)

	// Set MAC address
	if err := t.setMACAddress(sock, t.mac); err != nil {
		return err
	}

	// Set MTU
	if err := t.setMTU(sock, cfg.MTU); err != nil {
		return err
	}

	// Set IP address if provided
	if cfg.Address != "" {
		prefix, err := netip.ParsePrefix(cfg.Address)
		if err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
		if err := t.setAddress(sock, prefix); err != nil {
			return err
		}
	}

	// Bring interface up
	if err := t.setUp(sock); err != nil {
		return err
	}

	// Join bridge if specified
	if cfg.TAP.Bridge != "" {
		if err := t.joinBridge(cfg.TAP.Bridge); err != nil {
			return err
		}
	}

	return nil
}

// setMACAddress sets the interface MAC address.
func (t *linuxTAP) setMACAddress(sock int, mac net.HardwareAddr) error {
	var ifr [40]byte
	copy(ifr[:], t.name)

	// sockaddr_ll structure
	ifr[16] = unix.ARPHRD_ETHER & 0xFF        // sa_family (low byte)
	ifr[17] = (unix.ARPHRD_ETHER >> 8) & 0xFF // sa_family (high byte)
	copy(ifr[18:24], mac)                     // sa_data (MAC address)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFHWADDR, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &DeviceError{Op: "set MAC address", Err: errno}
	}

	return nil
}

// setMTU sets the interface MTU.
func (t *linuxTAP) setMTU(sock int, mtu int) error {
	var ifr [40]byte
	copy(ifr[:], t.name)

	*(*int32)(unsafe.Pointer(&ifr[16])) = int32(mtu) //nolint:gosec // G115: MTU is always a small bounded value

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &DeviceError{Op: "set MTU", Err: errno}
	}

	return nil
}

// setAddress sets the interface IP address and netmask.
func (t *linuxTAP) setAddress(sock int, prefix netip.Prefix) error {
	addr := prefix.Addr()

	if !addr.Is4() {
		return fmt.Errorf("only IPv4 addresses are supported for TAP devices")
	}

	ip := addr.As4()

	// Set IP address
	var ifrAddr [40]byte
	copy(ifrAddr[:], t.name)
	ifrAddr[16] = syscall.AF_INET
	ifrAddr[17] = 0
	copy(ifrAddr[20:24], ip[:])

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifrAddr[0])))
	if errno != 0 {
		return &DeviceError{Op: "set address", Err: errno}
	}

	// Set netmask
	var ifrMask [40]byte
	copy(ifrMask[:], t.name)
	ifrMask[16] = syscall.AF_INET
	ifrMask[17] = 0

	mask := net.CIDRMask(prefix.Bits(), 32)
	copy(ifrMask[20:24], mask)

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifrMask[0])))
	if errno != 0 {
		return &DeviceError{Op: "set netmask", Err: errno}
	}

	return nil
}

// setUp brings the interface up.
func (t *linuxTAP) setUp(sock int) error {
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

// joinBridge adds the TAP interface to a bridge.
func (t *linuxTAP) joinBridge(bridge string) error {
	cmd := exec.Command("ip", "link", "set", t.name, "master", bridge) //nolint:gosec // G204: bridge name is validated interface name
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "join bridge", Err: fmt.Errorf("%w: %s", err, string(output))}
	}
	return nil
}

// Name returns the interface name.
func (t *linuxTAP) Name() string {
	return t.name
}

// Type returns the device type.
func (t *linuxTAP) Type() DeviceType {
	return DeviceTAP
}

// Read reads an Ethernet frame from the TAP device.
func (t *linuxTAP) Read(buf []byte) (int, error) {
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

// Write writes an Ethernet frame to the TAP device.
func (t *linuxTAP) Write(buf []byte) (int, error) {
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

// Close closes the TAP device.
func (t *linuxTAP) Close() error {
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
func (t *linuxTAP) MTU() int {
	return t.mtu
}

// MACAddress returns the MAC address of the TAP interface.
func (t *linuxTAP) MACAddress() net.HardwareAddr {
	return t.mac
}

// SetMACAddress sets the MAC address of the TAP interface.
func (t *linuxTAP) SetMACAddress(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return ErrInvalidMACAddress
	}

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sock)

	// Bring interface down first
	var ifr [40]byte
	copy(ifr[:], t.name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return &DeviceError{Op: "get flags", Err: errno}
	}

	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	wasUp := flags&unix.IFF_UP != 0

	if wasUp {
		flags &^= unix.IFF_UP
		*(*uint16)(unsafe.Pointer(&ifr[16])) = flags
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 {
			return &DeviceError{Op: "set flags", Err: errno}
		}
	}

	// Set the MAC address
	if err := t.setMACAddress(sock, mac); err != nil {
		return err
	}

	t.mac = mac

	// Bring interface back up if it was up
	if wasUp {
		flags |= unix.IFF_UP | unix.IFF_RUNNING
		*(*uint16)(unsafe.Pointer(&ifr[16])) = flags
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 {
			return &DeviceError{Op: "set flags", Err: errno}
		}
	}

	return nil
}

// GetMACFromInterface retrieves the MAC address from the interface.
func (t *linuxTAP) GetMACFromInterface() (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil, &DeviceError{Op: "get interface", Err: err}
	}
	return iface.HardwareAddr, nil
}

// BridgedTo returns the bridge this interface is attached to, if any.
func (t *linuxTAP) BridgedTo() string {
	// Read /sys/class/net/<name>/master to get bridge
	path := fmt.Sprintf("/sys/class/net/%s/master", t.name)
	if target, err := os.Readlink(path); err == nil {
		// target is like "../../br0"
		for i := len(target) - 1; i >= 0; i-- {
			if target[i] == '/' {
				return target[i+1:]
			}
		}
		return target
	}
	return ""
}

// Statistics returns interface statistics.
func (t *linuxTAP) Statistics() (rx, tx uint64, err error) {
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return 0, 0, &DeviceError{Op: "get interface", Err: err}
	}

	// Read from /sys/class/net/<name>/statistics/
	rxPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface.Name)
	txPath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface.Name)

	rxData, err := os.ReadFile(rxPath)
	if err != nil {
		return 0, 0, &DeviceError{Op: "read rx stats", Err: err}
	}
	txData, err := os.ReadFile(txPath)
	if err != nil {
		return 0, 0, &DeviceError{Op: "read tx stats", Err: err}
	}

	rx, _ = strconv.ParseUint(string(rxData[:len(rxData)-1]), 10, 64) //nolint:errcheck // Best effort parsing, 0 on error is acceptable
	tx, _ = strconv.ParseUint(string(txData[:len(txData)-1]), 10, 64) //nolint:errcheck // Best effort parsing, 0 on error is acceptable

	return rx, tx, nil
}
