//go:build darwin

package device

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Darwin-specific constants for utun
	utunControlName = "com.apple.net.utun_control"
	utunOptIfname   = 2

	// Address family for prepended header
	afInet  = 2
	afInet6 = 30
)

// darwinTUN implements NetworkDevice for macOS using utun.
type darwinTUN struct {
	name   string
	mtu    int
	fd     int
	closed bool
	mu     sync.Mutex
}

// createPlatformTUN creates a TUN device on macOS.
func createPlatformTUN(cfg Config) (NetworkDevice, error) {
	// Create a system socket for utun control
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2) // SYSPROTO_CONTROL = 2
	if err != nil {
		if err == syscall.EPERM {
			return nil, ErrPermissionDenied
		}
		return nil, &DeviceError{Op: "socket", Err: err}
	}

	// Get the control ID for utun
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)

	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return nil, &DeviceError{Op: "ioctl CTLIOCGINFO", Err: err}
	}

	// Determine utun unit number
	var unit uint32
	if cfg.Name != "" && strings.HasPrefix(cfg.Name, "utun") {
		// Parse unit number from name
		numStr := strings.TrimPrefix(cfg.Name, "utun")
		if numStr != "" {
			num, err := strconv.ParseUint(numStr, 10, 32)
			if err == nil {
				unit = uint32(num)
			}
		}
	}

	// Connect to the utun control
	sa := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: unit,
	}

	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		if err == syscall.EBUSY {
			return nil, ErrDeviceAlreadyExists
		}
		return nil, &DeviceError{Op: "connect", Err: err}
	}

	// Get the actual interface name
	name, err := getUtunName(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Set non-blocking mode
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, &DeviceError{Op: "set nonblock", Err: err}
	}

	tun := &darwinTUN{
		name: name,
		mtu:  cfg.MTU,
		fd:   fd,
	}

	// Configure the interface
	if err := tun.configure(cfg); err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

// getUtunName retrieves the interface name from the utun control socket.
func getUtunName(fd int) (string, error) {
	var nameBuf [32]byte
	nameBufLen := uint32(len(nameBuf))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		2, // SYSPROTO_CONTROL
		utunOptIfname,
		uintptr(unsafe.Pointer(&nameBuf[0])),
		uintptr(unsafe.Pointer(&nameBufLen)),
		0,
	)
	if errno != 0 {
		return "", &DeviceError{Op: "getsockopt UTUN_OPT_IFNAME", Err: errno}
	}

	// Find null terminator
	name := string(nameBuf[:nameBufLen])
	for i := 0; i < len(name); i++ {
		if name[i] == 0 {
			name = name[:i]
			break
		}
	}

	return name, nil
}

// configure sets up the TUN interface with IP address and MTU.
func (t *darwinTUN) configure(cfg Config) error {
	prefix, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Use ifconfig to set up the interface (most reliable on macOS)
	addr := prefix.Addr()
	bits := prefix.Bits()

	if addr.Is4() {
		// Calculate the destination address for point-to-point
		// For simplicity, use the same address
		dstAddr := addr.String()

		// Set interface address: ifconfig utunX inet 10.255.0.1 10.255.0.1 netmask 255.255.255.0
		mask := net.CIDRMask(bits, 32)
		maskStr := net.IP(mask).String()

		cmd := exec.Command("ifconfig", t.name, "inet", addr.String(), dstAddr, "netmask", maskStr)
		if output, err := cmd.CombinedOutput(); err != nil {
			return &DeviceError{Op: "ifconfig address", Err: fmt.Errorf("%w: %s", err, string(output))}
		}
	} else {
		// IPv6
		cmd := exec.Command("ifconfig", t.name, "inet6", fmt.Sprintf("%s/%d", addr, bits))
		if output, err := cmd.CombinedOutput(); err != nil {
			return &DeviceError{Op: "ifconfig address6", Err: fmt.Errorf("%w: %s", err, string(output))}
		}
	}

	// Set MTU
	cmd := exec.Command("ifconfig", t.name, "mtu", strconv.Itoa(cfg.MTU))
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "ifconfig mtu", Err: fmt.Errorf("%w: %s", err, string(output))}
	}

	// Bring interface up
	cmd = exec.Command("ifconfig", t.name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "ifconfig up", Err: fmt.Errorf("%w: %s", err, string(output))}
	}

	return nil
}

// Name returns the interface name.
func (t *darwinTUN) Name() string {
	return t.name
}

// Type returns the device type.
func (t *darwinTUN) Type() DeviceType {
	return DeviceTUN
}

// Read reads a packet from the TUN device.
// On macOS, utun prepends a 4-byte header with the address family.
func (t *darwinTUN) Read(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	fd := t.fd
	t.mu.Unlock()

	// We need to read with the 4-byte header
	tempBuf := make([]byte, len(buf)+4)

	for {
		n, err := unix.Read(fd, tempBuf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// Use select to wait for data
				var readFds unix.FdSet
				readFds.Set(fd)

				_, err := unix.Select(fd+1, &readFds, nil, nil, nil)
				if err != nil {
					return 0, &DeviceError{Op: "select", Err: err}
				}
				continue
			}
			return 0, &DeviceError{Op: "read", Err: err}
		}

		if n <= 4 {
			continue // No actual packet data
		}

		// Copy packet data without the header
		copied := copy(buf, tempBuf[4:n])
		return copied, nil
	}
}

// Write writes a packet to the TUN device.
// On macOS, utun requires a 4-byte header with the address family.
func (t *darwinTUN) Write(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	fd := t.fd
	t.mu.Unlock()

	if len(buf) == 0 {
		return 0, nil
	}

	// Determine address family from IP version
	var af uint32
	version := buf[0] >> 4
	if version == 4 {
		af = afInet
	} else if version == 6 {
		af = afInet6
	} else {
		return 0, fmt.Errorf("unknown IP version: %d", version)
	}

	// Prepend the 4-byte header
	tempBuf := make([]byte, len(buf)+4)
	binary.BigEndian.PutUint32(tempBuf[:4], af)
	copy(tempBuf[4:], buf)

	n, err := unix.Write(fd, tempBuf)
	if err != nil {
		return 0, &DeviceError{Op: "write", Err: err}
	}

	// Return the number of packet bytes written (excluding header)
	if n > 4 {
		return n - 4, nil
	}
	return 0, nil
}

// Close closes the TUN device.
func (t *darwinTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	// Bring interface down
	exec.Command("ifconfig", t.name, "down").Run()

	return unix.Close(t.fd)
}

// MTU returns the MTU of the interface.
func (t *darwinTUN) MTU() int {
	return t.mtu
}

// File returns the underlying file descriptor wrapped in an os.File.
func (t *darwinTUN) File() *os.File {
	return os.NewFile(uintptr(t.fd), t.name)
}
