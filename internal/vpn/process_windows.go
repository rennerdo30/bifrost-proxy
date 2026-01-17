//go:build windows

package vpn

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TCP connection states
const (
	tcpStateListen = 2
	tcpStateEstab  = 5
)

// MIB_TCPROW_OWNER_PID represents a TCP connection with owner PID.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// MIB_TCP6ROW_OWNER_PID represents an IPv6 TCP connection with owner PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// MIB_UDPROW_OWNER_PID represents a UDP endpoint with owner PID.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// MIB_UDP6ROW_OWNER_PID represents an IPv6 UDP endpoint with owner PID.
type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

var (
	modiphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable  = modiphlpapi.NewProc("GetExtendedUdpTable")

	modkernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageName = modkernel32.NewProc("QueryFullProcessImageNameW")
)

// TCP_TABLE_CLASS values
const (
	tcpTableOwnerPIDAll = 5
)

// UDP_TABLE_CLASS values
const (
	udpTableOwnerPID = 1
)

// AF_INET values
const (
	afInetWindows  = 2
	afInet6Windows = 23
)

// windowsProcessLookup implements ProcessLookup for Windows.
type windowsProcessLookup struct{}

func newPlatformProcessLookup() ProcessLookup {
	return &windowsProcessLookup{}
}

// LookupBySocket finds the process for a socket on Windows.
func (w *windowsProcessLookup) LookupBySocket(local, remote netip.AddrPort, proto string) (*ProcessInfo, error) {
	var pid uint32
	var err error

	switch proto {
	case "tcp":
		if local.Addr().Is4() {
			pid, err = w.findTCPv4Process(local, remote)
		} else {
			pid, err = w.findTCPv6Process(local, remote)
		}
	case "udp":
		if local.Addr().Is4() {
			pid, err = w.findUDPv4Process(local)
		} else {
			pid, err = w.findUDPv6Process(local)
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}

	if err != nil {
		return nil, err
	}
	if pid == 0 {
		return nil, nil
	}

	return w.getProcessInfo(pid)
}

// findTCPv4Process finds the PID for a TCPv4 connection.
func (w *windowsProcessLookup) findTCPv4Process(local, remote netip.AddrPort) (uint32, error) {
	// Get table size
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInetWindows, tcpTableOwnerPIDAll, 0)

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInetWindows,
		tcpTableOwnerPIDAll,
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	// Parse table
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entries := unsafe.Slice((*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries)

	localAddr := local.Addr().As4()
	localIP := uint32(localAddr[0]) | uint32(localAddr[1])<<8 | uint32(localAddr[2])<<16 | uint32(localAddr[3])<<24
	localPort := uint32(local.Port())<<8 | uint32(local.Port())>>8 // Network byte order

	remoteAddr := remote.Addr().As4()
	remoteIP := uint32(remoteAddr[0]) | uint32(remoteAddr[1])<<8 | uint32(remoteAddr[2])<<16 | uint32(remoteAddr[3])<<24
	remotePort := uint32(remote.Port())<<8 | uint32(remote.Port())>>8

	for _, entry := range entries {
		if entry.LocalAddr == localIP && entry.LocalPort == localPort &&
			entry.RemoteAddr == remoteIP && entry.RemotePort == remotePort {
			return entry.OwningPID, nil
		}
	}

	return 0, nil
}

// findTCPv6Process finds the PID for a TCPv6 connection.
func (w *windowsProcessLookup) findTCPv6Process(local, remote netip.AddrPort) (uint32, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet6Windows, tcpTableOwnerPIDAll, 0)

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet6Windows,
		tcpTableOwnerPIDAll,
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entries := unsafe.Slice((*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries)

	localAddr := local.Addr().As16()
	remoteAddr := remote.Addr().As16()
	localPort := uint32(local.Port())<<8 | uint32(local.Port())>>8
	remotePort := uint32(remote.Port())<<8 | uint32(remote.Port())>>8

	for _, entry := range entries {
		if entry.LocalAddr == localAddr && entry.LocalPort == localPort &&
			entry.RemoteAddr == remoteAddr && entry.RemotePort == remotePort {
			return entry.OwningPID, nil
		}
	}

	return 0, nil
}

// findUDPv4Process finds the PID for a UDPv4 endpoint.
func (w *windowsProcessLookup) findUDPv4Process(local netip.AddrPort) (uint32, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInetWindows, udpTableOwnerPID, 0)

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInetWindows,
		udpTableOwnerPID,
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entries := unsafe.Slice((*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries)

	localAddr := local.Addr().As4()
	localIP := uint32(localAddr[0]) | uint32(localAddr[1])<<8 | uint32(localAddr[2])<<16 | uint32(localAddr[3])<<24
	localPort := uint32(local.Port())<<8 | uint32(local.Port())>>8

	for _, entry := range entries {
		if entry.LocalAddr == localIP && entry.LocalPort == localPort {
			return entry.OwningPID, nil
		}
	}

	return 0, nil
}

// findUDPv6Process finds the PID for a UDPv6 endpoint.
func (w *windowsProcessLookup) findUDPv6Process(local netip.AddrPort) (uint32, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet6Windows, udpTableOwnerPID, 0)

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet6Windows,
		udpTableOwnerPID,
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entries := unsafe.Slice((*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries)

	localAddr := local.Addr().As16()
	localPort := uint32(local.Port())<<8 | uint32(local.Port())>>8

	for _, entry := range entries {
		if entry.LocalAddr == localAddr && entry.LocalPort == localPort {
			return entry.OwningPID, nil
		}
	}

	return 0, nil
}

// getProcessInfo gets process information by PID.
func (w *windowsProcessLookup) getProcessInfo(pid uint32) (*ProcessInfo, error) {
	info := &ProcessInfo{
		PID: int(pid),
	}

	// Open the process
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return info, nil // Return what we have
	}
	defer windows.CloseHandle(handle)

	// Get the process name/path
	var size uint32 = 4096
	buf := make([]uint16, size)
	ret, _, _ := procQueryFullProcessImageName.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		info.Path = syscall.UTF16ToString(buf[:size])
		// Extract name from path
		for i := len(info.Path) - 1; i >= 0; i-- {
			if info.Path[i] == '\\' || info.Path[i] == '/' {
				info.Name = info.Path[i+1:]
				break
			}
		}
		if info.Name == "" {
			info.Name = info.Path
		}
	}

	return info, nil
}
