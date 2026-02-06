//go:build windows

package device

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows TAP driver constants
const (
	tapWindowsIoctlSetMediaStatus = 0x22004C
	tapWindowsIoctlGetMac         = 0x22001C
	tapWindowsIoctlGetVersion     = 0x220008
	tapWindowsIoctlGetMtu         = 0x220018

	networkAdaptersKey = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`
	networkConnKey     = `SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}`
)

// windowsTAP implements TAPDevice for Windows using TAP-Windows or OpenVPN TAP driver.
type windowsTAP struct {
	name   string
	mtu    int
	handle windows.Handle
	mac    net.HardwareAddr
	closed bool
	mu     sync.Mutex

	// Overlapped I/O
	readOverlapped  windows.Overlapped
	writeOverlapped windows.Overlapped
}

// createPlatformTAP creates a TAP device on Windows.
func createPlatformTAP(cfg Config) (NetworkDevice, error) {
	// Find TAP adapter
	adapterId, err := findTAPAdapter(cfg.Name)
	if err != nil {
		return nil, &DeviceError{Op: "find TAP adapter", Err: err}
	}

	// Open the TAP device
	devPath := `\\.\Global\` + adapterId + `.tap`
	pathPtr, err := windows.UTF16PtrFromString(devPath)
	if err != nil {
		return nil, &DeviceError{Op: "convert path", Err: err}
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, &DeviceError{Op: "open TAP device", Err: err}
	}

	tap := &windowsTAP{
		name:   cfg.Name,
		mtu:    cfg.MTU,
		handle: handle,
	}

	// Create events for overlapped I/O
	tap.readOverlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, &DeviceError{Op: "create read event", Err: err}
	}

	tap.writeOverlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(tap.readOverlapped.HEvent)
		windows.CloseHandle(handle)
		return nil, &DeviceError{Op: "create write event", Err: err}
	}

	// Get MAC address from driver
	if err := tap.getMACFromDriver(); err != nil {
		tap.Close()
		return nil, err
	}

	// Configure the interface
	if err := tap.configure(cfg); err != nil {
		tap.Close()
		return nil, err
	}

	return tap, nil
}

// findTAPAdapter finds a TAP adapter matching the given name or returns any available TAP adapter.
func findTAPAdapter(name string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, networkAdaptersKey, registry.READ)
	if err != nil {
		return "", fmt.Errorf("failed to open registry: %w", err)
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return "", fmt.Errorf("failed to read subkeys: %w", err)
	}

	for _, subkey := range subkeys {
		if len(subkey) != 4 {
			continue // Skip non-adapter entries
		}

		adapterKey, err := registry.OpenKey(key, subkey, registry.READ)
		if err != nil {
			continue
		}

		componentId, _, err := adapterKey.GetStringValue("ComponentId")
		adapterKey.Close()

		if err != nil {
			continue
		}

		// Check for TAP-Windows or OpenVPN TAP driver
		if componentId == "tap0901" || componentId == "tap0801" || componentId == "root\\tap0901" {
			// Get NetCfgInstanceId
			adapterKey, err = registry.OpenKey(key, subkey, registry.READ)
			if err != nil {
				continue
			}
			netCfgId, _, err := adapterKey.GetStringValue("NetCfgInstanceId")
			adapterKey.Close()

			if err != nil {
				continue
			}

			// If name is specified, check if it matches
			if name != "" {
				adapterName, err := getAdapterName(netCfgId)
				if err != nil || adapterName != name {
					continue
				}
			}

			return netCfgId, nil
		}
	}

	return "", fmt.Errorf("no TAP adapter found (is TAP-Windows or OpenVPN installed?)")
}

// getAdapterName gets the friendly name of a network adapter.
func getAdapterName(netCfgId string) (string, error) {
	connKey := fmt.Sprintf(`%s\%s\Connection`, networkConnKey, netCfgId)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, connKey, registry.READ)
	if err != nil {
		return "", err
	}
	defer key.Close()

	name, _, err := key.GetStringValue("Name")
	return name, err
}

// getMACFromDriver retrieves the MAC address from the TAP driver.
func (t *windowsTAP) getMACFromDriver() error {
	mac := make([]byte, 6)
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		t.handle,
		tapWindowsIoctlGetMac,
		nil,
		0,
		&mac[0],
		6,
		&bytesReturned,
		nil,
	)
	if err != nil {
		return &DeviceError{Op: "get MAC from driver", Err: err}
	}

	t.mac = mac
	return nil
}

// configure sets up the TAP interface with IP address and MTU.
func (t *windowsTAP) configure(cfg Config) error {
	// Set media status to connected
	status := uint32(1)
	var bytesReturned uint32
	err := windows.DeviceIoControl(
		t.handle,
		tapWindowsIoctlSetMediaStatus,
		(*byte)(unsafe.Pointer(&status)),
		4,
		nil,
		0,
		&bytesReturned,
		nil,
	)
	if err != nil {
		return &DeviceError{Op: "set media status", Err: err}
	}

	// Set IP address if provided
	if cfg.Address != "" {
		prefix, err := netip.ParsePrefix(cfg.Address)
		if err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
		addr := prefix.Addr()

		if addr.Is4() {
			cmd := exec.Command("netsh", "interface", "ip", "set", "address", //nolint:gosec // G204: Network device setup requires system commands
				fmt.Sprintf("name=%s", t.name),
				"source=static",
				fmt.Sprintf("addr=%s", addr),
				fmt.Sprintf("mask=%s", prefixToMask(prefix)),
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				return &DeviceError{Op: "netsh address", Err: fmt.Errorf("%w: %s", err, string(output))}
			}
		} else {
			cmd := exec.Command("netsh", "interface", "ipv6", "set", "address", //nolint:gosec // G204: Network device setup requires system commands
				fmt.Sprintf("interface=%s", t.name),
				fmt.Sprintf("address=%s/%d", addr, prefix.Bits()),
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				return &DeviceError{Op: "netsh address6", Err: fmt.Errorf("%w: %s", err, string(output))}
			}
		}
	}

	// Set MTU
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", //nolint:gosec // G204: Network device setup requires system commands
		t.name,
		fmt.Sprintf("mtu=%d", cfg.MTU),
		"store=persistent",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Non-fatal
		_ = output
	}

	return nil
}

// Name returns the interface name.
func (t *windowsTAP) Name() string {
	return t.name
}

// Type returns the device type.
func (t *windowsTAP) Type() DeviceType {
	return DeviceTAP
}

// Read reads an Ethernet frame from the TAP device.
func (t *windowsTAP) Read(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	handle := t.handle
	overlapped := &t.readOverlapped
	t.mu.Unlock()

	var bytesRead uint32
	err := windows.ReadFile(handle, buf, &bytesRead, overlapped)
	if err == windows.ERROR_IO_PENDING {
		_, err = windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)
		if err != nil {
			return 0, &DeviceError{Op: "wait read", Err: err}
		}
		err = windows.GetOverlappedResult(handle, overlapped, &bytesRead, false)
	}
	if err != nil {
		return 0, &DeviceError{Op: "read", Err: err}
	}

	return int(bytesRead), nil
}

// Write writes an Ethernet frame to the TAP device.
func (t *windowsTAP) Write(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	handle := t.handle
	overlapped := &t.writeOverlapped
	t.mu.Unlock()

	var bytesWritten uint32
	err := windows.WriteFile(handle, buf, &bytesWritten, overlapped)
	if err == windows.ERROR_IO_PENDING {
		_, err = windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)
		if err != nil {
			return 0, &DeviceError{Op: "wait write", Err: err}
		}
		err = windows.GetOverlappedResult(handle, overlapped, &bytesWritten, false)
	}
	if err != nil {
		return 0, &DeviceError{Op: "write", Err: err}
	}

	return int(bytesWritten), nil
}

// Close closes the TAP device.
func (t *windowsTAP) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	// Set media status to disconnected
	status := uint32(0)
	var bytesReturned uint32
	windows.DeviceIoControl(
		t.handle,
		tapWindowsIoctlSetMediaStatus,
		(*byte)(unsafe.Pointer(&status)),
		4,
		nil,
		0,
		&bytesReturned,
		nil,
	)

	// Close events and handle
	windows.CloseHandle(t.readOverlapped.HEvent)
	windows.CloseHandle(t.writeOverlapped.HEvent)
	return windows.CloseHandle(t.handle)
}

// MTU returns the MTU of the interface.
func (t *windowsTAP) MTU() int {
	return t.mtu
}

// MACAddress returns the MAC address of the TAP interface.
func (t *windowsTAP) MACAddress() net.HardwareAddr {
	return t.mac
}

// SetMACAddress sets the MAC address of the TAP interface.
// Note: On Windows, this typically requires driver support and may not work
// with all TAP drivers.
func (t *windowsTAP) SetMACAddress(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return ErrInvalidMACAddress
	}

	// Windows TAP drivers typically don't support changing MAC address
	// via ioctl. This would require registry modification and adapter restart.
	// For now, just update the local copy.
	t.mac = mac

	return nil
}

// GetMACFromInterface retrieves the MAC address from the interface.
func (t *windowsTAP) GetMACFromInterface() (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil, &DeviceError{Op: "get interface", Err: err}
	}
	return iface.HardwareAddr, nil
}

// buildTAPConfigPacket builds a TAP_WIN_IOCTL_CONFIG_TUN packet for TUN emulation.
// This is used when TAP is operated in TUN mode.
func buildTAPConfigPacket(localIP, remoteIP netip.Addr, netmask net.IPMask) []byte {
	packet := make([]byte, 12)
	copy(packet[0:4], localIP.AsSlice())
	copy(packet[4:8], remoteIP.AsSlice())
	copy(packet[8:12], netmask)
	return packet
}

// getTAPVersion returns the TAP driver version.
func (t *windowsTAP) getTAPVersion() (int, int, int, error) {
	version := make([]byte, 12)
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		t.handle,
		tapWindowsIoctlGetVersion,
		nil,
		0,
		&version[0],
		12,
		&bytesReturned,
		nil,
	)
	if err != nil {
		return 0, 0, 0, &DeviceError{Op: "get version", Err: err}
	}

	major := int(binary.LittleEndian.Uint32(version[0:4]))
	minor := int(binary.LittleEndian.Uint32(version[4:8]))
	debug := int(binary.LittleEndian.Uint32(version[8:12]))

	return major, minor, debug, nil
}

// Verify windowsTAP implements TAPDevice at compile time.
var _ TAPDevice = (*windowsTAP)(nil)

// init registers syscall import
func init() {
	// Force import of syscall for DeviceIoControl constants
	_ = syscall.DeviceIoControl
}
