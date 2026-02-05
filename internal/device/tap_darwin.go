//go:build darwin

package device

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
)

// darwinTAP implements TAPDevice for macOS using the tuntaposx driver.
// Note: This requires the tuntaposx kernel extension to be installed.
// On newer macOS versions, you may need to use the vmnet framework instead.
type darwinTAP struct {
	name   string
	mtu    int
	fd     *os.File
	mac    net.HardwareAddr
	closed bool
	mu     sync.Mutex
}

// createPlatformTAP creates a TAP device on macOS.
// This requires the tuntaposx kernel extension or similar.
func createPlatformTAP(cfg Config) (NetworkDevice, error) {
	// Try to open a TAP device using tuntaposx
	// tuntaposx creates devices as /dev/tapN where N is 0-15
	var fd *os.File
	var name string
	var err error

	if cfg.Name != "" && len(cfg.Name) > 3 && cfg.Name[:3] == "tap" {
		// Try specific device
		devPath := "/dev/" + cfg.Name
		fd, err = os.OpenFile(devPath, os.O_RDWR, 0)
		if err != nil {
			return nil, &DeviceError{Op: "open", Err: fmt.Errorf("failed to open %s (is tuntaposx installed?): %w", devPath, err)}
		}
		name = cfg.Name
	} else {
		// Find an available TAP device
		for i := 0; i < 16; i++ {
			devPath := fmt.Sprintf("/dev/tap%d", i)
			fd, err = os.OpenFile(devPath, os.O_RDWR, 0)
			if err == nil {
				name = fmt.Sprintf("tap%d", i)
				break
			}
		}
		if fd == nil {
			return nil, &DeviceError{Op: "open", Err: fmt.Errorf("no available TAP devices (is tuntaposx installed?): %w", err)}
		}
	}

	// Parse or generate MAC address
	var mac net.HardwareAddr
	if cfg.TAP.MACAddress != "" {
		mac, err = net.ParseMAC(cfg.TAP.MACAddress)
		if err != nil {
			fd.Close()
			return nil, &DeviceError{Op: "parse MAC", Err: err}
		}
	} else {
		mac, err = GenerateRandomMAC()
		if err != nil {
			fd.Close()
			return nil, err
		}
	}

	tap := &darwinTAP{
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

// configure sets up the TAP interface with IP address and MTU.
func (t *darwinTAP) configure(cfg Config) error {
	// Set MAC address using ifconfig
	if err := t.setMACAddressCmd(t.mac); err != nil {
		return err
	}

	// Set MTU
	cmd := exec.Command("ifconfig", t.name, "mtu", strconv.Itoa(cfg.MTU)) //nolint:gosec // G204: interface name and MTU are from validated config
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "ifconfig mtu", Err: fmt.Errorf("%w: %s", err, string(output))}
	}

	// Set IP address if provided
	if cfg.Address != "" {
		prefix, err := netip.ParsePrefix(cfg.Address)
		if err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
		addr := prefix.Addr()
		bits := prefix.Bits()

		if addr.Is4() {
			mask := net.CIDRMask(bits, 32)
			maskStr := net.IP(mask).String()
			cmd = exec.Command("ifconfig", t.name, "inet", addr.String(), "netmask", maskStr) //nolint:gosec // G204: interface name and addresses are validated
		} else {
			cmd = exec.Command("ifconfig", t.name, "inet6", fmt.Sprintf("%s/%d", addr, bits)) //nolint:gosec // G204: interface name and addresses are validated
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			return &DeviceError{Op: "ifconfig address", Err: fmt.Errorf("%w: %s", err, string(output))}
		}
	}

	// Bring interface up
	cmd = exec.Command("ifconfig", t.name, "up") //nolint:gosec // G204: interface name is from validated config
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "ifconfig up", Err: fmt.Errorf("%w: %s", err, string(output))}
	}

	// Join bridge if specified
	if cfg.TAP.Bridge != "" {
		if err := t.joinBridge(cfg.TAP.Bridge); err != nil {
			return err
		}
	}

	return nil
}

// setMACAddressCmd sets the MAC address using ifconfig.
func (t *darwinTAP) setMACAddressCmd(mac net.HardwareAddr) error {
	cmd := exec.Command("ifconfig", t.name, "lladdr", mac.String()) //nolint:gosec // G204: interface name and MAC are validated
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "ifconfig lladdr", Err: fmt.Errorf("%w: %s", err, string(output))}
	}
	return nil
}

// joinBridge adds the TAP interface to a bridge using ifconfig.
func (t *darwinTAP) joinBridge(bridge string) error {
	// On macOS, use ifconfig to add member to bridge
	cmd := exec.Command("ifconfig", bridge, "addm", t.name) //nolint:gosec // G204: bridge and interface names are from validated config
	if output, err := cmd.CombinedOutput(); err != nil {
		return &DeviceError{Op: "join bridge", Err: fmt.Errorf("%w: %s", err, string(output))}
	}
	return nil
}

// Name returns the interface name.
func (t *darwinTAP) Name() string {
	return t.name
}

// Type returns the device type.
func (t *darwinTAP) Type() DeviceType {
	return DeviceTAP
}

// Read reads an Ethernet frame from the TAP device.
func (t *darwinTAP) Read(buf []byte) (int, error) {
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
func (t *darwinTAP) Write(buf []byte) (int, error) {
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
func (t *darwinTAP) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	// Bring interface down
	_ = exec.Command("ifconfig", t.name, "down").Run() //nolint:errcheck,gosec // Best effort interface cleanup

	if t.fd != nil {
		return t.fd.Close()
	}
	return nil
}

// MTU returns the MTU of the interface.
func (t *darwinTAP) MTU() int {
	return t.mtu
}

// MACAddress returns the MAC address of the TAP interface.
func (t *darwinTAP) MACAddress() net.HardwareAddr {
	return t.mac
}

// SetMACAddress sets the MAC address of the TAP interface.
func (t *darwinTAP) SetMACAddress(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return ErrInvalidMACAddress
	}

	// Bring interface down first
	_ = exec.Command("ifconfig", t.name, "down").Run() //nolint:errcheck,gosec // Best effort interface control

	// Set the MAC address
	if err := t.setMACAddressCmd(mac); err != nil {
		return err
	}

	t.mac = mac

	// Bring interface back up
	_ = exec.Command("ifconfig", t.name, "up").Run() //nolint:errcheck,gosec // Best effort interface control

	return nil
}

// GetMACFromInterface retrieves the MAC address from the interface.
func (t *darwinTAP) GetMACFromInterface() (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil, &DeviceError{Op: "get interface", Err: err}
	}
	return iface.HardwareAddr, nil
}
