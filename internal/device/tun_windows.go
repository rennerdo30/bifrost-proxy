//go:build windows

package device

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	// Ring buffer sizes for WinTun
	tunRingCapacity = 0x400000 // 4 MiB

	// How long Read blocks on the ring's read-wait event before re-checking
	// whether the device was closed. Bounded so Close is never stuck behind
	// an idle interface.
	tunReadWaitMillis = 250
)

// windowsTUN implements NetworkDevice for Windows using WinTun.
type windowsTUN struct {
	name    string
	mtu     int
	adapter *wintun.Adapter
	session wintun.Session
	closed  bool
	mu      sync.Mutex
}

// createPlatformTUN creates a TUN device on Windows using WinTun.
func createPlatformTUN(cfg Config) (NetworkDevice, error) {
	// Create or open the WinTun adapter
	adapter, err := wintun.CreateAdapter(cfg.Name, "Bifrost", nil)
	if err != nil {
		// Try to open existing adapter
		adapter, err = wintun.OpenAdapter(cfg.Name)
		if err != nil {
			return nil, &DeviceError{Op: "create adapter", Err: err}
		}
	}

	// Start a session for packet I/O
	session, err := adapter.StartSession(tunRingCapacity)
	if err != nil {
		adapter.Close()
		return nil, &DeviceError{Op: "start session", Err: err}
	}

	tun := &windowsTUN{
		name:    cfg.Name,
		mtu:     cfg.MTU,
		adapter: adapter,
		session: session,
	}

	// Configure the interface
	if err := tun.configure(cfg); err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

// configure sets up the TUN interface with IP address and MTU.
func (t *windowsTUN) configure(cfg Config) error {
	prefix, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Get the LUID for the adapter
	luid := t.adapter.LUID()

	// Set the IP address using LUID
	addr := prefix.Addr()
	if addr.Is4() {
		// Use netsh to set IPv4 address
		cmd := exec.Command("netsh", "interface", "ip", "set", "address",
			fmt.Sprintf("name=%d", luid),
			"source=static",
			fmt.Sprintf("addr=%s", addr),
			fmt.Sprintf("mask=%s", prefixToMask(prefix)),
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			// The LUID form fails on some Windows builds; fall back to the
			// interface name. The first failure is expected there, so it is
			// only worth a debug line.
			slog.Debug("netsh address by LUID failed; retrying by interface name",
				"interface", t.name, "error", err, "output", string(output))
			cmd = exec.Command("netsh", "interface", "ip", "set", "address",
				fmt.Sprintf("name=%s", t.name),
				"source=static",
				fmt.Sprintf("addr=%s", addr),
				fmt.Sprintf("mask=%s", prefixToMask(prefix)),
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				return &DeviceError{Op: "netsh address", Err: fmt.Errorf("%w: %s", err, string(output))}
			}
		}
	} else {
		// IPv6
		cmd := exec.Command("netsh", "interface", "ipv6", "set", "address",
			fmt.Sprintf("interface=%s", t.name),
			fmt.Sprintf("address=%s/%d", addr, prefix.Bits()),
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return &DeviceError{Op: "netsh address6", Err: fmt.Errorf("%w: %s", err, string(output))}
		}
	}

	// Set MTU
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		t.name,
		fmt.Sprintf("mtu=%d", cfg.MTU),
		"store=persistent",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		// The interface still works with the default MTU, so this stays
		// non-fatal — but a silent discard hid real misconfigurations (an MTU
		// mismatch shows up later as blackholed large packets, nowhere near
		// this code). At minimum the operator gets to see it.
		slog.Warn("failed to set TUN interface MTU; the interface keeps the system default",
			"interface", t.name,
			"requested_mtu", cfg.MTU,
			"error", err,
			"output", string(output),
		)
	}

	return nil
}

// prefixToMask converts a prefix to a dotted decimal mask.
func prefixToMask(prefix netip.Prefix) string {
	bits := prefix.Bits()
	mask := uint32(0xFFFFFFFF) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xFF,
		(mask>>16)&0xFF,
		(mask>>8)&0xFF,
		mask&0xFF,
	)
}

// Name returns the interface name.
func (t *windowsTUN) Name() string {
	return t.name
}

// Type returns the device type.
func (t *windowsTUN) Type() DeviceType {
	return DeviceTUN
}

// Read reads a packet from the TUN device. It blocks on the ring's
// read-wait event while the interface is idle instead of spinning on
// ERROR_NO_MORE_ITEMS.
func (t *windowsTUN) Read(buf []byte) (int, error) {
	for {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return 0, ErrDeviceClosed
		}
		session := t.session
		t.mu.Unlock()

		pkt, err := session.ReceivePacket()
		if err == nil {
			n := copy(buf, pkt)
			session.ReleaseReceivePacket(pkt)
			return n, nil
		}
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, &DeviceError{Op: "receive", Err: err}
		}

		// Ring is empty: wait until WinTun signals a packet, or the wait
		// times out so the closed flag above is re-checked.
		if _, err := windows.WaitForSingleObject(session.ReadWaitEvent(), tunReadWaitMillis); err != nil {
			return 0, &DeviceError{Op: "receive wait", Err: err}
		}
	}
}

// Write writes a packet to the TUN device.
func (t *windowsTUN) Write(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrDeviceClosed
	}
	session := t.session
	t.mu.Unlock()

	// Allocate packet buffer from WinTun
	pkt, err := session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, &DeviceError{Op: "allocate", Err: err}
	}

	copy(pkt, buf)
	session.SendPacket(pkt)

	return len(buf), nil
}

// Close closes the TUN device.
func (t *windowsTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	// End the session
	t.session.End()

	// Close the adapter
	return t.adapter.Close()
}

// MTU returns the MTU of the interface.
func (t *windowsTUN) MTU() int {
	return t.mtu
}

// LUID returns the adapter's LUID (Windows-specific).
func (t *windowsTUN) LUID() uint64 {
	return uint64(t.adapter.LUID())
}

// Index returns the adapter's interface index.
func (t *windowsTUN) Index() (int, error) {
	return 0, nil
}
