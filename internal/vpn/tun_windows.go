//go:build windows

package vpn

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"

	"golang.zx2c4.com/wintun"
)

const (
	// Ring buffer sizes for WinTun
	tunRingCapacity = 0x400000 // 4 MiB
)

// windowsTUN implements TUNDevice for Windows using WinTun.
type windowsTUN struct {
	name    string
	mtu     int
	adapter *wintun.Adapter
	session wintun.Session
	closed  bool
	mu      sync.Mutex
}

// createPlatformTUN creates a TUN device on Windows using WinTun.
func createPlatformTUN(cfg TUNConfig) (TUNDevice, error) {
	// Create or open the WinTun adapter
	adapter, err := wintun.CreateAdapter(cfg.Name, "Bifrost", nil)
	if err != nil {
		// Try to open existing adapter
		adapter, err = wintun.OpenAdapter(cfg.Name)
		if err != nil {
			return nil, &TUNError{Op: "create adapter", Err: err}
		}
	}

	// Start a session for packet I/O
	session, err := adapter.StartSession(tunRingCapacity)
	if err != nil {
		adapter.Close()
		return nil, &TUNError{Op: "start session", Err: err}
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
func (t *windowsTUN) configure(cfg TUNConfig) error {
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
			// Try using interface name instead
			cmd = exec.Command("netsh", "interface", "ip", "set", "address",
				fmt.Sprintf("name=%s", t.name),
				"source=static",
				fmt.Sprintf("addr=%s", addr),
				fmt.Sprintf("mask=%s", prefixToMask(prefix)),
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				return &TUNError{Op: "netsh address", Err: fmt.Errorf("%w: %s", err, string(output))}
			}
		}
		_ = output
	} else {
		// IPv6
		cmd := exec.Command("netsh", "interface", "ipv6", "set", "address",
			fmt.Sprintf("interface=%s", t.name),
			fmt.Sprintf("address=%s/%d", addr, prefix.Bits()),
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return &TUNError{Op: "netsh address6", Err: fmt.Errorf("%w: %s", err, string(output))}
		}
	}

	// Set MTU
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		t.name,
		fmt.Sprintf("mtu=%d", cfg.MTU),
		"store=persistent",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Non-fatal, log and continue
		_ = output
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

// Read reads a packet from the TUN device.
func (t *windowsTUN) Read(packet []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrTUNClosed
	}
	session := t.session
	t.mu.Unlock()

	// Receive packet from WinTun
	pkt, err := session.ReceivePacket()
	if err != nil {
		return 0, &TUNError{Op: "receive", Err: err}
	}

	n := copy(packet, pkt)
	session.ReleaseReceivePacket(pkt)

	return n, nil
}

// Write writes a packet to the TUN device.
func (t *windowsTUN) Write(packet []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrTUNClosed
	}
	session := t.session
	t.mu.Unlock()

	// Allocate packet buffer from WinTun
	pkt, err := session.AllocateSendPacket(len(packet))
	if err != nil {
		return 0, &TUNError{Op: "allocate", Err: err}
	}

	copy(pkt, packet)
	session.SendPacket(pkt)

	return len(packet), nil
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
	luid := t.adapter.LUID()
	idx, err := luid.Index()
	if err != nil {
		return 0, err
	}
	return int(idx), nil
}
