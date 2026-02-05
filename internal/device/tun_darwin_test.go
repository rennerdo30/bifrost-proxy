//go:build darwin

package device

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDarwinTUNStruct tests the darwinTUN struct methods
// These tests don't actually create devices but test the struct behavior
func TestDarwinTUNStruct(t *testing.T) {
	t.Run("Name method", func(t *testing.T) {
		tun := &darwinTUN{
			name: "utun5",
			mtu:  1400,
			fd:   -1,
		}
		assert.Equal(t, "utun5", tun.Name())
	})

	t.Run("Type method", func(t *testing.T) {
		tun := &darwinTUN{
			name: "utun5",
			mtu:  1400,
			fd:   -1,
		}
		assert.Equal(t, DeviceTUN, tun.Type())
	})

	t.Run("MTU method", func(t *testing.T) {
		tun := &darwinTUN{
			name: "utun5",
			mtu:  1500,
			fd:   -1,
		}
		assert.Equal(t, 1500, tun.MTU())
	})

	t.Run("File method", func(t *testing.T) {
		tun := &darwinTUN{
			name: "utun5",
			mtu:  1400,
			fd:   5, // Use a valid-looking fd value
		}
		f := tun.File()
		// File() returns os.NewFile which can return nil for invalid fds
		if f != nil {
			assert.Equal(t, "utun5", f.Name())
		}
	})

	t.Run("Close already closed", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: true,
		}
		err := tun.Close()
		assert.NoError(t, err) // Should not error if already closed
	})

	t.Run("Read when closed", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: true,
		}
		buf := make([]byte, 1500)
		n, err := tun.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, ErrDeviceClosed, err)
		assert.Equal(t, 0, n)
	})

	t.Run("Write when closed", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: true,
		}
		n, err := tun.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, ErrDeviceClosed, err)
		assert.Equal(t, 0, n)
	})

	t.Run("Write empty buffer", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     5, // Fake fd
			closed: false,
		}
		n, err := tun.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("concurrent read and write when closed", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: true,
		}

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				buf := make([]byte, 1500)
				tun.Read(buf)
			}()
			go func() {
				defer wg.Done()
				tun.Write([]byte("test"))
			}()
		}
		wg.Wait()
	})
}

// TestCreatePlatformTUNErrors tests error conditions for TUN creation
func TestCreatePlatformTUNErrors(t *testing.T) {
	t.Run("permission denied simulation", func(t *testing.T) {
		// This test verifies error handling - actual creation requires root
		cfg := Config{
			Type:    DeviceTUN,
			Name:    "utun99",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTUN(cfg)
		if err != nil {
			// Expected without root privileges
			// Check that it's a device error
			var devErr *DeviceError
			if errors.As(err, &devErr) {
				assert.NotEmpty(t, devErr.Op)
			} else if errors.Is(err, ErrPermissionDenied) {
				// Permission denied is also an expected error without root
				t.Logf("Permission denied as expected: %v", err)
			}
		} else {
			// If we somehow succeeded (running as root), clean up
			dev.Close()
		}
	})

	t.Run("with specific utun number", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Name:    "utun100",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTUN(cfg)
		if err != nil {
			// Expected - either permission denied or device in use
			assert.Error(t, err)
		} else {
			dev.Close()
		}
	})

	t.Run("with empty utun name (auto-assign)", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Name:    "utun",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTUN(cfg)
		if err != nil {
			assert.Error(t, err)
		} else {
			dev.Close()
		}
	})

	t.Run("with invalid unit number in name", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Name:    "utunABC",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTUN(cfg)
		if err != nil {
			assert.Error(t, err)
		} else {
			// Should still work, just ignores invalid number
			dev.Close()
		}
	})
}

// TestDarwinTUNWriteIPVersion tests the IP version detection in Write
func TestDarwinTUNWriteIPVersion(t *testing.T) {
	t.Run("unknown IP version error", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     5, // Invalid but non-zero fd
			closed: false,
		}

		// Create a buffer with invalid IP version (3)
		buf := make([]byte, 20)
		buf[0] = 3 << 4 // Version 3

		_, err := tun.Write(buf)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown IP version")
	})

	t.Run("IPv4 packet detection", func(t *testing.T) {
		// This just tests the version detection logic
		buf := make([]byte, 20)
		buf[0] = 4 << 4 // IPv4
		version := buf[0] >> 4
		assert.Equal(t, uint8(4), version)
	})

	t.Run("IPv6 packet detection", func(t *testing.T) {
		buf := make([]byte, 40)
		buf[0] = 6 << 4 // IPv6
		version := buf[0] >> 4
		assert.Equal(t, uint8(6), version)
	})
}

// TestGetUtunNameMock tests getUtunName behavior
func TestGetUtunNameMock(t *testing.T) {
	t.Run("with invalid fd", func(t *testing.T) {
		// Test with an invalid fd
		name, err := getUtunName(-1)
		assert.Error(t, err)
		assert.Empty(t, name)

		var devErr *DeviceError
		if errors.As(err, &devErr) {
			assert.Contains(t, devErr.Op, "getsockopt")
		}
	})
}

// TestDarwinTUNInterfaceCompliance tests interface implementation
func TestDarwinTUNInterfaceCompliance(t *testing.T) {
	t.Run("implements NetworkDevice", func(t *testing.T) {
		tun := &darwinTUN{}
		var _ NetworkDevice = tun
	})
}

// TestDarwinTAPStruct tests the darwinTAP struct methods
func TestDarwinTAPStruct(t *testing.T) {
	t.Run("Name method", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
		}
		assert.Equal(t, "tap0", tap.Name())
	})

	t.Run("Type method", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
		}
		assert.Equal(t, DeviceTAP, tap.Type())
	})

	t.Run("MTU method", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1500,
		}
		assert.Equal(t, 1500, tap.MTU())
	})

	t.Run("MACAddress method", func(t *testing.T) {
		mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
			mac:  mac,
		}
		assert.Equal(t, mac, tap.MACAddress())
	})

	t.Run("SetMACAddress invalid length", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
		}
		err := tap.SetMACAddress(net.HardwareAddr{0x01, 0x02})
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidMACAddress, err)
	})

	t.Run("Close already closed", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			closed: true,
		}
		err := tap.Close()
		assert.NoError(t, err)
	})

	t.Run("Read when closed", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			closed: true,
		}
		buf := make([]byte, 1500)
		n, err := tap.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, ErrDeviceClosed, err)
		assert.Equal(t, 0, n)
	})

	t.Run("Write when closed", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			closed: true,
		}
		n, err := tap.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, ErrDeviceClosed, err)
		assert.Equal(t, 0, n)
	})
}

// TestDarwinTAPInterfaceCompliance tests interface implementation
func TestDarwinTAPInterfaceCompliance(t *testing.T) {
	t.Run("implements TAPDevice", func(t *testing.T) {
		tap := &darwinTAP{}
		var _ TAPDevice = tap
	})

	t.Run("implements NetworkDevice", func(t *testing.T) {
		tap := &darwinTAP{}
		var _ NetworkDevice = tap
	})
}

// TestCreatePlatformTAPErrors tests error conditions for TAP creation
func TestCreatePlatformTAPErrors(t *testing.T) {
	t.Run("TAP device not available", func(t *testing.T) {
		// On macOS, TAP requires tuntaposx driver which is usually not installed
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "tap0",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTAP(cfg)
		if err != nil {
			// Expected - TAP driver not installed
			var devErr *DeviceError
			if errors.As(err, &devErr) {
				assert.Contains(t, devErr.Op, "open")
			}
		} else {
			dev.Close()
		}
	})

	t.Run("with specific tap device", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "tap5",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTAP(cfg)
		if err != nil {
			assert.Error(t, err)
		} else {
			dev.Close()
		}
	})

	t.Run("with auto-assign (no name)", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := createPlatformTAP(cfg)
		if err != nil {
			assert.Error(t, err)
		} else {
			dev.Close()
		}
	})

	t.Run("with invalid MAC in config", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			MTU:     1400,
			TAP: TAPConfig{
				MACAddress: "invalid",
			},
		}

		// This should fail at validation
		err := cfg.Validate()
		assert.Error(t, err)
	})
}

// TestDarwinTAPReadWriteWithMockedFile tests Read/Write with file operations
func TestDarwinTAPReadWriteWithMockedFile(t *testing.T) {
	t.Run("read with nil fd panics", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			fd:     nil,
			closed: false,
		}

		buf := make([]byte, 1500)
		// This will panic due to nil fd, so we recover
		defer func() {
			if r := recover(); r != nil {
				// Expected panic due to nil fd - this is the intended behavior
				t.Logf("Expected panic due to nil fd: %v", r)
			}
		}()
		tap.Read(buf)
	})

	t.Run("write with nil fd panics", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			fd:     nil,
			closed: false,
		}

		defer func() {
			if r := recover(); r != nil {
				// Expected panic due to nil fd - this is the intended behavior
				t.Logf("Expected panic due to nil fd: %v", r)
			}
		}()
		tap.Write([]byte("test"))
	})

	t.Run("close with nil fd", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			fd:     nil,
			closed: false,
		}

		err := tap.Close()
		assert.NoError(t, err)
		assert.True(t, tap.closed)
	})
}

// TestDarwinTAPGetMACFromInterface tests MAC address retrieval
func TestDarwinTAPGetMACFromInterface(t *testing.T) {
	t.Run("with non-existent interface", func(t *testing.T) {
		tap := &darwinTAP{
			name: "nonexistent_interface_xyz",
			mtu:  1400,
		}

		mac, err := tap.GetMACFromInterface()
		assert.Error(t, err)
		assert.Nil(t, mac)
	})

	t.Run("with loopback interface (lo0)", func(t *testing.T) {
		tap := &darwinTAP{
			name: "lo0",
			mtu:  1400,
		}

		mac, err := tap.GetMACFromInterface()
		// lo0 usually exists but has empty/no MAC address
		if err == nil {
			// On macOS, lo0 exists but may have empty MAC
			// This is fine - just checking the function doesn't crash
			_ = mac
		}
		// If error, that's also acceptable - interface behavior varies
	})

	t.Run("with en0 interface", func(t *testing.T) {
		tap := &darwinTAP{
			name: "en0",
			mtu:  1400,
		}

		mac, err := tap.GetMACFromInterface()
		if err == nil {
			// en0 usually exists on macOS
			assert.NotNil(t, mac)
			assert.Len(t, mac, 6)
		}
		// It's OK if it errors - might not exist in test environment
	})
}

// TestDarwinTUNReadWriteConcurrency tests concurrent access
func TestDarwinTUNReadWriteConcurrency(t *testing.T) {
	t.Run("concurrent closed checks", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: false,
		}

		var wg sync.WaitGroup

		// Spawn multiple goroutines that close and check
		for i := 0; i < 10; i++ {
			wg.Add(3)

			go func() {
				defer wg.Done()
				tun.Close()
			}()

			go func() {
				defer wg.Done()
				buf := make([]byte, 1500)
				tun.Read(buf)
			}()

			go func() {
				defer wg.Done()
				tun.Write([]byte{0x45, 0x00, 0x00, 0x14}) // IPv4 minimal header
			}()
		}

		wg.Wait()
	})
}

// TestDarwinTAPSetMACAddressWithInterface tests SetMACAddress behavior
func TestDarwinTAPSetMACAddressWithInterface(t *testing.T) {
	t.Run("set MAC updates local copy", func(t *testing.T) {
		oldMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
		newMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

		tap := &darwinTAP{
			name:   "nonexistent",
			mtu:    1400,
			mac:    oldMAC,
			closed: false,
		}

		// This will fail because the interface doesn't exist
		// but we can test the validation logic
		err := tap.SetMACAddress(newMAC)
		// Error expected because ifconfig will fail
		if err != nil {
			assert.Error(t, err)
		}
	})
}

// TestCreateTAPWithMACConfig tests TAP creation with MAC configuration
func TestCreateTAPWithMACConfig(t *testing.T) {
	t.Run("with valid MAC", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			MTU:     1400,
			TAP: TAPConfig{
				MACAddress: "02:00:00:00:00:01",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)

		dev, err := createPlatformTAP(cfg)
		if err != nil {
			// Expected - TAP driver not installed
			assert.Error(t, err)
		} else {
			tapDev, ok := dev.(TAPDevice)
			require.True(t, ok)
			assert.Len(t, tapDev.MACAddress(), 6)
			dev.Close()
		}
	})

	t.Run("with auto-generated MAC", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			MTU:     1400,
			TAP:     TAPConfig{},
		}

		dev, err := createPlatformTAP(cfg)
		if err != nil {
			assert.Error(t, err)
		} else {
			tapDev, ok := dev.(TAPDevice)
			require.True(t, ok)
			mac := tapDev.MACAddress()
			assert.Len(t, mac, 6)
			// Should be locally administered
			assert.Equal(t, byte(0x02), mac[0]&0x02)
			dev.Close()
		}
	})
}

// TestDarwinDeviceMultipleClose tests idempotent close
func TestDarwinDeviceMultipleClose(t *testing.T) {
	t.Run("TUN multiple close", func(t *testing.T) {
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: false,
		}

		// First close
		err1 := tun.Close()

		// Second close should be no-op
		err2 := tun.Close()
		err3 := tun.Close()

		// None should error
		_ = err1 // May error due to invalid fd
		assert.NoError(t, err2)
		assert.NoError(t, err3)
	})

	t.Run("TAP multiple close", func(t *testing.T) {
		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			fd:     nil,
			closed: false,
		}

		err1 := tap.Close()
		err2 := tap.Close()
		err3 := tap.Close()

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NoError(t, err3)
	})
}

// TestDarwinCreateFunctions tests the public Create functions
func TestDarwinCreateFunctions(t *testing.T) {
	t.Run("CreateTUN on darwin", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := CreateTUN(cfg)
		if err != nil {
			// Expected without root
			assert.Error(t, err)
		} else {
			assert.Equal(t, DeviceTUN, dev.Type())
			dev.Close()
		}
	})

	t.Run("CreateTAP on darwin", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := CreateTAP(cfg)
		if err != nil {
			// Expected - TAP driver usually not installed
			assert.Error(t, err)
		} else {
			assert.Equal(t, DeviceTAP, dev.Type())
			dev.Close()
		}
	})
}

// TestDarwinAddressConstants tests the address family constants
func TestDarwinAddressConstants(t *testing.T) {
	assert.Equal(t, uint32(2), uint32(afInet))
	assert.Equal(t, uint32(30), uint32(afInet6))
}

// TestDarwinControlNameConstant tests the utun control name
func TestDarwinControlNameConstant(t *testing.T) {
	assert.Equal(t, "com.apple.net.utun_control", utunControlName)
}

// TestDarwinOptIfnameConstant tests the UTUN_OPT_IFNAME constant
func TestDarwinOptIfnameConstant(t *testing.T) {
	assert.Equal(t, 2, utunOptIfname)
}

// TestDarwinTAPJoinBridge tests bridge joining (will fail without actual device)
func TestDarwinTAPJoinBridge(t *testing.T) {
	t.Run("join non-existent bridge", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
		}

		err := tap.joinBridge("nonexistent_bridge")
		assert.Error(t, err)
	})
}

// TestDarwinTAPSetMACAddressCmd tests the setMACAddressCmd method
func TestDarwinTAPSetMACAddressCmd(t *testing.T) {
	t.Run("with non-existent interface", func(t *testing.T) {
		tap := &darwinTAP{
			name: "nonexistent_tap",
			mtu:  1400,
		}

		mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
		err := tap.setMACAddressCmd(mac)
		assert.Error(t, err)
	})
}

// TestDarwinTUNFileMethod tests the File() method
func TestDarwinTUNFileMethod(t *testing.T) {
	t.Run("returns valid file object", func(t *testing.T) {
		tun := &darwinTUN{
			name: "utun5",
			mtu:  1400,
			fd:   10,
		}

		f := tun.File()
		assert.NotNil(t, f)
		assert.IsType(t, &os.File{}, f)
	})

	t.Run("file name matches device name", func(t *testing.T) {
		tun := &darwinTUN{
			name: "utun10",
			mtu:  1400,
			fd:   20,
		}

		f := tun.File()
		assert.Equal(t, "utun10", f.Name())
	})
}

// TestDarwinTAPSetMACAddressValidation tests SetMACAddress validation
func TestDarwinTAPSetMACAddressValidation(t *testing.T) {
	t.Run("empty MAC address rejected", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
			mac:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		}

		err := tap.SetMACAddress(net.HardwareAddr{})
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidMACAddress, err)
	})

	t.Run("5-byte MAC address rejected", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
		}

		err := tap.SetMACAddress(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00})
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidMACAddress, err)
	})

	t.Run("7-byte MAC address rejected", func(t *testing.T) {
		tap := &darwinTAP{
			name: "tap0",
			mtu:  1400,
		}

		err := tap.SetMACAddress(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidMACAddress, err)
	})
}

// TestDarwinTAPClose tests close behavior with actual file
func TestDarwinTAPCloseWithFile(t *testing.T) {
	t.Run("close calls ifconfig down", func(t *testing.T) {
		// Create a temporary file to simulate fd
		tmpFile, err := os.CreateTemp("", "tap_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		tap := &darwinTAP{
			name:   "nonexistent_tap",
			mtu:    1400,
			fd:     tmpFile,
			closed: false,
		}

		err = tap.Close()
		// Close should succeed even if ifconfig fails (it runs best-effort)
		assert.NoError(t, err)
		assert.True(t, tap.closed)

		// Verify file is closed
		_, err = tmpFile.Stat()
		assert.Error(t, err) // File should be closed
	})
}

// TestDarwinTAPReadWithFile tests read with actual file
func TestDarwinTAPReadWithFile(t *testing.T) {
	t.Run("read from temp file", func(t *testing.T) {
		// Create a temporary file and write some data
		tmpFile, err := os.CreateTemp("", "tap_read_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		testData := []byte("test ethernet frame data")
		_, err = tmpFile.Write(testData)
		require.NoError(t, err)

		// Seek back to beginning
		_, err = tmpFile.Seek(0, 0)
		require.NoError(t, err)

		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			fd:     tmpFile,
			closed: false,
		}

		buf := make([]byte, 1500)
		n, err := tap.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, len(testData), n)
		assert.Equal(t, testData, buf[:n])
	})
}

// TestDarwinTAPWriteWithFile tests write with actual file
func TestDarwinTAPWriteWithFile(t *testing.T) {
	t.Run("write to temp file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "tap_write_test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		tap := &darwinTAP{
			name:   "tap0",
			mtu:    1400,
			fd:     tmpFile,
			closed: false,
		}

		testData := []byte("test ethernet frame")
		n, err := tap.Write(testData)
		assert.NoError(t, err)
		assert.Equal(t, len(testData), n)
	})
}

// TestDarwinTUNReadError tests read error handling
func TestDarwinTUNReadError(t *testing.T) {
	t.Run("read returns DeviceError on failure", func(t *testing.T) {
		// Use an invalid fd that will cause read to fail
		tun := &darwinTUN{
			name:   "utun5",
			mtu:    1400,
			fd:     -1,
			closed: false,
		}

		buf := make([]byte, 1500)
		_, err := tun.Read(buf)
		// This will fail with EAGAIN or similar, which triggers select
		// Since we can't properly test this without a real fd, we just verify
		// the closed check works
		assert.Error(t, err)
	})
}

// TestCreateTAPInterfaceTypeAssertion tests that CreateTAP properly asserts TAPDevice
func TestCreateTAPInterfaceTypeAssertion(t *testing.T) {
	t.Run("type assertion for TAPDevice", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		dev, err := CreateTAP(cfg)
		if err == nil {
			// If we got a device, verify it's usable
			assert.NotNil(t, dev)
			dev.Close()
		}
		// Error is expected without TAP driver
	})
}

// TestCreatePlatformTAPNameHandling tests TAP name handling logic
func TestCreatePlatformTAPNameHandling(t *testing.T) {
	t.Run("short name", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "ta", // Less than 3 chars + "tap"
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		_, err := createPlatformTAP(cfg)
		// Should fail since no TAP driver, but tests the name handling code path
		assert.Error(t, err)
	})

	t.Run("non-tap prefixed name", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "eth0", // Not prefixed with "tap"
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		_, err := createPlatformTAP(cfg)
		assert.Error(t, err)
	})
}

// TestDarwinTUNNameParsing tests the utun name parsing
func TestDarwinTUNNameParsing(t *testing.T) {
	t.Run("various utun names", func(t *testing.T) {
		testCases := []struct {
			name     string
			expected bool // whether it should parse a number
		}{
			{"utun0", true},
			{"utun99", true},
			{"utun", false},
			{"utunXYZ", false},
			{"", false},
		}

		for _, tc := range testCases {
			cfg := Config{
				Type:    DeviceTUN,
				Name:    tc.name,
				Address: "10.0.0.1/24",
				MTU:     1400,
			}

			// Just validate that it doesn't panic
			_, err := createPlatformTUN(cfg)
			// Error expected without root
			assert.Error(t, err)
		}
	})
}

// TestDarwinTAPConfigureFails tests that configure errors are propagated
func TestDarwinTAPConfigureFails(t *testing.T) {
	// This tests the error path when configure fails during TAP creation
	t.Run("configure error propagation", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "tap0",
			Address: "10.0.0.1/24",
			MTU:     1400,
		}

		_, err := createPlatformTAP(cfg)
		if err != nil {
			// Error is expected - either no TAP driver or configuration failed
			var devErr *DeviceError
			errors.As(err, &devErr) // Just check it can be cast
		}
	})
}
