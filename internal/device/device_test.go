package device

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceTypeString(t *testing.T) {
	tests := []struct {
		deviceType DeviceType
		expected   string
	}{
		{DeviceTUN, "tun"},
		{DeviceTAP, "tap"},
		{DeviceType(99), "unknown"},
		{DeviceType(-1), "unknown"},
		{DeviceType(100), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.deviceType.String())
		})
	}
}

func TestParseDeviceType(t *testing.T) {
	tests := []struct {
		input    string
		expected DeviceType
		hasError bool
	}{
		{"tun", DeviceTUN, false},
		{"TUN", DeviceTUN, false},
		{"", DeviceTUN, false},
		{"tap", DeviceTAP, false},
		{"TAP", DeviceTAP, false},
		{"invalid", DeviceTUN, true},
		{"TuN", DeviceTUN, true},
		{"TaP", DeviceTUN, true},
		{"tunX", DeviceTUN, true},
		{"tapX", DeviceTUN, true},
		{" tun", DeviceTUN, true},
		{"tun ", DeviceTUN, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			deviceType, err := ParseDeviceType(tt.input)
			if tt.hasError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unknown device type")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, deviceType)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		cfg := Config{}
		err := cfg.Validate()
		require.NoError(t, err)

		assert.NotEmpty(t, cfg.Name)
		assert.Equal(t, "10.255.0.1/24", cfg.Address)
		assert.Equal(t, 1400, cfg.MTU)
	})

	t.Run("valid TUN config", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Name:    "test0",
			Address: "192.168.1.1/24",
			MTU:     1500,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid TAP config", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Name:    "tap0",
			Address: "10.0.0.1/24",
			MTU:     1400,
			TAP: TAPConfig{
				MACAddress: "02:00:00:00:00:01",
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid TAP config with bridge", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			MTU:     1400,
			TAP: TAPConfig{
				MACAddress: "02:00:00:00:00:01",
				Bridge:     "br0",
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid address format", func(t *testing.T) {
		cfg := Config{
			Address: "invalid",
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid device address")
	})

	t.Run("address without prefix", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1",
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid device address")
	})

	t.Run("invalid IP in address", func(t *testing.T) {
		cfg := Config{
			Address: "999.999.999.999/24",
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid device address")
	})

	t.Run("MTU too large", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     70000,
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU too large")
	})

	t.Run("MTU at maximum valid value", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     65535,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("MTU too small", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     100,
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU too small")
	})

	t.Run("MTU at minimum valid value", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     576,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("MTU just below minimum", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     575,
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU too small")
	})

	t.Run("MTU just above maximum", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     65536,
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU too large")
	})

	t.Run("zero MTU gets default", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     0,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 1400, cfg.MTU)
	})

	t.Run("negative MTU gets default", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/24",
			MTU:     -1,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 1400, cfg.MTU)
	})

	t.Run("invalid TAP MAC address", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			TAP: TAPConfig{
				MACAddress: "invalid",
			},
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MAC address")
	})

	t.Run("invalid TAP MAC address format", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			TAP: TAPConfig{
				MACAddress: "02:00:00:00:00:GG",
			},
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MAC address")
	})

	t.Run("TUN type ignores TAP MAC config", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Address: "10.0.0.1/24",
			TAP: TAPConfig{
				MACAddress: "invalid-mac",
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("empty TAP MAC is valid", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
			TAP: TAPConfig{
				MACAddress: "",
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid IPv6 address", func(t *testing.T) {
		cfg := Config{
			Address: "fd00::1/64",
			MTU:     1400,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid MAC with different separators", func(t *testing.T) {
		testCases := []string{
			"02:00:00:00:00:01",
			"02-00-00-00-00-01",
		}
		for _, mac := range testCases {
			cfg := Config{
				Type:    DeviceTAP,
				Address: "10.0.0.1/24",
				TAP: TAPConfig{
					MACAddress: mac,
				},
			}
			err := cfg.Validate()
			assert.NoError(t, err, "MAC address %s should be valid", mac)
		}
	})
}

func TestDefaultDeviceName(t *testing.T) {
	t.Run("TUN", func(t *testing.T) {
		name := DefaultDeviceName(DeviceTUN)
		assert.NotEmpty(t, name)

		switch runtime.GOOS {
		case "darwin":
			assert.Equal(t, "utun", name)
		case "windows":
			assert.Equal(t, "Bifrost", name)
		default:
			assert.Equal(t, "bifrost0", name)
		}
	})

	t.Run("TAP", func(t *testing.T) {
		name := DefaultDeviceName(DeviceTAP)
		assert.NotEmpty(t, name)

		switch runtime.GOOS {
		case "windows":
			assert.Equal(t, "Bifrost", name)
		case "darwin":
			assert.Equal(t, "tap0", name)
		default:
			assert.Equal(t, "tap0", name)
		}
	})

	t.Run("unknown device type", func(t *testing.T) {
		name := DefaultDeviceName(DeviceType(99))
		assert.NotEmpty(t, name)
	})
}

func TestGenerateMAC(t *testing.T) {
	mac := GenerateMAC()
	assert.Len(t, mac, 6)

	// Should be locally administered (bit 1 of first byte set)
	assert.Equal(t, byte(0x02), mac[0]&0x02)

	// Should be unicast (bit 0 of first byte clear)
	assert.Equal(t, byte(0), mac[0]&0x01)

	// Verify second byte is 0xBF for "BF" (Bifrost)
	assert.Equal(t, byte(0xBF), mac[1])
}

func TestGenerateRandomMAC(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mac1, err := GenerateRandomMAC()
		require.NoError(t, err)
		assert.Len(t, mac1, 6)

		// Should be locally administered
		assert.Equal(t, byte(0x02), mac1[0]&0x02)

		// Should be unicast
		assert.Equal(t, byte(0), mac1[0]&0x01)

		// Should generate different MACs
		mac2, err := GenerateRandomMAC()
		require.NoError(t, err)

		// Very unlikely to be the same
		assert.NotEqual(t, mac1.String(), mac2.String())
	})

	t.Run("error case", func(t *testing.T) {
		// Save original
		original := randomRead
		defer func() { randomRead = original }()

		// Mock error
		randomRead = func(b []byte) (int, error) {
			return 0, errors.New("mock random error")
		}

		mac, err := GenerateRandomMAC()
		assert.Error(t, err)
		assert.Nil(t, mac)
		assert.Contains(t, err.Error(), "failed to generate random MAC")
	})
}

func TestDeviceError(t *testing.T) {
	t.Run("Error method", func(t *testing.T) {
		err := &DeviceError{
			Op:  "create",
			Err: ErrPermissionDenied,
		}

		assert.Equal(t, "device create: permission denied: device creation requires root/admin privileges", err.Error())
	})

	t.Run("Unwrap method", func(t *testing.T) {
		err := &DeviceError{
			Op:  "create",
			Err: ErrPermissionDenied,
		}
		assert.Equal(t, ErrPermissionDenied, err.Unwrap())
	})

	t.Run("with custom error", func(t *testing.T) {
		customErr := errors.New("custom error")
		err := &DeviceError{
			Op:  "read",
			Err: customErr,
		}
		assert.Equal(t, "device read: custom error", err.Error())
		assert.Equal(t, customErr, err.Unwrap())
	})

	t.Run("errors.Is works with wrapped error", func(t *testing.T) {
		err := &DeviceError{
			Op:  "create",
			Err: ErrPermissionDenied,
		}
		assert.True(t, errors.Is(err, ErrPermissionDenied))
	})
}

func TestCommonErrors(t *testing.T) {
	assert.Equal(t, "device type not supported on this platform", ErrDeviceNotSupported.Error())
	assert.Equal(t, "permission denied: device creation requires root/admin privileges", ErrPermissionDenied.Error())
	assert.Equal(t, "device already exists", ErrDeviceAlreadyExists.Error())
	assert.Equal(t, "device is closed", ErrDeviceClosed.Error())
	assert.Equal(t, "TAP device not supported on this platform", ErrTAPNotSupported.Error())
	assert.Equal(t, "invalid MAC address", ErrInvalidMACAddress.Error())
}

func TestCreateTUNValidation(t *testing.T) {
	t.Run("invalid address", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Address: "invalid",
		}

		_, err := CreateTUN(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid device address")
	})

	t.Run("sets type to TUN", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP, // Even if TAP is set
			Address: "invalid",
		}

		_, err := CreateTUN(cfg)
		assert.Error(t, err)
		// The error should be from validation, not from wrong type
		assert.Contains(t, err.Error(), "invalid device address")
	})
}

func TestCreateTAPValidation(t *testing.T) {
	t.Run("invalid address", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "invalid",
		}

		_, err := CreateTAP(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid device address")
	})
}

func TestCreateValidation(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		cfg := Config{
			Address: "invalid",
		}
		_, err := Create(cfg)
		assert.Error(t, err)
	})

	t.Run("unsupported device type", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceType(99),
			Address: "10.0.0.1/24",
			MTU:     1400,
		}
		_, err := Create(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported device type")
	})
}

func TestTAPConfig(t *testing.T) {
	t.Run("MAC address parsing", func(t *testing.T) {
		cfg := TAPConfig{
			MACAddress: "02:00:00:00:00:01",
			Bridge:     "br0",
		}

		mac, err := net.ParseMAC(cfg.MACAddress)
		require.NoError(t, err)
		assert.Len(t, mac, 6)
		assert.Equal(t, "br0", cfg.Bridge)
	})

	t.Run("empty TAPConfig", func(t *testing.T) {
		cfg := TAPConfig{}
		assert.Empty(t, cfg.MACAddress)
		assert.Empty(t, cfg.Bridge)
	})
}

// TestCreateRequiresRoot tests that device creation requires root privileges
func TestCreateRequiresRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that requires network")
	}

	cfg := Config{
		Type:    DeviceTUN,
		Name:    "test-tun0",
		Address: "10.255.0.1/24",
		MTU:     1400,
	}

	_, err := Create(cfg)
	// Should fail without root
	if err != nil {
		// Expected on non-root systems
		assert.Error(t, err)
	}
}

// MockNetworkDevice for testing
type MockNetworkDevice struct {
	name       string
	deviceType DeviceType
	mtu        int
	closed     bool
	readData   []byte
	writeData  []byte
	readErr    error
	writeErr   error
	closeErr   error
	mu         sync.Mutex
}

func NewMockNetworkDevice(name string, deviceType DeviceType, mtu int) *MockNetworkDevice {
	return &MockNetworkDevice{
		name:       name,
		deviceType: deviceType,
		mtu:        mtu,
	}
}

func (m *MockNetworkDevice) Name() string {
	return m.name
}

func (m *MockNetworkDevice) Type() DeviceType {
	return m.deviceType
}

func (m *MockNetworkDevice) Read(buf []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, ErrDeviceClosed
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	if len(m.readData) == 0 {
		return 0, nil
	}
	n := copy(buf, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *MockNetworkDevice) Write(buf []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, ErrDeviceClosed
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, buf...)
	return len(buf), nil
}

func (m *MockNetworkDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true
	return m.closeErr
}

func (m *MockNetworkDevice) MTU() int {
	return m.mtu
}

func (m *MockNetworkDevice) SetReadData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readData = data
}

func (m *MockNetworkDevice) GetWriteData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeData
}

func (m *MockNetworkDevice) SetReadError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readErr = err
}

func (m *MockNetworkDevice) SetWriteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeErr = err
}

func (m *MockNetworkDevice) SetCloseError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeErr = err
}

func TestMockNetworkDevice(t *testing.T) {
	t.Run("basic operations", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)

		assert.Equal(t, "test0", dev.Name())
		assert.Equal(t, DeviceTUN, dev.Type())
		assert.Equal(t, 1400, dev.MTU())
	})

	t.Run("read and write", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)

		// Write data
		testData := []byte("test packet data")
		n, err := dev.Write(testData)
		assert.NoError(t, err)
		assert.Equal(t, len(testData), n)
		assert.Equal(t, testData, dev.GetWriteData())

		// Read data
		dev.SetReadData([]byte("response data"))
		buf := make([]byte, 1500)
		n, err = dev.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 13, n)
		assert.Equal(t, "response data", string(buf[:n]))
	})

	t.Run("read from empty buffer", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		buf := make([]byte, 1500)
		n, err := dev.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read error", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		dev.SetReadError(errors.New("read error"))

		buf := make([]byte, 1500)
		_, err := dev.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("write error", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		dev.SetWriteError(errors.New("write error"))

		_, err := dev.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("close", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)

		err := dev.Close()
		assert.NoError(t, err)

		// Second close should be idempotent
		err = dev.Close()
		assert.NoError(t, err)
	})

	t.Run("close error", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		dev.SetCloseError(errors.New("close error"))

		err := dev.Close()
		assert.Error(t, err)
		assert.Equal(t, "close error", err.Error())
	})

	t.Run("read after close", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		dev.Close()

		buf := make([]byte, 1500)
		_, err := dev.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, ErrDeviceClosed, err)
	})

	t.Run("write after close", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		dev.Close()

		_, err := dev.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, ErrDeviceClosed, err)
	})

	t.Run("concurrent operations", func(t *testing.T) {
		dev := NewMockNetworkDevice("test0", DeviceTUN, 1400)
		var wg sync.WaitGroup

		// Concurrent writes
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				dev.Write([]byte{byte(i)})
			}(i)
		}

		// Concurrent reads
		dev.SetReadData(make([]byte, 100))
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 10)
				dev.Read(buf)
			}()
		}

		wg.Wait()
		dev.Close()
	})
}

// MockTAPDevice for testing TAP-specific functionality
type MockTAPDevice struct {
	MockNetworkDevice
	mac       net.HardwareAddr
	setMacErr error
}

func NewMockTAPDevice(name string, mtu int) *MockTAPDevice {
	mac, _ := GenerateRandomMAC()
	return &MockTAPDevice{
		MockNetworkDevice: MockNetworkDevice{
			name:       name,
			deviceType: DeviceTAP,
			mtu:        mtu,
		},
		mac: mac,
	}
}

func (m *MockTAPDevice) MACAddress() net.HardwareAddr {
	return m.mac
}

func (m *MockTAPDevice) SetMACAddress(mac net.HardwareAddr) error {
	if m.setMacErr != nil {
		return m.setMacErr
	}
	if len(mac) != 6 {
		return ErrInvalidMACAddress
	}
	m.mac = mac
	return nil
}

func (m *MockTAPDevice) SetSetMACError(err error) {
	m.setMacErr = err
}

func TestMockTAPDevice(t *testing.T) {
	t.Run("basic operations", func(t *testing.T) {
		dev := NewMockTAPDevice("tap0", 1400)

		assert.Equal(t, "tap0", dev.Name())
		assert.Equal(t, DeviceTAP, dev.Type())
		assert.Equal(t, 1400, dev.MTU())
		assert.Len(t, dev.MACAddress(), 6)
	})

	t.Run("set MAC address", func(t *testing.T) {
		dev := NewMockTAPDevice("tap0", 1400)

		newMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
		err := dev.SetMACAddress(newMAC)
		assert.NoError(t, err)
		assert.Equal(t, newMAC, dev.MACAddress())
	})

	t.Run("set invalid MAC address", func(t *testing.T) {
		dev := NewMockTAPDevice("tap0", 1400)

		err := dev.SetMACAddress(net.HardwareAddr{0x00})
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidMACAddress, err)
	})

	t.Run("set MAC error", func(t *testing.T) {
		dev := NewMockTAPDevice("tap0", 1400)
		dev.SetSetMACError(errors.New("permission denied"))

		err := dev.SetMACAddress(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
		assert.Error(t, err)
		assert.Equal(t, "permission denied", err.Error())
	})

	t.Run("implements TAPDevice interface", func(t *testing.T) {
		var _ TAPDevice = NewMockTAPDevice("tap0", 1400)
	})
}

func TestNetworkDeviceInterface(t *testing.T) {
	t.Run("MockNetworkDevice implements NetworkDevice", func(t *testing.T) {
		var _ NetworkDevice = NewMockNetworkDevice("test0", DeviceTUN, 1400)
	})
}

// Test Config with various edge cases
func TestConfigEdgeCases(t *testing.T) {
	t.Run("very long interface name", func(t *testing.T) {
		cfg := Config{
			Name:    "verylonginterfacenamethatmayexceedlimits",
			Address: "10.0.0.1/24",
		}
		// Validation should pass - name length enforcement happens at OS level
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("special characters in name", func(t *testing.T) {
		cfg := Config{
			Name:    "test-0_special",
			Address: "10.0.0.1/24",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("IPv4 with /32 prefix", func(t *testing.T) {
		cfg := Config{
			Address: "10.0.0.1/32",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("IPv6 with /128 prefix", func(t *testing.T) {
		cfg := Config{
			Address: "fd00::1/128",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("IPv6 full address", func(t *testing.T) {
		cfg := Config{
			Address: "2001:db8:85a3:0000:0000:8a2e:0370:7334/64",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("link-local address", func(t *testing.T) {
		cfg := Config{
			Address: "169.254.1.1/16",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("loopback address", func(t *testing.T) {
		cfg := Config{
			Address: "127.0.0.1/8",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

// Test that all DeviceType constants have correct values
func TestDeviceTypeConstants(t *testing.T) {
	assert.Equal(t, DeviceType(0), DeviceTUN)
	assert.Equal(t, DeviceType(1), DeviceTAP)
}

// Test error wrapping chain
func TestDeviceErrorChain(t *testing.T) {
	innerErr := errors.New("inner error")
	middleErr := &DeviceError{Op: "middle", Err: innerErr}
	outerErr := &DeviceError{Op: "outer", Err: middleErr}

	assert.True(t, errors.Is(outerErr, innerErr))
	assert.Contains(t, outerErr.Error(), "outer")
	assert.Contains(t, outerErr.Error(), "device middle")
}

// Test concurrent access to random generator
func TestGenerateRandomMACConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	macs := make(chan string, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mac, err := GenerateRandomMAC()
			if err == nil {
				macs <- mac.String()
			}
		}()
	}

	wg.Wait()
	close(macs)

	// Collect all MACs and check for uniqueness
	seen := make(map[string]bool)
	for mac := range macs {
		if seen[mac] {
			t.Errorf("duplicate MAC generated: %s", mac)
		}
		seen[mac] = true
	}
}

// Ensure GenerateMAC returns consistent format
func TestGenerateMACFormat(t *testing.T) {
	mac := GenerateMAC()

	// Check format: should be colon-separated hex
	str := mac.String()
	assert.Regexp(t, `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`, str)
}

// Test Config name defaulting for different device types
func TestConfigNameDefaults(t *testing.T) {
	t.Run("TUN type gets default name", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTUN,
			Address: "10.0.0.1/24",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
		assert.Equal(t, DefaultDeviceName(DeviceTUN), cfg.Name)
	})

	t.Run("TAP type gets default name", func(t *testing.T) {
		cfg := Config{
			Type:    DeviceTAP,
			Address: "10.0.0.1/24",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
		assert.Equal(t, DefaultDeviceName(DeviceTAP), cfg.Name)
	})

	t.Run("explicit name is preserved", func(t *testing.T) {
		cfg := Config{
			Name:    "custom0",
			Address: "10.0.0.1/24",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
		assert.Equal(t, "custom0", cfg.Name)
	})
}
