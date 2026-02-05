package sysproxy

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	cfg := Config{
		Address: "127.0.0.1:8080",
		Enabled: true,
	}

	assert.Equal(t, "127.0.0.1:8080", cfg.Address)
	assert.True(t, cfg.Enabled)
}

func TestConfig_Disabled(t *testing.T) {
	cfg := Config{
		Address: "",
		Enabled: false,
	}

	assert.Equal(t, "", cfg.Address)
	assert.False(t, cfg.Enabled)
}

func TestNew(t *testing.T) {
	mgr := New()
	assert.NotNil(t, mgr)

	// Verify it implements Manager interface
	var _ Manager = mgr
}

func TestManagerInterface(t *testing.T) {
	// Verify that the Manager interface is properly defined
	mgr := New()
	assert.NotNil(t, mgr)
}

func TestErrNotSupported(t *testing.T) {
	assert.NotNil(t, ErrNotSupported)
	assert.Contains(t, ErrNotSupported.Error(), "not supported")
}

// Platform-specific tests

func TestSetProxy(t *testing.T) {
	mgr := New()

	// On non-Windows platforms, this is a no-op that returns nil
	// On Windows, this would actually modify registry (skip in CI)
	if runtime.GOOS == "windows" {
		t.Skip("Skipping SetProxy test on Windows to avoid modifying system settings")
	}

	err := mgr.SetProxy("127.0.0.1:8080")
	assert.NoError(t, err)
}

func TestClearProxy(t *testing.T) {
	mgr := New()

	// On non-Windows platforms, this is a no-op that returns nil
	// On Windows, this would actually modify registry (skip in CI)
	if runtime.GOOS == "windows" {
		t.Skip("Skipping ClearProxy test on Windows to avoid modifying system settings")
	}

	err := mgr.ClearProxy()
	assert.NoError(t, err)
}

func TestSetAndClearProxy(t *testing.T) {
	mgr := New()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping proxy test on Windows to avoid modifying system settings")
	}

	// Set proxy
	err := mgr.SetProxy("127.0.0.1:8080")
	assert.NoError(t, err)

	// Clear proxy
	err = mgr.ClearProxy()
	assert.NoError(t, err)
}

func TestSetProxy_EmptyAddress(t *testing.T) {
	mgr := New()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping proxy test on Windows to avoid modifying system settings")
	}

	// Empty address - still no-op on non-Windows
	err := mgr.SetProxy("")
	assert.NoError(t, err)
}

func TestSetProxy_IPv6Address(t *testing.T) {
	mgr := New()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping proxy test on Windows to avoid modifying system settings")
	}

	// IPv6 address format
	err := mgr.SetProxy("[::1]:8080")
	assert.NoError(t, err)
}

func TestSetProxy_WithHostname(t *testing.T) {
	mgr := New()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping proxy test on Windows to avoid modifying system settings")
	}

	// Hostname instead of IP
	err := mgr.SetProxy("proxy.example.com:8080")
	assert.NoError(t, err)
}

func TestMultipleOperations(t *testing.T) {
	mgr := New()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping proxy test on Windows to avoid modifying system settings")
	}

	// Multiple set/clear operations
	for i := 0; i < 5; i++ {
		err := mgr.SetProxy("127.0.0.1:8080")
		assert.NoError(t, err)

		err = mgr.ClearProxy()
		assert.NoError(t, err)
	}
}

func TestConcurrentOperations(t *testing.T) {
	mgr := New()

	if runtime.GOOS == "windows" {
		t.Skip("Skipping proxy test on Windows to avoid modifying system settings")
	}

	// Test concurrent access (no-op on non-Windows, but tests for race conditions)
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_ = mgr.SetProxy("127.0.0.1:8080")
			_ = mgr.ClearProxy()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
