//go:build cgo

package tray

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These assert the CGo adapter, which only exists in a CGo build. They used to
// live in the untagged tray_test.go, which meant the test binary did not
// compile at all for a !cgo target — including every Windows cross-build, since
// cross-compiling disables CGo. Nothing reported it, because CI runs only on
// Linux and `go build` does not compile tests.

func TestRealMenuItem_Interface(t *testing.T) {
	var _ MenuItem = (*realMenuItem)(nil)
}

func TestRealSystrayAdapter_Interface(t *testing.T) {
	var _ SystrayAdapter = (*realSystrayAdapter)(nil)
}

func TestDefaultAdapter_IsRealAdapter(t *testing.T) {
	assert.NotNil(t, defaultAdapter)

	_, ok := defaultAdapter.(*realSystrayAdapter)
	assert.True(t, ok, "a CGo build must default to the real systray adapter")
}
