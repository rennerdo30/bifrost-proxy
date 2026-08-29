//go:build !cgo

package tray

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The !cgo counterpart of adapter_cgo_test.go. A build without CGo must fall
// back to the no-op adapter rather than the real one; that substitution was
// previously untested in the configuration where it actually applies.

func TestNoopMenuItem_Interface(t *testing.T) {
	var _ MenuItem = (*noopMenuItem)(nil)
}

func TestNoopSystrayAdapter_Interface(t *testing.T) {
	var _ SystrayAdapter = (*noopSystrayAdapter)(nil)
}

func TestDefaultAdapter_IsNoopAdapter(t *testing.T) {
	assert.NotNil(t, defaultAdapter)

	_, ok := defaultAdapter.(*noopSystrayAdapter)
	assert.True(t, ok, "a non-CGo build must default to the no-op systray adapter")
}

func TestNoopAdapter_IsInert(t *testing.T) {
	a := &noopSystrayAdapter{}

	// None of these may panic or block; the whole point is that a tray-less
	// build keeps running.
	a.SetIcon([]byte{1, 2, 3})
	a.SetTitle("bifrost")
	a.SetTooltip("tip")
	a.AddSeparator()
	a.Quit()

	item := a.AddMenuItem("label", "tooltip")
	require := assert.New(t)
	require.NotNil(item)
	require.NotNil(item.Clicked())
}
