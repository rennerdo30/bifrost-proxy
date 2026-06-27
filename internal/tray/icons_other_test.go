//go:build !windows

package tray

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlatformIcon_PassThrough(t *testing.T) {
	in := []byte("some-png-bytes")
	out := platformIcon(in)
	assert.Equal(t, in, out, "non-Windows platformIcon should return PNG bytes unchanged")
}
