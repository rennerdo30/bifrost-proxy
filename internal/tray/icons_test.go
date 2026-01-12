package tray

import (
	"bytes"
	"image/color"
	"image/png"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateIcon_ValidPNG(t *testing.T) {
	icon := createIcon(color.RGBA{R: 255, G: 0, B: 0, A: 255})
	require.NotEmpty(t, icon)

	// Verify it's a valid PNG by decoding it
	img, err := png.Decode(bytes.NewReader(icon))
	require.NoError(t, err)
	assert.NotNil(t, img)

	// Check dimensions
	bounds := img.Bounds()
	assert.Equal(t, 64, bounds.Dx())
	assert.Equal(t, 64, bounds.Dy())
}

func TestIcons_AreInitialized(t *testing.T) {
	// Verify all icons are initialized and valid
	icons := map[string][]byte{
		"connected":    iconConnected,
		"disconnected": iconDisconnected,
		"warning":      iconWarning,
		"error":        iconError,
	}

	for name, icon := range icons {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, icon, "icon %s should not be empty", name)

			// Verify it's a valid PNG
			img, err := png.Decode(bytes.NewReader(icon))
			require.NoError(t, err, "icon %s should be valid PNG", name)
			assert.NotNil(t, img)
		})
	}
}

func TestCreateIcon_HasCorrectColors(t *testing.T) {
	testColor := color.RGBA{R: 100, G: 150, B: 200, A: 255}
	icon := createIcon(testColor)

	img, err := png.Decode(bytes.NewReader(icon))
	require.NoError(t, err)

	// Check center pixel color (should be close to our color)
	centerColor := img.At(32, 32)
	r, g, b, a := centerColor.RGBA()

	// Convert from 16-bit to 8-bit
	r8, g8, b8, a8 := uint8(r>>8), uint8(g>>8), uint8(b>>8), uint8(a>>8)

	// Allow some tolerance for anti-aliasing/highlight effects
	assert.InDelta(t, 100, int(r8), 30, "red channel should be close")
	assert.InDelta(t, 150, int(g8), 30, "green channel should be close")
	assert.InDelta(t, 200, int(b8), 30, "blue channel should be close")
	assert.Equal(t, uint8(255), a8, "alpha should be fully opaque at center")
}

func TestCreateIcon_TransparentBackground(t *testing.T) {
	icon := createIcon(color.RGBA{R: 255, G: 0, B: 0, A: 255})

	img, err := png.Decode(bytes.NewReader(icon))
	require.NoError(t, err)

	// Check corner pixel (should be transparent)
	cornerColor := img.At(0, 0)
	_, _, _, a := cornerColor.RGBA()

	assert.Equal(t, uint32(0), a, "corner should be transparent")
}
