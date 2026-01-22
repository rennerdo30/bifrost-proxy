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

func TestMin(t *testing.T) {
	tests := []struct {
		name     string
		a        uint8
		b        uint8
		expected uint8
	}{
		{"a less than b", 10, 20, 10},
		{"a greater than b", 30, 15, 15},
		{"a equals b", 25, 25, 25},
		{"a is zero", 0, 50, 0},
		{"b is zero", 50, 0, 0},
		{"both zero", 0, 0, 0},
		{"max values", 255, 255, 255},
		{"a max b small", 255, 1, 1},
		{"a small b max", 1, 255, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := min(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateIcon_AntiAliasingEdge(t *testing.T) {
	// Test that anti-aliasing produces partially transparent pixels at the edge
	icon := createIcon(color.RGBA{R: 128, G: 128, B: 128, A: 255})

	img, err := png.Decode(bytes.NewReader(icon))
	require.NoError(t, err)

	// Check a pixel at the edge of the circle (around radius 28-29 from center)
	// The circle has radius 28, center at (32, 32), so check at (32+29, 32)
	edgeColor := img.At(61, 32) // Just outside the main circle
	_, _, _, a := edgeColor.RGBA()

	// Edge pixels should have partial alpha (anti-aliasing) or be transparent
	assert.Less(t, a, uint32(0xFFFF), "edge pixel should have reduced alpha for anti-aliasing")
}

func TestCreateIcon_HighlightRegion(t *testing.T) {
	// Test that the highlight region modifies pixels
	icon := createIcon(color.RGBA{R: 100, G: 100, B: 100, A: 255})

	img, err := png.Decode(bytes.NewReader(icon))
	require.NoError(t, err)

	// Check a pixel in the highlight region (upper portion of the circle)
	// Highlight is applied in the region: y from centerY - radius + 4 to centerY - 4
	// centerY = 32, radius = 28, so y from 8 to 28
	highlightColor := img.At(32, 12)
	r, g, b, a := highlightColor.RGBA()

	// The highlight should make the pixel slightly brighter (but within the alpha region)
	if a > 0 {
		r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)
		// Should be >= 100 (original) or higher due to lightening
		assert.GreaterOrEqual(t, int(r8), 100, "red channel should be at least original value")
		assert.GreaterOrEqual(t, int(g8), 100, "green channel should be at least original value")
		assert.GreaterOrEqual(t, int(b8), 100, "blue channel should be at least original value")
	}
}

func TestCreateIcon_DifferentColors(t *testing.T) {
	colors := []struct {
		name  string
		color color.RGBA
	}{
		{"pure red", color.RGBA{R: 255, G: 0, B: 0, A: 255}},
		{"pure green", color.RGBA{R: 0, G: 255, B: 0, A: 255}},
		{"pure blue", color.RGBA{R: 0, G: 0, B: 255, A: 255}},
		{"white", color.RGBA{R: 255, G: 255, B: 255, A: 255}},
		{"black", color.RGBA{R: 0, G: 0, B: 0, A: 255}},
		{"semi-transparent", color.RGBA{R: 128, G: 128, B: 128, A: 128}},
	}

	for _, tc := range colors {
		t.Run(tc.name, func(t *testing.T) {
			icon := createIcon(tc.color)
			require.NotEmpty(t, icon, "icon should not be empty")

			img, err := png.Decode(bytes.NewReader(icon))
			require.NoError(t, err, "should produce valid PNG")
			assert.NotNil(t, img)

			// Verify dimensions
			bounds := img.Bounds()
			assert.Equal(t, 64, bounds.Dx())
			assert.Equal(t, 64, bounds.Dy())
		})
	}
}

func TestCreateIcon_CircleBoundary(t *testing.T) {
	icon := createIcon(color.RGBA{R: 255, G: 0, B: 0, A: 255})

	img, err := png.Decode(bytes.NewReader(icon))
	require.NoError(t, err)

	// Check that pixels well inside the circle are opaque
	// Center is at (32, 32), radius is 28
	insideColor := img.At(32, 10) // 22 pixels from center, well inside radius 28
	_, _, _, a := insideColor.RGBA()
	assert.Equal(t, uint32(0xFFFF), a, "pixel inside circle should be opaque")

	// Check that pixels well outside the circle are transparent
	outsideColor := img.At(5, 5) // Far corner, definitely outside
	_, _, _, a = outsideColor.RGBA()
	assert.Equal(t, uint32(0), a, "pixel outside circle should be transparent")
}
