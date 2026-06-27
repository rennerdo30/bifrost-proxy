package tray

import (
	"encoding/binary"
	"image/color"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPngToICO_ProducesValidDIBICO verifies that pngToICO emits a classic
// BMP/DIB ICO container (not PNG-in-ICO) with the structure LoadImage expects:
// a 6-byte ICONDIR, a 16-byte ICONDIRENTRY, and a BITMAPINFOHEADER whose height
// is doubled (color bitmap + AND mask) at 32 bits per pixel.
func TestPngToICO_ProducesValidDIBICO(t *testing.T) {
	pngBytes := createIcon(color.RGBA{R: 10, G: 20, B: 30, A: 255})

	ico, err := pngToICO(pngBytes)
	require.NoError(t, err)
	require.Greater(t, len(ico), 6+16+40, "ICO must contain header, entry and a DIB header")

	// ICONDIR.
	assert.Equal(t, uint16(0), binary.LittleEndian.Uint16(ico[0:2]), "reserved must be 0")
	assert.Equal(t, uint16(1), binary.LittleEndian.Uint16(ico[2:4]), "type must be 1 (icon)")
	assert.Equal(t, uint16(1), binary.LittleEndian.Uint16(ico[4:6]), "count must be 1")

	// ICONDIRENTRY: dimensions are 64 (the generated icon size).
	assert.Equal(t, byte(64), ico[6], "width byte")
	assert.Equal(t, byte(64), ico[7], "height byte")
	assert.Equal(t, uint16(32), binary.LittleEndian.Uint16(ico[12:14]), "bits per pixel")

	imageSize := binary.LittleEndian.Uint32(ico[14:18])
	offset := binary.LittleEndian.Uint32(ico[18:22])
	assert.Equal(t, uint32(6+16), offset, "image data offset")
	require.Equal(t, len(ico), int(offset)+int(imageSize), "declared image size must match payload")

	// BITMAPINFOHEADER at the image offset.
	dib := ico[offset:]
	assert.Equal(t, uint32(40), binary.LittleEndian.Uint32(dib[0:4]), "BITMAPINFOHEADER size")
	width := int32(binary.LittleEndian.Uint32(dib[4:8]))
	height := int32(binary.LittleEndian.Uint32(dib[8:12]))
	assert.Equal(t, int32(64), width, "DIB width")
	assert.Equal(t, int32(128), height, "DIB height must be doubled for color+mask")
	assert.Equal(t, uint16(32), binary.LittleEndian.Uint16(dib[14:16]), "DIB bpp")
	assert.Equal(t, uint32(0), binary.LittleEndian.Uint32(dib[16:20]), "BI_RGB (uncompressed)")

	// It must NOT be a PNG payload (no PNG signature at the data offset).
	pngSig := []byte{0x89, 'P', 'N', 'G'}
	assert.NotEqual(t, pngSig, dib[:4], "payload must be a DIB, not PNG-in-ICO")
}

func TestPngToICO_RejectsInvalidPNG(t *testing.T) {
	_, err := pngToICO([]byte("not a png"))
	require.Error(t, err)
}

func TestIcoDimByte(t *testing.T) {
	assert.Equal(t, byte(64), icoDimByte(64))
	assert.Equal(t, byte(0), icoDimByte(256), "256 must encode as 0")
	assert.Equal(t, byte(0), icoDimByte(300))
}
