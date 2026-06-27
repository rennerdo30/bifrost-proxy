package tray

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
)

// pngToICO converts a PNG image into a classic uncompressed 32bpp BMP/DIB ICO
// container.
//
// The Windows systray backend loads the tray icon from a temporary file via
// LoadImage with IMAGE_ICON | LR_LOADFROMFILE. That code path does NOT reliably
// decode PNG-compressed icon entries (PNG-in-ICO is only understood by newer
// shell/scaling APIs such as LoadIconWithScaleDown). To be robustly loadable we
// emit a legacy DIB icon: a BITMAPINFOHEADER followed by a bottom-up 32bpp BGRA
// color bitmap and a 1bpp AND mask. This is the format LoadImage has supported
// since Windows 95.
//
// The image is converted to RGBA and stored verbatim at its native dimensions.
func pngToICO(pngBytes []byte) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return nil, fmt.Errorf("decode png: %w", err)
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width <= 0 || height <= 0 || width > 256 || height > 256 {
		return nil, fmt.Errorf("unsupported icon dimensions %dx%d", width, height)
	}

	rgba := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			rgba.Set(x, y, img.At(bounds.Min.X+x, bounds.Min.Y+y))
		}
	}

	// The AND mask is a 1bpp bitmap whose rows are padded to a 32-bit boundary.
	maskRowBytes := ((width + 31) / 32) * 4
	maskSize := maskRowBytes * height
	colorSize := width * height * 4

	const (
		bitmapInfoHeaderSize = 40
		iconDirSize          = 6
		iconDirEntrySize     = 16
	)

	// BITMAPINFOHEADER. biHeight is doubled because it covers both the XOR
	// (color) bitmap and the AND (mask) bitmap stacked together.
	var dib bytes.Buffer
	writeU32 := func(v uint32) { _ = binary.Write(&dib, binary.LittleEndian, v) }
	writeI32 := func(v int32) { _ = binary.Write(&dib, binary.LittleEndian, v) }
	writeU16 := func(v uint16) { _ = binary.Write(&dib, binary.LittleEndian, v) }

	writeU32(bitmapInfoHeaderSize)
	writeI32(int32(width))
	writeI32(int32(height * 2))
	writeU16(1)  // planes
	writeU16(32) // bits per pixel
	writeU32(0)  // BI_RGB (no compression)
	writeU32(uint32(colorSize + maskSize))
	writeI32(0) // X pixels per meter
	writeI32(0) // Y pixels per meter
	writeU32(0) // colors used
	writeU32(0) // important colors

	// XOR (color) bitmap: bottom-up rows, BGRA order.
	for y := height - 1; y >= 0; y-- {
		for x := 0; x < width; x++ {
			c := rgba.RGBAAt(x, y)
			dib.WriteByte(c.B)
			dib.WriteByte(c.G)
			dib.WriteByte(c.R)
			dib.WriteByte(c.A)
		}
	}

	// AND (transparency) mask: bottom-up, 1 bit per pixel. A set bit means the
	// pixel is transparent. Since the alpha channel already carries
	// transparency, mark fully transparent pixels in the mask too for backends
	// that ignore the alpha channel.
	for y := height - 1; y >= 0; y-- {
		row := make([]byte, maskRowBytes)
		for x := 0; x < width; x++ {
			if rgba.RGBAAt(x, y).A == 0 {
				row[x/8] |= 0x80 >> (uint(x) % 8)
			}
		}
		dib.Write(row)
	}

	dibBytes := dib.Bytes()

	// ICONDIR + ICONDIRENTRY + DIB payload.
	var out bytes.Buffer
	wU16 := func(v uint16) { _ = binary.Write(&out, binary.LittleEndian, v) }
	wU32 := func(v uint32) { _ = binary.Write(&out, binary.LittleEndian, v) }

	// ICONDIR.
	wU16(0) // reserved
	wU16(1) // type: icon
	wU16(1) // count

	// ICONDIRENTRY.
	out.WriteByte(icoDimByte(width))
	out.WriteByte(icoDimByte(height))
	out.WriteByte(0) // color count (0 for >=8bpp)
	out.WriteByte(0) // reserved
	wU16(1)          // color planes
	wU16(32)         // bits per pixel
	wU32(uint32(len(dibBytes)))
	wU32(iconDirSize + iconDirEntrySize) // offset to image data

	out.Write(dibBytes)
	return out.Bytes(), nil
}

// icoDimByte encodes an icon dimension into the single byte used by the ICO
// directory entry. Per the format, 256 is encoded as 0.
func icoDimByte(v int) byte {
	if v >= 256 {
		return 0
	}
	return byte(v)
}
