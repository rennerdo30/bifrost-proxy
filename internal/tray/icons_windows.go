//go:build windows

package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
)

// platformIcon returns the icon bytes in the format expected by the Windows
// system tray. The getlantern/systray implementation on Windows requires an
// ICO container; the generated icons are PNG, so they are wrapped in a
// single-image ICO here. Modern Windows (Vista+) supports PNG-compressed
// images embedded directly inside an ICO directory entry, so the PNG payload
// is stored verbatim.
//
// If the input cannot be decoded as a PNG (which should not happen for our
// generated icons), the original bytes are returned unchanged so the caller
// still receives a non-empty icon.
func platformIcon(pngBytes []byte) []byte {
	cfg, err := png.DecodeConfig(bytes.NewReader(pngBytes))
	if err != nil {
		return pngBytes
	}
	ico, err := pngToICO(pngBytes, cfg)
	if err != nil {
		return pngBytes
	}
	return ico
}

// icoWidthHeight encodes an image dimension into the single byte used by the
// ICO directory. Per the format, a value of 0 means 256 pixels.
func icoWidthHeight(v int) byte {
	if v >= 256 {
		return 0
	}
	return byte(v)
}

// pngToICO wraps a PNG payload in a minimal single-image ICO container.
func pngToICO(pngBytes []byte, cfg image.Config) ([]byte, error) {
	const (
		headerSize = 6  // ICONDIR
		entrySize  = 16 // ICONDIRENTRY
	)

	var buf bytes.Buffer

	// ICONDIR header.
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1)) // type: 1 = icon
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1)) // image count

	// ICONDIRENTRY.
	buf.WriteByte(icoWidthHeight(cfg.Width))
	buf.WriteByte(icoWidthHeight(cfg.Height))
	buf.WriteByte(0)                                                          // color palette
	buf.WriteByte(0)                                                          // reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))                    // color planes
	_ = binary.Write(&buf, binary.LittleEndian, uint16(32))                   // bits per pixel
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(pngBytes)))        // image size
	_ = binary.Write(&buf, binary.LittleEndian, uint32(headerSize+entrySize)) // offset

	buf.Write(pngBytes)
	return buf.Bytes(), nil
}
