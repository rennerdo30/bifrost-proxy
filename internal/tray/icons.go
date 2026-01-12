package tray

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
)

// Icon data (generated at init time)
var (
	// iconConnected is a green icon for connected state
	iconConnected []byte

	// iconDisconnected is a gray icon for disconnected state
	iconDisconnected []byte

	// iconWarning is a yellow icon for warning state
	iconWarning []byte

	// iconError is a red icon for error state
	iconError []byte
)

func init() {
	// Generate icons at init time
	iconConnected = createIcon(color.RGBA{R: 76, G: 175, B: 80, A: 255})       // Green
	iconDisconnected = createIcon(color.RGBA{R: 158, G: 158, B: 158, A: 255})  // Gray
	iconWarning = createIcon(color.RGBA{R: 255, G: 193, B: 7, A: 255})         // Yellow/amber
	iconError = createIcon(color.RGBA{R: 244, G: 67, B: 54, A: 255})           // Red
}

// createIcon creates a 64x64 PNG icon with a filled circle of the given color.
// Larger icons scale better on Windows high-DPI displays.
func createIcon(c color.Color) []byte {
	const size = 64
	const radius = 28
	const centerX, centerY = size / 2, size / 2

	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Fill with transparent background
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, color.Transparent)
		}
	}

	// Draw filled circle with anti-aliasing
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x - centerX)
			dy := float64(y - centerY)
			dist := dx*dx + dy*dy
			r2 := float64(radius * radius)

			if dist <= r2 {
				// Inside circle
				img.Set(x, y, c)
			} else if dist <= float64((radius+1)*(radius+1)) {
				// Anti-aliasing edge
				alpha := 1.0 - (dist-r2)/float64(2*radius+1)
				if alpha > 0 {
					rc, gc, bc, _ := c.RGBA()
					img.Set(x, y, color.RGBA{
						R: uint8(rc >> 8),
						G: uint8(gc >> 8),
						B: uint8(bc >> 8),
						A: uint8(alpha * 255),
					})
				}
			}
		}
	}

	// Add a subtle inner highlight
	for y := centerY - radius + 4; y < centerY - 4; y++ {
		for x := centerX - radius/2; x < centerX + radius/2; x++ {
			dx := float64(x - centerX)
			dy := float64(y - (centerY - radius/2))
			if dx*dx+dy*dy*2 < float64(radius*radius/4) {
				existing := img.RGBAAt(x, y)
				if existing.A > 0 {
					// Lighten slightly
					img.Set(x, y, color.RGBA{
						R: min(existing.R+20, 255),
						G: min(existing.G+20, 255),
						B: min(existing.B+20, 255),
						A: existing.A,
					})
				}
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func min(a, b uint8) uint8 {
	if a < b {
		return a
	}
	return b
}
