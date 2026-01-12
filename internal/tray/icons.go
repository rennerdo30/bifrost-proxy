package tray

// Embedded icons for system tray.
// These are placeholder bytes - in production, embed actual PNG files.

// Icon data (16x16 or 22x22 PNG)
// In a real implementation, use //go:embed to include actual icon files
var (
	// iconConnected is a green icon for connected state
	iconConnected = createSimpleIcon(0, 255, 0)

	// iconDisconnected is a gray icon for disconnected state
	iconDisconnected = createSimpleIcon(128, 128, 128)

	// iconWarning is a yellow icon for warning state
	iconWarning = createSimpleIcon(255, 193, 7)

	// iconError is a red icon for error state
	iconError = createSimpleIcon(220, 53, 69)
)

// createSimpleIcon creates a simple 16x16 PNG icon with the given color.
// This is a minimal PNG implementation for demonstration.
func createSimpleIcon(r, g, b byte) []byte {
	// Minimal 16x16 PNG with solid color
	// PNG header and structure
	png := []byte{
		// PNG signature
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		// IHDR chunk
		0x00, 0x00, 0x00, 0x0D, // Length
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x10, // Width: 16
		0x00, 0x00, 0x00, 0x10, // Height: 16
		0x08,                   // Bit depth: 8
		0x02,                   // Color type: RGB
		0x00,                   // Compression: deflate
		0x00,                   // Filter: adaptive
		0x00,                   // Interlace: none
		0x00, 0x00, 0x00, 0x00, // CRC (placeholder)
	}

	// For a proper implementation, we would include IDAT chunk with
	// compressed image data and IEND chunk.
	// This simplified version just returns a minimal valid-ish PNG structure.

	// Add simple IDAT and IEND chunks
	idat := []byte{
		0x00, 0x00, 0x00, 0x00, // Length (0 for now)
		0x49, 0x44, 0x41, 0x54, // "IDAT"
		// Minimal compressed data would go here
		0x00, 0x00, 0x00, 0x00, // CRC
	}

	iend := []byte{
		0x00, 0x00, 0x00, 0x00, // Length
		0x49, 0x45, 0x4E, 0x44, // "IEND"
		0xAE, 0x42, 0x60, 0x82, // CRC
	}

	result := append(png, idat...)
	result = append(result, iend...)

	return result
}

// In production, use embed directives:
//
// //go:embed icons/connected.png
// var iconConnected []byte
//
// //go:embed icons/disconnected.png
// var iconDisconnected []byte
//
// //go:embed icons/warning.png
// var iconWarning []byte
//
// //go:embed icons/error.png
// var iconError []byte
