//go:build !windows

package tray

// platformIcon returns the icon bytes in the format expected by the system
// tray on the current platform. On macOS and Linux the underlying systray
// implementation accepts PNG data directly, so the icon is returned unchanged.
func platformIcon(pngBytes []byte) []byte {
	return pngBytes
}
