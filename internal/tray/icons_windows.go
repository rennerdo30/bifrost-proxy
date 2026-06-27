//go:build windows

package tray

// platformIcon returns the icon bytes in the format expected by the Windows
// system tray. The getlantern/systray backend on Windows writes the icon to a
// temporary file and loads it with LoadImage(IMAGE_ICON | LR_LOADFROMFILE),
// which requires a classic BMP/DIB-based ICO container (PNG-compressed ICO
// entries are not reliably loaded by that API). pngToICO performs the
// conversion.
//
// If the input cannot be converted (which should not happen for our generated
// icons), the original PNG bytes are returned unchanged so the caller still
// receives a non-empty icon rather than nothing.
func platformIcon(pngBytes []byte) []byte {
	ico, err := pngToICO(pngBytes)
	if err != nil {
		return pngBytes
	}
	return ico
}
