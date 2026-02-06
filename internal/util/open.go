package util

import (
	"fmt"
	"os/exec"
	"runtime"
)

// OpenURL attempts to open a URL in the system default browser.
func OpenURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url) //nolint:gosec // G204: Opening URLs in browser requires OS commands
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // G204: Opening URLs in browser requires OS commands
	default:
		cmd = exec.Command("xdg-open", url) //nolint:gosec // G204: Opening URLs in browser requires OS commands
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open url: %w", err)
	}
	return nil
}
