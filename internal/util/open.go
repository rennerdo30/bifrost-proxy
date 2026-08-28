package util

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openURLCommand builds the platform command that opens url in the default
// browser. Split out from OpenURL so the per-platform choice is testable
// without actually launching a browser.
func openURLCommand(goos, url string) *exec.Cmd {
	switch goos {
	case "darwin":
		return exec.Command("open", url) //nolint:gosec // G204: Opening URLs in browser requires OS commands
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // G204: Opening URLs in browser requires OS commands
	default:
		return exec.Command("xdg-open", url) //nolint:gosec // G204: Opening URLs in browser requires OS commands
	}
}

// startCommand launches the browser command. A package variable so tests can
// exercise OpenURL's success and failure paths without spawning a browser.
var startCommand = func(cmd *exec.Cmd) error { return cmd.Start() }

// OpenURL attempts to open a URL in the system default browser.
func OpenURL(url string) error {
	if err := startCommand(openURLCommand(runtime.GOOS, url)); err != nil {
		return fmt.Errorf("open url: %w", err)
	}
	return nil
}
