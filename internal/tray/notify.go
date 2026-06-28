package tray

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Notifier sends desktop notifications. It is implemented per platform using
// native OS commands and can be replaced in tests.
type Notifier interface {
	// Notify shows a desktop notification with the given title and message.
	Notify(title, message string) error
}

// osNotifier sends notifications using native OS commands.
type osNotifier struct{}

// Notify displays a desktop notification using the platform-native tooling.
//
//   - macOS:   osascript "display notification"
//   - Linux:   notify-send
//   - Windows: PowerShell toast via the BurntToast-free balloon API
func (n *osNotifier) Notify(title, message string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf("display notification %q with title %q", message, title)
		cmd = exec.Command("osascript", "-e", script) //nolint:gosec // G204: notification requires OS commands; inputs are app-controlled strings
	case "windows":
		script := fmt.Sprintf(
			"[reflection.assembly]::loadwithpartialname('System.Windows.Forms');"+
				"[reflection.assembly]::loadwithpartialname('System.Drawing');"+
				"$n=New-Object System.Windows.Forms.NotifyIcon;"+
				"$n.Icon=[System.Drawing.SystemIcons]::Information;"+
				"$n.BalloonTipTitle=%q;$n.BalloonTipText=%q;"+
				"$n.Visible=$true;$n.ShowBalloonTip(5000);Start-Sleep -Seconds 5",
			title, message)
		cmd = exec.Command("powershell", "-NoProfile", "-Command", script) //nolint:gosec // G204: notification requires OS commands; inputs are app-controlled strings
	default:
		cmd = exec.Command("notify-send", title, message) //nolint:gosec // G204: notification requires OS commands; inputs are app-controlled strings
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("send notification: %w", err)
	}
	// Reap the process asynchronously so we do not leak zombies, but do not
	// block the caller waiting for the notification to be dismissed.
	go func() { _ = cmd.Wait() }() //nolint:errcheck // best-effort reaping of the notification process
	return nil
}

// defaultNotifier is the notifier used by Tray unless overridden.
var defaultNotifier Notifier = &osNotifier{}
