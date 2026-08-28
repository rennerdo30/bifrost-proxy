package util

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// The per-platform browser command is asserted directly so the choice is
// covered on every OS, without launching a browser in CI.
func TestOpenURLCommand(t *testing.T) {
	const url = "http://127.0.0.1:7383/"

	tests := []struct {
		goos string
		want []string
	}{
		{"darwin", []string{"open", url}},
		{"windows", []string{"rundll32", "url.dll,FileProtocolHandler", url}},
		{"linux", []string{"xdg-open", url}},
		{"freebsd", []string{"xdg-open", url}},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			cmd := openURLCommand(tt.goos, url)
			if len(cmd.Args) != len(tt.want) {
				t.Fatalf("args = %v, want %v", cmd.Args, tt.want)
			}
			for i, want := range tt.want {
				if cmd.Args[i] != want {
					t.Errorf("arg %d = %q, want %q", i, cmd.Args[i], want)
				}
			}
		})
	}
}

func TestOpenURLLaunchesTheCommand(t *testing.T) {
	original := startCommand
	t.Cleanup(func() { startCommand = original })

	var launched *exec.Cmd
	startCommand = func(cmd *exec.Cmd) error {
		launched = cmd
		return nil
	}

	if err := OpenURL("http://127.0.0.1:7383/"); err != nil {
		t.Fatalf("OpenURL() = %v, want nil", err)
	}
	if launched == nil {
		t.Fatal("OpenURL did not start a command")
	}
	if got := launched.Args[len(launched.Args)-1]; got != "http://127.0.0.1:7383/" {
		t.Errorf("launched with %q, want the URL as the final argument", got)
	}
}

func TestOpenURLWrapsLaunchFailure(t *testing.T) {
	original := startCommand
	t.Cleanup(func() { startCommand = original })

	// A missing browser helper must surface as an error, not be swallowed:
	// the caller logs it, and a silent failure looks like a browser that
	// opened.
	startCommand = func(*exec.Cmd) error { return errors.New("exec: \"xdg-open\": executable file not found in $PATH") }

	err := OpenURL("http://127.0.0.1:7383/")
	if err == nil {
		t.Fatal("OpenURL() = nil, want the launch failure")
	}
	if !strings.Contains(err.Error(), "open url:") {
		t.Errorf("error %q does not identify the operation", err)
	}
	if !strings.Contains(err.Error(), "executable file not found") {
		t.Errorf("error %q drops the underlying cause", err)
	}
}
