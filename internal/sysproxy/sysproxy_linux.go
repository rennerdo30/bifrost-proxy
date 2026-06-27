//go:build linux

package sysproxy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runner abstracts command execution so the logic can be unit tested without
// invoking the real gsettings binary.
type runner interface {
	run(ctx context.Context, name string, args ...string) ([]byte, error)
	lookPath(name string) (string, error)
}

type execRunner struct{}

func (execRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (execRunner) lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

type linuxManager struct {
	run runner
}

func newPlatformManager() Manager {
	return &linuxManager{run: execRunner{}}
}

// SetProxy configures the GNOME system proxy (org.gnome.system.proxy) via
// gsettings when available. On environments without gsettings/GNOME there is no
// reliable cross-desktop mechanism to set a system-wide proxy, so it returns
// ErrNotSupported and callers should fall back to manual configuration (e.g.
// http_proxy/https_proxy environment variables).
func (m *linuxManager) SetProxy(address string) error {
	host, port, err := splitHostPort(address)
	if err != nil {
		return err
	}

	if !m.gsettingsAvailable() {
		return fmt.Errorf("%w: gsettings (GNOME) not available; set http_proxy/https_proxy/all_proxy=%s manually", ErrNotSupported, address)
	}

	// Configure HTTP, HTTPS and SOCKS proxies to the same listener, then switch
	// the mode to manual so the settings take effect.
	steps := [][]string{
		{"set", "org.gnome.system.proxy.http", "host", host},
		{"set", "org.gnome.system.proxy.http", "port", port},
		{"set", "org.gnome.system.proxy.https", "host", host},
		{"set", "org.gnome.system.proxy.https", "port", port},
		{"set", "org.gnome.system.proxy.socks", "host", host},
		{"set", "org.gnome.system.proxy.socks", "port", port},
		{"set", "org.gnome.system.proxy", "mode", "manual"},
	}
	for _, args := range steps {
		if err := m.exec(args...); err != nil {
			return err
		}
	}
	return nil
}

// ClearProxy reverts the GNOME system proxy back to "none" via gsettings.
func (m *linuxManager) ClearProxy() error {
	if !m.gsettingsAvailable() {
		return fmt.Errorf("%w: gsettings (GNOME) not available; unset http_proxy/https_proxy/all_proxy manually", ErrNotSupported)
	}
	if err := m.exec("set", "org.gnome.system.proxy", "mode", "none"); err != nil {
		return err
	}
	return nil
}

func (m *linuxManager) exec(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), darwinCommandTimeout)
	defer cancel()

	out, err := m.run.run(ctx, "gsettings", args...)
	if err != nil {
		return fmt.Errorf("gsettings %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gsettingsAvailable reports whether the gsettings binary and the GNOME proxy
// schema are both present. Without the schema, `gsettings set` would error, so
// we detect it up front to return a clean ErrNotSupported.
func (m *linuxManager) gsettingsAvailable() bool {
	if _, err := m.run.lookPath("gsettings"); err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), darwinCommandTimeout)
	defer cancel()

	// `gsettings get` against the proxy schema succeeds only when the schema is
	// installed (typically via the GNOME/GSettings desktop integration).
	if _, err := m.run.run(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode"); err != nil {
		return false
	}
	return true
}
