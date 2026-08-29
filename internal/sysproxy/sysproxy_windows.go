//go:build windows

package sysproxy

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

var (
	modwininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modwininet.NewProc("InternetSetOptionW")
)

const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37

	// defaultProxyOverride is the bypass list written when the profile has
	// none. "<local>" is the value Windows' own proxy UI writes by default and
	// covers loopback plus any hostname without a dot, i.e. local and intranet
	// destinations.
	defaultProxyOverride = "<local>"

	// proxySettingsKey is the per-user Internet Settings key holding the
	// WinINET proxy configuration.
	proxySettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

type windowsManager struct{}

func newPlatformManager() Manager {
	return &windowsManager{}
}

func (m *windowsManager) SetProxy(address string) error {
	// QUERY_VALUE as well as SET_VALUE: the existing ProxyOverride has to be
	// read before deciding whether to write one.
	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}

	if err := k.SetStringValue("ProxyServer", address); err != nil {
		return fmt.Errorf("set ProxyServer: %w", err)
	}

	// Write a bypass list when the profile has none. Leaving ProxyOverride
	// unset does not mean "use a sensible default" - it means WinINET sends
	// loopback and intranet traffic through the proxy too, which breaks
	// locally-hosted services and needlessly tunnels LAN traffic. The
	// commented-out call this replaces left that to chance: it worked only for
	// users whose profile already happened to carry a bypass list.
	//
	// Only written when nothing usable is there, so a bypass list the user
	// configured is never clobbered. A read error is treated the same as an
	// empty value: there is no existing setting to preserve either way.
	if existing, _, overrideErr := k.GetStringValue("ProxyOverride"); overrideErr != nil || existing == "" {
		if err := k.SetStringValue("ProxyOverride", defaultProxyOverride); err != nil {
			return fmt.Errorf("set ProxyOverride: %w", err)
		}
	}

	notifySettingsChange()
	return nil
}

func (m *windowsManager) ClearProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	// ProxyOverride is deliberately left as-is. With ProxyEnable=0 WinINET
	// ignores it, and removing it could discard a list the user has since
	// customized.
	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}

	notifySettingsChange()
	return nil
}

func notifySettingsChange() {
	// Start checks for 1 (true) but return value is BOOL (int32 usually)
	// We ignore errors here as it's a notification attempt
	// Best effort notification: WinINET picks the new settings up on its own
	// schedule regardless, and LazyProc.Call's error is a non-nil Errno even on
	// success, so there is nothing meaningful to branch on.
	procInternetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0) //nolint:errcheck // best-effort refresh
	procInternetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)          //nolint:errcheck // best-effort refresh
}
