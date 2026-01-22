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
)

type windowsManager struct{}

func newPlatformManager() Manager {
	return &windowsManager{}
}

func (m *windowsManager) SetProxy(address string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
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

	// Optional: Set ProxyOverride to bypass local addresses if needed,
	// but user didn't explicitly ask for it. <local> is standard default.
	// For now, we leave existing overrides or could set a default if missing.
	// k.SetStringValue("ProxyOverride", "<local>")

	notifySettingsChange()
	return nil
}

func (m *windowsManager) ClearProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}

	notifySettingsChange()
	return nil
}

func notifySettingsChange() {
	// Start checks for 1 (true) but return value is BOOL (int32 usually)
	// We ignore errors here as it's a notification attempt
	procInternetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	procInternetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
}
