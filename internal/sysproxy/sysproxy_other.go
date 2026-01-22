//go:build !windows

package sysproxy

type noopManager struct{}

func newPlatformManager() Manager {
	return &noopManager{}
}

func (m *noopManager) SetProxy(address string) error {
	// No-op for non-Windows platforms (for now)
	return nil
}

func (m *noopManager) ClearProxy() error {
	return nil
}
