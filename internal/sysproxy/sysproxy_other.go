//go:build !windows && !darwin && !linux

package sysproxy

// unsupportedManager is used on platforms where automatic system proxy
// configuration is not yet implemented. It fails closed by returning
// ErrNotSupported so callers do not falsely report that the system proxy was
// configured.
type unsupportedManager struct{}

func newPlatformManager() Manager {
	return &unsupportedManager{}
}

func (m *unsupportedManager) SetProxy(address string) error {
	return ErrNotSupported
}

func (m *unsupportedManager) ClearProxy() error {
	return ErrNotSupported
}
