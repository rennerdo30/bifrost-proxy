//go:build linux

package sysproxy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRunner struct {
	calls       [][]string
	lookPathErr error
	getModeErr  error
	setErr      error
}

func (f *fakeRunner) lookPath(string) (string, error) {
	if f.lookPathErr != nil {
		return "", f.lookPathErr
	}
	return "/usr/bin/gsettings", nil
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "get":
		if f.getModeErr != nil {
			return []byte("No such schema"), f.getModeErr
		}
		return []byte("'none'\n"), nil
	case "set":
		if f.setErr != nil {
			return []byte("error"), f.setErr
		}
		return nil, nil
	}
	return nil, nil
}

func newAvailableRunner() *fakeRunner {
	return &fakeRunner{}
}

func TestLinuxSetProxy(t *testing.T) {
	f := newAvailableRunner()
	m := &linuxManager{run: f}

	require.NoError(t, m.SetProxy("127.0.0.1:8080"))
	joined := joinCalls(f.calls)
	assert.Contains(t, joined, "gsettings set org.gnome.system.proxy.http host 127.0.0.1")
	assert.Contains(t, joined, "gsettings set org.gnome.system.proxy.http port 8080")
	assert.Contains(t, joined, "gsettings set org.gnome.system.proxy.https host 127.0.0.1")
	assert.Contains(t, joined, "gsettings set org.gnome.system.proxy.socks host 127.0.0.1")
	assert.Contains(t, joined, "gsettings set org.gnome.system.proxy mode manual")
}

func TestLinuxSetProxyInvalidAddress(t *testing.T) {
	f := newAvailableRunner()
	m := &linuxManager{run: f}

	err := m.SetProxy("garbage")
	require.Error(t, err)
	assert.Empty(t, f.calls)
}

func TestLinuxSetProxyNoGsettingsBinary(t *testing.T) {
	f := &fakeRunner{lookPathErr: fmt.Errorf("not found")}
	m := &linuxManager{run: f}

	err := m.SetProxy("127.0.0.1:8080")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestLinuxSetProxyNoSchema(t *testing.T) {
	f := &fakeRunner{getModeErr: fmt.Errorf("No such schema")}
	m := &linuxManager{run: f}

	err := m.SetProxy("127.0.0.1:8080")
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestLinuxSetProxySetFails(t *testing.T) {
	f := &fakeRunner{setErr: fmt.Errorf("exit 1")}
	m := &linuxManager{run: f}

	err := m.SetProxy("127.0.0.1:8080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gsettings")
}

func TestLinuxClearProxy(t *testing.T) {
	f := newAvailableRunner()
	m := &linuxManager{run: f}

	require.NoError(t, m.ClearProxy())
	joined := joinCalls(f.calls)
	assert.Contains(t, joined, "gsettings set org.gnome.system.proxy mode none")
}

func TestLinuxClearProxyNotAvailable(t *testing.T) {
	f := &fakeRunner{lookPathErr: fmt.Errorf("not found")}
	m := &linuxManager{run: f}

	err := m.ClearProxy()
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestLinuxClearProxySetFails(t *testing.T) {
	f := &fakeRunner{setErr: fmt.Errorf("exit 1")}
	m := &linuxManager{run: f}

	err := m.ClearProxy()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gsettings")
}

func joinCalls(calls [][]string) string {
	var lines []string
	for _, c := range calls {
		lines = append(lines, strings.Join(c, " "))
	}
	return strings.Join(lines, "\n")
}
