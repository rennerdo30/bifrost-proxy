package service

import (
	"errors"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newControlTestManager(t *testing.T) *Manager {
	t.Helper()
	mgr, err := New(Config{Type: TypeServer, Name: "bifrost-test"})
	require.NoError(t, err)
	return mgr
}

func TestManagerControlCommands(t *testing.T) {
	mgr := newControlTestManager(t)

	tests := []struct {
		name     string
		platform string
		action   controlAction
		want     []string
	}{
		{"start systemd", "linux", controlStart, []string{systemctlCommand, "start", "bifrost-test"}},
		{"stop systemd", "linux", controlStop, []string{systemctlCommand, "stop", "bifrost-test"}},
		{"start launchd", "darwin", controlStart, []string{launchctlCommand, "load", mgr.launchdPath()}},
		{"stop launchd", "darwin", controlStop, []string{launchctlCommand, "unload", mgr.launchdPath()}},
		{"start windows", "windows", controlStart, []string{windowsServiceCommand, "start", "bifrost-test"}},
		{"stop windows", "windows", controlStop, []string{windowsServiceCommand, "stop", "bifrost-test"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := mgr.controlCommand(tt.platform, tt.action)
			require.NoError(t, err)
			assert.Equal(t, tt.want, cmd.Args)
		})
	}

	_, err := mgr.controlCommand("plan9", controlStart)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported platform")
}

func TestManagerStartStopExecutePlatformCommands(t *testing.T) {
	mgr := newControlTestManager(t)
	var calls [][]string
	mgr.runControl = func(cmd *exec.Cmd) ([]byte, error) {
		calls = append(calls, append([]string(nil), cmd.Args...))
		return nil, nil
	}

	require.NoError(t, mgr.Start())
	require.NoError(t, mgr.Stop())
	require.Len(t, calls, 2)

	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, []string{systemctlCommand, "start", "bifrost-test"}, calls[0])
		assert.Equal(t, []string{systemctlCommand, "stop", "bifrost-test"}, calls[1])
	case "darwin":
		assert.Equal(t, []string{launchctlCommand, "load", mgr.launchdPath()}, calls[0])
		assert.Equal(t, []string{launchctlCommand, "unload", mgr.launchdPath()}, calls[1])
	case "windows":
		assert.Equal(t, []string{windowsServiceCommand, "start", "bifrost-test"}, calls[0])
		assert.Equal(t, []string{windowsServiceCommand, "stop", "bifrost-test"}, calls[1])
	default:
		t.Fatalf("test does not support %s", runtime.GOOS)
	}
}

func TestManagerControlPreservesCommandFailureAndOutput(t *testing.T) {
	mgr := newControlTestManager(t)
	runErr := errors.New("command failed")
	mgr.runControl = func(*exec.Cmd) ([]byte, error) {
		return []byte("permission denied\n"), runErr
	}

	err := mgr.Start()
	require.Error(t, err)
	assert.ErrorIs(t, err, runErr)
	assert.Contains(t, err.Error(), "start service")
	assert.Contains(t, err.Error(), "permission denied")
}
