package service

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	// Create temp files for testing
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "bifrost-server")
	configPath := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))
	require.NoError(t, os.WriteFile(configPath, []byte("config: test"), 0644))

	cfg := Config{
		Type:       TypeServer,
		BinaryPath: binaryPath,
		ConfigPath: configPath,
	}

	mgr, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, mgr)
	assert.Equal(t, "bifrost-server", mgr.config.Name)
	assert.Equal(t, "Bifrost Proxy Server", mgr.config.Description)
	assert.True(t, filepath.IsAbs(mgr.config.BinaryPath))
	assert.True(t, filepath.IsAbs(mgr.config.ConfigPath))
	assert.Equal(t, tmpDir, mgr.config.WorkingDir)
}

func TestNew_Client(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "bifrost-client")
	configPath := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))
	require.NoError(t, os.WriteFile(configPath, []byte("config: test"), 0644))

	cfg := Config{
		Type:       TypeClient,
		BinaryPath: binaryPath,
		ConfigPath: configPath,
	}

	mgr, err := New(cfg)
	require.NoError(t, err)
	assert.Equal(t, "bifrost-client", mgr.config.Name)
	assert.Equal(t, "Bifrost Proxy Client", mgr.config.Description)
}

func TestNew_CustomName(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "bifrost-server")
	configPath := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))
	require.NoError(t, os.WriteFile(configPath, []byte("config: test"), 0644))

	cfg := Config{
		Type:        TypeServer,
		Name:        "my-custom-service",
		Description: "My Custom Description",
		BinaryPath:  binaryPath,
		ConfigPath:  configPath,
	}

	mgr, err := New(cfg)
	require.NoError(t, err)
	assert.Equal(t, "my-custom-service", mgr.config.Name)
	assert.Equal(t, "My Custom Description", mgr.config.Description)
}

func TestNew_RelativePaths(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "bifrost-server")
	configPath := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))
	require.NoError(t, os.WriteFile(configPath, []byte("config: test"), 0644))

	// Change to temp dir to test relative paths
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	cfg := Config{
		Type:       TypeServer,
		BinaryPath: "bifrost-server",
		ConfigPath: "config.yaml",
	}

	mgr, err := New(cfg)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(mgr.config.BinaryPath))
	assert.True(t, filepath.IsAbs(mgr.config.ConfigPath))
}

func TestPlatform(t *testing.T) {
	platform := Platform()
	assert.Equal(t, runtime.GOOS, platform)
	assert.Contains(t, []string{"linux", "darwin", "windows"}, platform)
}

func TestInstall_BinaryNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("config: test"), 0644))

	cfg := Config{
		Type:       TypeServer,
		BinaryPath: filepath.Join(tmpDir, "nonexistent"),
		ConfigPath: configPath,
	}

	mgr, err := New(cfg)
	require.NoError(t, err)

	err = mgr.Install()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "binary not found")
}

func TestInstall_ConfigNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "bifrost-server")
	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))

	cfg := Config{
		Type:       TypeServer,
		BinaryPath: binaryPath,
		ConfigPath: filepath.Join(tmpDir, "nonexistent.yaml"),
	}

	mgr, err := New(cfg)
	require.NoError(t, err)

	err = mgr.Install()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config not found")
}

func TestSystemdPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	mgr := &Manager{
		config: Config{
			Name: "bifrost-server",
		},
	}

	path := mgr.systemdPath()
	assert.Equal(t, "/etc/systemd/system/bifrost-server.service", path)
}

func TestLaunchdPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	mgr := &Manager{
		config: Config{
			Name: "bifrost-server",
		},
	}

	path := mgr.launchdPath()
	// Should be either LaunchDaemons or LaunchAgents
	assert.Contains(t, path, "bifrost-server.plist")
}

// TestStatus_NotInstalled tests status when service is not installed
func TestStatus_NotInstalled(t *testing.T) {
	mgr := &Manager{
		config: Config{
			Name: "bifrost-nonexistent-service-test",
		},
	}

	status, err := mgr.Status()
	require.NoError(t, err)
	assert.Equal(t, "not installed", status)
}
