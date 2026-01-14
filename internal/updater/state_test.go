package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadState_NewFile(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "test-state.json")

	state, err := LoadState(statePath)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, statePath, state.path)
	assert.True(t, state.LastCheck.IsZero())
	assert.Empty(t, state.LastNotifiedVersion)
	assert.Empty(t, state.SkippedVersion)
}

func TestLoadState_ExistingFile(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "test-state.json")

	// Create initial state
	initialState := &State{
		LastCheck:           time.Now(),
		LastNotifiedVersion: "1.0.0",
		SkippedVersion:      "0.9.0",
		path:                statePath,
	}
	err := initialState.Save()
	require.NoError(t, err)

	// Load it back
	state, err := LoadState(statePath)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.False(t, state.LastCheck.IsZero())
	assert.Equal(t, "1.0.0", state.LastNotifiedVersion)
	assert.Equal(t, "0.9.0", state.SkippedVersion)
}

func TestLoadState_CorruptedFile(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "test-state.json")

	// Write invalid JSON
	err := os.WriteFile(statePath, []byte("invalid json"), 0644)
	require.NoError(t, err)

	// Should create new state
	state, err := LoadState(statePath)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.True(t, state.LastCheck.IsZero())
}

func TestState_Save(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "test-state.json")

	state := &State{
		path: statePath,
	}
	state.MarkChecked()
	state.MarkNotified("1.0.0")

	err := state.Save()
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(statePath)
	require.NoError(t, err)
}

func TestState_ShouldCheck(t *testing.T) {
	state := &State{}

	// Should check if never checked
	assert.True(t, state.ShouldCheck(1*time.Hour))

	// Mark as checked
	state.MarkChecked()

	// Should not check if interval not passed
	assert.False(t, state.ShouldCheck(1*time.Hour))

	// Should check if interval passed (use very short interval for test)
	state.LastCheck = time.Now().Add(-2 * time.Hour)
	assert.True(t, state.ShouldCheck(1*time.Hour))
}

func TestState_MarkChecked(t *testing.T) {
	state := &State{}
	assert.True(t, state.LastCheck.IsZero())

	state.MarkChecked()
	assert.False(t, state.LastCheck.IsZero())
}

func TestState_MarkNotified(t *testing.T) {
	state := &State{}
	assert.Empty(t, state.LastNotifiedVersion)

	state.MarkNotified("1.0.0")
	assert.Equal(t, "1.0.0", state.LastNotifiedVersion)
}

func TestState_ShouldNotify(t *testing.T) {
	state := &State{}

	// Should notify if never notified
	assert.True(t, state.ShouldNotify("1.0.0"))

	// Mark as notified
	state.MarkNotified("1.0.0")

	// Should not notify same version
	assert.False(t, state.ShouldNotify("1.0.0"))

	// Should notify different version
	assert.True(t, state.ShouldNotify("1.0.1"))
}

func TestState_SkipVersion(t *testing.T) {
	state := &State{}
	assert.Empty(t, state.SkippedVersion)

	state.SkipVersion("1.0.0")
	assert.Equal(t, "1.0.0", state.SkippedVersion)
}

func TestState_IsSkipped(t *testing.T) {
	state := &State{}

	// Not skipped initially
	assert.False(t, state.IsSkipped("1.0.0"))

	// Skip version
	state.SkipVersion("1.0.0")
	assert.True(t, state.IsSkipped("1.0.0"))
	assert.False(t, state.IsSkipped("1.0.1"))
}

func TestDefaultStatePath(t *testing.T) {
	path := DefaultStatePath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "bifrost")
	assert.Contains(t, path, "update-state.json")
}
