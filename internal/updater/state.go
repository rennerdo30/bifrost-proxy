package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// State persists update checker state.
type State struct {
	LastCheck           time.Time `json:"last_check"`
	LastNotifiedVersion string    `json:"last_notified_version"`
	SkippedVersion      string    `json:"skipped_version"`

	path string
	mu   sync.RWMutex
}

// LoadState loads state from file, creating default if not exists.
func LoadState(path string) (*State, error) {
	s := &State{
		path: path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create directory if needed
			dir := filepath.Dir(path)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, s); err != nil {
		// Corrupted file, start fresh
		return &State{path: path}, nil
	}

	return s, nil
}

// Save persists the state to disk.
func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(s.path, data, 0644)
}

// ShouldCheck returns true if enough time has passed since last check.
func (s *State) ShouldCheck(interval time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.LastCheck.IsZero() {
		return true
	}
	return time.Since(s.LastCheck) >= interval
}

// MarkChecked updates the last check time.
func (s *State) MarkChecked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastCheck = time.Now()
}

// MarkNotified records that user was notified about a version.
func (s *State) MarkNotified(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastNotifiedVersion = version
}

// ShouldNotify returns true if user should be notified about this version.
func (s *State) ShouldNotify(version string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastNotifiedVersion != version
}

// SkipVersion marks a version as skipped (user chose to skip).
func (s *State) SkipVersion(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SkippedVersion = version
}

// IsSkipped returns true if a version was skipped.
func (s *State) IsSkipped(version string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SkippedVersion == version
}

// DefaultStatePath returns the default state file path.
// Unix: ~/.config/bifrost/update-state.json
// Windows: %APPDATA%/bifrost/update-state.json
func DefaultStatePath() string {
	var configDir string

	switch runtime.GOOS {
	case "windows":
		configDir = os.Getenv("APPDATA")
		if configDir == "" {
			configDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, "Library", "Application Support")
	default: // Linux and others
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			home, _ := os.UserHomeDir()
			configDir = filepath.Join(home, ".config")
		}
	}

	return filepath.Join(configDir, "bifrost", "update-state.json")
}
