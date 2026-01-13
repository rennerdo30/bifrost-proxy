//go:build windows

package updater

import (
	"os"
)

// atomicReplace on Windows requires special handling since
// you cannot replace a running executable directly.
func atomicReplace(src, dst string) error {
	// Windows strategy:
	// 1. Rename current binary to .old
	// 2. Move new binary to target location
	// 3. The .old file will be cleaned up on next run
	oldPath := dst + ".old"

	// Remove any existing .old file
	os.Remove(oldPath)

	// Rename current to .old
	if err := os.Rename(dst, oldPath); err != nil {
		return err
	}

	// Move new binary to target
	if err := os.Rename(src, dst); err != nil {
		// Try to restore
		os.Rename(oldPath, dst)
		return err
	}

	return nil
}

// cleanupOldBinary removes .old files from previous updates.
// This should be called early in program startup.
func cleanupOldBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	oldPath := exe + ".old"
	os.Remove(oldPath)
}
