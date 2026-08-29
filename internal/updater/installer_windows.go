//go:build windows

package updater

import (
	"fmt"
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

	// Remove any existing .old file. A failure here is not fatal: the rename
	// below overwrites it, and cleanupOldBinary retries on the next start.
	_ = os.Remove(oldPath) //nolint:errcheck // superseded by the rename below

	// Rename current to .old
	if err := os.Rename(dst, oldPath); err != nil {
		return err
	}

	// Move new binary to target
	if err := os.Rename(src, dst); err != nil {
		// Try to restore. If the restore ALSO fails there is no executable at
		// dst any more, which is the worst outcome this function can produce -
		// so it must not be swallowed. Report both errors: the second explains
		// why the install is broken, the first why it was attempted.
		if restoreErr := os.Rename(oldPath, dst); restoreErr != nil {
			return fmt.Errorf("install failed (%w) and rollback failed: %v; the previous binary is at %s",
				err, restoreErr, oldPath)
		}
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
