//go:build !windows

package updater

import (
	"os"
)

// atomicReplace performs atomic file replacement on Unix.
// On Unix, rename is atomic if on the same filesystem.
func atomicReplace(src, dst string) error {
	return os.Rename(src, dst)
}

// cleanupOldBinary is a no-op on Unix since atomic replace handles everything.
func cleanupOldBinary() {
	// No-op on Unix
}
