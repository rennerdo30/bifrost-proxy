package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
)

// Installer handles binary installation.
type Installer struct {
	binaryType BinaryType
}

// NewInstaller creates a new Installer.
func NewInstaller(binaryType BinaryType) *Installer {
	return &Installer{
		binaryType: binaryType,
	}
}

// Install installs an update from the downloaded archive.
func (i *Installer) Install(ctx context.Context, archivePath string) error {
	currentPath, err := i.GetCurrentBinaryPath()
	if err != nil {
		return fmt.Errorf("get current binary path: %w", err)
	}

	// Create backup
	backupPath, err := i.Backup()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupFailed, err)
	}
	logging.Info("Created backup", "path", backupPath)

	// Create temp file for new binary
	tempDir := filepath.Dir(currentPath)
	tempBinary := filepath.Join(tempDir, i.binaryType.BinaryName()+".new")

	// Extract new binary
	if err := i.ExtractBinary(archivePath, tempBinary); err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tempBinary, 0755); err != nil {
			os.Remove(tempBinary)
			return fmt.Errorf("chmod: %w", err)
		}
	}

	// Atomic replace
	if err := atomicReplace(tempBinary, currentPath); err != nil {
		logging.Error("Install failed, restoring backup", "error", err)
		if restoreErr := i.Restore(backupPath); restoreErr != nil {
			return fmt.Errorf("%w: install failed (%v) and restore failed (%v)", ErrInstallFailed, err, restoreErr)
		}
		return fmt.Errorf("%w: %v", ErrInstallFailed, err)
	}

	logging.Info("Binary updated successfully", "path", currentPath)
	return nil
}

// Backup creates a backup of the current binary.
func (i *Installer) Backup() (string, error) {
	currentPath, err := i.GetCurrentBinaryPath()
	if err != nil {
		return "", err
	}

	backupPath := currentPath + ".bak"

	// Remove existing backup
	os.Remove(backupPath)

	// Copy current binary to backup
	src, err := os.Open(currentPath)
	if err != nil {
		return "", fmt.Errorf("open current binary: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("create backup file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(backupPath)
		return "", fmt.Errorf("copy to backup: %w", err)
	}

	// Preserve permissions
	srcInfo, err := os.Stat(currentPath)
	if err == nil {
		os.Chmod(backupPath, srcInfo.Mode())
	}

	return backupPath, nil
}

// Restore restores the binary from backup.
func (i *Installer) Restore(backupPath string) error {
	currentPath, err := i.GetCurrentBinaryPath()
	if err != nil {
		return err
	}

	if err := os.Rename(backupPath, currentPath); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreFailed, err)
	}

	return nil
}

// GetCurrentBinaryPath returns the path to the currently running binary.
func (i *Installer) GetCurrentBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path: %w", err)
	}

	// Resolve symlinks
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}

	return exe, nil
}

// ExtractBinary extracts the target binary from an archive.
func (i *Installer) ExtractBinary(archivePath, destPath string) error {
	ext := strings.ToLower(filepath.Ext(archivePath))

	// Check for .tar.gz
	if strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz") {
		return i.extractTarGz(archivePath, destPath)
	}

	switch ext {
	case ".zip":
		return i.extractZip(archivePath, destPath)
	case ".gz":
		return i.extractTarGz(archivePath, destPath)
	default:
		return fmt.Errorf("unsupported archive format: %s", ext)
	}
}

// extractTarGz extracts a .tar.gz archive.
func (i *Installer) extractTarGz(archivePath, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	targetName := i.binaryType.BinaryName()

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Look for our binary
		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == targetName {
			out, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("create dest file: %w", err)
			}
			defer out.Close()

			if _, err := io.Copy(out, tr); err != nil {
				return fmt.Errorf("extract file: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("binary %s not found in archive", targetName)
}

// extractZip extracts a .zip archive.
func (i *Installer) extractZip(archivePath, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	targetName := i.binaryType.BinaryName()

	for _, f := range r.File {
		if filepath.Base(f.Name) == targetName {
			src, err := f.Open()
			if err != nil {
				return fmt.Errorf("open file in zip: %w", err)
			}
			defer src.Close()

			out, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("create dest file: %w", err)
			}
			defer out.Close()

			if _, err := io.Copy(out, src); err != nil {
				return fmt.Errorf("extract file: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("binary %s not found in archive", targetName)
}
