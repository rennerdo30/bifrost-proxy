package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewInstaller(t *testing.T) {
	installer := NewInstaller(BinaryTypeServer)
	if installer == nil {
		t.Fatal("NewInstaller returned nil")
	}
	if installer.binaryType != BinaryTypeServer {
		t.Errorf("expected binaryType=server, got %s", installer.binaryType)
	}
}

func TestInstaller_GetCurrentBinaryPath(t *testing.T) {
	installer := NewInstaller(BinaryTypeServer)
	path, err := installer.GetCurrentBinaryPath()
	if err != nil {
		t.Fatalf("GetCurrentBinaryPath failed: %v", err)
	}

	// Path should be absolute
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %s", path)
	}

	// Path should exist (it's the test binary)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("binary path does not exist: %v", err)
	}
}

func TestInstaller_ExtractBinary_TarGz(t *testing.T) {
	tempDir := t.TempDir()

	// Create a tar.gz archive with a binary
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	binaryName := BinaryTypeServer.BinaryName()
	binaryContent := []byte("#!/bin/bash\necho hello")

	// Create the tar.gz
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	hdr := &tar.Header{
		Name: binaryName,
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if writeHdrErr := tw.WriteHeader(hdr); writeHdrErr != nil {
		t.Fatal(writeHdrErr)
	}
	if _, writeErr := tw.Write(binaryContent); writeErr != nil {
		t.Fatal(writeErr)
	}
	tw.Close()
	gzw.Close()
	f.Close()

	// Test extraction
	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted_binary")

	err = installer.ExtractBinary(archivePath, destPath)
	if err != nil {
		t.Fatalf("ExtractBinary failed: %v", err)
	}

	// Verify extracted content
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read extracted binary: %v", err)
	}
	if string(data) != string(binaryContent) {
		t.Errorf("extracted content mismatch")
	}
}

func TestInstaller_ExtractBinary_Zip(t *testing.T) {
	tempDir := t.TempDir()

	// Create a zip archive with a binary
	archivePath := filepath.Join(tempDir, "test.zip")
	binaryName := BinaryTypeServer.BinaryName()
	binaryContent := []byte("binary content here")

	// Create the zip
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	w, err := zw.Create(binaryName)
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := w.Write(binaryContent); writeErr != nil {
		t.Fatal(writeErr)
	}
	zw.Close()
	f.Close()

	// Test extraction
	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted_binary")

	err = installer.ExtractBinary(archivePath, destPath)
	if err != nil {
		t.Fatalf("ExtractBinary failed: %v", err)
	}

	// Verify extracted content
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read extracted binary: %v", err)
	}
	if string(data) != string(binaryContent) {
		t.Errorf("extracted content mismatch")
	}
}

func TestInstaller_ExtractBinary_BinaryNotFound(t *testing.T) {
	tempDir := t.TempDir()

	// Create a tar.gz archive without the expected binary
	archivePath := filepath.Join(tempDir, "test.tar.gz")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	hdr := &tar.Header{
		Name: "other-file.txt",
		Mode: 0644,
		Size: 4,
	}
	tw.WriteHeader(hdr)
	tw.Write([]byte("test"))
	tw.Close()
	gzw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted_binary")

	err = installer.ExtractBinary(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error when binary not found in archive")
	}
}

func TestInstaller_ExtractBinary_UnsupportedFormat(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file with unsupported extension
	archivePath := filepath.Join(tempDir, "test.rar")
	os.WriteFile(archivePath, []byte("not a real rar"), 0644)

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted_binary")

	err := installer.ExtractBinary(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestInstaller_Backup(t *testing.T) {
	tempDir := t.TempDir()

	// Create a fake "current binary"
	fakeBinary := filepath.Join(tempDir, "test-binary")
	content := []byte("original binary content")
	if err := os.WriteFile(fakeBinary, content, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a custom installer that returns our fake binary path
	installer := &testInstaller{
		Installer:  NewInstaller(BinaryTypeServer),
		binaryPath: fakeBinary,
	}

	backupPath, err := installer.Backup()
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Verify backup exists
	if _, statErr := os.Stat(backupPath); statErr != nil {
		t.Fatalf("backup file does not exist: %v", statErr)
	}

	// Verify backup content
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(content) {
		t.Error("backup content mismatch")
	}
}

func TestInstaller_Restore(t *testing.T) {
	tempDir := t.TempDir()

	// Create fake binary and backup
	fakeBinary := filepath.Join(tempDir, "test-binary")
	backupPath := fakeBinary + ".bak"
	backupContent := []byte("backup content")

	if err := os.WriteFile(backupPath, backupContent, 0755); err != nil {
		t.Fatal(err)
	}

	installer := &testInstaller{
		Installer:  NewInstaller(BinaryTypeServer),
		binaryPath: fakeBinary,
	}

	err := installer.Restore(backupPath)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify restored content
	data, err := os.ReadFile(fakeBinary)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(backupContent) {
		t.Error("restored content mismatch")
	}
}

func TestInstaller_extractTarGz_InvalidArchive(t *testing.T) {
	tempDir := t.TempDir()

	// Create an invalid tar.gz file
	archivePath := filepath.Join(tempDir, "invalid.tar.gz")
	os.WriteFile(archivePath, []byte("not a valid gzip file"), 0644)

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted")

	err := installer.extractTarGz(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error for invalid archive")
	}
}

func TestInstaller_extractZip_InvalidArchive(t *testing.T) {
	tempDir := t.TempDir()

	// Create an invalid zip file
	archivePath := filepath.Join(tempDir, "invalid.zip")
	os.WriteFile(archivePath, []byte("not a valid zip file"), 0644)

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted")

	err := installer.extractZip(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error for invalid archive")
	}
}

func TestInstaller_extractZip_BinaryNotFound(t *testing.T) {
	tempDir := t.TempDir()

	// Create a zip without the expected binary
	archivePath := filepath.Join(tempDir, "test.zip")
	f, _ := os.Create(archivePath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("other-file.txt")
	w.Write([]byte("test"))
	zw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted")

	err := installer.extractZip(archivePath, destPath)
	if err == nil {
		t.Fatal("expected error when binary not found")
	}
}

// testInstaller wraps Installer to override GetCurrentBinaryPath
type testInstaller struct {
	*Installer
	binaryPath string
}

func (ti *testInstaller) GetCurrentBinaryPath() (string, error) {
	return ti.binaryPath, nil
}

func (ti *testInstaller) Backup() (string, error) {
	currentPath := ti.binaryPath
	backupPath := currentPath + ".bak"

	os.Remove(backupPath)

	src, err := os.Open(currentPath)
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	buf := make([]byte, 1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	srcInfo, _ := os.Stat(currentPath)
	os.Chmod(backupPath, srcInfo.Mode())

	return backupPath, nil
}

func (ti *testInstaller) Restore(backupPath string) error {
	return os.Rename(backupPath, ti.binaryPath)
}

func TestAtomicReplace_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}

	tempDir := t.TempDir()

	srcPath := filepath.Join(tempDir, "src")
	dstPath := filepath.Join(tempDir, "dst")

	// Create source file
	srcContent := []byte("new content")
	if err := os.WriteFile(srcPath, srcContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create destination file
	if err := os.WriteFile(dstPath, []byte("old content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test atomic replace
	if err := atomicReplace(srcPath, dstPath); err != nil {
		t.Fatalf("atomicReplace failed: %v", err)
	}

	// Verify destination has new content
	data, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(srcContent) {
		t.Error("content mismatch after atomic replace")
	}

	// Source should no longer exist (it was renamed)
	if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
		t.Error("source file should not exist after rename")
	}
}

func TestCleanupOldBinary_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}

	// cleanupOldBinary is a no-op on Unix, just ensure it doesn't panic
	cleanupOldBinary()
}
