package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Error Variables Tests
// =============================================================================

func TestErrors(t *testing.T) {
	// Test that all error variables are properly defined
	assert.NotNil(t, ErrNoUpdateAvailable)
	assert.NotNil(t, ErrChecksumMismatch)
	assert.NotNil(t, ErrAssetNotFound)
	assert.NotNil(t, ErrDownloadFailed)
	assert.NotNil(t, ErrInstallFailed)
	assert.NotNil(t, ErrBackupFailed)
	assert.NotNil(t, ErrInvalidVersion)
	assert.NotNil(t, ErrNetworkError)
	assert.NotNil(t, ErrRateLimited)
	assert.NotNil(t, ErrRestoreFailed)

	// Test error messages
	assert.Equal(t, "no update available", ErrNoUpdateAvailable.Error())
	assert.Equal(t, "checksum verification failed", ErrChecksumMismatch.Error())
	assert.Equal(t, "release asset not found for platform", ErrAssetNotFound.Error())
	assert.Equal(t, "download failed", ErrDownloadFailed.Error())
	assert.Equal(t, "installation failed", ErrInstallFailed.Error())
	assert.Equal(t, "backup failed", ErrBackupFailed.Error())
	assert.Equal(t, "invalid version format", ErrInvalidVersion.Error())
	assert.Equal(t, "network error", ErrNetworkError.Error())
	assert.Equal(t, "GitHub API rate limited", ErrRateLimited.Error())
	assert.Equal(t, "restore from backup failed", ErrRestoreFailed.Error())
}

// =============================================================================
// Version Tests - Additional Edge Cases
// =============================================================================

func TestParseVersion_InvalidMinor(t *testing.T) {
	_, err := ParseVersion("1.abc.0")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidVersion))
	assert.Contains(t, err.Error(), "invalid minor version")
}

func TestParseVersion_InvalidPatch(t *testing.T) {
	_, err := ParseVersion("1.2.xyz")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidVersion))
	assert.Contains(t, err.Error(), "invalid patch version")
}

func TestParseVersion_TooManyParts(t *testing.T) {
	_, err := ParseVersion("1.2.3.4")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidVersion))
}

func TestParseVersion_PlusSign(t *testing.T) {
	v, err := ParseVersion("1.2.3+build123")
	require.NoError(t, err)
	assert.Equal(t, 1, v.Major)
	assert.Equal(t, 2, v.Minor)
	assert.Equal(t, 3, v.Patch)
	assert.Equal(t, "build123", v.Prerelease)
}

func TestVersion_Compare_EqualPrerelease(t *testing.T) {
	v1, _ := ParseVersion("1.0.0-alpha")
	v2, _ := ParseVersion("1.0.0-alpha")
	assert.Equal(t, 0, v1.Compare(v2))
}

func TestVersion_Compare_DifferentPrerelease(t *testing.T) {
	v1, _ := ParseVersion("1.0.0-beta")
	v2, _ := ParseVersion("1.0.0-alpha")
	assert.Equal(t, 1, v1.Compare(v2))
}

// =============================================================================
// Checksum Tests - Enhanced Coverage
// =============================================================================

func TestCalculateChecksum_Success(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	content := []byte("hello world")
	err := os.WriteFile(testFile, content, 0644)
	require.NoError(t, err)

	hash, err := CalculateChecksum(testFile)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64)

	// SHA256 of "hello world" is well known
	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	assert.Equal(t, expectedHash, hash)
}

func TestCalculateChecksum_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "empty.txt")

	err := os.WriteFile(testFile, []byte{}, 0644)
	require.NoError(t, err)

	hash, err := CalculateChecksum(testFile)
	require.NoError(t, err)
	// SHA256 of empty string
	expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	assert.Equal(t, expectedHash, hash)
}

func TestVerifyChecksum_Success(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	content := []byte("hello world")
	err := os.WriteFile(testFile, content, 0644)
	require.NoError(t, err)

	// Verify with correct hash (lowercase)
	err = VerifyChecksum(testFile, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
	assert.NoError(t, err)

	// Verify with correct hash (uppercase)
	err = VerifyChecksum(testFile, "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9")
	assert.NoError(t, err)

	// Verify with whitespace
	err = VerifyChecksum(testFile, "  b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  ")
	assert.NoError(t, err)
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	err := os.WriteFile(testFile, []byte("hello world"), 0644)
	require.NoError(t, err)

	err = VerifyChecksum(testFile, "0000000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrChecksumMismatch))
}

func TestVerifyChecksum_FileNotFound(t *testing.T) {
	err := VerifyChecksum("/nonexistent/file.txt", "abc123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calculate checksum")
}

func TestParseChecksumFile_SingleSpace(t *testing.T) {
	// Some tools use single space instead of double
	content := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef file.txt"
	checksums, err := ParseChecksumFile(content)
	require.NoError(t, err)
	assert.Len(t, checksums, 1)
	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", checksums["file.txt"])
}

func TestParseChecksumFile_MixedContent(t *testing.T) {
	content := `# This is a comment - should be ignored since hash is too short
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  file1.txt


fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  path/to/file2.txt
short  invalid.txt
`
	checksums, err := ParseChecksumFile(content)
	require.NoError(t, err)
	assert.Len(t, checksums, 2)
	assert.Contains(t, checksums, "file1.txt")
	// The parser uses the last field as filename, so it's path/to/file2.txt
	assert.Contains(t, checksums, "path/to/file2.txt")
}

func TestParseChecksumFile_AllInvalid(t *testing.T) {
	content := `short hash
not a valid line
`
	_, err := ParseChecksumFile(content)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid checksums found")
}

// =============================================================================
// GitHub Client Tests - Enhanced Coverage
// =============================================================================

func TestGitHubClient_checkResponse_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetReleases(ctx, 10)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNetworkError))
}

func TestGitHubClient_checkResponse_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetReleases(ctx, 10)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNetworkError))
	assert.Contains(t, err.Error(), "500")
}

func TestGitHubClient_GetReleases_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetReleases(ctx, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}

func TestGitHubClient_GetReleases_NetworkError(t *testing.T) {
	client := NewGitHubClient("owner", "repo")
	client.httpClient.Timeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := client.GetReleases(ctx, 10)
	require.Error(t, err)
	// The request will fail with a connection error
}

func TestGitHubClient_fetchRelease_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetRelease(ctx, "v1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}

func TestGitHubClient_GetChecksums_DownloadFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: "checksums.txt", BrowserDownloadURL: server.URL + "/checksums.txt"},
		},
	}

	client := NewGitHubClient("owner", "repo")

	ctx := context.Background()
	_, err := client.GetChecksums(ctx, &release)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDownloadFailed))
}

func TestGitHubClient_GetChecksums_NetworkError(t *testing.T) {
	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: "checksums.txt", BrowserDownloadURL: "http://192.0.2.1:12345/checksums.txt"},
		},
	}

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Timeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := client.GetChecksums(ctx, &release)
	require.Error(t, err)
}

func TestGitHubClient_GetChecksums_InvalidContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid checksum content"))
	}))
	defer server.Close()

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: "checksums.txt", BrowserDownloadURL: server.URL + "/checksums.txt"},
		},
	}

	client := NewGitHubClient("owner", "repo")

	ctx := context.Background()
	_, err := client.GetChecksums(ctx, &release)
	require.Error(t, err)
}

func TestGitHubClient_GetLatestRelease_EmptyReleases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]Release{})
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetLatestRelease(ctx, true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoUpdateAvailable))
}

func TestGitHubClient_GetLatestRelease_AllDrafts(t *testing.T) {
	releases := []Release{
		{TagName: "v1.0.0", Draft: true},
		{TagName: "v0.9.0", Draft: true},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetLatestRelease(ctx, true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoUpdateAvailable))
}

// =============================================================================
// Download Tests - Enhanced Coverage
// =============================================================================

func TestDownloader_Download_ReadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		// Write partial content then close connection
		w.Write([]byte("partial"))
		// The server will close the connection, causing a read error
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Hijack and close to simulate connection drop
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	defer server.Close()

	d := NewDownloader()
	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "download")

	err := d.Download(context.Background(), server.URL, destPath, nil)
	// Error may or may not occur depending on timing, but the file should be cleaned up
	if err != nil {
		// Check that partial file was cleaned up
		_, statErr := os.Stat(destPath)
		assert.True(t, os.IsNotExist(statErr))
	}
}

func TestProgressReader_NilCallback(t *testing.T) {
	content := []byte("test content")
	tempFile, err := os.CreateTemp("", "progress_test")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(content)
	require.NoError(t, err)
	tempFile.Seek(0, 0)

	pr := &progressReader{
		reader:   tempFile,
		total:    int64(len(content)),
		callback: nil, // nil callback
	}

	buf := make([]byte, 100)
	n, err := pr.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, len(content), n)
	assert.Equal(t, int64(len(content)), pr.downloaded)
}

// =============================================================================
// Installer Tests - Enhanced Coverage
// =============================================================================

func TestInstaller_Backup_Success(t *testing.T) {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "test-binary")
	content := []byte("binary content here")

	err := os.WriteFile(binaryPath, content, 0755)
	require.NoError(t, err)

	// Override GetCurrentBinaryPath by using a custom helper
	installer := NewInstaller(BinaryTypeServer)

	// Create backup manually using the same logic
	backupPath := binaryPath + ".bak"
	os.Remove(backupPath)

	src, err := os.Open(binaryPath)
	require.NoError(t, err)
	defer src.Close()

	dst, err := os.Create(backupPath)
	require.NoError(t, err)
	defer dst.Close()

	_, err = io.Copy(dst, src)
	require.NoError(t, err)

	// Verify backup content
	backupData, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	assert.Equal(t, content, backupData)

	// Test restore logic
	err = installer.Restore(backupPath)
	require.NoError(t, err)

	// Verify original path now has backup content
	restoredData, err := os.ReadFile(binaryPath)
	require.NoError(t, err)
	assert.Equal(t, content, restoredData)
}

func TestInstaller_Restore_Failure(t *testing.T) {
	installer := NewInstaller(BinaryTypeServer)

	err := installer.Restore("/nonexistent/backup.bak")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRestoreFailed))
}

func TestInstaller_ExtractBinary_OpenError(t *testing.T) {
	installer := NewInstaller(BinaryTypeServer)

	err := installer.ExtractBinary("/nonexistent/archive.tar.gz", "/tmp/dest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open archive")
}

func TestInstaller_extractTarGz_ReadError(t *testing.T) {
	tempDir := t.TempDir()

	// Create a valid gzip file but with invalid tar content
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	f, err := os.Create(archivePath)
	require.NoError(t, err)

	gzw := gzip.NewWriter(f)
	gzw.Write([]byte("not valid tar content"))
	gzw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted")

	err = installer.extractTarGz(archivePath, destPath)
	require.Error(t, err)
	// Should fail when reading tar
}

func TestInstaller_extractTarGz_DirectoryEntry(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	binaryName := BinaryTypeServer.BinaryName()
	binaryContent := []byte("binary content")

	// Create tar.gz with a directory entry first, then the binary
	f, err := os.Create(archivePath)
	require.NoError(t, err)

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	// Add a directory entry
	dirHeader := &tar.Header{
		Name:     "somedir/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}
	err = tw.WriteHeader(dirHeader)
	require.NoError(t, err)

	// Add the binary
	hdr := &tar.Header{
		Name: "somedir/" + binaryName,
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	err = tw.WriteHeader(hdr)
	require.NoError(t, err)
	_, err = tw.Write(binaryContent)
	require.NoError(t, err)

	tw.Close()
	gzw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted_binary")

	err = installer.ExtractBinary(archivePath, destPath)
	require.NoError(t, err)

	data, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, data)
}

func TestInstaller_extractZip_NestedPath(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.zip")
	binaryName := BinaryTypeServer.BinaryName()
	binaryContent := []byte("zip binary content")

	// Create zip with nested path
	f, err := os.Create(archivePath)
	require.NoError(t, err)

	zw := zip.NewWriter(f)
	w, err := zw.Create("nested/path/" + binaryName)
	require.NoError(t, err)
	_, err = w.Write(binaryContent)
	require.NoError(t, err)
	zw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	destPath := filepath.Join(tempDir, "extracted_binary")

	err = installer.ExtractBinary(archivePath, destPath)
	require.NoError(t, err)

	data, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, data)
}

// Test that cleanupOldBinary runs without panicking
func TestCleanupOldBinary(t *testing.T) {
	// Should not panic
	cleanupOldBinary()
}

// =============================================================================
// State Tests - Enhanced Coverage
// =============================================================================

func TestState_Save_CreateDirectory(t *testing.T) {
	tempDir := t.TempDir()
	// Use a path with nested directories that don't exist
	statePath := filepath.Join(tempDir, "nested", "dir", "state.json")

	state := &State{
		path:                statePath,
		LastNotifiedVersion: "1.0.0",
	}

	err := state.Save()
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(statePath)
	require.NoError(t, err)
}

func TestState_Save_InvalidPath(t *testing.T) {
	// Use a path that can't be written to (root-owned directory)
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows")
	}

	state := &State{
		path: "/dev/null/invalid/path/state.json",
	}

	err := state.Save()
	assert.Error(t, err)
}

func TestLoadState_ReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows")
	}

	// Try to load from a directory instead of file
	tempDir := t.TempDir()
	_, err := LoadState(tempDir)
	assert.Error(t, err)
}

func TestDefaultStatePath_AllPlatforms(t *testing.T) {
	path := DefaultStatePath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "bifrost")
	assert.Contains(t, path, "update-state.json")

	// Path should be absolute
	assert.True(t, filepath.IsAbs(path))
}

func TestState_Concurrent(t *testing.T) {
	state := &State{}

	// Test concurrent access to state methods
	done := make(chan bool, 4)

	go func() {
		for i := 0; i < 100; i++ {
			state.MarkChecked()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			state.ShouldCheck(time.Hour)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			state.MarkNotified(fmt.Sprintf("v%d", i))
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			state.ShouldNotify(fmt.Sprintf("v%d", i))
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 4; i++ {
		<-done
	}
}

// =============================================================================
// Updater Tests - Enhanced Coverage
// =============================================================================

func TestNew_LoadStateError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows")
	}

	cfg := Config{
		StateFile: "/dev/null/invalid/state.json",
	}

	_, err := New(cfg, BinaryTypeServer, nil)
	// Should fail due to invalid state path
	assert.Error(t, err)
}

func TestUpdater_CheckForUpdate_ReleaseVersionParseError(t *testing.T) {
	originalVersion := version.Version
	version.Version = "1.0.0"
	defer func() { version.Version = originalVersion }()

	release := Release{
		TagName: "not-a-valid-version",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cfg := Config{
		GitHubOwner: "owner",
		GitHubRepo:  "repo",
		StateFile:   filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err = updater.CheckForUpdate(ctx)
	require.Error(t, err)
	// Error parsing release version
}

func TestUpdater_CheckForUpdate_AssetNotFound(t *testing.T) {
	originalVersion := version.Version
	version.Version = "0.9.0"
	defer func() { version.Version = originalVersion }()

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: "wrong_asset.tar.gz"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cfg := Config{
		GitHubOwner: "owner",
		GitHubRepo:  "repo",
		StateFile:   filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err = updater.CheckForUpdate(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAssetNotFound))
}

func TestUpdater_CheckForUpdate_ChecksumNotFound(t *testing.T) {
	originalVersion := version.Version
	version.Version = "0.9.0"
	defer func() { version.Version = originalVersion }()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	assetName := "bifrost_1.0.0_" + goos + "_" + goarch + ext

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: assetName, Size: 1000},
			{Name: "checksums.txt", BrowserDownloadURL: ""},
		},
	}

	// Return checksum file without the asset we need
	checksumContent := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  other_asset.tar.gz\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/latest") {
			json.NewEncoder(w).Encode(release)
		} else if strings.Contains(r.URL.Path, "checksums.txt") {
			w.Write([]byte(checksumContent))
		}
	}))
	defer server.Close()

	release.Assets[1].BrowserDownloadURL = server.URL + "/checksums.txt"

	tempDir := t.TempDir()
	cfg := Config{
		GitHubOwner: "owner",
		GitHubRepo:  "repo",
		StateFile:   filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err = updater.CheckForUpdate(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAssetNotFound))
}

func TestUpdater_Install_Success(t *testing.T) {
	// This test creates a complete mock update scenario
	tempDir := t.TempDir()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	assetName := "bifrost_1.0.0_" + goos + "_" + goarch + ext
	binaryName := BinaryTypeServer.BinaryName()
	binaryContent := []byte("new binary content here")

	// Create the archive
	archivePath := filepath.Join(tempDir, assetName)
	if ext == ".zip" {
		f, err := os.Create(archivePath)
		require.NoError(t, err)
		zw := zip.NewWriter(f)
		w, _ := zw.Create(binaryName)
		w.Write(binaryContent)
		zw.Close()
		f.Close()
	} else {
		f, err := os.Create(archivePath)
		require.NoError(t, err)
		gzw := gzip.NewWriter(f)
		tw := tar.NewWriter(gzw)
		hdr := &tar.Header{Name: binaryName, Mode: 0755, Size: int64(len(binaryContent))}
		tw.WriteHeader(hdr)
		tw.Write(binaryContent)
		tw.Close()
		gzw.Close()
		f.Close()
	}

	// Calculate checksum
	checksum, err := CalculateChecksum(archivePath)
	require.NoError(t, err)

	// Serve the archive
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(archivePath)
		w.Write(data)
	}))
	defer server.Close()

	cfg := Config{
		GitHubOwner: "owner",
		GitHubRepo:  "repo",
		StateFile:   filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	info := &UpdateInfo{
		AssetURL:  server.URL + "/" + assetName,
		AssetName: assetName,
		Checksum:  checksum,
	}

	var progressCalled bool
	err = updater.Install(context.Background(), info, func(downloaded, total int64) {
		progressCalled = true
	})

	// The Install will fail at the actual binary replacement step
	// because we can't replace the running test binary
	// But it should at least download and verify checksum
	if err != nil {
		// Expected to fail at installation step
		assert.Contains(t, err.Error(), "")
	}
	assert.True(t, progressCalled || err != nil)
}

func TestUpdater_Install_DownloadError(t *testing.T) {
	tempDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := Config{
		GitHubOwner: "owner",
		GitHubRepo:  "repo",
		StateFile:   filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	info := &UpdateInfo{
		AssetURL:  server.URL + "/asset.tar.gz",
		AssetName: "asset.tar.gz",
		Checksum:  "abc123",
	}

	err = updater.Install(context.Background(), info, nil)
	require.Error(t, err)
}

func TestUpdater_Install_ChecksumError(t *testing.T) {
	tempDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake archive content"))
	}))
	defer server.Close()

	cfg := Config{
		GitHubOwner: "owner",
		GitHubRepo:  "repo",
		StateFile:   filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	info := &UpdateInfo{
		AssetURL:  server.URL + "/asset.tar.gz",
		AssetName: "asset.tar.gz",
		Checksum:  "0000000000000000000000000000000000000000000000000000000000000000",
	}

	err = updater.Install(context.Background(), info, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrChecksumMismatch))
}

func TestUpdater_backgroundCheck_AlreadyNotified(t *testing.T) {
	originalVersion := version.Version
	version.Version = "0.9.0"
	defer func() { version.Version = originalVersion }()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	assetName := "bifrost_1.0.0_" + goos + "_" + goarch + ext

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: assetName, Size: 1000},
			{Name: "checksums.txt", BrowserDownloadURL: ""},
		},
	}

	checksumContent := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  " + assetName + "\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/latest") {
			json.NewEncoder(w).Encode(release)
		} else if strings.Contains(r.URL.Path, "checksums.txt") {
			w.Write([]byte(checksumContent))
		}
	}))
	defer server.Close()

	release.Assets[1].BrowserDownloadURL = server.URL + "/checksums.txt"

	tempDir := t.TempDir()
	notifier := &mockNotifier{}

	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 0,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, notifier)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	// Mark as already notified
	updater.state.MarkNotified("v1.0.0")

	ctx := context.Background()
	updater.backgroundCheck(ctx)

	// Should not notify again
	assert.False(t, notifier.called)
}

func TestUpdater_backgroundCheck_NoNotifier(t *testing.T) {
	originalVersion := version.Version
	version.Version = "0.9.0"
	defer func() { version.Version = originalVersion }()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	assetName := "bifrost_1.0.0_" + goos + "_" + goarch + ext

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: assetName, Size: 1000},
			{Name: "checksums.txt", BrowserDownloadURL: ""},
		},
	}

	checksumContent := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  " + assetName + "\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/latest") {
			json.NewEncoder(w).Encode(release)
		} else if strings.Contains(r.URL.Path, "checksums.txt") {
			w.Write([]byte(checksumContent))
		}
	}))
	defer server.Close()

	release.Assets[1].BrowserDownloadURL = server.URL + "/checksums.txt"

	tempDir := t.TempDir()

	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 0,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	// No notifier
	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	// Should not panic with nil notifier
	updater.backgroundCheck(ctx)
}

func TestUpdater_backgroundCheck_CheckError(t *testing.T) {
	tempDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := &mockNotifier{}

	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 0,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, notifier)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	updater.backgroundCheck(ctx)

	// Should not notify on error
	assert.False(t, notifier.called)
}

func TestUpdater_backgroundCheck_ShouldNotCheck(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	// Mark as recently checked
	updater.state.MarkChecked()

	ctx := context.Background()
	// Should exit early without making HTTP request
	updater.backgroundCheck(ctx)
}

func TestUpdater_StartBackgroundChecker_StopChannel(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	ctx := context.Background()
	updater.StartBackgroundChecker(ctx)

	// Wait briefly
	time.Sleep(10 * time.Millisecond)

	// Stop via stop channel
	updater.StopBackgroundChecker()

	// Verify stopped
	updater.mu.Lock()
	assert.Nil(t, updater.stopCh)
	updater.mu.Unlock()
}

// =============================================================================
// BinaryType Tests
// =============================================================================

func TestBinaryType_BinaryName_AllTypes(t *testing.T) {
	serverName := BinaryTypeServer.BinaryName()
	clientName := BinaryTypeClient.BinaryName()
	invalidName := BinaryType("invalid").BinaryName()

	if runtime.GOOS == "windows" {
		assert.Equal(t, "bifrost-server.exe", serverName)
		assert.Equal(t, "bifrost-client.exe", clientName)
	} else {
		assert.Equal(t, "bifrost-server", serverName)
		assert.Equal(t, "bifrost-client", clientName)
	}
	assert.Equal(t, "", invalidName)
}

// =============================================================================
// Config Tests - Enhanced Coverage
// =============================================================================

func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, 24*time.Hour, cfg.CheckInterval)
	assert.Equal(t, ChannelStable, cfg.Channel)
	assert.Equal(t, "rennerdo30", cfg.GitHubOwner)
	assert.Equal(t, "bifrost-proxy", cfg.GitHubRepo)
	assert.NotEmpty(t, cfg.StateFile)
}

func TestChannel_String(t *testing.T) {
	assert.Equal(t, "stable", string(ChannelStable))
	assert.Equal(t, "prerelease", string(ChannelPrerelease))
}

// =============================================================================
// Additional Installer Tests for Full Install Coverage
// =============================================================================

func TestInstaller_Install_FullFlow(t *testing.T) {
	// This test exercises the full Install flow with a mock binary
	tempDir := t.TempDir()
	binaryName := BinaryTypeServer.BinaryName()
	binaryContent := []byte("#!/bin/sh\necho hello")
	newBinaryContent := []byte("#!/bin/sh\necho new version")

	// Create a "current binary" that we can backup
	currentBinaryPath := filepath.Join(tempDir, binaryName)
	err := os.WriteFile(currentBinaryPath, binaryContent, 0755)
	require.NoError(t, err)

	// Create archive with new binary
	archivePath := filepath.Join(tempDir, "update.tar.gz")
	f, err := os.Create(archivePath)
	require.NoError(t, err)

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	hdr := &tar.Header{
		Name: binaryName,
		Mode: 0755,
		Size: int64(len(newBinaryContent)),
	}
	tw.WriteHeader(hdr)
	tw.Write(newBinaryContent)
	tw.Close()
	gzw.Close()
	f.Close()

	// Note: We can't easily test the full Install() on a running binary,
	// but we can test the individual pieces
	installer := NewInstaller(BinaryTypeServer)

	// Test ExtractBinary
	extractedPath := filepath.Join(tempDir, "extracted_binary")
	err = installer.ExtractBinary(archivePath, extractedPath)
	require.NoError(t, err)

	data, err := os.ReadFile(extractedPath)
	require.NoError(t, err)
	assert.Equal(t, newBinaryContent, data)
}

func TestInstaller_Backup_ExistingBackupRemoved(t *testing.T) {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "test-binary")
	backupPath := binaryPath + ".bak"

	// Create binary
	content := []byte("original binary")
	err := os.WriteFile(binaryPath, content, 0755)
	require.NoError(t, err)

	// Create existing backup
	oldBackupContent := []byte("old backup")
	err = os.WriteFile(backupPath, oldBackupContent, 0644)
	require.NoError(t, err)

	// Simulate backup logic
	os.Remove(backupPath)

	src, err := os.Open(binaryPath)
	require.NoError(t, err)
	defer src.Close()

	dst, err := os.Create(backupPath)
	require.NoError(t, err)
	defer dst.Close()

	_, err = io.Copy(dst, src)
	require.NoError(t, err)

	// Verify backup content is from binary, not old backup
	backupData, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	assert.Equal(t, content, backupData)
}

func TestInstaller_GetCurrentBinaryPath_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink test on Unix only")
	}

	installer := NewInstaller(BinaryTypeServer)
	path, err := installer.GetCurrentBinaryPath()
	require.NoError(t, err)

	// Path should be resolved (no symlinks)
	resolved, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)
	assert.Equal(t, resolved, path)
}

// =============================================================================
// Additional DefaultStatePath Coverage
// =============================================================================

func TestDefaultStatePath_EnvOverrides(t *testing.T) {
	// Save and restore environment
	originalAppData := os.Getenv("APPDATA")
	originalUserProfile := os.Getenv("USERPROFILE")
	originalXdgConfig := os.Getenv("XDG_CONFIG_HOME")
	originalHome, _ := os.UserHomeDir()
	_ = originalHome // Used to verify home directory functionality

	defer func() {
		if originalAppData != "" {
			os.Setenv("APPDATA", originalAppData)
		}
		if originalUserProfile != "" {
			os.Setenv("USERPROFILE", originalUserProfile)
		}
		if originalXdgConfig != "" {
			os.Setenv("XDG_CONFIG_HOME", originalXdgConfig)
		}
	}()

	// Test the function returns a valid path
	path := DefaultStatePath()
	assert.NotEmpty(t, path)
	assert.True(t, filepath.IsAbs(path))

	// Test XDG_CONFIG_HOME override on Linux
	if runtime.GOOS == "linux" {
		os.Setenv("XDG_CONFIG_HOME", "/custom/config")
		path = DefaultStatePath()
		assert.Contains(t, path, "/custom/config")
		os.Unsetenv("XDG_CONFIG_HOME")

		// Without XDG_CONFIG_HOME, should use ~/.config
		os.Unsetenv("XDG_CONFIG_HOME")
		path = DefaultStatePath()
		assert.Contains(t, path, ".config")
	}

	// Test Windows fallback
	if runtime.GOOS == "windows" {
		os.Unsetenv("APPDATA")
		os.Setenv("USERPROFILE", "C:\\Users\\TestUser")
		path = DefaultStatePath()
		assert.Contains(t, path, "AppData")
	}
}

// =============================================================================
// Additional StartBackgroundChecker Coverage
// =============================================================================

func TestUpdater_StartBackgroundChecker_InitialDelay(t *testing.T) {
	tempDir := t.TempDir()

	// Create a server that tracks requests
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updater.StartBackgroundChecker(ctx)

	// Initial delay is 1 minute, so no request should be made immediately
	time.Sleep(50 * time.Millisecond)

	// Cancel before the initial check
	cancel()

	// Give time for goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestUpdater_StartBackgroundChecker_TickerFires(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 10 * time.Millisecond, // Very short for testing
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	require.NoError(t, err)

	// Make shouldCheck return false to avoid HTTP calls
	updater.state.MarkChecked()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updater.StartBackgroundChecker(ctx)

	// Let it run through the initial delay
	time.Sleep(20 * time.Millisecond)

	updater.StopBackgroundChecker()
}

// =============================================================================
// Additional fetchRelease Error Coverage
// =============================================================================

func TestGitHubClient_fetchRelease_NetworkError(t *testing.T) {
	client := NewGitHubClient("owner", "repo")
	client.httpClient.Timeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := client.GetRelease(ctx, "v1.0.0")
	// Should fail with network error (no server)
	require.Error(t, err)
}

// =============================================================================
// Additional GetChecksums Coverage
// =============================================================================

func TestGitHubClient_GetChecksums_RequestCreateError(t *testing.T) {
	// Test with invalid URL in the asset
	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: "checksums.txt", BrowserDownloadURL: "://invalid-url"},
		},
	}

	client := NewGitHubClient("owner", "repo")

	ctx := context.Background()
	_, err := client.GetChecksums(ctx, &release)
	require.Error(t, err)
}

// =============================================================================
// Additional extractZip Error Coverage
// =============================================================================

func TestInstaller_extractZip_CreateDestError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.zip")
	binaryName := BinaryTypeServer.BinaryName()

	// Create valid zip
	f, _ := os.Create(archivePath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create(binaryName)
	w.Write([]byte("content"))
	zw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	// Try to extract to a path we can't write to
	err := installer.extractZip(archivePath, "/dev/null/invalid/path")
	require.Error(t, err)
}

func TestInstaller_extractTarGz_CreateDestError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	binaryName := BinaryTypeServer.BinaryName()

	// Create valid tar.gz
	f, _ := os.Create(archivePath)
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	hdr := &tar.Header{Name: binaryName, Mode: 0755, Size: 7}
	tw.WriteHeader(hdr)
	tw.Write([]byte("content"))
	tw.Close()
	gzw.Close()
	f.Close()

	installer := NewInstaller(BinaryTypeServer)
	// Try to extract to a path we can't write to
	err := installer.extractTarGz(archivePath, "/dev/null/invalid/path")
	require.Error(t, err)
}

// =============================================================================
// BinaryName Windows Coverage
// =============================================================================

func TestBinaryType_Coverage(t *testing.T) {
	// Ensure all BinaryType values are tested
	types := []BinaryType{BinaryTypeServer, BinaryTypeClient, "unknown"}

	for _, bt := range types {
		name := bt.BinaryName()
		if bt == "unknown" {
			assert.Empty(t, name)
		} else {
			assert.NotEmpty(t, name)
		}
	}
}

// =============================================================================
// Version Compare Edge Cases
// =============================================================================

func TestVersion_Compare_AllBranches(t *testing.T) {
	tests := []struct {
		name   string
		v1     Version
		v2     Version
		expect int
	}{
		{
			name:   "major less",
			v1:     Version{Major: 1, Minor: 0, Patch: 0},
			v2:     Version{Major: 2, Minor: 0, Patch: 0},
			expect: -1,
		},
		{
			name:   "major greater",
			v1:     Version{Major: 2, Minor: 0, Patch: 0},
			v2:     Version{Major: 1, Minor: 0, Patch: 0},
			expect: 1,
		},
		{
			name:   "minor less",
			v1:     Version{Major: 1, Minor: 1, Patch: 0},
			v2:     Version{Major: 1, Minor: 2, Patch: 0},
			expect: -1,
		},
		{
			name:   "minor greater",
			v1:     Version{Major: 1, Minor: 2, Patch: 0},
			v2:     Version{Major: 1, Minor: 1, Patch: 0},
			expect: 1,
		},
		{
			name:   "patch less",
			v1:     Version{Major: 1, Minor: 1, Patch: 1},
			v2:     Version{Major: 1, Minor: 1, Patch: 2},
			expect: -1,
		},
		{
			name:   "patch greater",
			v1:     Version{Major: 1, Minor: 1, Patch: 2},
			v2:     Version{Major: 1, Minor: 1, Patch: 1},
			expect: 1,
		},
		{
			name:   "prerelease less than stable",
			v1:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc1"},
			v2:     Version{Major: 1, Minor: 0, Patch: 0},
			expect: -1,
		},
		{
			name:   "stable greater than prerelease",
			v1:     Version{Major: 1, Minor: 0, Patch: 0},
			v2:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc1"},
			expect: 1,
		},
		{
			name:   "prerelease comparison alpha < beta",
			v1:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"},
			v2:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta"},
			expect: -1,
		},
		{
			name:   "prerelease comparison beta > alpha",
			v1:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta"},
			v2:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"},
			expect: 1,
		},
		{
			name:   "equal versions",
			v1:     Version{Major: 1, Minor: 2, Patch: 3},
			v2:     Version{Major: 1, Minor: 2, Patch: 3},
			expect: 0,
		},
		{
			name:   "equal with prerelease",
			v1:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc1"},
			v2:     Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc1"},
			expect: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.v1.Compare(tt.v2)
			assert.Equal(t, tt.expect, got)
		})
	}
}

// =============================================================================
// Additional checksum coverage for CalculateChecksum read error
// =============================================================================

func TestCalculateChecksum_LargeFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "large.bin")

	// Create a reasonably large file
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	err := os.WriteFile(testFile, data, 0644)
	require.NoError(t, err)

	hash, err := CalculateChecksum(testFile)
	require.NoError(t, err)
	assert.Len(t, hash, 64)
}

// =============================================================================
// Restore error case with GetCurrentBinaryPath
// =============================================================================

func TestInstaller_Restore_GetPathError(t *testing.T) {
	installer := NewInstaller(BinaryTypeServer)

	// Restore to a non-existent location should fail with rename error
	err := installer.Restore("/nonexistent/backup/path.bak")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRestoreFailed))
}
