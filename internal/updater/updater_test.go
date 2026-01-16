package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/version"
)

type mockNotifier struct {
	called bool
	info   UpdateInfo
}

func (m *mockNotifier) NotifyUpdateAvailable(info UpdateInfo) {
	m.called = true
	m.info = info
}

func TestNew(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.json")

	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 24 * time.Hour,
		StateFile:     statePath,
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if updater == nil {
		t.Fatal("New returned nil")
	}
	if updater.github == nil {
		t.Error("github client is nil")
	}
	if updater.state == nil {
		t.Error("state is nil")
	}
}

func TestNew_WithDefaultStatePath(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 24 * time.Hour,
		// StateFile is empty, should use default
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if updater == nil {
		t.Fatal("New returned nil")
	}
}

func TestUpdater_CheckForUpdate(t *testing.T) {
	// Save original version and restore after test
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
		TagName:     "v1.0.0",
		Name:        "Release v1.0.0",
		Body:        "Release notes",
		PublishedAt: time.Now(),
		HTMLURL:     "https://github.com/owner/repo/releases/tag/v1.0.0",
		Assets: []Asset{
			{Name: assetName, Size: 1000, BrowserDownloadURL: "https://example.com/" + assetName},
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

	// Update checksums.txt URL
	release.Assets[1].BrowserDownloadURL = server.URL + "/checksums.txt"

	tempDir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 24 * time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
		Channel:       ChannelStable,
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Override transport
	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	info, err := updater.CheckForUpdate(ctx)
	if err != nil {
		t.Fatalf("CheckForUpdate failed: %v", err)
	}

	if info.NewVersion != "v1.0.0" {
		t.Errorf("expected NewVersion=v1.0.0, got %s", info.NewVersion)
	}
	if info.CurrentVersion != "0.9.0" {
		t.Errorf("expected CurrentVersion=0.9.0, got %s", info.CurrentVersion)
	}
}

func TestUpdater_CheckForUpdate_NoUpdate(t *testing.T) {
	// Save original version and restore after test
	originalVersion := version.Version
	version.Version = "1.0.0"
	defer func() { version.Version = originalVersion }()

	release := Release{
		TagName: "v1.0.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 24 * time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
		Channel:       ChannelStable,
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatal(err)
	}

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err = updater.CheckForUpdate(ctx)
	if err != ErrNoUpdateAvailable {
		t.Errorf("expected ErrNoUpdateAvailable, got %v", err)
	}
}

func TestUpdater_CheckForUpdate_DevVersion(t *testing.T) {
	// Save original version and restore after test
	originalVersion := version.Version
	version.Version = "dev" // Unparseable version
	defer func() { version.Version = originalVersion }()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	assetName := "bifrost_1.0.0_" + goos + "_" + goarch + ext

	release := Release{
		TagName:     "v1.0.0",
		PublishedAt: time.Now(),
		Assets: []Asset{
			{Name: assetName, Size: 1000, BrowserDownloadURL: "https://example.com/" + assetName},
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
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 24 * time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatal(err)
	}

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	info, err := updater.CheckForUpdate(ctx)
	if err != nil {
		t.Fatalf("CheckForUpdate failed: %v", err)
	}

	// Dev version should be treated as 0.0.0, so any release is newer
	if info.NewVersion != "v1.0.0" {
		t.Errorf("expected NewVersion=v1.0.0, got %s", info.NewVersion)
	}
}

func TestUpdater_StartBackgroundChecker(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 100 * time.Millisecond,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the checker
	updater.StartBackgroundChecker(ctx)

	// Starting again should be a no-op
	updater.StartBackgroundChecker(ctx)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Stop the checker
	updater.StopBackgroundChecker()

	// Stopping again should be safe
	updater.StopBackgroundChecker()
}

func TestUpdater_StartBackgroundChecker_ContextCancel(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 1 * time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	updater.StartBackgroundChecker(ctx)

	// Cancel context immediately
	cancel()

	// Wait for goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestUpdater_SkipVersion(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 24 * time.Hour,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = updater.SkipVersion("v1.0.0")
	if err != nil {
		t.Fatalf("SkipVersion failed: %v", err)
	}

	if !updater.state.IsSkipped("v1.0.0") {
		t.Error("version should be marked as skipped")
	}
}

func TestUpdater_backgroundCheck_NotifiesOnUpdate(t *testing.T) {
	// Save original version and restore after test
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
		TagName:     "v1.0.0",
		PublishedAt: time.Now(),
		Assets: []Asset{
			{Name: assetName, Size: 1000, BrowserDownloadURL: "https://example.com/" + assetName},
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
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 0, // No delay
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, notifier)
	if err != nil {
		t.Fatal(err)
	}

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	// Directly call backgroundCheck
	ctx := context.Background()
	updater.backgroundCheck(ctx)

	if !notifier.called {
		t.Error("notifier should have been called")
	}
	if notifier.info.NewVersion != "v1.0.0" {
		t.Errorf("expected NewVersion=v1.0.0, got %s", notifier.info.NewVersion)
	}
}

func TestUpdater_backgroundCheck_SkippedVersion(t *testing.T) {
	// Save original version and restore after test
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
		TagName:     "v1.0.0",
		PublishedAt: time.Now(),
		Assets: []Asset{
			{Name: assetName, Size: 1000, BrowserDownloadURL: "https://example.com/" + assetName},
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
		Enabled:       true,
		GitHubOwner:   "owner",
		GitHubRepo:    "repo",
		CheckInterval: 0,
		StateFile:     filepath.Join(tempDir, "state.json"),
	}

	updater, err := New(cfg, BinaryTypeServer, notifier)
	if err != nil {
		t.Fatal(err)
	}

	updater.github.httpClient.Transport = &testTransport{serverURL: server.URL}

	// Skip the version
	updater.SkipVersion("v1.0.0")

	// Background check should not notify for skipped version
	ctx := context.Background()
	updater.backgroundCheck(ctx)

	if notifier.called {
		t.Error("notifier should NOT have been called for skipped version")
	}
}

func TestUpdateInfo_Fields(t *testing.T) {
	info := UpdateInfo{
		CurrentVersion: "1.0.0",
		NewVersion:     "1.1.0",
		ReleaseURL:     "https://example.com/release",
		ReleaseNotes:   "Bug fixes",
		PublishedAt:    time.Now(),
		AssetURL:       "https://example.com/asset.tar.gz",
		AssetName:      "asset.tar.gz",
		AssetSize:      1024,
		Checksum:       "abc123",
	}

	// Basic field verification
	if info.CurrentVersion != "1.0.0" {
		t.Error("CurrentVersion mismatch")
	}
	if info.NewVersion != "1.1.0" {
		t.Error("NewVersion mismatch")
	}
	if info.AssetSize != 1024 {
		t.Error("AssetSize mismatch")
	}
}
