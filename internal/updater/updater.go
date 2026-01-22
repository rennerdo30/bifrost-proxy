package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/logging"
	"github.com/rennerdo30/bifrost-proxy/internal/version"
)

// UpdateInfo contains information about an available update.
type UpdateInfo struct {
	CurrentVersion string    `json:"current_version"`
	NewVersion     string    `json:"new_version"`
	ReleaseURL     string    `json:"release_url"`
	ReleaseNotes   string    `json:"release_notes"`
	PublishedAt    time.Time `json:"published_at"`
	AssetURL       string    `json:"asset_url"`
	AssetName      string    `json:"asset_name"`
	AssetSize      int64     `json:"asset_size"`
	Checksum       string    `json:"checksum"`
}

// Notifier interface for update notifications.
type Notifier interface {
	NotifyUpdateAvailable(info UpdateInfo)
}

// Updater manages application updates.
type Updater struct {
	config     Config
	github     *GitHubClient
	state      *State
	notifier   Notifier
	binaryType BinaryType

	stopCh chan struct{}
	mu     sync.Mutex
}

// New creates a new Updater instance.
func New(cfg Config, binaryType BinaryType, notifier Notifier) (*Updater, error) {
	// Load state
	statePath := cfg.StateFile
	if statePath == "" {
		statePath = DefaultStatePath()
	}

	state, err := LoadState(statePath)
	if err != nil {
		return nil, err
	}

	return &Updater{
		config:     cfg,
		github:     NewGitHubClient(cfg.GitHubOwner, cfg.GitHubRepo),
		state:      state,
		notifier:   notifier,
		binaryType: binaryType,
	}, nil
}

// CheckForUpdate checks if a new version is available.
func (u *Updater) CheckForUpdate(ctx context.Context) (*UpdateInfo, error) {
	// Get current version
	currentVersionStr := version.Version
	currentVersion, err := ParseVersion(currentVersionStr)
	if err != nil {
		// If version is "dev" or unparseable, treat as very old
		currentVersion = Version{Major: 0, Minor: 0, Patch: 0}
	}

	// Get latest release
	includePrerelease := u.config.Channel.IsPrerelease()
	release, err := u.github.GetLatestRelease(ctx, includePrerelease)
	if err != nil {
		return nil, err
	}

	// Parse release version
	releaseVersion, err := ParseVersion(release.TagName)
	if err != nil {
		return nil, err
	}

	// Compare versions
	// Compare versions
	isNewer := false

	// Try SemVer comparison first
	if err == nil && releaseVersion.Major != 0 {
		// Valid SemVer found for current version
		isNewer = releaseVersion.IsNewerThan(currentVersion)
	} else {
		// Fallback to timestamp comparison for non-SemVer (nightlies/SHAs)
		// Only if the version strings are different (to avoid redeploying same SHA)
		if currentVersionStr != release.TagName {
			// Parse local build time
			// version.BuildTime is injected at build time, format expected: RFC3339
			localBuildTime, timeErr := time.Parse(time.RFC3339, version.BuildTime)
			if timeErr != nil {
				// If local build time is unknown/unparseable, assume update is available
				// This ensures dev builds always can update to a real release
				isNewer = true
			} else {
				isNewer = release.PublishedAt.After(localBuildTime)
			}
		}
	}

	if !isNewer {
		return nil, ErrNoUpdateAvailable
	}

	// Find asset for current platform
	asset, assetName, err := u.github.FindAssetForPlatform(release, u.binaryType)
	if err != nil {
		return nil, err
	}

	// Get checksum
	checksums, err := u.github.GetChecksums(ctx, release)
	if err != nil {
		return nil, err
	}

	checksum, ok := checksums[assetName]
	if !ok {
		return nil, ErrAssetNotFound
	}

	return &UpdateInfo{
		CurrentVersion: currentVersionStr,
		NewVersion:     release.TagName,
		ReleaseURL:     release.HTMLURL,
		ReleaseNotes:   release.Body,
		PublishedAt:    release.PublishedAt,
		AssetURL:       asset.BrowserDownloadURL,
		AssetName:      assetName,
		AssetSize:      asset.Size,
		Checksum:       checksum,
	}, nil
}

// Install downloads and installs the update.
func (u *Updater) Install(ctx context.Context, info *UpdateInfo, progress ProgressCallback) error {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "bifrost-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, info.AssetName)

	// Download
	downloader := NewDownloader()
	if err := downloader.Download(ctx, info.AssetURL, archivePath, progress); err != nil {
		return err
	}

	// Verify checksum
	if err := VerifyChecksum(archivePath, info.Checksum); err != nil {
		return err
	}

	// Install
	installer := NewInstaller(u.binaryType)
	if err := installer.Install(ctx, archivePath); err != nil {
		return err
	}

	return nil
}

// StartBackgroundChecker starts the periodic update checker.
func (u *Updater) StartBackgroundChecker(ctx context.Context) {
	u.mu.Lock()
	if u.stopCh != nil {
		u.mu.Unlock()
		return // Already running
	}
	u.stopCh = make(chan struct{})
	stopCh := u.stopCh // Capture under lock to avoid race
	u.mu.Unlock()

	go func() {
		// Initial delay before first check
		select {
		case <-time.After(1 * time.Minute):
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		}

		u.backgroundCheck(ctx)

		ticker := time.NewTicker(u.config.CheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				u.backgroundCheck(ctx)
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			}
		}
	}()
}

func (u *Updater) backgroundCheck(ctx context.Context) {
	// Respect state file to avoid redundant checks
	if !u.state.ShouldCheck(u.config.CheckInterval) {
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	info, err := u.CheckForUpdate(checkCtx)
	u.state.MarkChecked()
	if saveErr := u.state.Save(); saveErr != nil {
		logging.Debug("Failed to save update state", "error", saveErr)
	}

	if err != nil {
		if !errors.Is(err, ErrNoUpdateAvailable) {
			logging.Debug("Background update check failed", "error", err)
		}
		return
	}

	// Don't notify if already notified or user skipped this version
	if !u.state.ShouldNotify(info.NewVersion) || u.state.IsSkipped(info.NewVersion) {
		return
	}

	// Notify via callback
	if u.notifier != nil {
		u.notifier.NotifyUpdateAvailable(*info)
		u.state.MarkNotified(info.NewVersion)
		if saveErr := u.state.Save(); saveErr != nil {
			logging.Debug("Failed to save update state", "error", saveErr)
		}
	}
}

// StopBackgroundChecker stops the periodic update checker.
func (u *Updater) StopBackgroundChecker() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.stopCh != nil {
		close(u.stopCh)
		u.stopCh = nil
	}
}

// SkipVersion marks a version as skipped.
func (u *Updater) SkipVersion(version string) error {
	u.state.SkipVersion(version)
	return u.state.Save()
}
