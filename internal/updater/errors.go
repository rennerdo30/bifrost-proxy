// Package updater provides self-update functionality for Bifrost binaries.
package updater

import "errors"

var (
	// ErrNoUpdateAvailable indicates the current version is up to date.
	ErrNoUpdateAvailable = errors.New("no update available")

	// ErrChecksumMismatch indicates the downloaded file failed verification.
	ErrChecksumMismatch = errors.New("checksum verification failed")

	// ErrAssetNotFound indicates no release asset matches the current platform.
	ErrAssetNotFound = errors.New("release asset not found for platform")

	// ErrDownloadFailed indicates the download could not be completed.
	ErrDownloadFailed = errors.New("download failed")

	// ErrInstallFailed indicates the installation could not be completed.
	ErrInstallFailed = errors.New("installation failed")

	// ErrBackupFailed indicates the backup could not be created.
	ErrBackupFailed = errors.New("backup failed")

	// ErrInvalidVersion indicates the version string is malformed.
	ErrInvalidVersion = errors.New("invalid version format")

	// ErrNetworkError indicates a network-related failure.
	ErrNetworkError = errors.New("network error")

	// ErrRateLimited indicates the GitHub API rate limit was exceeded.
	ErrRateLimited = errors.New("GitHub API rate limited")

	// ErrRestoreFailed indicates the rollback could not be completed.
	ErrRestoreFailed = errors.New("restore from backup failed")
)
