package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	githubAPIURL = "https://api.github.com"
)

// GitHubClient interacts with GitHub Releases API.
type GitHubClient struct {
	httpClient *http.Client
	owner      string
	repo       string
}

// Release represents a GitHub release.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset represents a release asset.
type Asset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ContentType        string `json:"content_type"`
}

// NewGitHubClient creates a new GitHub API client.
func NewGitHubClient(owner, repo string) *GitHubClient {
	return &GitHubClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		owner: owner,
		repo:  repo,
	}
}

// GetLatestRelease fetches the latest release.
func (c *GitHubClient) GetLatestRelease(ctx context.Context, includePrerelease bool) (*Release, error) {
	if !includePrerelease {
		// Use the /latest endpoint which excludes prereleases
		url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIURL, c.owner, c.repo)
		return c.fetchRelease(ctx, url)
	}

	// For prereleases, we need to get all releases and find the latest
	// Fetch more releases to ensure we don't miss a newer version that was released earlier
	releases, err := c.GetReleases(ctx, 30) // Increased limit to cover more history
	if err != nil {
		return nil, err
	}

	var validReleases []Release
	for _, release := range releases {
		if !release.Draft {
			validReleases = append(validReleases, release)
		}
	}

	if len(validReleases) == 0 {
		return nil, fmt.Errorf("%w: no releases found", ErrNoUpdateAvailable)
	}

	// Sort by semantic version descending (newest first)
	sort.Slice(validReleases, func(i, j int) bool {
		v1, err1 := ParseVersion(validReleases[i].TagName)
		v2, err2 := ParseVersion(validReleases[j].TagName)

		// If both parse successfully, compare versions
		if err1 == nil && err2 == nil {
			return v1.IsNewerThan(v2)
		}

		// Fallback to PublishedAt if either fails to parse
		// Newer timestamp = appearing earlier in the sorted list (descending)
		return validReleases[i].PublishedAt.After(validReleases[j].PublishedAt)
	})

	return &validReleases[0], nil
}

// GetReleases fetches recent releases.
func (c *GitHubClient) GetReleases(ctx context.Context, limit int) ([]Release, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d", githubAPIURL, c.owner, c.repo, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Bifrost-Updater/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return releases, nil
}

// GetRelease fetches a specific release by tag.
func (c *GitHubClient) GetRelease(ctx context.Context, tag string) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", githubAPIURL, c.owner, c.repo, tag)
	return c.fetchRelease(ctx, url)
}

func (c *GitHubClient) fetchRelease(ctx context.Context, url string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Bifrost-Updater/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &release, nil
}

func (c *GitHubClient) checkResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("%w: release not found", ErrNoUpdateAvailable)
	case http.StatusForbidden:
		// Check if it's rate limiting
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return ErrRateLimited
		}
		return fmt.Errorf("%w: forbidden", ErrNetworkError)
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: status %d: %s", ErrNetworkError, resp.StatusCode, string(body))
	}
}

// GetChecksums downloads and parses the checksums.txt file.
func (c *GitHubClient) GetChecksums(ctx context.Context, release *Release) (map[string]string, error) {
	// Find checksums.txt asset
	var checksumAsset *Asset
	for i := range release.Assets {
		if release.Assets[i].Name == "checksums.txt" {
			checksumAsset = &release.Assets[i]
			break
		}
	}

	if checksumAsset == nil {
		return nil, fmt.Errorf("%w: checksums.txt not found in release", ErrAssetNotFound)
	}

	// Download checksums file
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumAsset.BrowserDownloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Bifrost-Updater/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: failed to download checksums", ErrDownloadFailed)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}

	return ParseChecksumFile(string(body))
}

// FindAssetForPlatform finds the appropriate asset for current OS/arch.
func (c *GitHubClient) FindAssetForPlatform(release *Release, binaryType BinaryType) (*Asset, string, error) {
	// Build expected filename pattern
	// GoReleaser format: bifrost_<version>_<os>_<arch>.<ext>
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Determine extension
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}

	// Extract version from tag (remove 'v' prefix if present)
	version := strings.TrimPrefix(release.TagName, "v")

	// Build filename pattern
	expectedName := fmt.Sprintf("bifrost_%s_%s_%s%s", version, goos, goarch, ext)

	for i := range release.Assets {
		if release.Assets[i].Name == expectedName {
			return &release.Assets[i], expectedName, nil
		}
	}

	return nil, "", fmt.Errorf("%w: looking for %s", ErrAssetNotFound, expectedName)
}

// BinaryType identifies which binary is being updated.
type BinaryType string

const (
	// BinaryTypeServer is the server binary.
	BinaryTypeServer BinaryType = "server"
	// BinaryTypeClient is the client binary.
	BinaryTypeClient BinaryType = "client"
)

// BinaryName returns the expected binary name for this type.
func (b BinaryType) BinaryName() string {
	switch b {
	case BinaryTypeServer:
		if runtime.GOOS == "windows" {
			return "bifrost-server.exe"
		}
		return "bifrost-server"
	case BinaryTypeClient:
		if runtime.GOOS == "windows" {
			return "bifrost-client.exe"
		}
		return "bifrost-client"
	default:
		return ""
	}
}
