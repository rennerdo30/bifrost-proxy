package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewGitHubClient(t *testing.T) {
	client := NewGitHubClient("owner", "repo")
	if client == nil {
		t.Fatal("NewGitHubClient returned nil")
	}
	if client.owner != "owner" {
		t.Errorf("expected owner=%q, got %q", "owner", client.owner)
	}
	if client.repo != "repo" {
		t.Errorf("expected repo=%q, got %q", "repo", client.repo)
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

func TestGitHubClient_GetLatestRelease(t *testing.T) {
	release := Release{
		TagName:     "v1.0.0",
		Name:        "Release v1.0.0",
		Body:        "Release notes",
		Prerelease:  false,
		Draft:       false,
		PublishedAt: time.Now(),
		HTMLURL:     "https://github.com/owner/repo/releases/tag/v1.0.0",
		Assets: []Asset{
			{Name: "file.tar.gz", Size: 1000, BrowserDownloadURL: "https://example.com/file.tar.gz"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("unexpected Accept header: %s", r.Header.Get("Accept"))
		}
		if r.Header.Get("User-Agent") != "Bifrost-Updater/1.0" {
			t.Errorf("unexpected User-Agent: %s", r.Header.Get("User-Agent"))
		}

		if strings.Contains(r.URL.Path, "/releases/latest") {
			json.NewEncoder(w).Encode(release)
		} else if strings.Contains(r.URL.Path, "/releases") {
			json.NewEncoder(w).Encode([]Release{release})
		}
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	// Override the API URL for testing (we need to use the test server URL)
	originalDo := client.httpClient.Transport
	client.httpClient.Transport = &testTransport{
		serverURL: server.URL,
		inner:     originalDo,
	}

	ctx := context.Background()
	got, err := client.GetLatestRelease(ctx, false)
	if err != nil {
		t.Fatalf("GetLatestRelease failed: %v", err)
	}

	if got.TagName != release.TagName {
		t.Errorf("expected TagName=%q, got %q", release.TagName, got.TagName)
	}
}

func TestGitHubClient_GetLatestRelease_WithPrerelease(t *testing.T) {
	releases := []Release{
		{
			TagName:     "v1.1.0-beta",
			Name:        "Beta Release",
			Prerelease:  true,
			Draft:       false,
			PublishedAt: time.Now(),
		},
		{
			TagName:     "v1.0.0",
			Name:        "Stable Release",
			Prerelease:  false,
			Draft:       false,
			PublishedAt: time.Now().Add(-24 * time.Hour),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	got, err := client.GetLatestRelease(ctx, true)
	if err != nil {
		t.Fatalf("GetLatestRelease with prerelease failed: %v", err)
	}

	// Should return the first non-draft release
	if got.TagName != "v1.1.0-beta" {
		t.Errorf("expected TagName=%q, got %q", "v1.1.0-beta", got.TagName)
	}
}

func TestGitHubClient_GetLatestRelease_NoDraftRelease(t *testing.T) {
	releases := []Release{
		{
			TagName: "v1.1.0-draft",
			Draft:   true,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetLatestRelease(ctx, true)
	if err == nil {
		t.Fatal("expected error when all releases are drafts")
	}
}

func TestGitHubClient_GetReleases(t *testing.T) {
	releases := []Release{
		{TagName: "v1.0.0"},
		{TagName: "v0.9.0"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	got, err := client.GetReleases(ctx, 10)
	if err != nil {
		t.Fatalf("GetReleases failed: %v", err)
	}

	if len(got) != 2 {
		t.Errorf("expected 2 releases, got %d", len(got))
	}
}

func TestGitHubClient_GetRelease(t *testing.T) {
	release := Release{
		TagName: "v1.0.0",
		Name:    "v1.0.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/tags/v1.0.0") {
			json.NewEncoder(w).Encode(release)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	got, err := client.GetRelease(ctx, "v1.0.0")
	if err != nil {
		t.Fatalf("GetRelease failed: %v", err)
	}

	if got.TagName != "v1.0.0" {
		t.Errorf("expected TagName=%q, got %q", "v1.0.0", got.TagName)
	}
}

func TestGitHubClient_checkResponse_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetReleases(ctx, 10)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if err != ErrRateLimited {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}
}

func TestGitHubClient_checkResponse_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGitHubClient("owner", "repo")
	client.httpClient.Transport = &testTransport{serverURL: server.URL}

	ctx := context.Background()
	_, err := client.GetRelease(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestGitHubClient_GetChecksums(t *testing.T) {
	// SHA256 hashes are 64 hex characters
	checksumContent := `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  bifrost_1.0.0_linux_amd64.tar.gz
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e  bifrost_1.0.0_darwin_amd64.tar.gz
`

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{
				Name:               "checksums.txt",
				BrowserDownloadURL: "", // Will be set by server
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "checksums.txt") {
			w.Write([]byte(checksumContent))
		}
	}))
	defer server.Close()

	// Set the download URL after server is started
	release.Assets[0].BrowserDownloadURL = server.URL + "/checksums.txt"

	client := NewGitHubClient("owner", "repo")

	ctx := context.Background()
	checksums, err := client.GetChecksums(ctx, &release)
	if err != nil {
		t.Fatalf("GetChecksums failed: %v", err)
	}

	if checksums["bifrost_1.0.0_linux_amd64.tar.gz"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Error("checksum mismatch for linux")
	}
	if checksums["bifrost_1.0.0_darwin_amd64.tar.gz"] != "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" {
		t.Error("checksum mismatch for darwin")
	}
}

func TestGitHubClient_GetChecksums_NoChecksumFile(t *testing.T) {
	release := Release{
		TagName: "v1.0.0",
		Assets:  []Asset{}, // No checksums.txt
	}

	client := NewGitHubClient("owner", "repo")

	ctx := context.Background()
	_, err := client.GetChecksums(ctx, &release)
	if err == nil {
		t.Fatal("expected error when checksums.txt not found")
	}
}

func TestGitHubClient_FindAssetForPlatform(t *testing.T) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}

	expectedName := "bifrost_1.0.0_" + goos + "_" + goarch + ext

	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: expectedName, Size: 1000, BrowserDownloadURL: "https://example.com/" + expectedName},
			{Name: "bifrost_1.0.0_other_arch.tar.gz", Size: 1000},
		},
	}

	client := NewGitHubClient("owner", "repo")
	asset, name, err := client.FindAssetForPlatform(&release, BinaryTypeServer)
	if err != nil {
		t.Fatalf("FindAssetForPlatform failed: %v", err)
	}

	if name != expectedName {
		t.Errorf("expected name=%q, got %q", expectedName, name)
	}
	if asset.Name != expectedName {
		t.Errorf("expected asset name=%q, got %q", expectedName, asset.Name)
	}
}

func TestGitHubClient_FindAssetForPlatform_NotFound(t *testing.T) {
	release := Release{
		TagName: "v1.0.0",
		Assets: []Asset{
			{Name: "bifrost_1.0.0_someother_arch.tar.gz"},
		},
	}

	client := NewGitHubClient("owner", "repo")
	_, _, err := client.FindAssetForPlatform(&release, BinaryTypeServer)
	if err == nil {
		t.Fatal("expected error when asset not found")
	}
}

func TestBinaryType_BinaryName(t *testing.T) {
	serverName := BinaryTypeServer.BinaryName()
	clientName := BinaryTypeClient.BinaryName()

	if runtime.GOOS == "windows" {
		if serverName != "bifrost-server.exe" {
			t.Errorf("expected bifrost-server.exe, got %s", serverName)
		}
		if clientName != "bifrost-client.exe" {
			t.Errorf("expected bifrost-client.exe, got %s", clientName)
		}
	} else {
		if serverName != "bifrost-server" {
			t.Errorf("expected bifrost-server, got %s", serverName)
		}
		if clientName != "bifrost-client" {
			t.Errorf("expected bifrost-client, got %s", clientName)
		}
	}

	// Test invalid binary type
	var invalid BinaryType = "invalid"
	if invalid.BinaryName() != "" {
		t.Error("expected empty string for invalid binary type")
	}
}

// testTransport rewrites requests to use the test server URL
type testTransport struct {
	serverURL string
	inner     http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace GitHub API URL with test server URL
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.serverURL, "http://")
	if t.inner != nil {
		return t.inner.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}
