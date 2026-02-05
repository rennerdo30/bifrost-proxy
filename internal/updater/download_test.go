package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewDownloader(t *testing.T) {
	d := NewDownloader()
	if d == nil {
		t.Fatal("NewDownloader returned nil")
	}
	if d.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

func TestDownloader_Download(t *testing.T) {
	content := []byte("test file content for download")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "Bifrost-Updater/1.0" {
			t.Errorf("unexpected User-Agent: %s", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Length", "30")
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer server.Close()

	d := NewDownloader()
	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "downloaded_file")

	// Test download with progress callback
	var progressCalled bool
	var lastDownloaded int64
	err := d.Download(context.Background(), server.URL, destPath, func(downloaded, total int64) {
		progressCalled = true
		lastDownloaded = downloaded
	})

	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if !progressCalled {
		t.Error("progress callback was not called")
	}

	if lastDownloaded != int64(len(content)) {
		t.Errorf("expected downloaded=%d, got %d", len(content), lastDownloaded)
	}

	// Verify file content
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", string(data), string(content))
	}
}

func TestDownloader_Download_WithoutProgress(t *testing.T) {
	content := []byte("test content")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer server.Close()

	d := NewDownloader()
	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "downloaded_file")

	// Test download without progress callback
	err := d.Download(context.Background(), server.URL, destPath, nil)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content mismatch")
	}
}

func TestDownloader_Download_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDownloader()
	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "downloaded_file")

	err := d.Download(context.Background(), server.URL, destPath, nil)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

func TestDownloader_Download_NetworkError(t *testing.T) {
	d := NewDownloader()
	d.httpClient.Timeout = 100 * time.Millisecond

	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "downloaded_file")

	err := d.Download(context.Background(), "http://192.0.2.1:12345/notexist", destPath, nil)
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestDownloader_Download_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte("late response"))
	}))
	defer server.Close()

	d := NewDownloader()
	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "downloaded_file")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := d.Download(ctx, server.URL, destPath, nil)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestDownloader_Download_InvalidDestPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content"))
	}))
	defer server.Close()

	d := NewDownloader()
	// Try to write to a directory that doesn't exist
	err := d.Download(context.Background(), server.URL, "/nonexistent/path/file", nil)
	if err == nil {
		t.Fatal("expected error for invalid dest path")
	}
}

func TestProgressReader(t *testing.T) {
	content := []byte("test content for progress reader")
	tempFile, err := os.CreateTemp("", "progress_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(content)
	if err != nil {
		t.Fatal(err)
	}
	tempFile.Seek(0, 0)

	var lastDownloaded int64
	var callCount int

	pr := &progressReader{
		reader: tempFile,
		total:  int64(len(content)),
		callback: func(downloaded, total int64) {
			lastDownloaded = downloaded
			callCount++
		},
	}

	buf := make([]byte, 10)
	for {
		n, err := pr.Read(buf)
		if err != nil {
			break
		}
		if n == 0 {
			break
		}
	}

	if callCount == 0 {
		t.Error("callback was never called")
	}
	if lastDownloaded != int64(len(content)) {
		t.Errorf("expected downloaded=%d, got %d", len(content), lastDownloaded)
	}
}
