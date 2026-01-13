package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ProgressCallback is called during download with progress info.
type ProgressCallback func(downloaded, total int64)

// Downloader handles file downloads.
type Downloader struct {
	httpClient *http.Client
}

// NewDownloader creates a new Downloader.
func NewDownloader() *Downloader {
	return &Downloader{
		httpClient: &http.Client{
			Timeout: 10 * time.Minute, // Large files may take time
		},
	}
}

// Download downloads a file to the specified path with progress reporting.
func (d *Downloader) Download(ctx context.Context, url, destPath string, progress ProgressCallback) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Bifrost-Updater/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrDownloadFailed, resp.StatusCode)
	}

	// Create destination file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	// Wrap reader with progress reporting if callback provided
	var reader io.Reader = resp.Body
	if progress != nil {
		reader = &progressReader{
			reader:   resp.Body,
			total:    resp.ContentLength,
			callback: progress,
		}
	}

	// Copy with buffer
	_, err = io.Copy(out, reader)
	if err != nil {
		os.Remove(destPath) // Clean up partial file
		return fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}

	return nil
}

// progressReader wraps an io.Reader to report progress.
type progressReader struct {
	reader     io.Reader
	total      int64
	downloaded int64
	callback   ProgressCallback
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.downloaded += int64(n)
		if pr.callback != nil {
			pr.callback(pr.downloaded, pr.total)
		}
	}
	return n, err
}
