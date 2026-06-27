package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// rotatingWriter is a simple size-based rotating log file writer.
//
// When the active file would exceed maxSize bytes, it is renamed with a
// timestamp suffix and a fresh file is opened. At most maxBackups rotated files
// are retained (oldest first are deleted); maxBackups <= 0 keeps all backups.
//
// It is safe for concurrent use.
type rotatingWriter struct {
	path       string
	maxSize    int64 // bytes; <= 0 means never rotate
	maxBackups int

	mu   sync.Mutex
	file *os.File
	size int64
}

// newRotatingWriter opens (or creates) the log file at path and returns a
// size-based rotating writer.
func newRotatingWriter(path string, maxSize int64, maxBackups int) (*rotatingWriter, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: Config directory permissions are appropriate
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	w := &rotatingWriter{
		path:       path,
		maxSize:    maxSize,
		maxBackups: maxBackups,
	}

	if err := w.openExisting(); err != nil {
		return nil, err
	}

	return w, nil
}

// openExisting opens the active log file in append mode and records its size.
func (w *rotatingWriter) openExisting() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // G302: Log file permissions are appropriate
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	w.file = f
	w.size = info.Size()
	return nil
}

// Write implements io.Writer, rotating the file when the size limit is reached.
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.maxSize > 0 && w.size+int64(len(p)) > w.maxSize && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the active file, renames it with a timestamp suffix, opens a
// fresh file and prunes old backups. The caller must hold w.mu.
func (w *rotatingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("failed to close log file for rotation: %w", err)
	}

	ts := time.Now().Format("20060102-150405.000")
	rotated := fmt.Sprintf("%s.%s", w.path, ts)
	if err := os.Rename(w.path, rotated); err != nil {
		// Try to reopen the original so logging can continue.
		_ = w.openExisting()
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	if err := w.openExisting(); err != nil {
		return err
	}

	w.pruneBackups()
	return nil
}

// pruneBackups deletes the oldest rotated files when more than maxBackups exist.
// Errors are ignored (best effort). The caller must hold w.mu.
func (w *rotatingWriter) pruneBackups() {
	if w.maxBackups <= 0 {
		return
	}

	matches, err := filepath.Glob(w.path + ".*")
	if err != nil || len(matches) <= w.maxBackups {
		return
	}

	// Sort lexicographically; the timestamp suffix makes this chronological.
	sort.Strings(matches)
	for _, old := range matches[:len(matches)-w.maxBackups] {
		_ = os.Remove(old)
	}
}

// Close closes the underlying file.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
