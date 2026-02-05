package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DiskStorage stores cache entries on disk.
type DiskStorage struct {
	mu sync.RWMutex

	// basePath is the root directory for cache files.
	basePath string

	// dataPath is the directory for content files.
	dataPath string

	// maxSize is the maximum total size in bytes.
	maxSize int64

	// currentSize tracks the total size of cached content.
	currentSize int64

	// index maintains an in-memory index of all cached files.
	index map[string]*Metadata

	// cleanupInterval is how often to run cleanup.
	cleanupInterval time.Duration

	// shardCount is the number of subdirectories.
	shardCount int

	// stats tracks storage statistics.
	stats struct {
		hitCount      atomic.Int64
		missCount     atomic.Int64
		evictionCount atomic.Int64
	}

	// stopCh signals background goroutines to stop.
	stopCh chan struct{}

	// closed indicates if the storage has been stopped.
	closed bool
}

// NewDiskStorage creates a new disk storage.
func NewDiskStorage(cfg *DiskConfig) (*DiskStorage, error) {
	if cfg == nil {
		return nil, errors.New("disk config is required")
	}
	if cfg.Path == "" {
		return nil, errors.New("disk path is required")
	}

	shardCount := cfg.ShardCount
	if shardCount <= 0 {
		shardCount = 256
	}

	cleanupInterval := cfg.CleanupInterval.Duration()
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Hour
	}

	return &DiskStorage{
		basePath:        cfg.Path,
		dataPath:        filepath.Join(cfg.Path, "data"),
		maxSize:         cfg.MaxSize.Int64(),
		index:           make(map[string]*Metadata),
		cleanupInterval: cleanupInterval,
		shardCount:      shardCount,
		stopCh:          make(chan struct{}),
	}, nil
}

// Start initializes the storage backend.
func (d *DiskStorage) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Create directories
	if err := os.MkdirAll(d.dataPath, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Create shard directories
	for i := 0; i < d.shardCount; i++ {
		shardDir := filepath.Join(d.dataPath, fmt.Sprintf("%02x", i))
		if err := os.MkdirAll(shardDir, 0755); err != nil {
			return fmt.Errorf("failed to create shard directory: %w", err)
		}
	}

	// Load index from disk
	if err := d.loadIndex(); err != nil {
		slog.Warn("failed to load cache index", "error", err)
		// Start fresh
		d.index = make(map[string]*Metadata)
		d.currentSize = 0
	}

	d.closed = false
	d.stopCh = make(chan struct{})

	// Start background cleanup
	go d.cleanupLoop()

	slog.Info("disk cache storage started",
		"path", d.basePath,
		"max_size", ByteSize(d.maxSize).String(),
		"entries", len(d.index),
		"current_size", ByteSize(d.currentSize).String(),
	)

	return nil
}

// Stop gracefully shuts down the storage backend.
func (d *DiskStorage) Stop(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	close(d.stopCh)
	d.closed = true

	// Save index
	d.saveIndex()

	slog.Info("disk cache storage stopped")
	return nil
}

// Get retrieves a cache entry by key.
func (d *DiskStorage) Get(ctx context.Context, key string) (*Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil, ErrStorageClosed
	}

	meta, ok := d.index[key]
	if !ok {
		d.stats.missCount.Add(1)
		return nil, ErrNotFound
	}

	// Check if expired
	if meta.IsExpired() {
		d.removeEntry(key)
		d.stats.missCount.Add(1)
		return nil, ErrNotFound
	}

	// Open data file
	dataPath := d.dataFilePath(key)
	file, err := os.Open(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Index inconsistency - remove from index
			delete(d.index, key)
			d.stats.missCount.Add(1)
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Update access stats
	meta.UpdateAccess()
	d.stats.hitCount.Add(1)

	return &Entry{
		Metadata: d.copyMetadata(meta),
		Body:     file,
	}, nil
}

// Put stores a cache entry.
func (d *DiskStorage) Put(ctx context.Context, key string, entry *Entry) error {
	if entry == nil || entry.Metadata == nil {
		return ErrInvalidKey
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStorageClosed
	}

	// Remove existing entry if present
	if _, ok := d.index[key]; ok {
		d.removeEntry(key)
	}

	// Create temp file for writing
	dataPath := d.dataFilePath(key)
	shardDir := filepath.Dir(dataPath)
	if err := os.MkdirAll(shardDir, 0755); err != nil {
		return fmt.Errorf("failed to create shard directory: %w", err)
	}

	tempFile, err := os.CreateTemp(shardDir, ".cache-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// Write content
	var size int64
	if entry.Body != nil {
		size, err = io.Copy(tempFile, entry.Body)
		entry.Body.Close()
		if err != nil {
			tempFile.Close()
			os.Remove(tempPath)
			return fmt.Errorf("failed to write content: %w", err)
		}
	}
	tempFile.Close()

	// Check size limit
	if d.maxSize > 0 && size > d.maxSize {
		os.Remove(tempPath)
		return ErrEntrySizeExceeded
	}

	// Evict entries until we have space
	for d.maxSize > 0 && d.currentSize+size > d.maxSize {
		if !d.evictOne() {
			os.Remove(tempPath)
			return ErrStorageFull
		}
	}

	// Rename to final path
	if err := os.Rename(tempPath, dataPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	// Update metadata
	meta := d.copyMetadata(entry.Metadata)
	meta.Size = size
	meta.Tier = "disk"

	// Add to index
	d.index[key] = meta
	d.currentSize += size

	// Write metadata file
	if err := d.saveMetadata(key, meta); err != nil {
		slog.Warn("failed to save metadata file", "key", truncateKey(key), "error", err)
	}

	slog.Debug("cache entry stored on disk",
		"key", truncateKey(key),
		"size", size,
		"host", meta.Host,
	)

	return nil
}

// Delete removes a cache entry by key.
func (d *DiskStorage) Delete(ctx context.Context, key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStorageClosed
	}

	d.removeEntry(key)
	return nil
}

// Exists checks if a key exists in the cache.
func (d *DiskStorage) Exists(ctx context.Context, key string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return false
	}

	meta, ok := d.index[key]
	if !ok {
		return false
	}

	return !meta.IsExpired()
}

// GetMetadata returns only the metadata for a key.
func (d *DiskStorage) GetMetadata(ctx context.Context, key string) (*Metadata, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrStorageClosed
	}

	meta, ok := d.index[key]
	if !ok {
		return nil, ErrNotFound
	}

	if meta.IsExpired() {
		return nil, ErrNotFound
	}

	return d.copyMetadata(meta), nil
}

// GetRange retrieves a byte range from a cached entry.
func (d *DiskStorage) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, error) {
	d.mu.RLock()

	if d.closed {
		d.mu.RUnlock()
		return nil, ErrStorageClosed
	}

	meta, ok := d.index[key]
	if !ok {
		d.mu.RUnlock()
		return nil, ErrNotFound
	}

	if meta.IsExpired() {
		d.mu.RUnlock()
		return nil, ErrNotFound
	}

	dataPath := d.dataFilePath(key)
	d.mu.RUnlock()

	file, err := os.Open(dataPath)
	if err != nil {
		return nil, err
	}

	// Seek to start position
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}

	// Return limited reader
	length := end - start + 1
	return NewLimitedReadCloser(file, length), nil
}

// List returns all metadata entries.
func (d *DiskStorage) List(ctx context.Context, domain string, offset, limit int) ([]*Metadata, int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, 0, ErrStorageClosed
	}

	var results []*Metadata
	var total int64

	// Collect and filter entries
	entries := make([]*Metadata, 0, len(d.index))
	for _, meta := range d.index {
		if meta.IsExpired() {
			continue
		}
		if domain != "" && meta.Host != domain {
			continue
		}
		entries = append(entries, meta)
	}

	// Sort by access time (most recent first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].AccessedAt.After(entries[j].AccessedAt)
	})

	total = int64(len(entries))

	// Apply pagination
	for i, meta := range entries {
		if i < offset {
			continue
		}
		if limit > 0 && len(results) >= limit {
			break
		}
		results = append(results, d.copyMetadata(meta))
	}

	return results, total, nil
}

// Clear removes all entries from the storage.
func (d *DiskStorage) Clear(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrStorageClosed
	}

	// Remove all files
	if err := os.RemoveAll(d.dataPath); err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	// Recreate directories
	if err := os.MkdirAll(d.dataPath, 0755); err != nil {
		return fmt.Errorf("failed to recreate cache directory: %w", err)
	}

	for i := 0; i < d.shardCount; i++ {
		shardDir := filepath.Join(d.dataPath, fmt.Sprintf("%02x", i))
		if err := os.MkdirAll(shardDir, 0755); err != nil {
			return fmt.Errorf("failed to recreate shard directory: %w", err)
		}
	}

	// Clear index
	d.index = make(map[string]*Metadata)
	d.currentSize = 0

	slog.Info("disk cache cleared")
	return nil
}

// Stats returns storage statistics.
func (d *DiskStorage) Stats() StorageStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var usedPercent float64
	if d.maxSize > 0 {
		usedPercent = float64(d.currentSize) / float64(d.maxSize) * 100
	}

	return StorageStats{
		Entries:       int64(len(d.index)),
		TotalSize:     d.currentSize,
		MaxSize:       d.maxSize,
		UsedPercent:   usedPercent,
		HitCount:      d.stats.hitCount.Load(),
		MissCount:     d.stats.missCount.Load(),
		EvictionCount: d.stats.evictionCount.Load(),
	}
}

// dataFilePath returns the path for a cache entry's data file.
func (d *DiskStorage) dataFilePath(key string) string {
	shard := d.shardForKey(key)
	return filepath.Join(d.dataPath, shard, key+".dat")
}

// metaFilePath returns the path for a cache entry's metadata file.
func (d *DiskStorage) metaFilePath(key string) string {
	shard := d.shardForKey(key)
	return filepath.Join(d.dataPath, shard, key+".meta")
}

// shardForKey returns the shard directory for a key.
func (d *DiskStorage) shardForKey(key string) string {
	// Use first 2 hex chars for sharding
	if len(key) >= 2 {
		return key[:2]
	}
	// Fallback: hash the key
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:1])
}

// removeEntry removes an entry from index and disk.
func (d *DiskStorage) removeEntry(key string) {
	meta, ok := d.index[key]
	if !ok {
		return
	}

	// Remove from index
	delete(d.index, key)
	d.currentSize -= meta.Size

	// Remove files - log errors to help diagnose disk space leaks
	if err := os.Remove(d.dataFilePath(key)); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove cache data file",
			"key", truncateKey(key),
			"error", err,
		)
	}
	if err := os.Remove(d.metaFilePath(key)); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove cache metadata file",
			"key", truncateKey(key),
			"error", err,
		)
	}
}

// evictOne removes the least recently used entry.
func (d *DiskStorage) evictOne() bool {
	if len(d.index) == 0 {
		return false
	}

	// Find LRU entry
	var victimKey string
	var victimTime time.Time
	for key, meta := range d.index {
		if victimKey == "" || meta.AccessedAt.Before(victimTime) {
			victimKey = key
			victimTime = meta.AccessedAt
		}
	}

	if victimKey == "" {
		return false
	}

	slog.Debug("evicting cache entry from disk",
		"key", truncateKey(victimKey),
	)

	d.removeEntry(victimKey)
	d.stats.evictionCount.Add(1)
	return true
}

// loadIndex loads the cache index from disk.
func (d *DiskStorage) loadIndex() error {
	d.index = make(map[string]*Metadata)
	d.currentSize = 0

	// Walk through all shard directories
	return filepath.Walk(d.dataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			slog.Warn("failed to recover cache entry",
				"path", path,
				"error", err,
			)
			return nil // Skip errors
		}
		if info.IsDir() {
			return nil
		}

		// Look for .meta files
		if filepath.Ext(path) != ".meta" {
			return nil
		}

		// Read metadata
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("failed to read cache metadata",
				"path", path,
				"error", err,
			)
			return nil // Skip errors
		}

		var meta Metadata
		if unmarshalErr := json.Unmarshal(data, &meta); unmarshalErr != nil {
			slog.Warn("failed to read cache data",
				"path", path,
				"error", unmarshalErr,
			)
			return nil // Skip invalid files
		}

		// Verify data file exists
		dataPath := path[:len(path)-5] + ".dat"
		dataInfo, err := os.Stat(dataPath)
		if err != nil {
			// Orphaned metadata file - clean up and log if removal fails
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				slog.Warn("failed to remove orphaned cache metadata file",
					"path", path,
					"error", removeErr,
				)
			}
			return nil
		}

		// Update size from actual file
		meta.Size = dataInfo.Size()

		// Skip expired entries
		if meta.IsExpired() {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				slog.Warn("failed to remove expired cache metadata file",
					"path", path,
					"error", removeErr,
				)
			}
			if removeErr := os.Remove(dataPath); removeErr != nil && !os.IsNotExist(removeErr) {
				slog.Warn("failed to remove expired cache data file",
					"path", dataPath,
					"error", removeErr,
				)
			}
			return nil
		}

		d.index[meta.Key] = &meta
		d.currentSize += meta.Size

		return nil
	})
}

// saveIndex saves metadata for all entries.
func (d *DiskStorage) saveIndex() {
	for key, meta := range d.index {
		if err := d.saveMetadata(key, meta); err != nil {
			slog.Warn("failed to save metadata", "key", truncateKey(key), "error", err)
		}
	}
}

// saveMetadata saves metadata for a single entry.
func (d *DiskStorage) saveMetadata(key string, meta *Metadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	metaPath := d.metaFilePath(key)
	return os.WriteFile(metaPath, data, 0600)
}

// cleanupLoop runs periodic cleanup.
func (d *DiskStorage) cleanupLoop() {
	ticker := time.NewTicker(d.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired entries.
func (d *DiskStorage) cleanupExpired() {
	d.mu.Lock()
	defer d.mu.Unlock()

	var expired []string
	now := time.Now()

	for key, meta := range d.index {
		if now.After(meta.ExpiresAt) {
			expired = append(expired, key)
		}
	}

	for _, key := range expired {
		d.removeEntry(key)
	}

	if len(expired) > 0 {
		slog.Debug("cleaned up expired cache entries from disk",
			"count", len(expired),
		)
	}
}

// copyMetadata creates a deep copy of metadata.
func (d *DiskStorage) copyMetadata(meta *Metadata) *Metadata {
	if meta == nil {
		return nil
	}

	copy := *meta

	// Deep copy headers
	if meta.Headers != nil {
		copy.Headers = make(map[string][]string)
		for k, v := range meta.Headers {
			copy.Headers[k] = append([]string(nil), v...)
		}
	}

	// Deep copy cache control
	if meta.CacheControl != nil {
		cc := *meta.CacheControl
		copy.CacheControl = &cc
	}

	return &copy
}

// Compile-time interface check
var _ Storage = (*DiskStorage)(nil)
