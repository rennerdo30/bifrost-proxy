package cache

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
)

// TieredStorage combines memory and disk storage.
// Small files are stored in memory, large files on disk.
type TieredStorage struct {
	mu sync.RWMutex

	// memory is the hot tier for small/frequent files.
	memory *MemoryStorage

	// disk is the cold tier for large files.
	disk *DiskStorage

	// memoryThreshold is the size threshold for memory vs disk.
	// Files smaller than or equal to this are stored in memory.
	memoryThreshold int64

	// closed indicates if the storage has been stopped.
	closed bool
}

// NewTieredStorage creates a new tiered storage.
func NewTieredStorage(tieredCfg *TieredConfig, memoryCfg *MemoryConfig, diskCfg *DiskConfig) (*TieredStorage, error) {
	disk, err := NewDiskStorage(diskCfg)
	if err != nil {
		return nil, err
	}

	threshold := int64(10 * 1024 * 1024) // 10MB default
	if tieredCfg != nil && tieredCfg.MemoryThreshold > 0 {
		threshold = tieredCfg.MemoryThreshold.Int64()
	}

	return &TieredStorage{
		memory:          NewMemoryStorage(memoryCfg),
		disk:            disk,
		memoryThreshold: threshold,
	}, nil
}

// Start initializes both storage backends.
func (t *TieredStorage) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.memory.Start(ctx); err != nil {
		return err
	}

	if err := t.disk.Start(ctx); err != nil {
		t.memory.Stop(ctx)
		return err
	}

	t.closed = false
	slog.Info("tiered cache storage started",
		"memory_threshold", ByteSize(t.memoryThreshold).String(),
	)

	return nil
}

// Stop gracefully shuts down both storage backends.
func (t *TieredStorage) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true

	var firstErr error
	if err := t.memory.Stop(ctx); err != nil {
		firstErr = err
	}

	if err := t.disk.Stop(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	slog.Info("tiered cache storage stopped")
	return firstErr
}

// Get retrieves a cache entry by key.
// Checks memory first, then disk.
func (t *TieredStorage) Get(ctx context.Context, key string) (*Entry, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, ErrStorageClosed
	}
	t.mu.RUnlock()

	// Check memory first
	entry, err := t.memory.Get(ctx, key)
	if err == nil {
		return entry, nil
	}

	// Check disk
	return t.disk.Get(ctx, key)
}

// Put stores a cache entry in the appropriate tier.
func (t *TieredStorage) Put(ctx context.Context, key string, entry *Entry) error {
	if entry == nil || entry.Metadata == nil {
		return ErrInvalidKey
	}

	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrStorageClosed
	}
	t.mu.RUnlock()

	// Read the body to determine size and decide tier
	var data []byte
	if entry.Body != nil {
		var err error
		data, err = io.ReadAll(entry.Body)
		entry.Body.Close()
		if err != nil {
			return err
		}
	}

	size := int64(len(data))

	// Create new entry with buffered body
	newEntry := &Entry{
		Metadata: entry.Metadata,
		Body:     io.NopCloser(bytes.NewReader(data)),
	}

	// Choose tier based on size
	if size <= t.memoryThreshold {
		slog.Debug("storing in memory tier",
			"key", truncateKey(key),
			"size", size,
		)
		return t.memory.Put(ctx, key, newEntry)
	}

	slog.Debug("storing in disk tier",
		"key", truncateKey(key),
		"size", size,
	)
	return t.disk.Put(ctx, key, newEntry)
}

// Delete removes a cache entry from both tiers.
func (t *TieredStorage) Delete(ctx context.Context, key string) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrStorageClosed
	}
	t.mu.RUnlock()

	// Delete from both tiers (idempotent)
	t.memory.Delete(ctx, key)
	t.disk.Delete(ctx, key)
	return nil
}

// Exists checks if a key exists in either tier.
func (t *TieredStorage) Exists(ctx context.Context, key string) bool {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return false
	}
	t.mu.RUnlock()

	if t.memory.Exists(ctx, key) {
		return true
	}
	return t.disk.Exists(ctx, key)
}

// GetMetadata returns metadata from either tier.
func (t *TieredStorage) GetMetadata(ctx context.Context, key string) (*Metadata, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, ErrStorageClosed
	}
	t.mu.RUnlock()

	// Check memory first
	meta, err := t.memory.GetMetadata(ctx, key)
	if err == nil {
		return meta, nil
	}

	// Check disk
	return t.disk.GetMetadata(ctx, key)
}

// GetRange retrieves a byte range from either tier.
func (t *TieredStorage) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, ErrStorageClosed
	}
	t.mu.RUnlock()

	// Check memory first
	reader, err := t.memory.GetRange(ctx, key, start, end)
	if err == nil {
		return reader, nil
	}

	// Check disk
	return t.disk.GetRange(ctx, key, start, end)
}

// List returns metadata from both tiers.
func (t *TieredStorage) List(ctx context.Context, domain string, offset, limit int) ([]*Metadata, int64, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, 0, ErrStorageClosed
	}
	t.mu.RUnlock()

	// Get from both tiers
	memEntries, memTotal, err := t.memory.List(ctx, domain, 0, 0)
	if err != nil {
		return nil, 0, err
	}

	diskEntries, diskTotal, err := t.disk.List(ctx, domain, 0, 0)
	if err != nil {
		return nil, 0, err
	}

	// Combine results
	all := append(memEntries, diskEntries...)
	total := memTotal + diskTotal

	// Apply pagination
	if offset >= len(all) {
		return nil, total, nil
	}

	end := offset + limit
	if limit <= 0 || end > len(all) {
		end = len(all)
	}

	return all[offset:end], total, nil
}

// Clear removes all entries from both tiers.
func (t *TieredStorage) Clear(ctx context.Context) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrStorageClosed
	}
	t.mu.RUnlock()

	var firstErr error
	if err := t.memory.Clear(ctx); err != nil {
		firstErr = err
	}

	if err := t.disk.Clear(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// Stats returns combined storage statistics.
func (t *TieredStorage) Stats() StorageStats {
	memStats := t.memory.Stats()
	diskStats := t.disk.Stats()

	totalSize := memStats.TotalSize + diskStats.TotalSize
	maxSize := memStats.MaxSize + diskStats.MaxSize

	var usedPercent float64
	if maxSize > 0 {
		usedPercent = float64(totalSize) / float64(maxSize) * 100
	}

	return StorageStats{
		Entries:       memStats.Entries + diskStats.Entries,
		TotalSize:     totalSize,
		MaxSize:       maxSize,
		UsedPercent:   usedPercent,
		HitCount:      memStats.HitCount + diskStats.HitCount,
		MissCount:     memStats.MissCount + diskStats.MissCount,
		EvictionCount: memStats.EvictionCount + diskStats.EvictionCount,
	}
}

// MemoryStats returns memory tier statistics.
func (t *TieredStorage) MemoryStats() StorageStats {
	return t.memory.Stats()
}

// DiskStats returns disk tier statistics.
func (t *TieredStorage) DiskStats() StorageStats {
	return t.disk.Stats()
}

// Compile-time interface check
var _ Storage = (*TieredStorage)(nil)
