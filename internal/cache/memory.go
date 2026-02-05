package cache

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryStorage is an in-memory cache storage with LRU eviction.
type MemoryStorage struct {
	mu sync.RWMutex

	// entries maps cache keys to list elements for O(1) access
	entries map[string]*list.Element

	// lruList is ordered by access time (most recent at front)
	lruList *list.List

	// currentSize tracks the total size of cached content
	currentSize int64

	// maxSize is the maximum allowed storage size in bytes
	maxSize int64

	// maxEntries is the maximum number of entries (0 = unlimited)
	maxEntries int

	// evictPolicy determines how entries are evicted
	evictPolicy EvictionPolicy

	// stats tracks storage statistics
	stats struct {
		hitCount      atomic.Int64
		missCount     atomic.Int64
		evictionCount atomic.Int64
	}

	// closed indicates if the storage has been stopped
	closed bool
}

// memoryEntry wraps an entry in the LRU list.
type memoryEntry struct {
	key      string
	metadata *Metadata
	data     []byte
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage(cfg *MemoryConfig) *MemoryStorage {
	if cfg == nil {
		cfg = &MemoryConfig{
			MaxSize:     ByteSize(256 * 1024 * 1024), // 256MB default
			MaxEntries:  10000,
			EvictPolicy: "lru",
		}
	}

	policy := EvictionLRU
	switch cfg.EvictPolicy {
	case "lfu":
		policy = EvictionLFU
	case "fifo":
		policy = EvictionFIFO
	}

	return &MemoryStorage{
		entries:     make(map[string]*list.Element),
		lruList:     list.New(),
		maxSize:     cfg.MaxSize.Int64(),
		maxEntries:  cfg.MaxEntries,
		evictPolicy: policy,
	}
}

// Get retrieves a cache entry by key.
func (m *MemoryStorage) Get(ctx context.Context, key string) (*Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	elem, ok := m.entries[key]
	if !ok {
		m.stats.missCount.Add(1)
		return nil, ErrNotFound
	}

	me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry

	// Check if expired
	if me.metadata.IsExpired() {
		m.removeElement(elem)
		m.stats.missCount.Add(1)
		return nil, ErrNotFound
	}

	// Move to front (most recently used)
	if m.evictPolicy == EvictionLRU {
		m.lruList.MoveToFront(elem)
	}

	// Update access stats
	me.metadata.UpdateAccess()
	m.stats.hitCount.Add(1)

	// Return a copy to avoid data races
	return &Entry{
		Metadata: m.copyMetadata(me.metadata),
		Body:     NewBytesReadCloser(me.data),
	}, nil
}

// Put stores a cache entry.
func (m *MemoryStorage) Put(ctx context.Context, key string, entry *Entry) error {
	if entry == nil || entry.Metadata == nil {
		return ErrInvalidKey
	}

	// Read the body into memory
	var data []byte
	if entry.Body != nil {
		var err error
		data, err = io.ReadAll(entry.Body)
		entry.Body.Close()
		if err != nil {
			return err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	entrySize := int64(len(data))

	// Check if entry is too large
	if m.maxSize > 0 && entrySize > m.maxSize {
		return ErrEntrySizeExceeded
	}

	// Remove existing entry if present
	if elem, ok := m.entries[key]; ok {
		m.removeElement(elem)
	}

	// Evict entries until we have space
	for m.maxSize > 0 && m.currentSize+entrySize > m.maxSize {
		if !m.evictOne() {
			return ErrStorageFull
		}
	}

	// Check entry count limit
	for m.maxEntries > 0 && len(m.entries) >= m.maxEntries {
		if !m.evictOne() {
			return ErrStorageFull
		}
	}

	// Create new entry
	meta := m.copyMetadata(entry.Metadata)
	meta.Size = entrySize
	meta.Tier = "memory"

	me := &memoryEntry{
		key:      key,
		metadata: meta,
		data:     data,
	}

	// Add to front of list
	elem := m.lruList.PushFront(me)
	m.entries[key] = elem
	m.currentSize += entrySize

	slog.Debug("cache entry stored in memory",
		"key", truncateKey(key),
		"size", entrySize,
		"host", meta.Host,
	)

	return nil
}

// Delete removes a cache entry by key.
func (m *MemoryStorage) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	if elem, ok := m.entries[key]; ok {
		m.removeElement(elem)
	}
	return nil
}

// Exists checks if a key exists in the cache.
func (m *MemoryStorage) Exists(ctx context.Context, key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false
	}

	elem, ok := m.entries[key]
	if !ok {
		return false
	}

	me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
	return !me.metadata.IsExpired()
}

// GetMetadata returns only the metadata for a key.
func (m *MemoryStorage) GetMetadata(ctx context.Context, key string) (*Metadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	elem, ok := m.entries[key]
	if !ok {
		return nil, ErrNotFound
	}

	me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
	if me.metadata.IsExpired() {
		return nil, ErrNotFound
	}

	return m.copyMetadata(me.metadata), nil
}

// GetRange retrieves a byte range from a cached entry.
func (m *MemoryStorage) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrStorageClosed
	}

	elem, ok := m.entries[key]
	if !ok {
		return nil, ErrNotFound
	}

	me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
	if me.metadata.IsExpired() {
		return nil, ErrNotFound
	}

	// Validate range
	dataLen := int64(len(me.data))
	if start < 0 {
		start = 0
	}
	if end >= dataLen {
		end = dataLen - 1
	}
	if start > end || start >= dataLen {
		return nil, io.EOF
	}

	// Return the range
	rangeData := me.data[start : end+1]
	return NewBytesReadCloser(rangeData), nil
}

// List returns all metadata entries.
func (m *MemoryStorage) List(ctx context.Context, domain string, offset, limit int) ([]*Metadata, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, 0, ErrStorageClosed
	}

	var results []*Metadata
	var total int64

	for elem := m.lruList.Front(); elem != nil; elem = elem.Next() {
		me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
		if me.metadata.IsExpired() {
			continue
		}

		// Filter by domain if specified
		if domain != "" && me.metadata.Host != domain {
			continue
		}

		total++

		// Apply pagination
		if int(total) <= offset {
			continue
		}
		if limit > 0 && len(results) >= limit {
			continue
		}

		results = append(results, m.copyMetadata(me.metadata))
	}

	return results, total, nil
}

// Clear removes all entries from the storage.
func (m *MemoryStorage) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageClosed
	}

	m.entries = make(map[string]*list.Element)
	m.lruList.Init()
	m.currentSize = 0

	slog.Info("memory cache cleared")
	return nil
}

// Stats returns storage statistics.
func (m *MemoryStorage) Stats() StorageStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var usedPercent float64
	if m.maxSize > 0 {
		usedPercent = float64(m.currentSize) / float64(m.maxSize) * 100
	}

	return StorageStats{
		Entries:       int64(len(m.entries)),
		TotalSize:     m.currentSize,
		MaxSize:       m.maxSize,
		UsedPercent:   usedPercent,
		HitCount:      m.stats.hitCount.Load(),
		MissCount:     m.stats.missCount.Load(),
		EvictionCount: m.stats.evictionCount.Load(),
	}
}

// Start initializes the storage backend.
func (m *MemoryStorage) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = false
	slog.Info("memory cache storage started",
		"max_size", ByteSize(m.maxSize).String(),
		"max_entries", m.maxEntries,
		"evict_policy", m.evictPolicy,
	)
	return nil
}

// Stop gracefully shuts down the storage backend.
func (m *MemoryStorage) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.entries = make(map[string]*list.Element)
	m.lruList.Init()
	m.currentSize = 0

	slog.Info("memory cache storage stopped")
	return nil
}

// removeElement removes an element from both the map and list.
// Must be called with lock held.
func (m *MemoryStorage) removeElement(elem *list.Element) {
	me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
	delete(m.entries, me.key)
	m.lruList.Remove(elem)
	m.currentSize -= int64(len(me.data))
}

// evictOne removes the least valuable entry based on eviction policy.
// Must be called with lock held. Returns false if nothing to evict.
func (m *MemoryStorage) evictOne() bool {
	if m.lruList.Len() == 0 {
		return false
	}

	var victim *list.Element

	switch m.evictPolicy {
	case EvictionLRU:
		// Evict from back (least recently used)
		victim = m.lruList.Back()
	case EvictionFIFO:
		// Evict from back (oldest)
		victim = m.lruList.Back()
	case EvictionLFU:
		// Find least frequently used
		var minCount int64 = -1
		for elem := m.lruList.Back(); elem != nil; elem = elem.Prev() {
			me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
			if minCount < 0 || me.metadata.AccessCount < minCount {
				minCount = me.metadata.AccessCount
				victim = elem
			}
		}
	}

	if victim == nil {
		return false
	}

	me := victim.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
	slog.Debug("evicting cache entry",
		"key", truncateKey(me.key),
		"size", len(me.data),
		"policy", m.evictPolicy,
	)

	m.removeElement(victim)
	m.stats.evictionCount.Add(1)
	return true
}

// copyMetadata creates a deep copy of metadata.
func (m *MemoryStorage) copyMetadata(meta *Metadata) *Metadata {
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

// CleanupExpired removes all expired entries.
func (m *MemoryStorage) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expired []*list.Element
	now := time.Now()

	for elem := m.lruList.Front(); elem != nil; elem = elem.Next() {
		me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
		if now.After(me.metadata.ExpiresAt) {
			expired = append(expired, elem)
		}
	}

	for _, elem := range expired {
		m.removeElement(elem)
	}

	if len(expired) > 0 {
		slog.Debug("cleaned up expired cache entries",
			"count", len(expired),
		)
	}

	return len(expired)
}

// DataForKey returns a copy of the raw data for a key (for testing).
func (m *MemoryStorage) DataForKey(key string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	elem, ok := m.entries[key]
	if !ok {
		return nil, false
	}

	me := elem.Value.(*memoryEntry) //nolint:errcheck // Type is always *memoryEntry
	data := make([]byte, len(me.data))
	copy(data, me.data)
	return data, true
}

// Compile-time interface check
var _ Storage = (*MemoryStorage)(nil)

// bytesBuffer is a bytes.Buffer that implements io.ReadCloser.
type bytesBuffer struct {
	*bytes.Buffer
}

func (b *bytesBuffer) Close() error {
	return nil
}
