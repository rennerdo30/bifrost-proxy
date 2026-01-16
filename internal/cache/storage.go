package cache

import (
	"context"
	"errors"
	"io"
)

// Common errors for storage operations.
var (
	// ErrNotFound indicates the requested entry was not found in cache.
	ErrNotFound = errors.New("cache entry not found")

	// ErrStorageFull indicates the storage has reached its capacity limit.
	ErrStorageFull = errors.New("cache storage full")

	// ErrEntrySizeExceeded indicates the entry exceeds the maximum allowed size.
	ErrEntrySizeExceeded = errors.New("entry size exceeds maximum")

	// ErrInvalidKey indicates the cache key is invalid.
	ErrInvalidKey = errors.New("invalid cache key")

	// ErrStorageClosed indicates the storage has been closed.
	ErrStorageClosed = errors.New("storage is closed")
)

// Storage is the interface for cache storage backends.
// Implementations must be safe for concurrent access.
type Storage interface {
	// Get retrieves a cache entry by key.
	// Returns ErrNotFound if the key doesn't exist.
	Get(ctx context.Context, key string) (*Entry, error)

	// Put stores a cache entry.
	// The entry's Body will be fully consumed and the reader closed.
	// Returns ErrEntrySizeExceeded if the content is too large.
	// Returns ErrStorageFull if there's no space and eviction fails.
	Put(ctx context.Context, key string, entry *Entry) error

	// Delete removes a cache entry by key.
	// Returns nil if the key doesn't exist (idempotent).
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in the cache.
	// This is a fast check that doesn't load the content.
	Exists(ctx context.Context, key string) bool

	// GetMetadata returns only the metadata for a key (fast lookup).
	// Returns ErrNotFound if the key doesn't exist.
	GetMetadata(ctx context.Context, key string) (*Metadata, error)

	// GetRange retrieves a byte range from a cached entry.
	// Returns ErrNotFound if the key doesn't exist.
	// The returned reader must be closed by the caller.
	GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, error)

	// List returns all metadata entries, optionally filtered by domain.
	// If domain is empty, returns all entries.
	// Results are paginated using offset and limit.
	List(ctx context.Context, domain string, offset, limit int) ([]*Metadata, int64, error)

	// Clear removes all entries from the storage.
	Clear(ctx context.Context) error

	// Stats returns storage statistics.
	Stats() StorageStats

	// Start initializes the storage backend.
	// Must be called before any other operations.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the storage backend.
	// Flushes pending writes and releases resources.
	Stop(ctx context.Context) error
}

// StorageType represents the type of storage backend.
type StorageType string

const (
	// StorageTypeMemory is in-memory LRU storage.
	StorageTypeMemory StorageType = "memory"

	// StorageTypeDisk is file-based disk storage.
	StorageTypeDisk StorageType = "disk"

	// StorageTypeTiered combines memory and disk storage.
	StorageTypeTiered StorageType = "tiered"
)

// EvictionPolicy defines how entries are evicted when storage is full.
type EvictionPolicy string

const (
	// EvictionLRU evicts least recently used entries.
	EvictionLRU EvictionPolicy = "lru"

	// EvictionLFU evicts least frequently used entries.
	EvictionLFU EvictionPolicy = "lfu"

	// EvictionFIFO evicts oldest entries first.
	EvictionFIFO EvictionPolicy = "fifo"
)

// SizeReader wraps an io.Reader with size information.
type SizeReader struct {
	Reader io.Reader
	Size   int64
}

// Read implements io.Reader.
func (sr *SizeReader) Read(p []byte) (n int, err error) {
	return sr.Reader.Read(p)
}

// LimitedReadCloser wraps an io.ReadCloser with a size limit.
type LimitedReadCloser struct {
	rc        io.ReadCloser
	remaining int64
}

// NewLimitedReadCloser creates a new limited reader.
func NewLimitedReadCloser(rc io.ReadCloser, limit int64) *LimitedReadCloser {
	return &LimitedReadCloser{
		rc:        rc,
		remaining: limit,
	}
}

// Read implements io.Reader with size limiting.
func (lrc *LimitedReadCloser) Read(p []byte) (n int, err error) {
	if lrc.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > lrc.remaining {
		p = p[:lrc.remaining]
	}
	n, err = lrc.rc.Read(p)
	lrc.remaining -= int64(n)
	return n, err
}

// Close implements io.Closer.
func (lrc *LimitedReadCloser) Close() error {
	return lrc.rc.Close()
}

// NopCloser wraps an io.Reader to add a no-op Close method.
type NopCloser struct {
	io.Reader
}

// Close implements io.Closer.
func (NopCloser) Close() error { return nil }

// BytesReadCloser wraps a byte slice as an io.ReadCloser.
type BytesReadCloser struct {
	data   []byte
	offset int
}

// NewBytesReadCloser creates a new bytes reader.
func NewBytesReadCloser(data []byte) *BytesReadCloser {
	return &BytesReadCloser{data: data}
}

// Read implements io.Reader.
func (br *BytesReadCloser) Read(p []byte) (n int, err error) {
	if br.offset >= len(br.data) {
		return 0, io.EOF
	}
	n = copy(p, br.data[br.offset:])
	br.offset += n
	return n, nil
}

// Close implements io.Closer.
func (br *BytesReadCloser) Close() error {
	return nil
}

// Seek implements io.Seeker.
func (br *BytesReadCloser) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = int64(br.offset) + offset
	case io.SeekEnd:
		newOffset = int64(len(br.data)) + offset
	}
	if newOffset < 0 || newOffset > int64(len(br.data)) {
		return 0, errors.New("invalid seek position")
	}
	br.offset = int(newOffset)
	return newOffset, nil
}
