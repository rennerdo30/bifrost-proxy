package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// SizeReader Tests (storage.go:112)
// ============================================================================

func TestSizeReader_Read(t *testing.T) {
	data := []byte("test data")
	sr := &SizeReader{
		Reader: bytes.NewReader(data),
		Size:   int64(len(data)),
	}

	buf := make([]byte, 5)
	n, err := sr.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, []byte("test "), buf)

	// Read remaining
	n, err = sr.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, []byte("data"), buf[:4])

	// Read at EOF
	n, err = sr.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

// ============================================================================
// BytesReadCloser Seek Edge Cases (storage.go:183)
// ============================================================================

func TestBytesReadCloser_SeekEdgeCases(t *testing.T) {
	data := []byte("0123456789")
	brc := NewBytesReadCloser(data)

	// SeekCurrent
	brc.Read(make([]byte, 3)) // Move to position 3
	pos, err := brc.Seek(2, io.SeekCurrent)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	// SeekEnd
	pos, err = brc.Seek(-3, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(7), pos)

	// Invalid seek position (negative)
	_, err = brc.Seek(-100, io.SeekStart)
	assert.Error(t, err)

	// Invalid seek position (beyond end)
	_, err = brc.Seek(100, io.SeekStart)
	assert.Error(t, err)
}

// ============================================================================
// Disk Storage - evictOne (disk.go:514)
// ============================================================================

func TestDiskStorage_EvictOne(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-evict-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         ByteSize(100), // Very small to trigger eviction
		CleanupInterval: Duration(1 * time.Hour),
		ShardCount:      4,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	// Add entries that fill storage
	for i := 0; i < 5; i++ {
		entry := &Entry{
			Metadata: &Metadata{
				Key:        string(rune('a' + i)),
				ExpiresAt:  time.Now().Add(1 * time.Hour),
				AccessedAt: time.Now().Add(time.Duration(-i) * time.Minute), // Make "a" oldest
			},
			Body: io.NopCloser(bytes.NewReader(make([]byte, 30))),
		}
		// Need to directly add to storage to trigger eviction
		err := storage.Put(ctx, string(rune('a'+i)), entry)
		if err != nil {
			// Expected - storage full after a few entries
			break
		}
	}

	// Verify eviction happened by checking stats
	stats := storage.Stats()
	assert.Greater(t, stats.EvictionCount, int64(0))
}

// ============================================================================
// Disk Storage - loadIndex (disk.go:543)
// ============================================================================

func TestDiskStorage_LoadIndex(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-loadindex-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         ByteSize(10 * MB),
		CleanupInterval: Duration(1 * time.Hour),
		ShardCount:      16,
	}

	// First, create storage and add entries
	storage1, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage1.Start(ctx)
	require.NoError(t, err)

	// Add an entry
	entry := &Entry{
		Metadata: &Metadata{
			Key:           "persist-test",
			URL:           "http://example.com/test",
			Host:          "example.com",
			StatusCode:    200,
			ContentLength: 10,
			ContentType:   "text/plain",
			Headers:       http.Header{"Content-Type": []string{"text/plain"}},
			CacheControl:  &CacheControl{MaxAge: 3600},
			CreatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			AccessedAt:    time.Now(),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("test data!"))),
	}
	err = storage1.Put(ctx, "persist-test", entry)
	require.NoError(t, err)

	// Stop storage (saves index)
	err = storage1.Stop(ctx)
	require.NoError(t, err)

	// Create new storage and verify it loads the index
	storage2, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	err = storage2.Start(ctx)
	require.NoError(t, err)
	defer storage2.Stop(ctx)

	// Entry should be found
	assert.True(t, storage2.Exists(ctx, "persist-test"))

	got, err := storage2.Get(ctx, "persist-test")
	require.NoError(t, err)
	data, _ := io.ReadAll(got.Body)
	got.Close()
	assert.Equal(t, "test data!", string(data))
}

func TestDiskStorage_LoadIndex_OrphanedMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-orphan-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create shard directory
	shardDir := filepath.Join(tmpDir, "data", "ab")
	err = os.MkdirAll(shardDir, 0755)
	require.NoError(t, err)

	// Create orphaned .meta file (without corresponding .dat file)
	meta := &Metadata{
		Key:       "orphaned",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	metaData, _ := json.Marshal(meta)
	err = os.WriteFile(filepath.Join(shardDir, "orphaned.meta"), metaData, 0644)
	require.NoError(t, err)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         ByteSize(10 * MB),
		CleanupInterval: Duration(1 * time.Hour),
		ShardCount:      256,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	// Orphaned entry should have been cleaned up
	assert.False(t, storage.Exists(ctx, "orphaned"))
}

func TestDiskStorage_LoadIndex_ExpiredEntry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-expired-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create shard directory
	shardDir := filepath.Join(tmpDir, "data", "ex")
	err = os.MkdirAll(shardDir, 0755)
	require.NoError(t, err)

	// Create expired .meta file with corresponding .dat file
	meta := &Metadata{
		Key:       "expired",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
	}
	metaData, _ := json.Marshal(meta)
	err = os.WriteFile(filepath.Join(shardDir, "expired.meta"), metaData, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(shardDir, "expired.dat"), []byte("data"), 0644)
	require.NoError(t, err)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         ByteSize(10 * MB),
		CleanupInterval: Duration(1 * time.Hour),
		ShardCount:      256,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	// Expired entry should have been cleaned up during load
	assert.False(t, storage.Exists(ctx, "expired"))
}

func TestDiskStorage_LoadIndex_InvalidMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-invalid-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create shard directory
	shardDir := filepath.Join(tmpDir, "data", "iv")
	err = os.MkdirAll(shardDir, 0755)
	require.NoError(t, err)

	// Create invalid .meta file
	err = os.WriteFile(filepath.Join(shardDir, "invalid.meta"), []byte("not json"), 0644)
	require.NoError(t, err)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         ByteSize(10 * MB),
		CleanupInterval: Duration(1 * time.Hour),
		ShardCount:      256,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	// Should not have loaded invalid entry
	stats := storage.Stats()
	assert.Equal(t, int64(0), stats.Entries)
}

// ============================================================================
// Disk Storage - copyMetadata (disk.go:660)
// ============================================================================

func TestDiskStorage_CopyMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-copymeta-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: ByteSize(10 * MB),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entry with headers and cache control
	entry := &Entry{
		Metadata: &Metadata{
			Key:          "copymeta-test",
			Headers:      http.Header{"X-Test": []string{"value1", "value2"}},
			CacheControl: &CacheControl{MaxAge: 3600, Public: true},
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("data"))),
	}
	storage.Put(ctx, "copymeta-test", entry)

	// Get the entry (which uses copyMetadata)
	got, err := storage.Get(ctx, "copymeta-test")
	require.NoError(t, err)
	defer got.Close()

	// Verify headers were copied
	assert.Equal(t, []string{"value1", "value2"}, got.Metadata.Headers["X-Test"])

	// Verify cache control was copied
	assert.Equal(t, 3600, got.Metadata.CacheControl.MaxAge)
	assert.True(t, got.Metadata.CacheControl.Public)
}

func TestDiskStorage_CopyMetadataNil(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-nilmeta-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: ByteSize(10 * MB),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	// Test nil metadata handling
	result := storage.copyMetadata(nil)
	assert.Nil(t, result)
}

// ============================================================================
// Disk Storage - shardForKey edge case (disk.go:487)
// ============================================================================

func TestDiskStorage_ShardForKeyShort(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-shard-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:       tmpDir,
		MaxSize:    ByteSize(10 * MB),
		ShardCount: 256,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	// Test with very short key (less than 2 chars)
	shard := storage.shardForKey("a")
	assert.NotEmpty(t, shard)

	// Should use hash fallback
	assert.Len(t, shard, 2)
}

// ============================================================================
// Disk Storage - Closed operations (disk.go)
// ============================================================================

func TestDiskStorage_Closed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-closed-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: ByteSize(10 * MB),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	storage.Stop(ctx)

	// Operations on closed storage should fail
	_, err = storage.Get(ctx, "test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	entry := &Entry{
		Metadata: &Metadata{Key: "test", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	err = storage.Put(ctx, "test", entry)
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = storage.Delete(ctx, "test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	assert.False(t, storage.Exists(ctx, "test"))

	_, err = storage.GetMetadata(ctx, "test")
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = storage.GetRange(ctx, "test", 0, 10)
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, _, err = storage.List(ctx, "", 0, 0)
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = storage.Clear(ctx)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// ============================================================================
// Disk Storage - Get with missing data file (disk.go:153)
// ============================================================================

func TestDiskStorage_GetMissingDataFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-missing-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: ByteSize(10 * MB),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add an entry
	entry := &Entry{
		Metadata: &Metadata{
			Key:       "missing-data",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("data"))),
	}
	storage.Put(ctx, "missing-data", entry)

	// Manually delete the data file to simulate corruption
	dataPath := storage.dataFilePath("missing-data")
	os.Remove(dataPath)

	// Get should return ErrNotFound and clean up the index
	_, err = storage.Get(ctx, "missing-data")
	assert.ErrorIs(t, err, ErrNotFound)
}

// ============================================================================
// Disk Storage - GetRange with expired entry (disk.go:336)
// ============================================================================

func TestDiskStorage_GetRangeExpired(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-range-expired-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: ByteSize(10 * MB),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add an entry that's already expired
	entry := &Entry{
		Metadata: &Metadata{
			Key:       "expired-range",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("data"))),
	}
	storage.Put(ctx, "expired-range", entry)

	// GetRange should fail for expired entry
	_, err = storage.GetRange(ctx, "expired-range", 0, 2)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ============================================================================
// Disk Storage - GetMetadata expired (disk.go:315)
// ============================================================================

func TestDiskStorage_GetMetadataExpired(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-meta-expired-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: ByteSize(10 * MB),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add an entry that's already expired
	entry := &Entry{
		Metadata: &Metadata{
			Key:       "expired-meta",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("data"))),
	}
	storage.Put(ctx, "expired-meta", entry)

	// GetMetadata should fail for expired entry
	_, err = storage.GetMetadata(ctx, "expired-meta")
	assert.ErrorIs(t, err, ErrNotFound)
}

// ============================================================================
// Memory Storage - copyMetadata nil (memory.go:446)
// ============================================================================

func TestMemoryStorage_CopyMetadataNil(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    ByteSize(10 * MB),
		MaxEntries: 100,
	})

	// Test nil metadata handling
	result := storage.copyMetadata(nil)
	assert.Nil(t, result)
}

// ============================================================================
// Memory Storage - GetRange edge cases (memory.go:252)
// ============================================================================

func TestMemoryStorage_GetRangeEdgeCases(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    ByteSize(10 * MB),
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entry
	entry := &Entry{
		Metadata: &Metadata{
			Key:       "range-test",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("0123456789"))),
	}
	storage.Put(ctx, "range-test", entry)

	t.Run("negative start", func(t *testing.T) {
		reader, err := storage.GetRange(ctx, "range-test", -5, 5)
		require.NoError(t, err)
		data, _ := io.ReadAll(reader)
		reader.Close()
		assert.Equal(t, "012345", string(data))
	})

	t.Run("end beyond data", func(t *testing.T) {
		reader, err := storage.GetRange(ctx, "range-test", 5, 100)
		require.NoError(t, err)
		data, _ := io.ReadAll(reader)
		reader.Close()
		assert.Equal(t, "56789", string(data))
	})

	t.Run("start beyond data", func(t *testing.T) {
		_, err := storage.GetRange(ctx, "range-test", 100, 200)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("start greater than end", func(t *testing.T) {
		_, err := storage.GetRange(ctx, "range-test", 5, 2)
		assert.Equal(t, io.EOF, err)
	})
}

// ============================================================================
// Cache Manager - NewManager edge cases (cache.go:41)
// ============================================================================

func TestNewManager_NilConfig(t *testing.T) {
	manager, err := NewManager(nil)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestNewManager_InvalidRuleConfig(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:    "invalid",
				Domains: []string{"*.example.com"},
				Enabled: true,
				// This is actually valid, but let's test edge cases
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestNewManager_UnknownPreset(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Presets: []string{"unknown_preset", "steam"}, // First is unknown
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestNewManager_DiskStorage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "manager-disk-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "disk",
			Disk: &DiskConfig{
				Path:    tmpDir,
				MaxSize: ByteSize(10 * MB),
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestNewManager_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "invalid_type",
		},
	}

	_, err := NewManager(cfg)
	assert.Error(t, err)
}

// ============================================================================
// Cache Manager - Start/Stop error paths (cache.go:106, 129)
// ============================================================================

func TestManager_StartStop_AlreadyRunning(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start twice
	err = manager.Start(ctx)
	require.NoError(t, err)

	err = manager.Start(ctx) // Second start should be no-op
	assert.NoError(t, err)

	// Stop twice
	err = manager.Stop(ctx)
	require.NoError(t, err)

	err = manager.Stop(ctx) // Second stop should be no-op
	assert.NoError(t, err)
}

// ============================================================================
// Cache Manager - Put edge cases (cache.go:207)
// ============================================================================

func TestManager_Put_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled: false,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	req := createTestRequest("GET", "http://example.com/test")
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just no-op
}

func TestManager_Put_NoMatchingRule(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		// No presets or rules
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://example.com/test")
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just no-op
}

func TestManager_Put_ContentTypeMismatch(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:         "images",
				Domains:      []string{"*.example.com"},
				Enabled:      true,
				ContentTypes: []string{"image/*"}, // Only images
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test.txt")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/plain"}}, // Not an image
		ContentLength: 4,
	}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just not cached
}

func TestManager_Put_ContentTooLarge(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		MaxFileSize: ByteSize(10), // Very small
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:    "test",
				Domains: []string{"*.example.com"},
				Enabled: true,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{},
		ContentLength: 100, // Larger than max
	}
	body := io.NopCloser(bytes.NewReader(make([]byte, 100)))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just not cached
}

func TestManager_Put_RuleMaxSize(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:    "test",
				Domains: []string{"*.example.com"},
				Enabled: true,
				MaxSize: ByteSize(10), // Very small rule limit
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{},
		ContentLength: 100, // Larger than rule max
	}
	body := io.NopCloser(bytes.NewReader(make([]byte, 100)))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just not cached
}

func TestManager_Put_NoStore(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:                "test",
				Domains:             []string{"*.example.com"},
				Enabled:             true,
				RespectCacheControl: true,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Cache-Control": []string{"no-store"}},
	}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just not cached
}

func TestManager_Put_Private(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:                "test",
				Domains:             []string{"*.example.com"},
				Enabled:             true,
				RespectCacheControl: true,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Cache-Control": []string{"private"}},
	}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just not cached
}

func TestManager_Put_WithMaxAge(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(24 * time.Hour),
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:                "test",
				Domains:             []string{"*.example.com"},
				Enabled:             true,
				RespectCacheControl: true,
				TTL:                 Duration(48 * time.Hour), // Rule TTL
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Cache-Control": []string{"max-age=3600"}}, // 1 hour, shorter
	}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	assert.NoError(t, err)

	// Entry should be cached with shorter TTL
	entry, err := manager.Get(ctx, req)
	require.NoError(t, err)
	entry.Close()
}

func TestManager_Put_StripHeaders(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:         "test",
				Domains:      []string{"*.example.com"},
				Enabled:      true,
				StripHeaders: []string{"X-Custom-Header"},
			},
		},
		DefaultTTL: Duration(1 * time.Hour),
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":    []string{"text/plain"},
			"X-Custom-Header": []string{"should be stripped"},
		},
	}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	require.NoError(t, err)

	entry, err := manager.Get(ctx, req)
	require.NoError(t, err)
	defer entry.Close()

	// Custom header should be stripped
	assert.Empty(t, entry.Metadata.Headers["X-Custom-Header"])
}

func TestManager_Put_WithLastModified(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Rules: []RuleConfig{
			{
				Name:    "test",
				Domains: []string{"*.example.com"},
				Enabled: true,
			},
		},
		DefaultTTL: Duration(1 * time.Hour),
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	lastModified := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	req := createTestRequest("GET", "http://cdn.example.com/test")
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Last-Modified": []string{lastModified.Format(http.TimeFormat)},
		},
	}
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	err = manager.Put(ctx, req, resp, body)
	require.NoError(t, err)

	entry, err := manager.Get(ctx, req)
	require.NoError(t, err)
	defer entry.Close()

	assert.Equal(t, lastModified.Unix(), entry.Metadata.LastModified.Unix())
}

// ============================================================================
// Cache Manager - Reload edge cases (cache.go:385)
// ============================================================================

func TestManager_Reload_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	// Reload with invalid config
	invalidCfg := &Config{
		Enabled: true,
		Storage: StorageConfig{Type: "invalid"},
	}
	err = manager.Reload(invalidCfg)
	assert.Error(t, err)
}

func TestManager_Reload_WithUnknownPreset(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	// Reload with unknown preset
	newCfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Presets: []string{"unknown_preset"},
	}
	err = manager.Reload(newCfg)
	assert.NoError(t, err) // Should skip unknown preset
}

// ============================================================================
// Config - Duration/ByteSize unmarshal edge cases
// ============================================================================

func TestDuration_UnmarshalYAML_Error(t *testing.T) {
	var d Duration
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "invalid_duration"}
	err := d.UnmarshalYAML(node)
	assert.Error(t, err)
}

func TestDuration_UnmarshalJSON_Error(t *testing.T) {
	var d Duration
	err := d.UnmarshalJSON([]byte(`"invalid_duration"`))
	assert.Error(t, err)
}

func TestByteSize_UnmarshalYAML_Error(t *testing.T) {
	var b ByteSize
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "invalid_size"}
	err := b.UnmarshalYAML(node)
	assert.Error(t, err)
}

func TestByteSize_UnmarshalJSON_Error(t *testing.T) {
	var b ByteSize
	err := b.UnmarshalJSON([]byte(`"invalid_size"`))
	assert.Error(t, err)

	// Test with invalid JSON
	err = b.UnmarshalJSON([]byte(`not_valid_json`))
	assert.Error(t, err)
}

// ============================================================================
// Config - Validate edge cases
// ============================================================================

func TestConfig_Validate_MemoryMissing(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "memory",
			// Memory config is nil
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memory storage config required")
}

func TestConfig_Validate_DiskMissing(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "disk",
			// Disk config is nil
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disk storage config required")
}

func TestConfig_Validate_TieredDiskPathMissing(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "tiered",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
			Disk:   &DiskConfig{Path: ""}, // Empty path
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disk storage path is required")
}

// ============================================================================
// Key Generator - edge cases
// ============================================================================

func TestKeyGenerator_GenerateKey_EmptyHost(t *testing.T) {
	kg := DefaultKeyGenerator()

	req := &http.Request{
		Method: "GET",
		URL:    nil,
		Host:   "",
	}

	key := kg.GenerateKey(req)
	assert.NotEmpty(t, key)
}

func TestKeyGenerator_GenerateKey_NoSortQuery(t *testing.T) {
	kg := &KeyGenerator{
		SortQueryParams: false,
	}

	req := createTestRequest("GET", "http://example.com/path?b=2&a=1")

	key := kg.GenerateKey(req)
	assert.NotEmpty(t, key)
}

func TestKeyGenerator_SortedQuery_Empty(t *testing.T) {
	kg := DefaultKeyGenerator()

	result := kg.sortedQuery(nil)
	assert.Empty(t, result)
}

// ============================================================================
// Range - ParseRangeSpec edge cases
// ============================================================================

func TestParseRangeSpec_EmptyRangePart(t *testing.T) {
	spec, err := ParseRangeSpec("bytes=0-100,,200-300", 1000)
	require.NoError(t, err)
	assert.Len(t, spec.Ranges, 2) // Empty part skipped
}

func TestParseRangeSpec_EmptySpec(t *testing.T) {
	spec, err := ParseRangeSpec("bytes=", 1000)
	assert.Error(t, err)
	assert.Nil(t, spec)
}

func TestParseSingleRange_SuffixZero(t *testing.T) {
	_, err := parseSingleRange("-0", 1000)
	assert.Error(t, err)
}

func TestParseSingleRange_StartNegative(t *testing.T) {
	_, err := parseSingleRange("-10-5", 1000)
	assert.Error(t, err)
}

// ============================================================================
// Range - NewRangeReader error
// ============================================================================

type errorSeeker struct {
	io.Reader
}

func (e *errorSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestNewRangeReader_SeekError(t *testing.T) {
	_, err := NewRangeReader(&errorSeeker{}, 10, 20)
	assert.Error(t, err)
}

// ============================================================================
// Validator - ShouldCache edge cases
// ============================================================================

func TestValidator_ShouldCache_AuthorizationWithPublic(t *testing.T) {
	v := NewValidator()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Cache-Control": []string{"public"}},
	}

	// With public directive, should be cacheable
	assert.True(t, v.ShouldCache(req, resp))
}

func TestValidator_ShouldCache_RequestNoStore(t *testing.T) {
	v := NewValidator()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Cache-Control", "no-store")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}

	assert.False(t, v.ShouldCache(req, resp))
}

// ============================================================================
// Validator - BuildConditionalRequest edge cases
// ============================================================================

func TestValidator_BuildConditionalRequest_NilEntry(t *testing.T) {
	v := NewValidator()
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	v.BuildConditionalRequest(req, nil)
	assert.Empty(t, req.Header.Get("If-None-Match"))
}

func TestValidator_BuildConditionalRequest_NoETagNoLastModified(t *testing.T) {
	v := NewValidator()
	entry := &Entry{
		Metadata: &Metadata{},
	}
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	v.BuildConditionalRequest(req, entry)
	assert.Empty(t, req.Header.Get("If-None-Match"))
	assert.Empty(t, req.Header.Get("If-Modified-Since"))
}

// ============================================================================
// Validator - HandleConditionalResponse with updated ETag
// ============================================================================

func TestValidator_HandleConditionalResponse_UpdatedETag(t *testing.T) {
	v := NewValidator()
	entry := &Entry{
		Metadata: &Metadata{
			ETag: "old-etag",
		},
	}
	resp := &http.Response{
		StatusCode: 304,
		Header:     make(http.Header),
	}
	resp.Header.Set("ETag", "new-etag")

	valid := v.HandleConditionalResponse(entry, resp)
	assert.True(t, valid)
	assert.Equal(t, "new-etag", entry.Metadata.ETag)
}

// ============================================================================
// Rules - Match edge cases
// ============================================================================

func TestRuleSet_Match_DisabledRule(t *testing.T) {
	rs := NewRuleSet()

	rule, _ := NewRuleFromConfig(RuleConfig{
		Name:    "disabled",
		Domains: []string{"*.example.com"},
		Enabled: false, // Disabled
	})
	rs.Add(rule)

	req := createTestRequest("GET", "http://cdn.example.com/test")
	matched := rs.Match(req)
	assert.Nil(t, matched)
}

func TestRuleSet_Match_NoMatcher(t *testing.T) {
	rs := NewRuleSet()

	// Rule with nil matcher
	rule := &Rule{
		Name:    "no-matcher",
		Enabled: true,
		Matcher: nil,
	}
	rs.Add(rule)

	req := createTestRequest("GET", "http://example.com/test")
	matched := rs.Match(req)
	// Should match since no matcher means all domains
	assert.NotNil(t, matched)
	assert.Equal(t, "no-matcher", matched.Name)
}

func TestRuleSet_Match_EmptyHost(t *testing.T) {
	rs := NewRuleSet()

	rule, _ := NewRuleFromConfig(RuleConfig{
		Name:    "test",
		Domains: []string{"*"},
		Enabled: true,
	})
	rs.Add(rule)

	req := &http.Request{
		Method: "GET",
		Host:   "",
		URL:    &url.URL{Host: "example.com"}, // Provide URL fallback
	}
	matched := rs.Match(req)
	// Should use URL host as fallback
	assert.NotNil(t, matched)
}

func TestRuleSet_MatchHost_Disabled(t *testing.T) {
	rs := NewRuleSet()

	rule, _ := NewRuleFromConfig(RuleConfig{
		Name:    "disabled",
		Domains: []string{"*.example.com"},
		Enabled: false,
	})
	rs.Add(rule)

	matched := rs.MatchHost("cdn.example.com")
	assert.Nil(t, matched)
}

// ============================================================================
// Rule - MatchesContentType edge cases
// ============================================================================

func TestRule_MatchesContentType_Wildcard(t *testing.T) {
	rule := &Rule{
		ContentTypes: []string{"*"},
	}
	assert.True(t, rule.MatchesContentType("anything"))
}

func TestRule_MatchesContentType_StarStar(t *testing.T) {
	rule := &Rule{
		ContentTypes: []string{"*/*"},
	}
	assert.True(t, rule.MatchesContentType("application/json"))
}

// ============================================================================
// Rule - MatchesMethod edge cases
// ============================================================================

func TestRule_MatchesMethod_ExplicitMethods(t *testing.T) {
	rule := &Rule{
		Methods: []string{"GET", "HEAD"},
	}

	assert.True(t, rule.MatchesMethod("GET"))
	assert.True(t, rule.MatchesMethod("get")) // Case insensitive
	assert.True(t, rule.MatchesMethod("HEAD"))
	assert.False(t, rule.MatchesMethod("POST"))
}

// ============================================================================
// LoadRulesFromConfig error
// ============================================================================

// Note: NewRuleFromConfig doesn't currently return errors for valid configs,
// but we test the success path
func TestLoadRulesFromConfig_Success(t *testing.T) {
	configs := []RuleConfig{
		{Name: "rule1", Domains: []string{"*.example.com"}, Enabled: true},
	}

	rs, err := LoadRulesFromConfig(configs)
	require.NoError(t, err)
	assert.Len(t, rs.All(), 1)
}

// ============================================================================
// Tiered Storage - edge cases
// ============================================================================

func TestTieredStorage_PutNilEntry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-nil-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage, err := NewTieredStorage(
		nil, // Use defaults
		&MemoryConfig{MaxSize: ByteSize(1 * MB)},
		&DiskConfig{Path: tmpDir, MaxSize: ByteSize(10 * MB)},
	)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	err = storage.Put(ctx, "test", nil)
	assert.Error(t, err)
}

func TestTieredStorage_PutNilMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-nilmeta-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage, err := NewTieredStorage(
		nil,
		&MemoryConfig{MaxSize: ByteSize(1 * MB)},
		&DiskConfig{Path: tmpDir, MaxSize: ByteSize(10 * MB)},
	)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	entry := &Entry{
		Metadata: nil,
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	err = storage.Put(ctx, "test", entry)
	assert.Error(t, err)
}

func TestTieredStorage_ListEmpty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-listempty-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage, err := NewTieredStorage(
		nil,
		&MemoryConfig{MaxSize: ByteSize(1 * MB)},
		&DiskConfig{Path: tmpDir, MaxSize: ByteSize(10 * MB)},
	)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// List with offset beyond entries
	list, total, err := storage.List(ctx, "", 100, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Len(t, list, 0)
}

func TestTieredStorage_GetRangeFallbackToDisk(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-range-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage, err := NewTieredStorage(
		&TieredConfig{MemoryThreshold: ByteSize(10)}, // Very small threshold
		&MemoryConfig{MaxSize: ByteSize(1 * MB)},
		&DiskConfig{Path: tmpDir, MaxSize: ByteSize(10 * MB)},
	)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add large entry (goes to disk)
	entry := &Entry{
		Metadata: &Metadata{Key: "disk-entry", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader(make([]byte, 100))),
	}
	storage.Put(ctx, "disk-entry", entry)

	// GetRange should fallback to disk
	reader, err := storage.GetRange(ctx, "disk-entry", 0, 10)
	require.NoError(t, err)
	reader.Close()
}

func TestTieredStorage_GetMetadataFallbackToDisk(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-meta-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage, err := NewTieredStorage(
		&TieredConfig{MemoryThreshold: ByteSize(10)},
		&MemoryConfig{MaxSize: ByteSize(1 * MB)},
		&DiskConfig{Path: tmpDir, MaxSize: ByteSize(10 * MB)},
	)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add large entry (goes to disk)
	entry := &Entry{
		Metadata: &Metadata{Key: "disk-meta", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader(make([]byte, 100))),
	}
	storage.Put(ctx, "disk-meta", entry)

	// GetMetadata should fallback to disk
	meta, err := storage.GetMetadata(ctx, "disk-meta")
	require.NoError(t, err)
	assert.NotNil(t, meta)
}

// ============================================================================
// Interceptor - serveRangeRequest edge cases
// ============================================================================

func TestInterceptor_ServeRangeRequest_InvalidRange(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(1 * time.Hour),
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	// Put an entry
	req := createTestRequest("GET", "http://cdn.steamcontent.com/depot/123/chunk")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: 11,
	}
	body := io.NopCloser(bytes.NewReader([]byte("hello world")))
	manager.Put(ctx, req, resp, body)

	// Request with invalid range
	req.Header.Set("Range", "invalid_range")

	clientConn, serverConn := createPipeConn(t)
	defer clientConn.Close()
	defer serverConn.Close()

	// This should fall back to serving full content
	go io.Copy(io.Discard, clientConn)

	handled, err := interceptor.HandleRequest(ctx, serverConn, req)
	serverConn.Close()
	assert.NoError(t, err)
	assert.True(t, handled)
}

func TestInterceptor_ServeRangeRequest_MultipleRanges(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(1 * time.Hour),
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	// Put an entry
	req := createTestRequest("GET", "http://cdn.steamcontent.com/depot/123/chunk")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: 100,
	}
	body := io.NopCloser(bytes.NewReader(make([]byte, 100)))
	manager.Put(ctx, req, resp, body)

	// Request with multiple ranges (not supported, falls back to full)
	req.Header.Set("Range", "bytes=0-10, 20-30")

	clientConn, serverConn := createPipeConn(t)
	defer clientConn.Close()
	defer serverConn.Close()

	// Drain response
	go io.Copy(io.Discard, clientConn)

	handled, err := interceptor.HandleRequest(ctx, serverConn, req)
	serverConn.Close()
	assert.NoError(t, err)
	assert.True(t, handled)
}

// ============================================================================
// ResponseWriter - WriteHeader already called
// ============================================================================

func TestResponseWriter_WriteHeaderTwice(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: ByteSize(10 * MB)},
		},
	}

	manager, _ := NewManager(cfg)
	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	clientConn, serverConn := createPipeConn(t)
	defer clientConn.Close()
	defer serverConn.Close()

	req := createTestRequest("GET", "http://example.com/test")
	rw := interceptor.NewResponseWriter(serverConn, req)

	rw.WriteHeader(200)
	rw.WriteHeader(404) // Second call should be ignored

	assert.Equal(t, 200, rw.statusCode)
}

// ============================================================================
// parseDirectiveValue edge cases (entry.go:154)
// ============================================================================

func TestParseDirectiveValue_NoPrefix(t *testing.T) {
	var value int
	ok, err := parseDirectiveValue("other=3600", "max-age=", &value)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, value)
}

// ============================================================================
// CoalesceRanges edge cases
// ============================================================================

func TestCoalesceRanges_Empty(t *testing.T) {
	result := CoalesceRanges([]ByteRange{})
	assert.Empty(t, result)
}

func TestCoalesceRanges_Single(t *testing.T) {
	result := CoalesceRanges([]ByteRange{{0, 100}})
	assert.Len(t, result, 1)
}

func TestCoalesceRanges_Adjacent(t *testing.T) {
	result := CoalesceRanges([]ByteRange{{0, 100}, {101, 200}})
	assert.Len(t, result, 1)
	assert.Equal(t, ByteRange{0, 200}, result[0])
}

// ============================================================================
// Disk Storage - NewDiskStorage errors
// ============================================================================

func TestNewDiskStorage_NilConfig(t *testing.T) {
	_, err := NewDiskStorage(nil)
	assert.Error(t, err)
}

func TestNewDiskStorage_EmptyPath(t *testing.T) {
	_, err := NewDiskStorage(&DiskConfig{Path: ""})
	assert.Error(t, err)
}

func TestNewDiskStorage_DefaultShardCount(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-default-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:       tmpDir,
		MaxSize:    ByteSize(10 * MB),
		ShardCount: 0, // Should default to 256
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.Equal(t, 256, storage.shardCount)
}

func TestNewDiskStorage_DefaultCleanupInterval(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-cleanup-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         ByteSize(10 * MB),
		CleanupInterval: 0, // Should default to 1 hour
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.Equal(t, 1*time.Hour, storage.cleanupInterval)
}

// ============================================================================
// Memory Storage - NewMemoryStorage with nil config
// ============================================================================

func TestNewMemoryStorage_NilConfig(t *testing.T) {
	storage := NewMemoryStorage(nil)
	assert.NotNil(t, storage)
	// Should use defaults
	assert.Equal(t, int64(256*1024*1024), storage.maxSize) // 256MB
	assert.Equal(t, 10000, storage.maxEntries)
}

// ============================================================================
// Memory Storage - Put nil entry
// ============================================================================

func TestMemoryStorage_PutNilEntry(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{MaxSize: ByteSize(10 * MB)})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	err := storage.Put(ctx, "test", nil)
	assert.Error(t, err)
}

func TestMemoryStorage_PutNilMetadata(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{MaxSize: ByteSize(10 * MB)})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	entry := &Entry{Metadata: nil}
	err := storage.Put(ctx, "test", entry)
	assert.Error(t, err)
}

// ============================================================================
// Memory Storage - Put replaces existing
// ============================================================================

func TestMemoryStorage_PutReplaceExisting(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{MaxSize: ByteSize(10 * MB)})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// First put
	entry1 := &Entry{
		Metadata: &Metadata{Key: "replace", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("first"))),
	}
	storage.Put(ctx, "replace", entry1)

	// Second put with same key
	entry2 := &Entry{
		Metadata: &Metadata{Key: "replace", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("second"))),
	}
	storage.Put(ctx, "replace", entry2)

	// Get and verify
	got, err := storage.Get(ctx, "replace")
	require.NoError(t, err)
	data, _ := io.ReadAll(got.Body)
	got.Close()
	assert.Equal(t, "second", string(data))
}

// ============================================================================
// Memory Storage - List with limit=0 returns all
// ============================================================================

func TestMemoryStorage_ListNoLimit(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{MaxSize: ByteSize(10 * MB)})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entries
	for i := 0; i < 5; i++ {
		entry := &Entry{
			Metadata: &Metadata{Key: string(rune('a' + i)), ExpiresAt: time.Now().Add(1 * time.Hour)},
			Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
		}
		storage.Put(ctx, string(rune('a'+i)), entry)
	}

	// List with limit=0 (no limit)
	list, total, err := storage.List(ctx, "", 0, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, list, 5)
}

// ============================================================================
// Validator edge cases
// ============================================================================

func TestValidator_CalculateFreshness_Expired(t *testing.T) {
	v := NewValidator()
	entry := &Entry{
		Metadata: &Metadata{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		},
	}

	freshness := v.CalculateFreshness(entry)
	assert.Equal(t, time.Duration(0), freshness)
}

// ============================================================================
// Helper function
// ============================================================================

func createPipeConn(t *testing.T) (clientConn, serverConn *pipeConn) {
	client, server, err := createPipe()
	require.NoError(t, err)
	return client, server
}

type pipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeConn) Read(b []byte) (n int, err error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (n int, err error) { return p.w.Write(b) }
func (p *pipeConn) Close() error {
	p.r.Close()
	p.w.Close()
	return nil
}
func (p *pipeConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }
func (p *pipeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

func createPipe() (*pipeConn, *pipeConn, error) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &pipeConn{r: r1, w: w2}, &pipeConn{r: r2, w: w1}, nil
}

// ============================================================================
// bytesBuffer.Close test (memory.go:522)
// ============================================================================

func TestBytesBuffer_Close(t *testing.T) {
	buf := &bytesBuffer{Buffer: bytes.NewBuffer([]byte("test data"))}
	err := buf.Close()
	assert.NoError(t, err)
}
