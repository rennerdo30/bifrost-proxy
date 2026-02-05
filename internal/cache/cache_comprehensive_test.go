package cache

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// Cache Manager Tests
// ============================================================================

func TestManager_GetPut(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(24 * time.Hour),
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize:    10 * MB,
				MaxEntries: 100,
			},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, manager.Start(ctx))
	defer manager.Stop(ctx)

	t.Run("put and get", func(t *testing.T) {
		req := createTestRequest("GET", "http://cdn.steamcontent.com/depot/123/chunk")
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type":   []string{"application/octet-stream"},
				"Content-Length": []string{"11"},
			},
			ContentLength: 11,
		}
		body := io.NopCloser(bytes.NewReader([]byte("hello world")))

		err := manager.Put(ctx, req, resp, body)
		require.NoError(t, err)

		entry, err := manager.Get(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, entry)
		entry.Close()
	})

	t.Run("get miss", func(t *testing.T) {
		req := createTestRequest("GET", "http://cdn.steamcontent.com/nonexistent")
		_, err := manager.Get(ctx, req)
		assert.Error(t, err)
	})

	t.Run("get when disabled", func(t *testing.T) {
		disabledCfg := &Config{
			Enabled: false,
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 10 * MB},
			},
		}
		disabledMgr, err := NewManager(disabledCfg)
		require.NoError(t, err)
		req := createTestRequest("GET", "http://example.com/test")
		_, err = disabledMgr.Get(ctx, req)
		assert.Error(t, err)
	})
}

func TestManager_DeleteClear(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize:    10 * MB,
				MaxEntries: 100,
			},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, manager.Start(ctx))
	defer manager.Stop(ctx)

	// Put an entry
	req := createTestRequest("GET", "http://cdn.steamcontent.com/test")
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: 4}
	body := io.NopCloser(bytes.NewReader([]byte("test")))
	manager.Put(ctx, req, resp, body)

	key := manager.KeyFor(req)

	t.Run("delete", func(t *testing.T) {
		err := manager.Delete(ctx, key)
		assert.NoError(t, err)
	})

	t.Run("clear", func(t *testing.T) {
		// Put again
		body := io.NopCloser(bytes.NewReader([]byte("test")))
		manager.Put(ctx, req, resp, body)

		err := manager.Clear(ctx)
		assert.NoError(t, err)
	})
}

func TestManager_Stats(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize:    10 * MB,
				MaxEntries: 100,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	stats := manager.Stats()
	assert.True(t, stats.Enabled)
	assert.Equal(t, "memory", stats.StorageType)
}

func TestManager_RulesStorage(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize: 10 * MB,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	assert.NotNil(t, manager.Rules())
	assert.NotNil(t, manager.Storage())
	assert.NotNil(t, manager.GetKeyGenerator())
}

func TestManager_Reload(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize: 10 * MB,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	newCfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(48 * time.Hour),
		Storage: StorageConfig{
			Type: "memory",
			Memory: &MemoryConfig{
				MaxSize: 20 * MB,
			},
		},
		Presets: []string{"steam"},
	}

	err = manager.Reload(newCfg)
	assert.NoError(t, err)
}

func TestManager_KeyFor(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, _ := NewManager(cfg)
	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	req := createTestRequest("GET", "http://cdn.steamcontent.com/test")
	key := manager.KeyFor(req)
	assert.NotEmpty(t, key)
}

func TestManager_PutNotCacheable(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, _ := NewManager(cfg)
	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	// 404 response should not be cached
	req := createTestRequest("GET", "http://cdn.steamcontent.com/test")
	resp := &http.Response{StatusCode: 404, Header: http.Header{}}
	body := io.NopCloser(bytes.NewReader([]byte("not found")))

	err := manager.Put(ctx, req, resp, body)
	assert.NoError(t, err) // No error, just not stored
}

func TestIsSensitiveHeader(t *testing.T) {
	assert.True(t, isSensitiveHeader("Authorization"))
	assert.True(t, isSensitiveHeader("cookie"))
	assert.True(t, isSensitiveHeader("Set-Cookie"))
	assert.False(t, isSensitiveHeader("Content-Type"))
	assert.False(t, isSensitiveHeader("Cache-Control"))
}

func TestCreateStorage(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		cfg := &Config{
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 10 * MB},
			},
		}
		storage, err := createStorage(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, storage)
	})

	t.Run("invalid type", func(t *testing.T) {
		cfg := &Config{
			Storage: StorageConfig{Type: "invalid"},
		}
		_, err := createStorage(cfg)
		assert.Error(t, err)
	})
}

// ============================================================================
// Config Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "tiered", cfg.Storage.Type)
	assert.NotNil(t, cfg.Storage.Memory)
	assert.NotNil(t, cfg.Storage.Disk)
}

func TestConfig_ValidateDisk(t *testing.T) {
	t.Run("disk requires path", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type: "disk",
				Disk: &DiskConfig{Path: ""},
			},
		}
		assert.Error(t, cfg.Validate())
	})

	t.Run("disk valid", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type: "disk",
				Disk: &DiskConfig{Path: "/tmp/cache"},
			},
		}
		assert.NoError(t, cfg.Validate())
	})
}

func TestConfig_ValidateTiered(t *testing.T) {
	t.Run("tiered requires memory", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type: "tiered",
				Disk: &DiskConfig{Path: "/tmp"},
			},
		}
		assert.Error(t, cfg.Validate())
	})

	t.Run("tiered requires disk", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type:   "tiered",
				Memory: &MemoryConfig{MaxSize: 10 * MB},
			},
		}
		assert.Error(t, cfg.Validate())
	})
}

func TestConfig_ValidateRules(t *testing.T) {
	t.Run("rule without name", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 10 * MB},
			},
			Rules: []RuleConfig{
				{Domains: []string{"*.example.com"}},
			},
		}
		assert.Error(t, cfg.Validate())
	})

	t.Run("rule without domains", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 10 * MB},
			},
			Rules: []RuleConfig{
				{Name: "test"},
			},
		}
		assert.Error(t, cfg.Validate())
	})
}

func TestDuration_MarshalUnmarshal(t *testing.T) {
	t.Run("YAML marshal", func(t *testing.T) {
		d := Duration(24 * time.Hour)
		data, err := d.MarshalYAML()
		assert.NoError(t, err)
		assert.Equal(t, "24h0m0s", data)
	})

	t.Run("YAML unmarshal", func(t *testing.T) {
		var d Duration
		node := &yaml.Node{Kind: yaml.ScalarNode, Value: "24h"}
		err := d.UnmarshalYAML(node)
		assert.NoError(t, err)
		assert.Equal(t, 24*time.Hour, d.Duration())
	})

	t.Run("JSON marshal", func(t *testing.T) {
		d := Duration(1 * time.Hour)
		data, err := d.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, `"1h0m0s"`, string(data))
	})

	t.Run("JSON unmarshal", func(t *testing.T) {
		var d Duration
		err := d.UnmarshalJSON([]byte(`"1h"`))
		assert.NoError(t, err)
		assert.Equal(t, 1*time.Hour, d.Duration())
	})

	t.Run("JSON unmarshal empty", func(t *testing.T) {
		var d Duration
		err := d.UnmarshalJSON([]byte(`""`))
		assert.NoError(t, err)
		assert.Equal(t, time.Duration(0), d.Duration())
	})
}

func TestByteSize_MarshalUnmarshal(t *testing.T) {
	t.Run("YAML marshal", func(t *testing.T) {
		b := 10 * MB
		data, err := b.MarshalYAML()
		assert.NoError(t, err)
		assert.Contains(t, data.(string), "MB")
	})

	t.Run("YAML unmarshal", func(t *testing.T) {
		var b ByteSize
		node := &yaml.Node{Kind: yaml.ScalarNode, Value: "100MB"}
		err := b.UnmarshalYAML(node)
		assert.NoError(t, err)
		assert.Equal(t, int64(100*MB), b.Int64())
	})

	t.Run("JSON marshal", func(t *testing.T) {
		b := 1 * GB
		data, err := b.MarshalJSON()
		assert.NoError(t, err)
		assert.Contains(t, string(data), "GB")
	})

	t.Run("JSON unmarshal string", func(t *testing.T) {
		var b ByteSize
		err := b.UnmarshalJSON([]byte(`"500MB"`))
		assert.NoError(t, err)
		assert.Equal(t, int64(500*MB), b.Int64())
	})

	t.Run("JSON unmarshal number", func(t *testing.T) {
		var b ByteSize
		err := b.UnmarshalJSON([]byte(`1024`))
		assert.NoError(t, err)
		assert.Equal(t, int64(1024), b.Int64())
	})
}

func TestByteSize_String(t *testing.T) {
	tests := []struct {
		size   ByteSize
		expect string
	}{
		{ByteSize(500), "500B"},
		{ByteSize(1024), "1.00KB"},
		{10 * MB, "10.00MB"},
		{5 * GB, "5.00GB"},
		{2 * TB, "2.00TB"},
		{1 * PB, "1.00PB"},
	}

	for _, tc := range tests {
		t.Run(tc.expect, func(t *testing.T) {
			assert.Equal(t, tc.expect, tc.size.String())
		})
	}
}

func TestParseByteSize_Errors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		size, err := parseByteSize("")
		assert.NoError(t, err)
		assert.Equal(t, ByteSize(0), size)
	})

	t.Run("invalid unit", func(t *testing.T) {
		_, err := parseByteSize("100XB")
		assert.Error(t, err)
	})

	t.Run("invalid number", func(t *testing.T) {
		_, err := parseByteSize("abcMB")
		assert.Error(t, err)
	})
}

func TestParseDuration_Errors(t *testing.T) {
	_, err := parseDuration("invalid")
	assert.Error(t, err)
}

// ============================================================================
// Entry Tests
// ============================================================================

func TestEntry_Close(t *testing.T) {
	entry := &Entry{
		Metadata: &Metadata{},
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	err := entry.Close()
	assert.NoError(t, err)

	// Nil body
	entry2 := &Entry{Metadata: &Metadata{}}
	err = entry2.Close()
	assert.NoError(t, err)
}

func TestMetadata_IsFresh(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		m := &Metadata{ExpiresAt: time.Now().Add(1 * time.Hour)}
		assert.True(t, m.IsFresh())
	})

	t.Run("expired", func(t *testing.T) {
		m := &Metadata{ExpiresAt: time.Now().Add(-1 * time.Hour)}
		assert.False(t, m.IsFresh())
	})
}

func TestStorageStats_HitRate(t *testing.T) {
	t.Run("no requests", func(t *testing.T) {
		stats := StorageStats{HitCount: 0, MissCount: 0}
		assert.Equal(t, 0.0, stats.HitRate())
	})

	t.Run("with requests", func(t *testing.T) {
		stats := StorageStats{HitCount: 80, MissCount: 20}
		assert.Equal(t, 0.8, stats.HitRate())
	})
}

func TestTruncateKey(t *testing.T) {
	t.Run("short key", func(t *testing.T) {
		assert.Equal(t, "abc", truncateKey("abc"))
	})

	t.Run("long key", func(t *testing.T) {
		longKey := "abcdefghijklmnopqrstuvwxyz"
		assert.Equal(t, "abcdefghijklmnop...", truncateKey(longKey))
	})
}

// ============================================================================
// Key Generator Tests
// ============================================================================

func TestKeyGenerator_GenerateKeyFromURL(t *testing.T) {
	kg := DefaultKeyGenerator()

	key, err := kg.GenerateKeyFromURL("GET", "http://example.com/path?query=1")
	require.NoError(t, err)
	assert.NotEmpty(t, key)
	assert.Len(t, key, 64)

	// Test with invalid URL
	_, err = kg.GenerateKeyFromURL("GET", "://invalid")
	assert.Error(t, err)
}

func TestGenerateSimpleKey(t *testing.T) {
	key := GenerateSimpleKey("GET", "example.com", "/path")
	assert.NotEmpty(t, key)
	assert.Len(t, key, 64)

	// Same inputs should produce same key
	key2 := GenerateSimpleKey("GET", "example.com", "/path")
	assert.Equal(t, key, key2)

	// Different inputs should produce different key
	key3 := GenerateSimpleKey("POST", "example.com", "/path")
	assert.NotEqual(t, key, key3)
}

func TestKeyPrefix(t *testing.T) {
	key := "abcdef123456"

	prefix := KeyPrefix(key, 2)
	assert.Equal(t, "ab", prefix)

	prefix = KeyPrefix(key, 4)
	assert.Equal(t, "abcd", prefix)

	// Key shorter than n
	shortKey := "ab"
	prefix = KeyPrefix(shortKey, 10)
	assert.Equal(t, "ab", prefix)
}

func TestKeyGenerator_WithVaryHeaders(t *testing.T) {
	kg := &KeyGenerator{
		IncludeHeaders: []string{"Accept-Encoding"},
	}

	req1 := createTestRequest("GET", "http://example.com/path")
	req1.Header.Set("Accept-Encoding", "gzip")

	req2 := createTestRequest("GET", "http://example.com/path")
	req2.Header.Set("Accept-Encoding", "br")

	key1 := kg.GenerateKey(req1)
	key2 := kg.GenerateKey(req2)

	assert.NotEqual(t, key1, key2)
}

// ============================================================================
// Memory Storage Tests
// ============================================================================

func TestMemoryStorage_GetMetadata(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Put an entry
	entry := &Entry{
		Metadata: &Metadata{
			Key:         "meta-test",
			URL:         "http://example.com/test",
			ContentType: "text/plain",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	storage.Put(ctx, "meta-test", entry)

	t.Run("get metadata", func(t *testing.T) {
		meta, err := storage.GetMetadata(ctx, "meta-test")
		require.NoError(t, err)
		assert.Equal(t, "http://example.com/test", meta.URL)
	})

	t.Run("get metadata not found", func(t *testing.T) {
		_, err := storage.GetMetadata(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestMemoryStorage_List(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entries
	for i := 0; i < 5; i++ {
		entry := &Entry{
			Metadata: &Metadata{
				Key:       string(rune('a' + i)),
				Host:      "example.com",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("test"))),
		}
		storage.Put(ctx, string(rune('a'+i)), entry)
	}

	t.Run("list all", func(t *testing.T) {
		list, total, err := storage.List(ctx, "", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, int64(5), total)
		assert.Len(t, list, 5)
	})

	t.Run("list with domain filter", func(t *testing.T) {
		list, _, err := storage.List(ctx, "example.com", 0, 0)
		require.NoError(t, err)
		assert.Len(t, list, 5)
	})

	t.Run("list with pagination", func(t *testing.T) {
		list, total, err := storage.List(ctx, "", 1, 2)
		require.NoError(t, err)
		assert.Equal(t, int64(5), total)
		assert.Len(t, list, 2)
	})
}

func TestMemoryStorage_Clear(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entry
	entry := &Entry{
		Metadata: &Metadata{Key: "test", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	storage.Put(ctx, "test", entry)

	err := storage.Clear(ctx)
	require.NoError(t, err)

	assert.False(t, storage.Exists(ctx, "test"))
}

func TestMemoryStorage_Stats(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	stats := storage.Stats()
	assert.Equal(t, int64(0), stats.Entries)
}

func TestMemoryStorage_CleanupExpired(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add expired entry
	entry := &Entry{
		Metadata: &Metadata{Key: "expired", ExpiresAt: time.Now().Add(-1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	storage.Put(ctx, "expired", entry)

	count := storage.CleanupExpired()
	assert.Equal(t, 1, count)
}

func TestMemoryStorage_DataForKey(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entry
	entry := &Entry{
		Metadata: &Metadata{Key: "data-test", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("hello"))),
	}
	storage.Put(ctx, "data-test", entry)

	data, ok := storage.DataForKey("data-test")
	assert.True(t, ok)
	assert.Equal(t, []byte("hello"), data)

	_, ok = storage.DataForKey("nonexistent")
	assert.False(t, ok)
}

func TestMemoryStorage_LFUEviction(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:     ByteSize(100),
		MaxEntries:  3,
		EvictPolicy: "lfu",
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entries
	for i := 0; i < 3; i++ {
		entry := &Entry{
			Metadata: &Metadata{Key: string(rune('a' + i)), ExpiresAt: time.Now().Add(1 * time.Hour)},
			Body:     io.NopCloser(bytes.NewReader([]byte("x"))),
		}
		storage.Put(ctx, string(rune('a'+i)), entry)
	}

	// Access "a" multiple times
	storage.Get(ctx, "a")
	storage.Get(ctx, "a")

	// Add 4th entry
	entry := &Entry{
		Metadata: &Metadata{Key: "d", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("x"))),
	}
	storage.Put(ctx, "d", entry)

	// "a" should still exist (most frequently used)
	assert.True(t, storage.Exists(ctx, "a"))
}

func TestMemoryStorage_FIFOEviction(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:     ByteSize(100),
		MaxEntries:  3,
		EvictPolicy: "fifo",
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add entries
	for i := 0; i < 3; i++ {
		entry := &Entry{
			Metadata: &Metadata{Key: string(rune('a' + i)), ExpiresAt: time.Now().Add(1 * time.Hour)},
			Body:     io.NopCloser(bytes.NewReader([]byte("x"))),
		}
		storage.Put(ctx, string(rune('a'+i)), entry)
	}

	// Add 4th entry
	entry := &Entry{
		Metadata: &Metadata{Key: "d", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("x"))),
	}
	storage.Put(ctx, "d", entry)

	// First entry "a" should be evicted (FIFO)
	assert.False(t, storage.Exists(ctx, "a"))
}

func TestMemoryStorage_EntrySizeExceeded(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    ByteSize(10), // Very small
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	defer storage.Stop(ctx)

	entry := &Entry{
		Metadata: &Metadata{Key: "large", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader(make([]byte, 100))), // 100 bytes > 10
	}
	err := storage.Put(ctx, "large", entry)
	assert.Error(t, err)
}

func TestMemoryStorage_Closed(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    10 * MB,
		MaxEntries: 100,
	})
	ctx := context.Background()
	storage.Start(ctx)
	storage.Stop(ctx)

	// Operations on closed storage
	_, err := storage.Get(ctx, "test")
	assert.Error(t, err)

	entry := &Entry{
		Metadata: &Metadata{Key: "test", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	err = storage.Put(ctx, "test", entry)
	assert.Error(t, err)

	err = storage.Delete(ctx, "test")
	assert.Error(t, err)

	_, err = storage.GetMetadata(ctx, "test")
	assert.Error(t, err)

	_, err = storage.GetRange(ctx, "test", 0, 10)
	assert.Error(t, err)

	_, _, err = storage.List(ctx, "", 0, 0)
	assert.Error(t, err)

	err = storage.Clear(ctx)
	assert.Error(t, err)
}

// ============================================================================
// Rules Tests
// ============================================================================

func TestRuleSet_RemoveGet(t *testing.T) {
	rs := NewRuleSet()

	rule, _ := NewRuleFromConfig(RuleConfig{
		Name:    "test",
		Domains: []string{"*.example.com"},
		Enabled: true,
	})
	rs.Add(rule)

	t.Run("get existing", func(t *testing.T) {
		got := rs.Get("test")
		assert.NotNil(t, got)
		assert.Equal(t, "test", got.Name)
	})

	t.Run("get nonexistent", func(t *testing.T) {
		got := rs.Get("nonexistent")
		assert.Nil(t, got)
	})

	t.Run("remove", func(t *testing.T) {
		ok := rs.Remove("test")
		assert.True(t, ok)
		assert.Nil(t, rs.Get("test"))
	})

	t.Run("remove nonexistent", func(t *testing.T) {
		ok := rs.Remove("nonexistent")
		assert.False(t, ok)
	})
}

func TestRuleSet_MatchHost(t *testing.T) {
	rs := NewRuleSet()

	rule, _ := NewRuleFromConfig(RuleConfig{
		Name:    "test",
		Domains: []string{"*.example.com"},
		Enabled: true,
	})
	rs.Add(rule)

	t.Run("match", func(t *testing.T) {
		got := rs.MatchHost("cdn.example.com")
		assert.NotNil(t, got)
	})

	t.Run("no match", func(t *testing.T) {
		got := rs.MatchHost("other.com")
		assert.Nil(t, got)
	})

	t.Run("with port", func(t *testing.T) {
		got := rs.MatchHost("cdn.example.com:7080")
		assert.NotNil(t, got)
	})
}

func TestRuleSet_Clear(t *testing.T) {
	rs := NewRuleSet()

	rule, _ := NewRuleFromConfig(RuleConfig{
		Name:    "test",
		Domains: []string{"*.example.com"},
		Enabled: true,
	})
	rs.Add(rule)

	rs.Clear()
	assert.Empty(t, rs.All())
}

func TestRule_MatchesContentType(t *testing.T) {
	rule := &Rule{
		ContentTypes: []string{"application/json", "text/*"},
	}

	assert.True(t, rule.MatchesContentType("application/json"))
	assert.True(t, rule.MatchesContentType("application/json; charset=utf-8"))
	assert.True(t, rule.MatchesContentType("text/plain"))
	assert.True(t, rule.MatchesContentType("text/html"))
	assert.False(t, rule.MatchesContentType("application/xml"))

	// Empty content types = match all
	rule2 := &Rule{}
	assert.True(t, rule2.MatchesContentType("anything"))
}

func TestRule_ShouldStripHeader(t *testing.T) {
	rule := &Rule{
		StripHeaders: []string{"X-Custom-Header", "X-Another"},
	}

	assert.True(t, rule.ShouldStripHeader("X-Custom-Header"))
	assert.True(t, rule.ShouldStripHeader("x-custom-header"))
	assert.False(t, rule.ShouldStripHeader("Content-Type"))
}

func TestLoadRulesFromConfig(t *testing.T) {
	configs := []RuleConfig{
		{Name: "rule1", Domains: []string{"*.example.com"}, Enabled: true},
		{Name: "rule2", Domains: []string{"*.test.com"}, Enabled: true},
	}

	rs, err := LoadRulesFromConfig(configs)
	require.NoError(t, err)
	assert.Len(t, rs.All(), 2)
}

func TestRule_AddDuplicateName(t *testing.T) {
	rs := NewRuleSet()

	rule1, _ := NewRuleFromConfig(RuleConfig{
		Name:    "test",
		Domains: []string{"*.example.com"},
		Enabled: true,
	})
	rs.Add(rule1)

	rule2, _ := NewRuleFromConfig(RuleConfig{
		Name:    "test", // Same name
		Domains: []string{"*.other.com"},
		Enabled: true,
	})
	rs.Add(rule2)

	// Should replace
	assert.Len(t, rs.All(), 1)
	assert.Equal(t, []string{"*.other.com"}, rs.Get("test").Domains)
}

// ============================================================================
// Presets Tests
// ============================================================================

func TestAllPresets(t *testing.T) {
	presets := AllPresets()
	assert.NotEmpty(t, presets)
	assert.Contains(t, presets, PresetSteam)
}

func TestPresetNames(t *testing.T) {
	names := PresetNames()
	assert.NotEmpty(t, names)
	assert.Contains(t, names, PresetSteam)
}

func TestLoadPresets(t *testing.T) {
	rules := LoadPresets([]string{"steam", "epic", "unknown"})
	assert.Len(t, rules, 2) // Unknown is skipped
}

func TestGetPresetInfo(t *testing.T) {
	info := GetPresetInfo(PresetSteam)
	require.NotNil(t, info)
	assert.Equal(t, "steam", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.NotEmpty(t, info.Domains)

	// Unknown preset
	info = GetPresetInfo("unknown")
	assert.Nil(t, info)
}

func TestAllPresetInfo(t *testing.T) {
	infos := AllPresetInfo()
	assert.NotEmpty(t, infos)
}

// ============================================================================
// Range Tests
// ============================================================================

func TestByteRange_LengthContentRange(t *testing.T) {
	r := ByteRange{Start: 0, End: 499}

	assert.Equal(t, int64(500), r.Length())
	assert.Equal(t, "bytes 0-499/1000", r.ContentRange(1000))
}

func TestRangeSpec_Methods(t *testing.T) {
	spec := &RangeSpec{
		Ranges: []ByteRange{{0, 499}, {500, 999}},
	}

	assert.True(t, spec.IsSatisfiable(1000))
	assert.Equal(t, int64(1000), spec.TotalLength())
	assert.False(t, spec.IsSingleRange())

	// Single range
	spec2 := &RangeSpec{
		Ranges: []ByteRange{{0, 499}},
	}
	assert.True(t, spec2.IsSingleRange())
	assert.True(t, spec2.IsSatisfiable(1000))

	// Nil spec
	var nilSpec *RangeSpec
	assert.False(t, nilSpec.IsSatisfiable(1000))
	assert.Equal(t, int64(0), nilSpec.TotalLength())
	assert.False(t, nilSpec.IsSingleRange())
}

func TestRangeSpec_UnsatisfiableRange(t *testing.T) {
	// When all ranges are invalid (start >= size), returns error
	spec, err := ParseRangeSpec("bytes=2000-3000", 1000)
	assert.Error(t, err) // "no valid ranges" error
	assert.Nil(t, spec)
}

func TestRangeReader(t *testing.T) {
	data := []byte("0123456789")
	reader := bytes.NewReader(data)

	rr, err := NewRangeReader(reader, 2, 5)
	require.NoError(t, err)

	// Read in chunks
	buf := make([]byte, 3)
	n, err := rr.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, []byte("234"), buf)

	n, err = rr.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []byte("5"), buf[:1])

	// Already at EOF
	_, err = rr.Read(buf)
	assert.Equal(t, io.EOF, err)
}

func TestMultipartRangeWriter(t *testing.T) {
	var buf bytes.Buffer
	mrw := NewMultipartRangeWriter(&buf, "text/plain", 1000)

	assert.NotEmpty(t, mrw.Boundary())
	assert.Contains(t, mrw.ContentType(), "multipart/byteranges")

	err := mrw.WritePart(ByteRange{0, 4}, []byte("hello"))
	assert.NoError(t, err)

	err = mrw.Close()
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "hello")
	assert.Contains(t, buf.String(), "Content-Range")
}

func TestCoalesceRanges(t *testing.T) {
	ranges := []ByteRange{
		{0, 100},
		{50, 150}, // Overlapping
		{200, 300},
		{250, 350}, // Overlapping
		{500, 600},
	}

	coalesced := CoalesceRanges(ranges)
	assert.Len(t, coalesced, 3)
	assert.Equal(t, ByteRange{0, 150}, coalesced[0])
	assert.Equal(t, ByteRange{200, 350}, coalesced[1])
	assert.Equal(t, ByteRange{500, 600}, coalesced[2])
}

func TestUnsatisfiableRangeError(t *testing.T) {
	err := &UnsatisfiableRangeError{Size: 1000}
	assert.Contains(t, err.Error(), "1000")
	assert.Equal(t, "bytes */1000", err.ContentRangeHeader())
}

// ============================================================================
// Storage Helper Tests
// ============================================================================

func TestBytesReadCloser(t *testing.T) {
	data := []byte("hello world")
	brc := NewBytesReadCloser(data)

	// Read
	buf := make([]byte, 5)
	n, err := brc.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, []byte("hello"), buf)

	// Seek
	pos, err := brc.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	// Close
	err = brc.Close()
	assert.NoError(t, err)
}

func TestLimitedReadCloser(t *testing.T) {
	data := []byte("hello world")
	rc := io.NopCloser(bytes.NewReader(data))
	lrc := NewLimitedReadCloser(rc, 5)

	buf, err := io.ReadAll(lrc)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf)

	err = lrc.Close()
	assert.NoError(t, err)
}

func TestNopCloser(t *testing.T) {
	data := []byte("test")
	nrc := NopCloser{Reader: bytes.NewReader(data)}

	buf, _ := io.ReadAll(nrc)
	assert.Equal(t, data, buf)

	err := nrc.Close()
	assert.NoError(t, err)
}

// ============================================================================
// Validator Tests
// ============================================================================

func TestValidator_NeedsRevalidation(t *testing.T) {
	v := NewValidator()

	t.Run("no cache control", func(t *testing.T) {
		entry := &Entry{Metadata: &Metadata{}}
		assert.False(t, v.NeedsRevalidation(entry))
	})

	t.Run("must-revalidate and expired", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
				CacheControl: &CacheControl{MustRevalidate: true},
			},
		}
		assert.True(t, v.NeedsRevalidation(entry))
	})

	t.Run("must-revalidate but fresh", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				ExpiresAt:    time.Now().Add(1 * time.Hour), // Still fresh
				CacheControl: &CacheControl{MustRevalidate: true},
			},
		}
		assert.False(t, v.NeedsRevalidation(entry))
	})

	t.Run("nil entry", func(t *testing.T) {
		assert.True(t, v.NeedsRevalidation(nil))
	})
}

func TestValidator_BuildConditionalRequest(t *testing.T) {
	v := NewValidator()

	entry := &Entry{
		Metadata: &Metadata{
			ETag:         `"abc123"`,
			LastModified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/test", nil)
	v.BuildConditionalRequest(req, entry)

	assert.Equal(t, `"abc123"`, req.Header.Get("If-None-Match"))
	assert.NotEmpty(t, req.Header.Get("If-Modified-Since"))
}

func TestValidator_HandleConditionalResponse(t *testing.T) {
	v := NewValidator()

	entry := &Entry{
		Metadata: &Metadata{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": []string{"text/plain"}},
		},
	}

	t.Run("304 response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 304,
			Header:     http.Header{"Cache-Control": []string{"max-age=3600"}},
		}
		valid := v.HandleConditionalResponse(entry, resp)
		assert.True(t, valid)
	})

	t.Run("200 response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
		}
		valid := v.HandleConditionalResponse(entry, resp)
		assert.False(t, valid)
	})
}

func TestValidator_ShouldCache(t *testing.T) {
	v := NewValidator()

	t.Run("GET 200", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/test", nil)
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		assert.True(t, v.ShouldCache(req, resp))
	})

	t.Run("POST", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "http://example.com/test", nil)
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		assert.False(t, v.ShouldCache(req, resp))
	})

	t.Run("Authorization header", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/test", nil)
		req.Header.Set("Authorization", "Bearer token")
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		assert.False(t, v.ShouldCache(req, resp))
	})

	t.Run("no-store response", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/test", nil)
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Cache-Control": []string{"no-store"}},
		}
		assert.False(t, v.ShouldCache(req, resp))
	})

	t.Run("Set-Cookie response", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/test", nil)
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Set-Cookie": []string{"session=abc"}},
		}
		assert.False(t, v.ShouldCache(req, resp))
	})

	t.Run("304 response", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/test", nil)
		resp := &http.Response{StatusCode: 304, Header: http.Header{}}
		assert.False(t, v.ShouldCache(req, resp))
	})
}

func TestValidator_CalculateFreshness(t *testing.T) {
	v := NewValidator()

	entry := &Entry{
		Metadata: &Metadata{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
	}

	freshness := v.CalculateFreshness(entry)
	assert.InDelta(t, 1*time.Hour.Seconds(), freshness.Seconds(), 1)

	// Nil entry
	assert.Equal(t, time.Duration(0), v.CalculateFreshness(nil))
}

func TestValidator_CalculateAge(t *testing.T) {
	v := NewValidator()

	entry := &Entry{
		Metadata: &Metadata{
			CreatedAt: time.Now().Add(-30 * time.Minute),
		},
	}

	age := v.CalculateAge(entry)
	assert.InDelta(t, 30*time.Minute.Seconds(), age.Seconds(), 1)

	// Nil entry
	assert.Equal(t, time.Duration(0), v.CalculateAge(nil))
}

func TestValidator_IsStale(t *testing.T) {
	v := NewValidator()

	t.Run("fresh", func(t *testing.T) {
		entry := &Entry{Metadata: &Metadata{ExpiresAt: time.Now().Add(1 * time.Hour)}}
		assert.False(t, v.IsStale(entry))
	})

	t.Run("stale", func(t *testing.T) {
		entry := &Entry{Metadata: &Metadata{ExpiresAt: time.Now().Add(-1 * time.Hour)}}
		assert.True(t, v.IsStale(entry))
	})

	t.Run("nil entry", func(t *testing.T) {
		assert.True(t, v.IsStale(nil))
	})
}

func TestValidator_CanServeStale(t *testing.T) {
	v := NewValidator()

	t.Run("with immutable", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				ExpiresAt:    time.Now().Add(-1 * time.Hour),
				CacheControl: &CacheControl{Immutable: true},
			},
		}
		assert.True(t, v.CanServeStale(entry))
	})

	t.Run("with must-revalidate", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				ExpiresAt:    time.Now().Add(-1 * time.Hour),
				CacheControl: &CacheControl{MustRevalidate: true},
			},
		}
		assert.False(t, v.CanServeStale(entry))
	})

	t.Run("without cache control", func(t *testing.T) {
		entry := &Entry{Metadata: &Metadata{ExpiresAt: time.Now().Add(-1 * time.Hour)}}
		assert.False(t, v.CanServeStale(entry))
	})

	t.Run("nil entry", func(t *testing.T) {
		assert.False(t, v.CanServeStale(nil))
	})
}

// ============================================================================
// Metrics Tests
// ============================================================================

func TestMetrics(t *testing.T) {
	// Use nil registry for testing (no actual registration)
	m := NewMetrics(nil)
	assert.NotNil(t, m)

	// These should not panic
	m.RecordHit("example.com", 1024)
	m.RecordMiss("example.com", "not_found")
	m.RecordOriginBytes(1024)
	m.RecordCachedBytes(2048)
	m.RecordEviction("memory", "lru")
	m.UpdateStorageMetrics("memory", 100, int64(10*MB), int64(100*MB))
	m.UpdateRuleMetrics(5, 3)
	m.ObserveOperation("get", 0.01)
}

func TestMetrics_Nil(t *testing.T) {
	var m *Metrics

	// These should not panic on nil receiver
	m.RecordHit("example.com", 1024)
	m.RecordMiss("example.com", "not_found")
	m.RecordOriginBytes(1024)
	m.RecordCachedBytes(2048)
	m.RecordEviction("memory", "lru")
	m.UpdateStorageMetrics("memory", 100, int64(10*MB), int64(100*MB))
	m.UpdateRuleMetrics(5, 3)
	m.ObserveOperation("get", 0.01)
}

// ============================================================================
// Disk Storage Tests
// ============================================================================

func TestDiskStorage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         100 * MB,
		CleanupInterval: Duration(1 * time.Hour),
		ShardCount:      16,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	t.Run("put and get", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				Key:           "disk-test",
				URL:           "http://example.com/test",
				Host:          "example.com",
				StatusCode:    200,
				ContentLength: 11,
				ContentType:   "text/plain",
				CreatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("hello world"))),
		}

		err := storage.Put(ctx, "disk-test", entry)
		require.NoError(t, err)

		got, err := storage.Get(ctx, "disk-test")
		require.NoError(t, err)
		defer got.Close()

		data, _ := io.ReadAll(got.Body)
		assert.Equal(t, "hello world", string(data))
	})

	t.Run("get not found", func(t *testing.T) {
		_, err := storage.Get(ctx, "nonexistent")
		assert.Error(t, err)
	})

	t.Run("exists", func(t *testing.T) {
		assert.True(t, storage.Exists(ctx, "disk-test"))
		assert.False(t, storage.Exists(ctx, "nonexistent"))
	})

	t.Run("get metadata", func(t *testing.T) {
		meta, err := storage.GetMetadata(ctx, "disk-test")
		require.NoError(t, err)
		assert.Equal(t, "http://example.com/test", meta.URL)
	})

	t.Run("get range", func(t *testing.T) {
		reader, err := storage.GetRange(ctx, "disk-test", 0, 4)
		require.NoError(t, err)
		defer reader.Close()

		data, _ := io.ReadAll(reader)
		assert.Equal(t, "hello", string(data))
	})

	t.Run("list", func(t *testing.T) {
		list, total, err := storage.List(ctx, "", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, list, 1)
	})

	t.Run("stats", func(t *testing.T) {
		stats := storage.Stats()
		assert.Equal(t, int64(1), stats.Entries)
	})

	t.Run("delete", func(t *testing.T) {
		err := storage.Delete(ctx, "disk-test")
		require.NoError(t, err)
		assert.False(t, storage.Exists(ctx, "disk-test"))
	})

	t.Run("clear", func(t *testing.T) {
		// Add entry first
		entry := &Entry{
			Metadata: &Metadata{Key: "to-clear", ExpiresAt: time.Now().Add(1 * time.Hour)},
			Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
		}
		storage.Put(ctx, "to-clear", entry)

		err := storage.Clear(ctx)
		require.NoError(t, err)
	})
}

// ============================================================================
// Tiered Storage Tests
// ============================================================================

func TestTieredStorage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tieredCfg := &TieredConfig{
		MemoryThreshold: ByteSize(100), // Small threshold
	}
	memoryCfg := &MemoryConfig{
		MaxSize:    1 * MB,
		MaxEntries: 100,
	}
	diskCfg := &DiskConfig{
		Path:    tmpDir,
		MaxSize: 10 * MB,
	}

	storage, err := NewTieredStorage(tieredCfg, memoryCfg, diskCfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	t.Run("small file goes to memory", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{Key: "small", ExpiresAt: time.Now().Add(1 * time.Hour)},
			Body:     io.NopCloser(bytes.NewReader([]byte("small"))), // 5 bytes < 100
		}
		err := storage.Put(ctx, "small", entry)
		require.NoError(t, err)

		got, err := storage.Get(ctx, "small")
		require.NoError(t, err)
		got.Close()

		// Check it's in memory tier
		assert.True(t, storage.memory.Exists(ctx, "small"))
	})

	t.Run("large file goes to disk", func(t *testing.T) {
		largeData := make([]byte, 200) // 200 bytes > 100
		entry := &Entry{
			Metadata: &Metadata{Key: "large", ExpiresAt: time.Now().Add(1 * time.Hour)},
			Body:     io.NopCloser(bytes.NewReader(largeData)),
		}
		err := storage.Put(ctx, "large", entry)
		require.NoError(t, err)

		got, err := storage.Get(ctx, "large")
		require.NoError(t, err)
		got.Close()

		// Check it's in disk tier
		assert.True(t, storage.disk.Exists(ctx, "large"))
	})

	t.Run("exists", func(t *testing.T) {
		assert.True(t, storage.Exists(ctx, "small"))
		assert.True(t, storage.Exists(ctx, "large"))
		assert.False(t, storage.Exists(ctx, "nonexistent"))
	})

	t.Run("get metadata", func(t *testing.T) {
		meta, err := storage.GetMetadata(ctx, "small")
		require.NoError(t, err)
		assert.NotNil(t, meta)
	})

	t.Run("get range", func(t *testing.T) {
		reader, err := storage.GetRange(ctx, "small", 0, 2)
		require.NoError(t, err)
		defer reader.Close()

		data, _ := io.ReadAll(reader)
		assert.Equal(t, "sma", string(data))
	})

	t.Run("list", func(t *testing.T) {
		list, total, err := storage.List(ctx, "", 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Len(t, list, 2)
	})

	t.Run("stats", func(t *testing.T) {
		stats := storage.Stats()
		assert.Equal(t, int64(2), stats.Entries)

		memStats := storage.MemoryStats()
		assert.Equal(t, int64(1), memStats.Entries)

		diskStats := storage.DiskStats()
		assert.Equal(t, int64(1), diskStats.Entries)
	})

	t.Run("delete", func(t *testing.T) {
		err := storage.Delete(ctx, "small")
		require.NoError(t, err)
		assert.False(t, storage.Exists(ctx, "small"))
	})

	t.Run("clear", func(t *testing.T) {
		err := storage.Clear(ctx)
		require.NoError(t, err)
	})
}

func TestTieredStorage_Closed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tiered-closed-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage, err := NewTieredStorage(
		&TieredConfig{MemoryThreshold: ByteSize(100)},
		&MemoryConfig{MaxSize: 1 * MB},
		&DiskConfig{Path: tmpDir, MaxSize: 10 * MB},
	)
	require.NoError(t, err)

	ctx := context.Background()
	storage.Start(ctx)
	storage.Stop(ctx)

	// Operations on closed storage
	_, err = storage.Get(ctx, "test")
	assert.Error(t, err)

	entry := &Entry{
		Metadata: &Metadata{Key: "test", ExpiresAt: time.Now().Add(1 * time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	err = storage.Put(ctx, "test", entry)
	assert.Error(t, err)

	err = storage.Delete(ctx, "test")
	assert.Error(t, err)

	assert.False(t, storage.Exists(ctx, "test"))

	_, err = storage.GetMetadata(ctx, "test")
	assert.Error(t, err)

	_, err = storage.GetRange(ctx, "test", 0, 10)
	assert.Error(t, err)

	_, _, err = storage.List(ctx, "", 0, 0)
	assert.Error(t, err)

	err = storage.Clear(ctx)
	assert.Error(t, err)
}

// ============================================================================
// Interceptor Tests
// ============================================================================

func TestInterceptor_HandleRequest(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	t.Run("cache miss", func(t *testing.T) {
		req := createTestRequest("GET", "http://cdn.steamcontent.com/test")

		server := httptest.NewServer(nil)
		defer server.Close()

		conn, _ := net.Dial("tcp", server.Listener.Addr().String())
		defer conn.Close()

		handled, err := interceptor.HandleRequest(ctx, conn, req)
		assert.NoError(t, err)
		assert.False(t, handled) // Miss
	})

	t.Run("nil manager", func(t *testing.T) {
		nilInterceptor := NewInterceptor(nil)
		req := createTestRequest("GET", "http://example.com/test")

		handled, err := nilInterceptor.HandleRequest(ctx, nil, req)
		assert.NoError(t, err)
		assert.False(t, handled)
	})

	t.Run("POST request", func(t *testing.T) {
		req := createTestRequest("POST", "http://cdn.steamcontent.com/test")

		handled, err := interceptor.HandleRequest(ctx, nil, req)
		assert.NoError(t, err)
		assert.False(t, handled)
	})
}

func TestInterceptor_StoreResponse(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	t.Run("store cacheable response", func(t *testing.T) {
		req := createTestRequest("GET", "http://cdn.steamcontent.com/test")
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
			ContentLength: 5,
			Body:          io.NopCloser(bytes.NewReader([]byte("hello"))),
		}

		newBody, err := interceptor.StoreResponse(ctx, req, resp)
		require.NoError(t, err)

		data, _ := io.ReadAll(newBody)
		newBody.Close()
		assert.Equal(t, "hello", string(data))
	})

	t.Run("nil manager", func(t *testing.T) {
		nilInterceptor := NewInterceptor(nil)
		req := createTestRequest("GET", "http://example.com/test")
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
		}

		body, err := nilInterceptor.StoreResponse(ctx, req, resp)
		assert.NoError(t, err)
		assert.Equal(t, resp.Body, body)
	})
}

func TestResponseWriter(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
	}

	manager, _ := NewManager(cfg)
	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	server := httptest.NewServer(nil)
	defer server.Close()

	conn, _ := net.Dial("tcp", server.Listener.Addr().String())
	defer conn.Close()

	req := createTestRequest("GET", "http://example.com/test")

	rw := interceptor.NewResponseWriter(conn, req)

	assert.NotNil(t, rw.Header())

	rw.WriteHeader(200)
	n, err := rw.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)

	// Write again (without WriteHeader - should auto-set 200)
	rw2 := interceptor.NewResponseWriter(conn, req)
	n, err = rw2.Write([]byte("world"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
}

func TestParseByteRange_EdgeCases(t *testing.T) {
	t.Run("invalid spec format", func(t *testing.T) {
		_, err := parseByteRange("invalid", 1000)
		assert.Error(t, err)
	})

	t.Run("invalid start number", func(t *testing.T) {
		_, err := parseByteRange("abc-100", 1000)
		assert.Error(t, err)
	})

	t.Run("invalid end number", func(t *testing.T) {
		_, err := parseByteRange("0-abc", 1000)
		assert.Error(t, err)
	})

	t.Run("start greater than end", func(t *testing.T) {
		_, err := parseByteRange("500-100", 1000)
		assert.Error(t, err)
	})

	t.Run("suffix range invalid number", func(t *testing.T) {
		_, err := parseByteRange("-abc", 1000)
		assert.Error(t, err)
	})
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestCacheIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-integration-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(1 * time.Hour),
		Storage: StorageConfig{
			Type: "tiered",
			Tiered: &TieredConfig{
				MemoryThreshold: 1 * KB,
			},
			Memory: &MemoryConfig{
				MaxSize:    1 * MB,
				MaxEntries: 100,
			},
			Disk: &DiskConfig{
				Path:    filepath.Join(tmpDir, "cache"),
				MaxSize: 10 * MB,
			},
		},
		Presets: []string{"steam", "epic"},
		Rules: []RuleConfig{
			{
				Name:     "custom",
				Domains:  []string{"*.custom.com"},
				Enabled:  true,
				TTL:      Duration(2 * time.Hour),
				Priority: 50,
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop(ctx)

	// Test ShouldCache
	steamReq := createTestRequest("GET", "http://cdn.steamcontent.com/depot/123/chunk")
	assert.True(t, manager.ShouldCache(steamReq))

	customReq := createTestRequest("GET", "http://cdn.custom.com/file.bin")
	assert.True(t, manager.ShouldCache(customReq))

	randomReq := createTestRequest("GET", "http://random-domain.com/file")
	assert.False(t, manager.ShouldCache(randomReq))

	// Test Put and Get
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: 100,
	}
	body := io.NopCloser(bytes.NewReader(make([]byte, 100)))

	err = manager.Put(ctx, steamReq, resp, body)
	require.NoError(t, err)

	entry, err := manager.Get(ctx, steamReq)
	require.NoError(t, err)
	assert.NotNil(t, entry)
	entry.Close()

	// Test Stats
	stats := manager.Stats()
	assert.True(t, stats.Enabled)
	assert.Equal(t, "tiered", stats.StorageType)
	assert.Equal(t, 3, stats.RulesCount) // steam + epic + custom
}

// ============================================================================
// Additional Interceptor Tests for Coverage
// ============================================================================

func TestInterceptor_CacheHit(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(1 * time.Hour),
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	// Put an entry in cache first
	req := createTestRequest("GET", "http://cdn.steamcontent.com/depot/123/chunk")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: 11,
	}
	body := io.NopCloser(bytes.NewReader([]byte("hello world")))
	err = manager.Put(ctx, req, resp, body)
	require.NoError(t, err)

	// Use net.Pipe to get a proper bidirectional connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Start a goroutine to read and discard the response
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			_, readErr := clientConn.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	// Request should be served from cache
	handled, err := interceptor.HandleRequest(ctx, serverConn, req)
	serverConn.Close() // Close to signal done reading
	<-done
	assert.NoError(t, err)
	assert.True(t, handled)
}

func TestInterceptor_CacheHitWithRange(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		DefaultTTL: Duration(1 * time.Hour),
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	// Put an entry in cache first
	req := createTestRequest("GET", "http://cdn.steamcontent.com/depot/123/chunk")
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: 11,
	}
	body := io.NopCloser(bytes.NewReader([]byte("hello world")))
	err = manager.Put(ctx, req, resp, body)
	require.NoError(t, err)

	// Use net.Pipe to get a proper bidirectional connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Start a goroutine to read and discard the response
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			_, readErr := clientConn.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	// Add Range header
	req.Header.Set("Range", "bytes=0-4")

	// Request should be served from cache with range
	handled, err := interceptor.HandleRequest(ctx, serverConn, req)
	serverConn.Close() // Close to signal done reading
	<-done
	assert.NoError(t, err)
	assert.True(t, handled)
}

func TestResponseWriter_Flush(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Storage: StorageConfig{
			Type:   "memory",
			Memory: &MemoryConfig{MaxSize: 10 * MB},
		},
		Presets: []string{"steam"},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	interceptor := NewInterceptor(manager)

	// Create a test server to get a connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	req := createTestRequest("GET", "http://cdn.steamcontent.com/test")
	rw := interceptor.NewResponseWriter(conn, req)

	rw.WriteHeader(200)
	rw.Header().Set("Content-Type", "text/plain")
	rw.Write([]byte("test content"))

	err = rw.Flush(ctx)
	assert.NoError(t, err)
}

// ============================================================================
// Additional Disk Storage Tests for Coverage
// ============================================================================

func TestDiskStorage_EdgeCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-edge-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         1 * MB,
		CleanupInterval: Duration(100 * time.Millisecond),
		ShardCount:      4,
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	t.Run("get range not found", func(t *testing.T) {
		_, err := storage.GetRange(ctx, "nonexistent", 0, 100)
		assert.Error(t, err)
	})

	t.Run("delete nonexistent", func(t *testing.T) {
		err := storage.Delete(ctx, "nonexistent")
		assert.NoError(t, err) // Should be idempotent
	})

	t.Run("list with domain filter", func(t *testing.T) {
		// Add entry with specific host
		entry := &Entry{
			Metadata: &Metadata{
				Key:       "test-list",
				Host:      "example.com",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("test"))),
		}
		storage.Put(ctx, "test-list", entry)

		list, total, err := storage.List(ctx, "example.com", 0, 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, total, int64(1))
		assert.GreaterOrEqual(t, len(list), 1)
	})
}

func TestDiskStorage_CleanupExpired(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disk-cleanup-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &DiskConfig{
		Path:            tmpDir,
		MaxSize:         1 * MB,
		CleanupInterval: Duration(100 * time.Millisecond),
	}

	storage, err := NewDiskStorage(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = storage.Start(ctx)
	require.NoError(t, err)

	// Add expired entry
	entry := &Entry{
		Metadata: &Metadata{
			Key:       "expired-disk",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("expired"))),
	}
	storage.Put(ctx, "expired-disk", entry)

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	storage.Stop(ctx)
}

// ============================================================================
// Additional Config Tests for Coverage
// ============================================================================

func TestConfig_EdgeCases(t *testing.T) {
	t.Run("parse duration with days", func(t *testing.T) {
		var d Duration
		node := &yaml.Node{Kind: yaml.ScalarNode, Value: "7d"}
		err := d.UnmarshalYAML(node)
		assert.NoError(t, err)
		assert.Equal(t, 7*24*time.Hour, d.Duration())
	})

	t.Run("parse byte size with TB", func(t *testing.T) {
		var b ByteSize
		node := &yaml.Node{Kind: yaml.ScalarNode, Value: "2TB"}
		err := b.UnmarshalYAML(node)
		assert.NoError(t, err)
		assert.Equal(t, int64(2*TB), b.Int64())
	})

	t.Run("validate with invalid preset", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 10 * MB},
			},
			Presets: []string{"invalid_preset"},
		}
		// Should not error - invalid presets are just skipped
		assert.NoError(t, cfg.Validate())
	})
}

// ============================================================================
// Additional Entry Tests for Coverage
// ============================================================================

func TestCacheControl_EdgeCases(t *testing.T) {
	t.Run("parse no-cache", func(t *testing.T) {
		cc := ParseCacheControl("no-cache")
		assert.True(t, cc.NoCache)
	})

	t.Run("parse private", func(t *testing.T) {
		cc := ParseCacheControl("private")
		assert.True(t, cc.Private)
	})

	t.Run("parse public", func(t *testing.T) {
		cc := ParseCacheControl("public")
		assert.True(t, cc.Public)
	})

	t.Run("parse immutable", func(t *testing.T) {
		cc := ParseCacheControl("immutable")
		assert.True(t, cc.Immutable)
	})

	t.Run("parse multiple directives", func(t *testing.T) {
		cc := ParseCacheControl("public, max-age=3600, immutable")
		assert.True(t, cc.Public)
		assert.True(t, cc.Immutable)
		assert.Equal(t, 3600, cc.MaxAge)
	})

	t.Run("parse s-maxage", func(t *testing.T) {
		cc := ParseCacheControl("s-maxage=7200")
		assert.Equal(t, 7200, cc.SMaxAge)
	})
}

func TestMetadata_EdgeCases(t *testing.T) {
	t.Run("IsExpired true", func(t *testing.T) {
		m := &Metadata{ExpiresAt: time.Now().Add(-1 * time.Hour)}
		assert.True(t, m.IsExpired())
	})

	t.Run("IsExpired false", func(t *testing.T) {
		m := &Metadata{ExpiresAt: time.Now().Add(1 * time.Hour)}
		assert.False(t, m.IsExpired())
	})
}

// ============================================================================
// Additional Validator Tests for Coverage
// ============================================================================

func TestValidator_IsFresh_EdgeCases(t *testing.T) {
	v := NewValidator()

	t.Run("nil entry", func(t *testing.T) {
		assert.False(t, v.IsFresh(nil))
	})

	t.Run("entry with no-store", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				CacheControl: &CacheControl{NoStore: true},
			},
		}
		assert.False(t, v.IsFresh(entry))
	})

	t.Run("entry with max-age exceeded", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				CreatedAt:    time.Now().Add(-2 * time.Hour),
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				CacheControl: &CacheControl{MaxAge: 3600}, // 1 hour max-age, but created 2 hours ago
			},
		}
		assert.False(t, v.IsFresh(entry))
	})
}

// Note: createTestRequest is defined in cache_test.go
