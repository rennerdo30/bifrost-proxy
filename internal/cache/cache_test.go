package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyGenerator_GenerateKey(t *testing.T) {
	kg := DefaultKeyGenerator()

	t.Run("basic key generation", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path", nil)
		key := kg.GenerateKey(req)
		assert.NotEmpty(t, key)
		assert.Len(t, key, 64) // SHA256 hex
	})

	t.Run("same request produces same key", func(t *testing.T) {
		req1, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path", nil)
		req2, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path", nil)
		assert.Equal(t, kg.GenerateKey(req1), kg.GenerateKey(req2))
	})

	t.Run("different paths produce different keys", func(t *testing.T) {
		req1, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path1", nil)
		req2, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path2", nil)
		assert.NotEqual(t, kg.GenerateKey(req1), kg.GenerateKey(req2))
	})

	t.Run("query strings affect key", func(t *testing.T) {
		req1, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path?a=1", nil)
		req2, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path?a=2", nil)
		assert.NotEqual(t, kg.GenerateKey(req1), kg.GenerateKey(req2))
	})

	t.Run("ignore query when configured", func(t *testing.T) {
		kgIgnore := &KeyGenerator{IgnoreQuery: true}
		req1, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path?a=1", nil)
		req2, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path?a=2", nil)
		assert.Equal(t, kgIgnore.GenerateKey(req1), kgIgnore.GenerateKey(req2))
	})
}

func TestMemoryStorage_Basic(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:     ByteSize(1024 * 1024), // 1MB
		MaxEntries:  100,
		EvictPolicy: "lru",
	})
	ctx := context.Background()

	err := storage.Start(ctx)
	require.NoError(t, err)
	defer storage.Stop(ctx)

	t.Run("put and get", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				Key:           "test-key",
				URL:           "http://example.com/file.bin",
				Host:          "example.com",
				StatusCode:    200,
				ContentLength: 11,
				ContentType:   "application/octet-stream",
				CreatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("hello world"))),
		}

		err := storage.Put(ctx, "test-key", entry)
		require.NoError(t, err)

		got, err := storage.Get(ctx, "test-key")
		require.NoError(t, err)
		assert.Equal(t, 200, got.Metadata.StatusCode)

		body, _ := io.ReadAll(got.Body)
		got.Body.Close()
		assert.Equal(t, "hello world", string(body))
	})

	t.Run("get non-existent", func(t *testing.T) {
		_, err := storage.Get(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				Key:       "delete-me",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("data"))),
		}
		storage.Put(ctx, "delete-me", entry)

		err := storage.Delete(ctx, "delete-me")
		require.NoError(t, err)

		assert.False(t, storage.Exists(ctx, "delete-me"))
	})

	t.Run("exists", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				Key:       "exists-key",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("data"))),
		}
		storage.Put(ctx, "exists-key", entry)

		assert.True(t, storage.Exists(ctx, "exists-key"))
		assert.False(t, storage.Exists(ctx, "does-not-exist"))
	})

	t.Run("expired entry not found", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				Key:       "expired-key",
				ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
			},
			Body: io.NopCloser(bytes.NewReader([]byte("data"))),
		}
		storage.Put(ctx, "expired-key", entry)

		_, err := storage.Get(ctx, "expired-key")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestMemoryStorage_LRUEviction(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:     ByteSize(100), // Very small
		MaxEntries:  3,
		EvictPolicy: "lru",
	})
	ctx := context.Background()

	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Add 3 entries (at max capacity)
	for i := 0; i < 3; i++ {
		entry := &Entry{
			Metadata: &Metadata{
				Key:       string(rune('a' + i)),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Body: io.NopCloser(bytes.NewReader([]byte("x"))),
		}
		storage.Put(ctx, string(rune('a'+i)), entry)
	}

	// Access "a" to make it most recently used
	storage.Get(ctx, "a")

	// Add a 4th entry - should evict "b" (oldest accessed)
	entry := &Entry{
		Metadata: &Metadata{
			Key:       "d",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte("x"))),
	}
	storage.Put(ctx, "d", entry)

	// "b" should be evicted
	assert.False(t, storage.Exists(ctx, "b"), "b should be evicted")
	// "a" should still exist (was accessed recently)
	assert.True(t, storage.Exists(ctx, "a"), "a should exist")
}

func TestMemoryStorage_GetRange(t *testing.T) {
	storage := NewMemoryStorage(&MemoryConfig{
		MaxSize:    ByteSize(1024 * 1024),
		MaxEntries: 100,
	})
	ctx := context.Background()

	storage.Start(ctx)
	defer storage.Stop(ctx)

	// Store entry with known content
	content := "0123456789ABCDEF"
	entry := &Entry{
		Metadata: &Metadata{
			Key:           "range-test",
			ContentLength: int64(len(content)),
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		},
		Body: io.NopCloser(bytes.NewReader([]byte(content))),
	}
	storage.Put(ctx, "range-test", entry)

	t.Run("partial range", func(t *testing.T) {
		reader, err := storage.GetRange(ctx, "range-test", 0, 4)
		require.NoError(t, err)
		data, _ := io.ReadAll(reader)
		reader.Close()
		assert.Equal(t, "01234", string(data))
	})

	t.Run("middle range", func(t *testing.T) {
		reader, err := storage.GetRange(ctx, "range-test", 5, 9)
		require.NoError(t, err)
		data, _ := io.ReadAll(reader)
		reader.Close()
		assert.Equal(t, "56789", string(data))
	})
}

func TestRuleSet_Match(t *testing.T) {
	rs := NewRuleSet()

	// Add rules
	rule1, _ := NewRuleFromConfig(RuleConfig{
		Name:     "steam",
		Domains:  []string{"*.steamcontent.com"},
		Enabled:  true,
		TTL:      Duration(24 * time.Hour),
		Priority: 100,
	})
	rs.Add(rule1)

	rule2, _ := NewRuleFromConfig(RuleConfig{
		Name:     "generic",
		Domains:  []string{"*"},
		Enabled:  true,
		TTL:      Duration(1 * time.Hour),
		Priority: 1,
	})
	rs.Add(rule2)

	t.Run("matches high priority rule", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://cdn.steamcontent.com/file.bin", nil)
		rule := rs.Match(req)
		require.NotNil(t, rule)
		assert.Equal(t, "steam", rule.Name)
	})

	t.Run("falls back to generic", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://other.com/file.bin", nil)
		rule := rs.Match(req)
		require.NotNil(t, rule)
		assert.Equal(t, "generic", rule.Name)
	})

	t.Run("no match for POST", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "http://cdn.steamcontent.com/file.bin", nil)
		rule := rs.Match(req)
		assert.Nil(t, rule) // Default is GET only
	})
}

func TestPresets(t *testing.T) {
	t.Run("get preset", func(t *testing.T) {
		preset, ok := GetPreset(PresetSteam)
		require.True(t, ok)
		assert.Equal(t, PresetSteam, preset.Name)
		assert.NotEmpty(t, preset.Domains)
	})

	t.Run("unknown preset", func(t *testing.T) {
		_, ok := GetPreset("unknown")
		assert.False(t, ok)
	})

	t.Run("preset to rule", func(t *testing.T) {
		preset, _ := GetPreset(PresetSteam)
		rule := PresetToRule(preset)
		assert.Equal(t, "steam", rule.Name)
		assert.True(t, rule.Enabled)
		assert.NotNil(t, rule.Matcher)
	})
}

func TestParseCacheControl(t *testing.T) {
	tests := []struct {
		header string
		expect *CacheControl
	}{
		{
			header: "max-age=3600",
			expect: &CacheControl{MaxAge: 3600},
		},
		{
			header: "no-cache",
			expect: &CacheControl{NoCache: true},
		},
		{
			header: "no-store, private",
			expect: &CacheControl{NoStore: true, Private: true},
		},
		{
			header: "public, max-age=86400, immutable",
			expect: &CacheControl{Public: true, MaxAge: 86400, Immutable: true},
		},
		{
			header: "",
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			cc := ParseCacheControl(tc.header)
			if tc.expect == nil {
				assert.Nil(t, cc)
			} else {
				require.NotNil(t, cc)
				assert.Equal(t, tc.expect.MaxAge, cc.MaxAge)
				assert.Equal(t, tc.expect.NoCache, cc.NoCache)
				assert.Equal(t, tc.expect.NoStore, cc.NoStore)
				assert.Equal(t, tc.expect.Private, cc.Private)
				assert.Equal(t, tc.expect.Public, cc.Public)
				assert.Equal(t, tc.expect.Immutable, cc.Immutable)
			}
		})
	}
}

func TestByteSize_Parse(t *testing.T) {
	tests := []struct {
		input  string
		expect ByteSize
	}{
		{"1024", 1024},
		{"10KB", 10 * KB},
		{"10kb", 10 * KB},
		{"100MB", 100 * MB},
		{"5GB", 5 * GB},
		{"1TB", 1 * TB},
		{"1.5GB", ByteSize(1.5 * float64(GB))},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			size, err := parseByteSize(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expect, size)
		})
	}
}

func TestDuration_ParseDays(t *testing.T) {
	tests := []struct {
		input  string
		expect time.Duration
	}{
		{"1h", 1 * time.Hour},
		{"24h", 24 * time.Hour},
		{"1d", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"1d12h", 36 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			dur, err := parseDuration(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expect, dur)
		})
	}
}

func TestRangeSpec_Parse(t *testing.T) {
	tests := []struct {
		header   string
		size     int64
		expected []ByteRange
		err      bool
	}{
		{"bytes=0-499", 1000, []ByteRange{{0, 499}}, false},
		{"bytes=500-999", 1000, []ByteRange{{500, 999}}, false},
		{"bytes=500-", 1000, []ByteRange{{500, 999}}, false},
		{"bytes=-100", 1000, []ByteRange{{900, 999}}, false},
		{"bytes=0-0", 1000, []ByteRange{{0, 0}}, false},
		{"invalid", 1000, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			spec, err := ParseRangeSpec(tc.header, tc.size)
			if tc.err {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, spec)
				assert.Equal(t, tc.expected, spec.Ranges)
			}
		})
	}
}

func TestValidator_IsFresh(t *testing.T) {
	v := NewValidator()

	t.Run("fresh entry", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
		}
		assert.True(t, v.IsFresh(entry))
	})

	t.Run("expired entry", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				CreatedAt: time.Now().Add(-2 * time.Hour),
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
		}
		assert.False(t, v.IsFresh(entry))
	})

	t.Run("no-cache directive", func(t *testing.T) {
		entry := &Entry{
			Metadata: &Metadata{
				CreatedAt:    time.Now(),
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				CacheControl: &CacheControl{NoCache: true},
			},
		}
		assert.False(t, v.IsFresh(entry))
	})
}

func TestManager_ShouldCache(t *testing.T) {
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
	manager.Start(ctx)
	defer manager.Stop(ctx)

	t.Run("should cache steam content", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://cdn.steamcontent.com/depot/123/chunk", nil)
		assert.True(t, manager.ShouldCache(req))
	})

	t.Run("should not cache POST", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "http://cdn.steamcontent.com/depot/123/chunk", nil)
		assert.False(t, manager.ShouldCache(req))
	})

	t.Run("should not cache unmatched domain", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://random-domain.com/file", nil)
		assert.False(t, manager.ShouldCache(req))
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			DefaultTTL: Duration(24 * time.Hour),
			Storage: StorageConfig{
				Type: "memory",
				Memory: &MemoryConfig{
					MaxSize: 100 * MB,
				},
			},
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("disabled config skips validation", func(t *testing.T) {
		cfg := &Config{Enabled: false}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("invalid storage type", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{Type: "invalid"},
		}
		assert.Error(t, cfg.Validate())
	})

	t.Run("duplicate rule names", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 100 * MB},
			},
			Rules: []RuleConfig{
				{Name: "rule1", Domains: []string{"*.example.com"}},
				{Name: "rule1", Domains: []string{"*.other.com"}},
			},
		}
		assert.Error(t, cfg.Validate())
	})
}

func TestInterceptor_ParseRangeHeader(t *testing.T) {
	tests := []struct {
		header        string
		contentLength int64
		expectRanges  []byteRange
	}{
		{"bytes=0-499", 1000, []byteRange{{0, 499}}},
		{"bytes=500-", 1000, []byteRange{{500, 999}}},
		{"bytes=-200", 1000, []byteRange{{800, 999}}},
		{"bytes=0-0", 100, []byteRange{{0, 0}}},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			ranges, err := parseRangeHeader(tc.header, tc.contentLength)
			require.NoError(t, err)
			assert.Equal(t, tc.expectRanges, ranges)
		})
	}
}

func TestMetadata_IsCacheable(t *testing.T) {
	t.Run("200 OK is cacheable", func(t *testing.T) {
		m := &Metadata{StatusCode: 200}
		assert.True(t, m.IsCacheable())
	})

	t.Run("206 Partial Content is cacheable", func(t *testing.T) {
		m := &Metadata{StatusCode: 206}
		assert.True(t, m.IsCacheable())
	})

	t.Run("404 Not Found is not cacheable", func(t *testing.T) {
		m := &Metadata{StatusCode: 404}
		assert.False(t, m.IsCacheable())
	})

	t.Run("no-store is not cacheable", func(t *testing.T) {
		m := &Metadata{
			StatusCode:   200,
			CacheControl: &CacheControl{NoStore: true},
		}
		assert.False(t, m.IsCacheable())
	})

	t.Run("private is not cacheable", func(t *testing.T) {
		m := &Metadata{
			StatusCode:   200,
			CacheControl: &CacheControl{Private: true},
		}
		assert.False(t, m.IsCacheable())
	})
}

func createTestRequest(method, urlStr string) *http.Request {
	u, _ := url.Parse(urlStr)
	return &http.Request{
		Method: method,
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
	}
}
