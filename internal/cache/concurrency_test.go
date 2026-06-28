package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_ReloadDuringTraffic exercises Reload concurrently with Get/Put/
// KeyFor/Stats traffic. It is intended to be run with -race to detect data
// races on the rules pointer and the shared key generator (the previous code
// mutated keyGen.IgnoreQuery on every request without synchronization).
func TestManager_ReloadDuringTraffic(t *testing.T) {
	baseCfg := func() *Config {
		return &Config{
			Enabled:    true,
			DefaultTTL: Duration(time.Hour),
			Storage: StorageConfig{
				Type:   "memory",
				Memory: &MemoryConfig{MaxSize: 10 * MB, MaxEntries: 1000},
			},
			Rules: []RuleConfig{
				{
					Name:        "everything",
					Domains:     []string{"*"},
					Enabled:     true,
					TTL:         Duration(time.Hour),
					IgnoreQuery: false,
				},
			},
		}
	}

	manager, err := NewManager(baseCfg())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, manager.Start(ctx))
	defer func() { _ = manager.Stop(ctx) }()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reloader: continuously swaps rules, toggling IgnoreQuery.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ignore := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			cfg := baseCfg()
			cfg.Rules[0].IgnoreQuery = ignore
			ignore = !ignore
			_ = manager.Reload(cfg)
		}
	}()

	// Traffic workers: Put/Get/KeyFor/Stats concurrently.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req := createTestRequest("GET", "http://example.com/path?a=1&b=2")
				resp := &http.Response{
					StatusCode:    http.StatusOK,
					Header:        http.Header{"Content-Length": []string{"5"}},
					ContentLength: 5,
				}
				body := io.NopCloser(bytes.NewReader([]byte("hello")))
				_ = manager.Put(ctx, req, resp, body)

				if entry, getErr := manager.Get(ctx, req); getErr == nil {
					entry.Close()
				}
				_ = manager.KeyFor(req)
				_ = manager.Stats()
				_ = manager.ShouldCache(req)
				_ = manager.Rules()
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestKeyGenerator_GenerateKeyWithOptions verifies the per-call ignoreQuery
// option does not mutate the shared generator and matches the field-based path.
func TestKeyGenerator_GenerateKeyWithOptions(t *testing.T) {
	kg := DefaultKeyGenerator()
	require.False(t, kg.IgnoreQuery)

	req1 := createTestRequest("GET", "http://example.com/p?a=1")
	req2 := createTestRequest("GET", "http://example.com/p?a=2")

	// With ignoreQuery=true, the two keys collapse to the same value.
	assert.Equal(t,
		kg.GenerateKeyWithOptions(req1, true),
		kg.GenerateKeyWithOptions(req2, true),
	)

	// With ignoreQuery=false, the query string is part of the key.
	assert.NotEqual(t,
		kg.GenerateKeyWithOptions(req1, false),
		kg.GenerateKeyWithOptions(req2, false),
	)

	// The shared generator field must be unchanged after the calls above.
	assert.False(t, kg.IgnoreQuery)

	// GenerateKey delegates to GenerateKeyWithOptions using the field value.
	assert.Equal(t, kg.GenerateKey(req1), kg.GenerateKeyWithOptions(req1, kg.IgnoreQuery))
}

// TestIsPathSafeKey verifies the disk key guard rejects path-injection vectors.
func TestIsPathSafeKey(t *testing.T) {
	safe := []string{
		"a",
		"test",
		"test-key",
		"deadbeef",
		strings.Repeat("0", 64), // typical SHA256 hex digest length
	}
	for _, k := range safe {
		assert.Truef(t, IsPathSafeKey(k), "expected %q to be path-safe", k)
	}

	unsafe := []string{
		"",
		".",
		"..",
		"../etc/passwd",
		"a/b",
		"a\\b",
		"/abs",
		"with\x00nul",
		"ctrl\nchar",
	}
	for _, k := range unsafe {
		assert.Falsef(t, IsPathSafeKey(k), "expected %q to be rejected", k)
	}
}

// TestDiskStorage_RejectsUnsafeKeys ensures the disk backend refuses to build
// paths from keys containing traversal sequences, closing the path-injection
// vector at Put and at the path constructors.
func TestDiskStorage_RejectsUnsafeKeys(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewDiskStorage(&DiskConfig{Path: tmpDir, MaxSize: 10 * MB})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, storage.Start(ctx))
	defer func() { _ = storage.Stop(ctx) }()

	unsafeKeys := []string{"../escape", "sub/dir", "..", ""}
	for _, key := range unsafeKeys {
		entry := &Entry{
			Metadata: &Metadata{Key: key, ExpiresAt: time.Now().Add(time.Hour)},
			Body:     io.NopCloser(bytes.NewReader([]byte("data"))),
		}
		putErr := storage.Put(ctx, key, entry)
		assert.ErrorIsf(t, putErr, ErrInvalidKey, "Put(%q) should be rejected", key)

		_, dErr := storage.dataFilePath(key)
		assert.Errorf(t, dErr, "dataFilePath(%q) should error", key)
		_, mErr := storage.metaFilePath(key)
		assert.Errorf(t, mErr, "metaFilePath(%q) should error", key)
	}

	// A legitimate hex key still works end to end.
	validKey := strings.Repeat("a", 64)
	entry := &Entry{
		Metadata: &Metadata{Key: validKey, ExpiresAt: time.Now().Add(time.Hour)},
		Body:     io.NopCloser(bytes.NewReader([]byte("data"))),
	}
	require.NoError(t, storage.Put(ctx, validKey, entry))
	dataPath, dErr := storage.dataFilePath(validKey)
	require.NoError(t, dErr)
	assert.True(t, strings.HasPrefix(dataPath, tmpDir), "data file must stay inside cache dir")
}
