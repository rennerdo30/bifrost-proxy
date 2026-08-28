package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errStoragePutFailed is what the stub below returns from every Put.
var errStoragePutFailed = errors.New("storage is read-only")

// failingPutStorage is a real Storage with only Put replaced, so the stub does
// not have to reimplement the other eleven methods.
type failingPutStorage struct {
	Storage
}

func (failingPutStorage) Put(context.Context, string, *Entry) error {
	return errStoragePutFailed
}

func storeErrorTestManager(t *testing.T) (*Manager, context.Context) {
	t.Helper()

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
		// Put returns early unless some rule matches the request, so the
		// storage layer is only reached with a rule in place.
		Rules: []RuleConfig{
			{
				Name:    "test-cdn",
				Domains: []string{"cdn.example.com"},
				Enabled: true,
				TTL:     Duration(time.Hour),
			},
		},
	}

	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, manager.Start(ctx))
	t.Cleanup(func() { _ = manager.Stop(ctx) })

	return manager, ctx
}

// TestManager_StoreErrorCounter covers the counter that makes an unwritable
// cache visible. Without it, a cache that cannot write at all - wrong
// permissions, a full disk, a read-only mount - is indistinguishable from a
// cache nothing happens to match: a permanent 0% hit rate and, at the default
// log level, no error at all.
func TestManager_StoreErrorCounter(t *testing.T) {
	manager, _ := storeErrorTestManager(t)

	assert.Zero(t, manager.StoreErrorCount(), "a fresh manager has no store errors")
	assert.Zero(t, manager.Stats().StoreErrorCount)

	// RecordStoreError returns the running total so the caller can warn only on
	// the first failure instead of flooding the log.
	assert.Equal(t, int64(1), manager.RecordStoreError())
	assert.Equal(t, int64(2), manager.RecordStoreError())
	assert.Equal(t, int64(3), manager.RecordStoreError())

	assert.Equal(t, int64(3), manager.StoreErrorCount())
	assert.Equal(t, int64(3), manager.Stats().StoreErrorCount,
		"the count must be visible through Stats, which is what operators see")
}

// TestManager_PutSurfacesStorageError asserts Manager.Put returns the storage
// failure rather than absorbing it, which is what makes the interceptor's
// error branch - and therefore the counter - reachable.
func TestManager_PutSurfacesStorageError(t *testing.T) {
	manager, ctx := storeErrorTestManager(t)

	manager.mu.Lock()
	manager.storage = failingPutStorage{Storage: manager.storage}
	manager.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://cdn.example.com/file.bin", nil)
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
		Request:    req,
	}
	body := io.NopCloser(strings.NewReader("payload"))

	err = manager.Put(ctx, req, resp, body)
	require.Error(t, err, "a storage write failure must not be swallowed by Put")
	assert.ErrorIs(t, err, errStoragePutFailed)
}
