package cache

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A workload served entirely from disk must report a hit rate of 1.0. The old
// Stats summed the per-tier counters, so every disk hit also counted the
// probing memory miss and the rate read 0.5 — any alert keyed on cache hit
// rate was wrong by up to 2x.
func TestTieredStats_DiskHitIsNotAMemoryMiss(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTieredStorage(
		&TieredConfig{MemoryThreshold: 4}, // anything bigger than 4 bytes goes to disk
		&MemoryConfig{MaxSize: 1 << 20},
		&DiskConfig{Path: dir, MaxSize: 1 << 20},
	)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, ts.Start(ctx))
	defer ts.Stop(ctx) //nolint:errcheck // test cleanup

	body := []byte("this body is larger than the threshold")
	require.NoError(t, ts.Put(ctx, "k", &Entry{
		Metadata: &Metadata{Key: "k", StatusCode: 200, ExpiresAt: time.Now().Add(time.Hour)},
		Body:     io.NopCloser(bytes.NewReader(body)),
	}))

	for i := 0; i < 4; i++ {
		e, getErr := ts.Get(ctx, "k")
		require.NoError(t, getErr)
		_, _ = io.ReadAll(e.Body)
		e.Body.Close()
	}
	_, err = ts.Get(ctx, "definitely-missing")
	require.Error(t, err)

	stats := ts.Stats()
	assert.Equal(t, int64(4), stats.HitCount, "four disk hits are four HITS")
	assert.Equal(t, int64(1), stats.MissCount, "exactly one real miss")
}
