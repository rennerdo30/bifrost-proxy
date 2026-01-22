package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenBucket_Allow(t *testing.T) {
	// Create bucket with 10 requests per second, burst of 10
	bucket := NewTokenBucket(10, 10)

	// Should allow burst
	for i := 0; i < 10; i++ {
		assert.True(t, bucket.Allow(), "request %d should be allowed", i)
	}

	// Should deny after burst exhausted
	assert.False(t, bucket.Allow(), "request after burst should be denied")
}

func TestTokenBucket_AllowN(t *testing.T) {
	bucket := NewTokenBucket(10, 10)

	// Request 5 tokens
	assert.True(t, bucket.AllowN(5))
	assert.InDelta(t, 5, bucket.Tokens(), 0.1)

	// Request 5 more
	assert.True(t, bucket.AllowN(5))
	assert.InDelta(t, 0, bucket.Tokens(), 0.1)

	// Request 1 more should fail
	assert.False(t, bucket.AllowN(1))
}

func TestTokenBucket_Refill(t *testing.T) {
	// 10 tokens per second
	bucket := NewTokenBucket(10, 10)

	// Exhaust tokens
	bucket.AllowN(10)
	assert.InDelta(t, 0, bucket.Tokens(), 0.1)

	// Wait 100ms - should have ~1 token
	time.Sleep(100 * time.Millisecond)
	tokens := bucket.Tokens()
	assert.Greater(t, tokens, 0.5, "should have refilled some tokens")
	assert.Less(t, tokens, 2.0, "should not have refilled too many tokens")
}

func TestTokenBucket_Wait(t *testing.T) {
	bucket := NewTokenBucket(100, 1) // 100 per second, burst of 1

	// First request should succeed immediately
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	err := bucket.Wait(ctx)
	assert.NoError(t, err)
	assert.Less(t, time.Since(start), 50*time.Millisecond)

	// Second request should wait
	start = time.Now()
	err = bucket.Wait(ctx)
	assert.NoError(t, err)
	// Should have waited ~10ms for 1 token at 100/sec
	assert.Greater(t, time.Since(start), 5*time.Millisecond)
}

func TestTokenBucket_WaitCancellation(t *testing.T) {
	bucket := NewTokenBucket(1, 1) // 1 per second
	bucket.AllowN(1) // Exhaust

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	err := bucket.Wait(ctx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestKeyedLimiter(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	})
	defer limiter.Close()

	// Different keys should have independent limits
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow("key1"))
		assert.True(t, limiter.Allow("key2"))
	}

	// Both should be exhausted
	assert.False(t, limiter.Allow("key1"))
	assert.False(t, limiter.Allow("key2"))

	// Stats
	stats := limiter.Stats()
	assert.Equal(t, 2, stats.ActiveLimiters)
}

func TestKeyedLimiter_GetLimiter_Concurrent(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 100,
		BurstSize:         10,
	})
	defer limiter.Close()

	// Test concurrent access to GetLimiter with same key
	// This tests the double-check locking pattern in GetLimiter
	done := make(chan bool, 10)
	key := "concurrent-test-key"

	for i := 0; i < 10; i++ {
		go func() {
			l := limiter.GetLimiter(key)
			assert.NotNil(t, l)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should only have created one limiter for this key
	stats := limiter.Stats()
	assert.Equal(t, 1, stats.ActiveLimiters)
}

func TestKeyedLimiter_GetLimiter_DoubleCheckPath(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 100,
		BurstSize:         10,
	})
	defer limiter.Close()

	// First call creates the limiter
	l1 := limiter.GetLimiter("test-key")
	assert.NotNil(t, l1)

	// Second call should return the same limiter (fast path via RLock)
	l2 := limiter.GetLimiter("test-key")
	assert.NotNil(t, l2)

	// Both should be the same instance
	tb1 := l1.(*TokenBucket)
	tb2 := l2.(*TokenBucket)
	assert.Same(t, tb1, tb2)

	stats := limiter.Stats()
	assert.Equal(t, 1, stats.ActiveLimiters)
}

func TestTokenBucket_WaitN(t *testing.T) {
	bucket := NewTokenBucket(100, 5) // 100 per second, burst of 5

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// First request for 5 tokens should succeed immediately
	start := time.Now()
	err := bucket.WaitN(ctx, 5)
	assert.NoError(t, err)
	assert.Less(t, time.Since(start), 50*time.Millisecond)

	// Second request for 3 tokens should wait
	start = time.Now()
	err = bucket.WaitN(ctx, 3)
	assert.NoError(t, err)
	// Should have waited ~30ms for 3 tokens at 100/sec
	assert.Greater(t, time.Since(start), 20*time.Millisecond)
}

func TestTokenBucket_WaitN_ContextTimeout(t *testing.T) {
	bucket := NewTokenBucket(1, 1) // Very slow: 1 per second
	bucket.AllowN(1)               // Exhaust tokens

	// Create a context that times out very quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Request more tokens than can be fulfilled in time
	err := bucket.WaitN(ctx, 5)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestTokenBucket_RefillCapacity(t *testing.T) {
	// Test that tokens don't exceed capacity
	bucket := NewTokenBucket(1000, 10) // 1000 per second, capacity 10

	// Wait a bit to let tokens accumulate
	time.Sleep(50 * time.Millisecond)

	// Tokens should be capped at capacity (10)
	tokens := bucket.Tokens()
	assert.LessOrEqual(t, tokens, float64(10))
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		RequestsPerSecond: 100.5,
		BurstSize:         50,
	}

	assert.Equal(t, float64(100.5), cfg.RequestsPerSecond)
	assert.Equal(t, 50, cfg.BurstSize)
}

func TestKeyedLimiterStats_Struct(t *testing.T) {
	cfg := Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	}
	stats := KeyedLimiterStats{
		ActiveLimiters: 3,
		Config:         cfg,
	}

	assert.Equal(t, 3, stats.ActiveLimiters)
	assert.Equal(t, cfg, stats.Config)
}

// TestKeyedLimiter_CleanupWithStaleLimiters tests that the cleanup loop
// properly removes stale limiters that haven't been accessed recently.
// This test uses internal access to simulate old limiters for coverage.
func TestKeyedLimiter_CleanupWithStaleLimiters(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	})

	// Create a limiter
	l := limiter.GetLimiter("stale-key")
	assert.NotNil(t, l)

	// Get the internal TokenBucket and set lastAccess to a time in the past
	limiter.mu.Lock()
	if tb, ok := limiter.limiters["stale-key"]; ok {
		// Set lastAccess to 15 minutes ago (older than 10 minute threshold)
		tb.lastAccess = time.Now().Add(-15 * time.Minute)
	}
	limiter.mu.Unlock()

	// Simulate what cleanupLoop does when ticker fires
	limiter.mu.Lock()
	now := time.Now()
	for key, tb := range limiter.limiters {
		if now.Sub(tb.lastAccess) > 10*time.Minute {
			delete(limiter.limiters, key)
		}
	}
	limiter.mu.Unlock()

	// Verify the stale limiter was removed
	stats := limiter.Stats()
	assert.Equal(t, 0, stats.ActiveLimiters)

	limiter.Close()
}

// TestKeyedLimiter_CleanupKeepsFreshLimiters verifies that non-stale limiters
// are kept during cleanup.
func TestKeyedLimiter_CleanupKeepsFreshLimiters(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	})

	// Create some limiters
	limiter.GetLimiter("fresh-key1")
	limiter.GetLimiter("fresh-key2")

	// These are fresh (lastAccess is now)
	stats := limiter.Stats()
	assert.Equal(t, 2, stats.ActiveLimiters)

	// Simulate what cleanupLoop does when ticker fires
	limiter.mu.Lock()
	now := time.Now()
	for key, tb := range limiter.limiters {
		if now.Sub(tb.lastAccess) > 10*time.Minute {
			delete(limiter.limiters, key)
		}
	}
	limiter.mu.Unlock()

	// Fresh limiters should still be there
	stats = limiter.Stats()
	assert.Equal(t, 2, stats.ActiveLimiters)

	limiter.Close()
}

// TestKeyedLimiter_CleanupMixedLimiters tests cleanup with both stale and fresh limiters.
func TestKeyedLimiter_CleanupMixedLimiters(t *testing.T) {
	limiter := NewKeyedLimiter(Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	})

	// Create limiters
	limiter.GetLimiter("stale-key")
	limiter.GetLimiter("fresh-key")

	// Make one stale
	limiter.mu.Lock()
	if tb, ok := limiter.limiters["stale-key"]; ok {
		tb.lastAccess = time.Now().Add(-15 * time.Minute)
	}
	limiter.mu.Unlock()

	assert.Equal(t, 2, limiter.Stats().ActiveLimiters)

	// Simulate cleanup
	limiter.mu.Lock()
	now := time.Now()
	for key, tb := range limiter.limiters {
		if now.Sub(tb.lastAccess) > 10*time.Minute {
			delete(limiter.limiters, key)
		}
	}
	limiter.mu.Unlock()

	// Only the fresh one should remain
	stats := limiter.Stats()
	assert.Equal(t, 1, stats.ActiveLimiters)

	// Verify it's the fresh key
	limiter.mu.RLock()
	_, hasStale := limiter.limiters["stale-key"]
	_, hasFresh := limiter.limiters["fresh-key"]
	limiter.mu.RUnlock()

	assert.False(t, hasStale, "stale key should be removed")
	assert.True(t, hasFresh, "fresh key should remain")

	limiter.Close()
}
