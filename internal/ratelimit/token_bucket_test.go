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
