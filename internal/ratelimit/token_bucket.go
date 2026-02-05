package ratelimit

import (
	"context"
	"sync"
	"time"
)

// TokenBucket implements a token bucket rate limiter.
type TokenBucket struct {
	rate       float64   // tokens per second
	capacity   int       // maximum tokens
	tokens     float64   // current tokens
	lastUpdate time.Time // last time tokens were updated
	lastAccess time.Time // last time the limiter was accessed
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket rate limiter.
func NewTokenBucket(rate float64, capacity int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		capacity:   capacity,
		tokens:     float64(capacity), // Start full
		lastUpdate: time.Now(),
		lastAccess: time.Now(),
	}
}

// Allow checks if a request is allowed (consumes 1 token).
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if n requests are allowed (consumes n tokens).
func (tb *TokenBucket) AllowN(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	tb.lastAccess = time.Now()

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}

	return false
}

// Wait blocks until a request is allowed or context is canceled.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	return tb.WaitN(ctx, 1)
}

// WaitN blocks until n requests are allowed or context is canceled.
func (tb *TokenBucket) WaitN(ctx context.Context, n int) error {
	for {
		tb.mu.Lock()
		tb.refill()
		tb.lastAccess = time.Now()

		if tb.tokens >= float64(n) {
			tb.tokens -= float64(n)
			tb.mu.Unlock()
			return nil
		}

		// Calculate wait time
		tokensNeeded := float64(n) - tb.tokens
		waitTime := time.Duration(tokensNeeded / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		// Wait
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Try again
		}
	}
}

// refill adds tokens based on elapsed time.
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.capacity) {
		tb.tokens = float64(tb.capacity)
	}
}

// Tokens returns the current number of tokens.
func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.tokens
}

// Rate returns the token rate.
func (tb *TokenBucket) Rate() float64 {
	return tb.rate
}

// Capacity returns the bucket capacity.
func (tb *TokenBucket) Capacity() int {
	return tb.capacity
}
