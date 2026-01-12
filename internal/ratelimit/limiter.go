// Package ratelimit provides rate limiting and bandwidth throttling.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter is the interface for rate limiters.
type Limiter interface {
	// Allow checks if a request is allowed.
	Allow() bool

	// AllowN checks if n requests are allowed.
	AllowN(n int) bool

	// Wait blocks until a request is allowed or context is cancelled.
	Wait(ctx context.Context) error

	// WaitN blocks until n requests are allowed or context is cancelled.
	WaitN(ctx context.Context, n int) error
}

// Config holds rate limiter configuration.
type Config struct {
	// RequestsPerSecond is the rate limit in requests per second.
	RequestsPerSecond float64 `yaml:"requests_per_second"`

	// BurstSize is the maximum burst size.
	BurstSize int `yaml:"burst_size"`
}

// KeyedLimiter provides per-key rate limiting.
type KeyedLimiter struct {
	config   Config
	limiters map[string]*TokenBucket
	mu       sync.RWMutex
	cleanup  *time.Ticker
	done     chan struct{}
}

// NewKeyedLimiter creates a new keyed rate limiter.
func NewKeyedLimiter(cfg Config) *KeyedLimiter {
	kl := &KeyedLimiter{
		config:   cfg,
		limiters: make(map[string]*TokenBucket),
		cleanup:  time.NewTicker(5 * time.Minute),
		done:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go kl.cleanupLoop()

	return kl
}

// GetLimiter returns a limiter for the given key, creating one if necessary.
func (kl *KeyedLimiter) GetLimiter(key string) Limiter {
	kl.mu.RLock()
	limiter, exists := kl.limiters[key]
	kl.mu.RUnlock()

	if exists {
		return limiter
	}

	kl.mu.Lock()
	defer kl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists = kl.limiters[key]; exists {
		return limiter
	}

	limiter = NewTokenBucket(kl.config.RequestsPerSecond, kl.config.BurstSize)
	kl.limiters[key] = limiter
	return limiter
}

// Allow checks if a request for the given key is allowed.
func (kl *KeyedLimiter) Allow(key string) bool {
	return kl.GetLimiter(key).Allow()
}

// Wait blocks until a request for the given key is allowed.
func (kl *KeyedLimiter) Wait(ctx context.Context, key string) error {
	return kl.GetLimiter(key).Wait(ctx)
}

// cleanupLoop periodically removes inactive limiters.
func (kl *KeyedLimiter) cleanupLoop() {
	for {
		select {
		case <-kl.cleanup.C:
			kl.mu.Lock()
			now := time.Now()
			for key, limiter := range kl.limiters {
				if now.Sub(limiter.lastAccess) > 10*time.Minute {
					delete(kl.limiters, key)
				}
			}
			kl.mu.Unlock()
		case <-kl.done:
			return
		}
	}
}

// Close stops the cleanup goroutine.
func (kl *KeyedLimiter) Close() {
	close(kl.done)
	kl.cleanup.Stop()
}

// UpdateConfig updates the rate limiter configuration.
// New limiters will use the updated config. Existing limiters are cleared
// so they'll be recreated with the new settings on next access.
func (kl *KeyedLimiter) UpdateConfig(cfg Config) {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	kl.config = cfg
	// Clear existing limiters so they get recreated with new config
	kl.limiters = make(map[string]*TokenBucket)
}

// Stats returns statistics about the keyed limiter.
func (kl *KeyedLimiter) Stats() KeyedLimiterStats {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	return KeyedLimiterStats{
		ActiveLimiters: len(kl.limiters),
		Config:         kl.config,
	}
}

// KeyedLimiterStats holds statistics about a keyed limiter.
type KeyedLimiterStats struct {
	ActiveLimiters int    `json:"active_limiters"`
	Config         Config `json:"config"`
}
