// Package auth provides authentication for Bifrost.
package auth

import (
	"sync"
	"time"
)

// BruteForceProtector protects against brute force authentication attacks.
// It tracks failed login attempts per IP address and username, implementing
// exponential backoff for repeated failures.
type BruteForceProtector struct {
	attempts    map[string]*attemptTracker
	mu          sync.RWMutex
	maxAttempts int           // Max failed attempts before lockout
	lockoutTime time.Duration // Initial lockout duration
	maxLockout  time.Duration // Maximum lockout duration (for exponential backoff)
	windowSize  time.Duration // Time window for counting attempts
	cleanupTick *time.Ticker
	done        chan struct{}
}

type attemptTracker struct {
	failedCount  int
	firstAttempt time.Time
	lastAttempt  time.Time
	lockedUntil  time.Time
	lockoutCount int // Number of times locked out (for exponential backoff)
}

// BruteForceConfig configures brute force protection.
type BruteForceConfig struct {
	// MaxAttempts is the maximum failed attempts before lockout (default: 5)
	MaxAttempts int `yaml:"max_attempts"`
	// LockoutTime is the initial lockout duration (default: 1 minute)
	LockoutTime time.Duration `yaml:"lockout_time"`
	// MaxLockout is the maximum lockout duration for exponential backoff (default: 1 hour)
	MaxLockout time.Duration `yaml:"max_lockout"`
	// WindowSize is the time window for counting attempts (default: 15 minutes)
	WindowSize time.Duration `yaml:"window_size"`
}

// NewBruteForceProtector creates a new brute force protector.
func NewBruteForceProtector(cfg BruteForceConfig) *BruteForceProtector {
	// Set defaults
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.LockoutTime <= 0 {
		cfg.LockoutTime = 1 * time.Minute
	}
	if cfg.MaxLockout <= 0 {
		cfg.MaxLockout = 1 * time.Hour
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 15 * time.Minute
	}

	bf := &BruteForceProtector{
		attempts:    make(map[string]*attemptTracker),
		maxAttempts: cfg.MaxAttempts,
		lockoutTime: cfg.LockoutTime,
		maxLockout:  cfg.MaxLockout,
		windowSize:  cfg.WindowSize,
		cleanupTick: time.NewTicker(5 * time.Minute),
		done:        make(chan struct{}),
	}

	go bf.cleanupLoop()

	return bf
}

// IsAllowed checks if an authentication attempt is allowed for the given key.
// The key should be a combination of IP address and/or username.
// Returns true if allowed, false if blocked due to too many failed attempts.
func (bf *BruteForceProtector) IsAllowed(key string) bool {
	bf.mu.RLock()
	tracker, exists := bf.attempts[key]
	bf.mu.RUnlock()

	if !exists {
		return true
	}

	now := time.Now()

	// Check if currently locked out
	if now.Before(tracker.lockedUntil) {
		return false
	}

	// If lockout has expired, allow the attempt (they've served their time)
	// The tracker will be reset on next failure or success
	if !tracker.lockedUntil.IsZero() && now.After(tracker.lockedUntil) {
		return true
	}

	// Check if outside the window (reset)
	if now.Sub(tracker.firstAttempt) > bf.windowSize {
		return true
	}

	// Check if under the limit
	return tracker.failedCount < bf.maxAttempts
}

// RecordFailure records a failed authentication attempt.
func (bf *BruteForceProtector) RecordFailure(key string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	tracker, exists := bf.attempts[key]

	if !exists {
		bf.attempts[key] = &attemptTracker{
			failedCount:  1,
			firstAttempt: now,
			lastAttempt:  now,
		}
		return
	}

	// Reset if outside window
	if now.Sub(tracker.firstAttempt) > bf.windowSize {
		tracker.failedCount = 1
		tracker.firstAttempt = now
		tracker.lastAttempt = now
		return
	}

	tracker.failedCount++
	tracker.lastAttempt = now

	// Check if should lock out
	if tracker.failedCount >= bf.maxAttempts {
		// Exponential backoff: lockoutTime * 2^lockoutCount
		lockoutDuration := bf.lockoutTime * time.Duration(1<<tracker.lockoutCount)
		if lockoutDuration > bf.maxLockout {
			lockoutDuration = bf.maxLockout
		}
		tracker.lockedUntil = now.Add(lockoutDuration)
		tracker.lockoutCount++
	}
}

// RecordSuccess records a successful authentication, resetting the tracker.
func (bf *BruteForceProtector) RecordSuccess(key string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	delete(bf.attempts, key)
}

// GetLockoutRemaining returns the remaining lockout time for a key.
// Returns 0 if not locked out.
func (bf *BruteForceProtector) GetLockoutRemaining(key string) time.Duration {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	tracker, exists := bf.attempts[key]
	if !exists {
		return 0
	}

	remaining := time.Until(tracker.lockedUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// cleanupLoop periodically removes old entries.
func (bf *BruteForceProtector) cleanupLoop() {
	for {
		select {
		case <-bf.cleanupTick.C:
			bf.cleanup()
		case <-bf.done:
			return
		}
	}
}

func (bf *BruteForceProtector) cleanup() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	for key, tracker := range bf.attempts {
		// Remove if:
		// 1. Outside window AND not locked out, or
		// 2. Lockout has expired and outside window
		outsideWindow := now.Sub(tracker.firstAttempt) > bf.windowSize
		lockoutExpired := now.After(tracker.lockedUntil)

		if outsideWindow && lockoutExpired {
			delete(bf.attempts, key)
		}
	}
}

// Close stops the cleanup goroutine.
func (bf *BruteForceProtector) Close() {
	close(bf.done)
	bf.cleanupTick.Stop()
}

// Stats returns statistics about the brute force protector.
func (bf *BruteForceProtector) Stats() BruteForceStats {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	lockedOut := 0
	now := time.Now()
	for _, tracker := range bf.attempts {
		if now.Before(tracker.lockedUntil) {
			lockedOut++
		}
	}

	return BruteForceStats{
		TrackedKeys:     len(bf.attempts),
		CurrentLockouts: lockedOut,
		MaxAttempts:     bf.maxAttempts,
		LockoutTime:     bf.lockoutTime,
		WindowSize:      bf.windowSize,
	}
}

// BruteForceStats holds statistics about brute force protection.
type BruteForceStats struct {
	TrackedKeys     int           `json:"tracked_keys"`
	CurrentLockouts int           `json:"current_lockouts"`
	MaxAttempts     int           `json:"max_attempts"`
	LockoutTime     time.Duration `json:"lockout_time"`
	WindowSize      time.Duration `json:"window_size"`
}
