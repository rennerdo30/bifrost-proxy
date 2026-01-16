package auth

import (
	"testing"
	"time"
)

func TestBruteForceProtector_Basic(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 3,
		LockoutTime: 100 * time.Millisecond,
		WindowSize:  1 * time.Second,
	})
	defer bf.Close()

	key := "test-ip"

	// First attempts should be allowed
	if !bf.IsAllowed(key) {
		t.Error("first attempt should be allowed")
	}

	// Record failures
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	// Should still be allowed (under limit)
	if !bf.IsAllowed(key) {
		t.Error("should be allowed after 2 failures")
	}

	// Third failure triggers lockout
	bf.RecordFailure(key)

	// Should now be blocked
	if bf.IsAllowed(key) {
		t.Error("should be blocked after 3 failures")
	}

	// Check lockout remaining
	remaining := bf.GetLockoutRemaining(key)
	if remaining <= 0 {
		t.Error("should have lockout remaining")
	}

	// Wait for lockout to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !bf.IsAllowed(key) {
		t.Error("should be allowed after lockout expires")
	}
}

func TestBruteForceProtector_SuccessResets(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 3,
		LockoutTime: 100 * time.Millisecond,
		WindowSize:  1 * time.Second,
	})
	defer bf.Close()

	key := "test-ip"

	// Record some failures
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	// Success should reset
	bf.RecordSuccess(key)

	// Should be fully allowed again
	if !bf.IsAllowed(key) {
		t.Error("should be allowed after success")
	}

	// Can have more failures now
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	if !bf.IsAllowed(key) {
		t.Error("should be allowed after 2 new failures")
	}
}

func TestBruteForceProtector_ExponentialBackoff(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 2,
		LockoutTime: 50 * time.Millisecond,
		MaxLockout:  500 * time.Millisecond,
		WindowSize:  2 * time.Second,
	})
	defer bf.Close()

	key := "test-ip"

	// First lockout
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	firstLockout := bf.GetLockoutRemaining(key)
	if firstLockout <= 0 {
		t.Fatal("should be locked out")
	}

	// Wait for lockout to expire
	time.Sleep(60 * time.Millisecond)

	// Second lockout should be longer (exponential backoff)
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	secondLockout := bf.GetLockoutRemaining(key)
	if secondLockout <= firstLockout {
		t.Errorf("second lockout (%v) should be longer than first (%v)", secondLockout, firstLockout)
	}
}

func TestBruteForceProtector_WindowReset(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 3,
		LockoutTime: 100 * time.Millisecond,
		WindowSize:  100 * time.Millisecond, // Short window for testing
	})
	defer bf.Close()

	key := "test-ip"

	// Record some failures
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be fully reset
	if !bf.IsAllowed(key) {
		t.Error("should be allowed after window expires")
	}

	// Failure count should have reset
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	// Still allowed (only 2 failures in new window)
	if !bf.IsAllowed(key) {
		t.Error("should be allowed after 2 failures in new window")
	}
}

func TestBruteForceProtector_Stats(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 2,
		LockoutTime: 1 * time.Second,
		WindowSize:  1 * time.Second,
	})
	defer bf.Close()

	// Initial stats
	stats := bf.Stats()
	if stats.TrackedKeys != 0 {
		t.Errorf("expected 0 tracked keys, got %d", stats.TrackedKeys)
	}

	// Add some failures
	bf.RecordFailure("ip1")
	bf.RecordFailure("ip1")
	bf.RecordFailure("ip2")

	stats = bf.Stats()
	if stats.TrackedKeys != 2 {
		t.Errorf("expected 2 tracked keys, got %d", stats.TrackedKeys)
	}
	if stats.CurrentLockouts != 1 {
		t.Errorf("expected 1 lockout, got %d", stats.CurrentLockouts)
	}
}
