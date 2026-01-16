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

func TestBruteForceProtector_GetLockoutRemaining_NonExistent(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 3,
		LockoutTime: 1 * time.Second,
		WindowSize:  1 * time.Second,
	})
	defer bf.Close()

	// Non-existent key should return 0
	remaining := bf.GetLockoutRemaining("nonexistent")
	if remaining != 0 {
		t.Errorf("expected 0 lockout remaining for non-existent key, got %v", remaining)
	}
}

func TestBruteForceProtector_GetLockoutRemaining_NotLockedOut(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 5,
		LockoutTime: 1 * time.Second,
		WindowSize:  1 * time.Second,
	})
	defer bf.Close()

	// Record some failures but not enough to lockout
	bf.RecordFailure("test-key")
	bf.RecordFailure("test-key")

	// Should return 0 (not locked out yet)
	remaining := bf.GetLockoutRemaining("test-key")
	if remaining != 0 {
		t.Errorf("expected 0 lockout remaining for non-locked key, got %v", remaining)
	}
}

func TestBruteForceProtector_GetLockoutRemaining_Expired(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 2,
		LockoutTime: 50 * time.Millisecond,
		WindowSize:  1 * time.Second,
	})
	defer bf.Close()

	// Lock out
	bf.RecordFailure("test-key")
	bf.RecordFailure("test-key")

	// Wait for lockout to expire
	time.Sleep(100 * time.Millisecond)

	// Should return 0 (lockout expired)
	remaining := bf.GetLockoutRemaining("test-key")
	if remaining != 0 {
		t.Errorf("expected 0 lockout remaining after expiry, got %v", remaining)
	}
}

func TestBruteForceProtector_Cleanup(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 2,
		LockoutTime: 50 * time.Millisecond,
		WindowSize:  50 * time.Millisecond, // Short window for testing
	})
	defer bf.Close()

	// Add some entries
	bf.RecordFailure("key1")
	bf.RecordFailure("key2")
	bf.RecordFailure("key2") // This will lock out key2

	stats := bf.Stats()
	if stats.TrackedKeys != 2 {
		t.Errorf("expected 2 tracked keys, got %d", stats.TrackedKeys)
	}

	// Wait for window and lockout to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup
	bf.cleanup()

	// All keys should be cleaned up
	stats = bf.Stats()
	if stats.TrackedKeys != 0 {
		t.Errorf("expected 0 tracked keys after cleanup, got %d", stats.TrackedKeys)
	}
}

func TestBruteForceProtector_Cleanup_KeepsActiveEntries(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 2,
		LockoutTime: 1 * time.Second, // Long lockout
		WindowSize:  50 * time.Millisecond,
	})
	defer bf.Close()

	// Add an entry that will be locked out
	bf.RecordFailure("locked-key")
	bf.RecordFailure("locked-key")

	// Add an entry within the window
	bf.RecordFailure("recent-key")

	stats := bf.Stats()
	if stats.TrackedKeys != 2 {
		t.Errorf("expected 2 tracked keys, got %d", stats.TrackedKeys)
	}

	// Wait for window to expire (but not lockout)
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup
	bf.cleanup()

	// locked-key should be kept (still locked out)
	// recent-key should be cleaned up (outside window, not locked)
	stats = bf.Stats()
	if stats.TrackedKeys != 1 {
		t.Errorf("expected 1 tracked key after cleanup, got %d", stats.TrackedKeys)
	}
}

func TestBruteForceProtector_DefaultConfig(t *testing.T) {
	// Test with all defaults
	bf := NewBruteForceProtector(BruteForceConfig{})
	defer bf.Close()

	stats := bf.Stats()
	if stats.MaxAttempts != 5 {
		t.Errorf("expected default MaxAttempts of 5, got %d", stats.MaxAttempts)
	}
	if stats.LockoutTime != 1*time.Minute {
		t.Errorf("expected default LockoutTime of 1 minute, got %v", stats.LockoutTime)
	}
	if stats.WindowSize != 15*time.Minute {
		t.Errorf("expected default WindowSize of 15 minutes, got %v", stats.WindowSize)
	}
}

func TestBruteForceProtector_MaxLockoutCap(t *testing.T) {
	bf := NewBruteForceProtector(BruteForceConfig{
		MaxAttempts: 2,
		LockoutTime: 100 * time.Millisecond,
		MaxLockout:  200 * time.Millisecond, // Cap at 200ms
		WindowSize:  2 * time.Second,
	})
	defer bf.Close()

	key := "test-ip"

	// First lockout (100ms)
	bf.RecordFailure(key)
	bf.RecordFailure(key)
	time.Sleep(110 * time.Millisecond)

	// Second lockout (would be 200ms, but still within cap)
	bf.RecordFailure(key)
	bf.RecordFailure(key)
	time.Sleep(210 * time.Millisecond)

	// Third lockout (would be 400ms, but capped at 200ms)
	bf.RecordFailure(key)
	bf.RecordFailure(key)

	remaining := bf.GetLockoutRemaining(key)
	// Should be capped at MaxLockout (200ms)
	if remaining > 200*time.Millisecond {
		t.Errorf("lockout should be capped at MaxLockout, got %v", remaining)
	}
}
