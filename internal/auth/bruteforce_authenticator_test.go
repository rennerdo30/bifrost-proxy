package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// countingAuthenticator records how many times Authenticate was called and
// returns a fixed result based on whether the password matches.
type countingAuthenticator struct {
	calls    int
	password string
}

func (c *countingAuthenticator) Authenticate(_ context.Context, username, password string) (*auth.UserInfo, error) {
	c.calls++
	if password == c.password {
		return &auth.UserInfo{Username: username}, nil
	}
	return nil, auth.NewAuthError("counting", "authenticate", auth.ErrInvalidCredentials)
}
func (c *countingAuthenticator) Name() string { return "counting" }
func (c *countingAuthenticator) Type() string { return "counting" }

func newTestProtector(t *testing.T) *auth.BruteForceProtector {
	t.Helper()
	p := auth.NewBruteForceProtector(auth.BruteForceConfig{
		MaxAttempts: 3,
		LockoutTime: time.Minute,
		MaxLockout:  time.Hour,
		WindowSize:  time.Minute,
	})
	t.Cleanup(p.Close)
	return p
}

func TestBruteForceAuthenticator_LocksOutAfterFailures(t *testing.T) {
	inner := &countingAuthenticator{password: "correct"}
	p := newTestProtector(t)
	bf := auth.NewBruteForceAuthenticator(inner, p)

	ctx := context.Background()

	// 3 failed attempts reach the threshold.
	for i := 0; i < 3; i++ {
		if _, err := bf.Authenticate(ctx, "alice", "wrong"); err == nil {
			t.Fatalf("attempt %d: expected error", i)
		}
	}

	// The 4th attempt must be rejected before reaching the inner authenticator.
	callsBefore := inner.calls
	_, err := bf.Authenticate(ctx, "alice", "wrong")
	if err == nil {
		t.Fatal("expected lockout error")
	}
	if !auth.IsTooManyAttempts(err) {
		t.Fatalf("expected ErrTooManyAttempts, got %v", err)
	}
	if inner.calls != callsBefore {
		t.Errorf("inner authenticator should not be called while locked out (before=%d after=%d)", callsBefore, inner.calls)
	}
}

func TestBruteForceAuthenticator_SuccessResets(t *testing.T) {
	inner := &countingAuthenticator{password: "correct"}
	p := newTestProtector(t)
	bf := auth.NewBruteForceAuthenticator(inner, p)
	ctx := context.Background()

	// Two failures, then a success resets the counter.
	_, _ = bf.Authenticate(ctx, "bob", "wrong")
	_, _ = bf.Authenticate(ctx, "bob", "wrong")
	if _, err := bf.Authenticate(ctx, "bob", "correct"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// After reset, failures start over and do not immediately lock out.
	if _, err := bf.Authenticate(ctx, "bob", "wrong"); err == nil {
		t.Fatal("expected invalid credentials")
	} else if auth.IsTooManyAttempts(err) {
		t.Fatal("should not be locked out immediately after a successful reset")
	}
}

func TestBruteForceAuthenticator_ScopedByIP(t *testing.T) {
	inner := &countingAuthenticator{password: "correct"}
	p := newTestProtector(t)
	bf := auth.NewBruteForceAuthenticator(inner, p)

	ctxA := auth.SetClientIP(context.Background(), "10.0.0.1")
	ctxB := auth.SetClientIP(context.Background(), "10.0.0.2")

	// Lock out source A for alice.
	for i := 0; i < 3; i++ {
		_, _ = bf.Authenticate(ctxA, "alice", "wrong")
	}
	if _, err := bf.Authenticate(ctxA, "alice", "wrong"); !auth.IsTooManyAttempts(err) {
		t.Fatalf("source A should be locked out, got %v", err)
	}

	// Source B for the same username must NOT be locked out.
	if _, err := bf.Authenticate(ctxB, "alice", "wrong"); auth.IsTooManyAttempts(err) {
		t.Fatal("source B should not be affected by source A lockout")
	}
}

func TestBruteForceAuthenticator_SkipNotCountedAndPassthrough(t *testing.T) {
	p := newTestProtector(t)
	bf := auth.NewBruteForceAuthenticator(skipAuthenticator{}, p)
	ctx := context.Background()

	// Many skips must never trigger a lockout, since no credential was evaluated.
	for i := 0; i < 10; i++ {
		_, err := bf.Authenticate(ctx, "carol", "x")
		if !auth.IsAuthSkip(err) {
			t.Fatalf("attempt %d: expected ErrAuthSkip passthrough, got %v", i, err)
		}
	}

	if bf.Name() != "skip" || bf.Type() != "skip" {
		t.Errorf("expected wrapped name/type 'skip', got %s/%s", bf.Name(), bf.Type())
	}
	if bf.Unwrap() == nil || bf.Protector() == nil {
		t.Error("Unwrap and Protector must return non-nil")
	}
}
