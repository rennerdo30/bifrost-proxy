package auth

import (
	"context"
	"errors"
	"fmt"
)

// ErrTooManyAttempts indicates that authentication is temporarily blocked for a
// principal because of repeated failed attempts (brute-force protection).
var ErrTooManyAttempts = errors.New("too many failed authentication attempts; try again later")

// bruteForceIPContextKey is the context key carrying the client IP so that
// brute-force tracking can be scoped per (username, IP) instead of per username
// alone. It is unexported to keep callers using SetClientIP.
type bruteForceIPContextKey struct{}

// SetClientIP returns a child context carrying the client IP address, used by
// BruteForceAuthenticator to scope lockouts per source. Callers (proxy /
// listener layers) should populate this before invoking the authenticator.
func SetClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, bruteForceIPContextKey{}, ip)
}

// clientIPFromContext extracts the client IP previously stored with SetClientIP.
func clientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(bruteForceIPContextKey{}).(string) //nolint:errcheck // empty string is valid if absent
	return ip
}

// BruteForceAuthenticator wraps another Authenticator with brute-force
// protection. It tracks failed attempts (per username, and per source IP when
// available) and rejects further attempts once the configured threshold is
// reached, until the lockout window elapses.
//
// It fails closed: a locked-out principal is rejected with ErrTooManyAttempts
// before the wrapped authenticator is consulted, so the credential check (and
// any expensive backend call) is skipped entirely.
type BruteForceAuthenticator struct {
	inner     Authenticator
	protector *BruteForceProtector
}

// NewBruteForceAuthenticator wraps inner with brute-force protection using the
// supplied protector. The caller owns the protector lifecycle and must call
// protector.Close() on shutdown.
func NewBruteForceAuthenticator(inner Authenticator, protector *BruteForceProtector) *BruteForceAuthenticator {
	return &BruteForceAuthenticator{inner: inner, protector: protector}
}

// key derives the brute-force tracking key for a request. When a client IP is
// available it scopes the key to (username, IP) so that a lockout for one source
// does not lock out the same username from a different source, while still
// limiting credential stuffing against a single account from one source.
func (b *BruteForceAuthenticator) key(ctx context.Context, username string) string {
	if ip := clientIPFromContext(ctx); ip != "" {
		return fmt.Sprintf("%s|%s", username, ip)
	}
	return username
}

// Authenticate enforces brute-force protection around the wrapped authenticator.
func (b *BruteForceAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	key := b.key(ctx, username)

	if !b.protector.IsAllowed(key) {
		return nil, NewAuthError(b.inner.Type(), "bruteforce", ErrTooManyAttempts)
	}

	userInfo, err := b.inner.Authenticate(ctx, username, password)
	if err != nil {
		// Do not count "skip" decisions as failures: the provider did not even
		// evaluate the credentials, so they must not contribute to a lockout.
		if !IsAuthSkip(err) {
			b.protector.RecordFailure(key)
		}
		return nil, err
	}

	b.protector.RecordSuccess(key)
	return userInfo, nil
}

// Name returns the wrapped authenticator's name.
func (b *BruteForceAuthenticator) Name() string {
	return b.inner.Name()
}

// Type returns the wrapped authenticator's type.
func (b *BruteForceAuthenticator) Type() string {
	return b.inner.Type()
}

// Unwrap returns the wrapped authenticator.
func (b *BruteForceAuthenticator) Unwrap() Authenticator {
	return b.inner
}

// Protector returns the underlying brute-force protector (for stats/shutdown).
func (b *BruteForceAuthenticator) Protector() *BruteForceProtector {
	return b.protector
}
