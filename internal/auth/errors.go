package auth

import (
	"errors"
	"fmt"
)

// Common authentication errors.
var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserNotFound          = errors.New("user not found")
	ErrUserDisabled          = errors.New("user disabled")
	ErrAuthRequired          = errors.New("authentication required")
	ErrAuthMethodUnsupported = errors.New("authentication method not supported")
	ErrConfigInvalid         = errors.New("invalid auth configuration")
	ErrConnectionFailed      = errors.New("authentication service connection failed")
	ErrTimeout               = errors.New("authentication timeout")

	// ErrAuthSkip signals that an authenticator could not make a decision for
	// the supplied credentials and the caller (e.g. a ChainAuthenticator)
	// should continue with the next provider. It is NOT a success: returning it
	// must never grant access. Providers use it instead of fabricating an
	// anonymous success so that a permissive provider early in a chain cannot
	// short-circuit and bypass stricter providers behind it.
	ErrAuthSkip = errors.New("authenticator skipped: no decision")
)

// IsAuthSkip reports whether an error indicates the authenticator declined to
// make a decision and the chain should continue.
func IsAuthSkip(err error) bool {
	return errors.Is(err, ErrAuthSkip)
}

// AuthError wraps an authentication error with additional context.
type AuthError struct {
	Authenticator string
	Operation     string
	Err           error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("auth %s: %s: %v", e.Authenticator, e.Operation, e.Err)
}

func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new AuthError.
func NewAuthError(authenticator, op string, err error) *AuthError {
	return &AuthError{
		Authenticator: authenticator,
		Operation:     op,
		Err:           err,
	}
}

// IsInvalidCredentials checks if an error indicates invalid credentials.
func IsInvalidCredentials(err error) bool {
	return errors.Is(err, ErrInvalidCredentials)
}

// IsAuthRequired checks if an error indicates authentication is required.
func IsAuthRequired(err error) bool {
	return errors.Is(err, ErrAuthRequired)
}

// IsTooManyAttempts checks if an error indicates the principal is temporarily
// locked out by brute-force protection.
func IsTooManyAttempts(err error) bool {
	return errors.Is(err, ErrTooManyAttempts)
}
