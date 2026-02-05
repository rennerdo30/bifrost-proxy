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
)

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
