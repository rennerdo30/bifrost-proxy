// Package util provides common utilities for Bifrost.
package util

import (
	"errors"
)

// Common error types for Bifrost.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrNotConnected  = errors.New("not connected")
	ErrTimeout       = errors.New("timeout")
	ErrAuthRequired  = errors.New("authentication required")
	ErrAuthFailed    = errors.New("authentication failed")
	ErrAccessDenied  = errors.New("access denied")
	ErrBackendDown   = errors.New("backend unavailable")
	ErrRateLimited   = errors.New("rate limited")
	ErrShuttingDown  = errors.New("server shutting down")
)

// IsTimeout checks if an error is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}
