// Package util provides common utilities for Bifrost.
package util

import (
	"errors"
	"fmt"
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

// WrapError wraps an error with additional context.
func WrapError(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// WrapErrorf wraps an error with formatted context.
func WrapErrorf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(format+": %w", append(args, err)...)
}

// IsNotFound checks if an error is a not found error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsTimeout checks if an error is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsAuthError checks if an error is an authentication error.
func IsAuthError(err error) bool {
	return errors.Is(err, ErrAuthRequired) || errors.Is(err, ErrAuthFailed)
}

// MultiError collects multiple errors.
type MultiError struct {
	Errors []error
}

// NewMultiError creates a new MultiError.
func NewMultiError() *MultiError {
	return &MultiError{}
}

// Add adds an error to the collection.
func (m *MultiError) Add(err error) {
	if err != nil {
		m.Errors = append(m.Errors, err)
	}
}

// Err returns nil if there are no errors, or the MultiError itself.
func (m *MultiError) Err() error {
	if len(m.Errors) == 0 {
		return nil
	}
	return m
}

// Error implements the error interface.
func (m *MultiError) Error() string {
	if len(m.Errors) == 0 {
		return ""
	}
	if len(m.Errors) == 1 {
		return m.Errors[0].Error()
	}
	return fmt.Sprintf("%d errors occurred: %v", len(m.Errors), m.Errors)
}

// Unwrap returns the underlying errors for errors.Is/As support.
func (m *MultiError) Unwrap() []error {
	return m.Errors
}
