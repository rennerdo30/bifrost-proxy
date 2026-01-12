package backend

import (
	"errors"
	"fmt"
)

// Backend errors.
var (
	ErrBackendNotFound    = errors.New("backend not found")
	ErrBackendExists      = errors.New("backend already exists")
	ErrBackendUnavailable = errors.New("backend unavailable")
	ErrBackendNotStarted  = errors.New("backend not started")
	ErrBackendStopped     = errors.New("backend stopped")
	ErrConnectionFailed   = errors.New("connection failed")
	ErrDialTimeout        = errors.New("dial timeout")
	ErrNoHealthyBackend   = errors.New("no healthy backend available")
	ErrInvalidBackendType = errors.New("invalid backend type")
)

// BackendError wraps an error with backend context.
type BackendError struct {
	Backend string
	Op      string
	Err     error
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("backend %s: %s: %v", e.Backend, e.Op, e.Err)
}

func (e *BackendError) Unwrap() error {
	return e.Err
}

// NewBackendError creates a new BackendError.
func NewBackendError(backend, op string, err error) *BackendError {
	return &BackendError{
		Backend: backend,
		Op:      op,
		Err:     err,
	}
}

// IsBackendError checks if an error is a BackendError.
func IsBackendError(err error) bool {
	var be *BackendError
	return errors.As(err, &be)
}

// GetBackendName returns the backend name from a BackendError.
func GetBackendName(err error) string {
	var be *BackendError
	if errors.As(err, &be) {
		return be.Backend
	}
	return ""
}
