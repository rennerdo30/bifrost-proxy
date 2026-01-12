package backend

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackendError_Error(t *testing.T) {
	err := &BackendError{
		Backend: "test-backend",
		Op:      "dial",
		Err:     errors.New("connection refused"),
	}

	msg := err.Error()
	assert.Contains(t, msg, "test-backend")
	assert.Contains(t, msg, "dial")
	assert.Contains(t, msg, "connection refused")
}

func TestBackendError_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &BackendError{
		Backend: "test",
		Op:      "connect",
		Err:     innerErr,
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, innerErr, unwrapped)
}

func TestBackendError_ErrorsIs(t *testing.T) {
	innerErr := ErrConnectionFailed
	err := &BackendError{
		Backend: "test",
		Op:      "dial",
		Err:     innerErr,
	}

	// Should be able to use errors.Is
	assert.True(t, errors.Is(err, ErrConnectionFailed))
}

func TestNewBackendError(t *testing.T) {
	innerErr := errors.New("test error")
	err := NewBackendError("my-backend", "operation", innerErr)

	assert.Equal(t, "my-backend", err.Backend)
	assert.Equal(t, "operation", err.Op)
	assert.Equal(t, innerErr, err.Err)
}

func TestIsBackendError_True(t *testing.T) {
	err := &BackendError{
		Backend: "test",
		Op:      "dial",
		Err:     errors.New("test"),
	}

	assert.True(t, IsBackendError(err))
}

func TestIsBackendError_False(t *testing.T) {
	err := errors.New("regular error")
	assert.False(t, IsBackendError(err))
}

func TestIsBackendError_Wrapped(t *testing.T) {
	innerErr := &BackendError{
		Backend: "test",
		Op:      "dial",
		Err:     errors.New("test"),
	}
	wrappedErr := errors.Join(errors.New("outer"), innerErr)

	assert.True(t, IsBackendError(wrappedErr))
}

func TestGetBackendName_WithBackendError(t *testing.T) {
	err := &BackendError{
		Backend: "my-backend",
		Op:      "dial",
		Err:     errors.New("test"),
	}

	name := GetBackendName(err)
	assert.Equal(t, "my-backend", name)
}

func TestGetBackendName_WithoutBackendError(t *testing.T) {
	err := errors.New("regular error")
	name := GetBackendName(err)
	assert.Equal(t, "", name)
}

func TestGetBackendName_Nil(t *testing.T) {
	name := GetBackendName(nil)
	assert.Equal(t, "", name)
}

func TestErrorVariables(t *testing.T) {
	// Verify error variables exist and are distinct
	assert.NotNil(t, ErrBackendNotFound)
	assert.NotNil(t, ErrBackendExists)
	assert.NotNil(t, ErrBackendUnavailable)
	assert.NotNil(t, ErrBackendNotStarted)
	assert.NotNil(t, ErrBackendStopped)
	assert.NotNil(t, ErrConnectionFailed)
	assert.NotNil(t, ErrDialTimeout)
	assert.NotNil(t, ErrNoHealthyBackend)
	assert.NotNil(t, ErrInvalidBackendType)

	// Verify they are different
	assert.NotEqual(t, ErrBackendNotFound, ErrBackendExists)
	assert.NotEqual(t, ErrConnectionFailed, ErrDialTimeout)
}
