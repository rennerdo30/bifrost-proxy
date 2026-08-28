package util

import (
	"fmt"
	"testing"
)

func TestCommonErrors(t *testing.T) {
	// Verify all common errors are defined
	commonErrors := []error{
		ErrNotFound,
		ErrAlreadyExists,
		ErrInvalidConfig,
		ErrNotConnected,
		ErrTimeout,
		ErrAuthRequired,
		ErrAuthFailed,
		ErrAccessDenied,
		ErrBackendDown,
		ErrRateLimited,
		ErrShuttingDown,
	}

	for _, err := range commonErrors {
		if err == nil {
			t.Error("Common error is nil")
		}
		if err.Error() == "" {
			t.Error("Common error has empty message")
		}
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"timeout error", ErrTimeout, true},
		{"wrapped timeout", fmt.Errorf("dialing backend: %w", ErrTimeout), true},
		{"other error", ErrNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTimeout(tt.err); got != tt.want {
				t.Errorf("IsTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}
