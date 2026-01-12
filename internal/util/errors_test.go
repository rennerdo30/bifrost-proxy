package util

import (
	"errors"
	"strings"
	"testing"
)

func TestWrapError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		msg     string
		wantNil bool
		wantMsg string
	}{
		{
			name:    "wrap nil error",
			err:     nil,
			msg:     "context",
			wantNil: true,
		},
		{
			name:    "wrap real error",
			err:     errors.New("original"),
			msg:     "context",
			wantNil: false,
			wantMsg: "context: original",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapError(tt.err, tt.msg)

			if tt.wantNil {
				if result != nil {
					t.Errorf("WrapError() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("WrapError() returned nil, want error")
			}

			if result.Error() != tt.wantMsg {
				t.Errorf("WrapError().Error() = %s, want %s", result.Error(), tt.wantMsg)
			}

			// Verify the original error is wrapped
			if !errors.Is(result, tt.err) {
				t.Error("Wrapped error should contain original error")
			}
		})
	}
}

func TestWrapErrorf(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		format  string
		args    []any
		wantNil bool
		wantMsg string
	}{
		{
			name:    "wrap nil error",
			err:     nil,
			format:  "failed at %s",
			args:    []any{"step1"},
			wantNil: true,
		},
		{
			name:    "wrap with format",
			err:     errors.New("original"),
			format:  "failed at %s with code %d",
			args:    []any{"step1", 42},
			wantNil: false,
			wantMsg: "failed at step1 with code 42: original",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapErrorf(tt.err, tt.format, tt.args...)

			if tt.wantNil {
				if result != nil {
					t.Errorf("WrapErrorf() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("WrapErrorf() returned nil, want error")
			}

			if result.Error() != tt.wantMsg {
				t.Errorf("WrapErrorf().Error() = %s, want %s", result.Error(), tt.wantMsg)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"not found error", ErrNotFound, true},
		{"wrapped not found", WrapError(ErrNotFound, "context"), true},
		{"other error", ErrTimeout, false},
		{"random error", errors.New("random"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
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
		{"wrapped timeout", WrapError(ErrTimeout, "context"), true},
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

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"auth required", ErrAuthRequired, true},
		{"auth failed", ErrAuthFailed, true},
		{"wrapped auth required", WrapError(ErrAuthRequired, "context"), true},
		{"wrapped auth failed", WrapError(ErrAuthFailed, "context"), true},
		{"other error", ErrNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthError(tt.err); got != tt.want {
				t.Errorf("IsAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewMultiError(t *testing.T) {
	me := NewMultiError()

	if me == nil {
		t.Fatal("NewMultiError() returned nil")
	}
	if len(me.Errors) != 0 {
		t.Errorf("NewMultiError().Errors has %d elements, want 0", len(me.Errors))
	}
}

func TestMultiError_Add(t *testing.T) {
	me := NewMultiError()

	// Add nil error - should be ignored
	me.Add(nil)
	if len(me.Errors) != 0 {
		t.Error("Add(nil) should not add to error list")
	}

	// Add real error
	err1 := errors.New("error 1")
	me.Add(err1)
	if len(me.Errors) != 1 {
		t.Errorf("After Add(), got %d errors, want 1", len(me.Errors))
	}

	// Add another error
	err2 := errors.New("error 2")
	me.Add(err2)
	if len(me.Errors) != 2 {
		t.Errorf("After second Add(), got %d errors, want 2", len(me.Errors))
	}
}

func TestMultiError_Err(t *testing.T) {
	me := NewMultiError()

	// Empty should return nil
	if me.Err() != nil {
		t.Error("Err() on empty MultiError should return nil")
	}

	// With errors should return itself
	me.Add(errors.New("test"))
	if me.Err() != me {
		t.Error("Err() with errors should return the MultiError itself")
	}
}

func TestMultiError_Error(t *testing.T) {
	tests := []struct {
		name   string
		errors []error
		want   string
	}{
		{
			name:   "empty",
			errors: nil,
			want:   "",
		},
		{
			name:   "single error",
			errors: []error{errors.New("single error")},
			want:   "single error",
		},
		{
			name:   "multiple errors",
			errors: []error{errors.New("err1"), errors.New("err2")},
			want:   "2 errors occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			me := NewMultiError()
			for _, err := range tt.errors {
				me.Add(err)
			}

			result := me.Error()
			if !strings.Contains(result, tt.want) {
				t.Errorf("Error() = %s, want to contain %s", result, tt.want)
			}
		})
	}
}

func TestMultiError_Unwrap(t *testing.T) {
	me := NewMultiError()
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	me.Add(err1)
	me.Add(err2)

	unwrapped := me.Unwrap()
	if len(unwrapped) != 2 {
		t.Errorf("Unwrap() returned %d errors, want 2", len(unwrapped))
	}

	if unwrapped[0] != err1 {
		t.Error("First unwrapped error should be err1")
	}
	if unwrapped[1] != err2 {
		t.Error("Second unwrapped error should be err2")
	}
}

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
