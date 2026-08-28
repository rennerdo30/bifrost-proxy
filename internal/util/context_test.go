package util

import (
	"context"
	"testing"
)

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	id := "test-request-123"

	ctx = WithRequestID(ctx, id)
	result := GetRequestID(ctx)

	if result != id {
		t.Errorf("GetRequestID() = %s, want %s", result, id)
	}
}

func TestGetRequestID_Empty(t *testing.T) {
	ctx := context.Background()
	result := GetRequestID(ctx)

	if result != "" {
		t.Errorf("GetRequestID() from empty context = %s, want empty string", result)
	}
}

func TestWithUsername(t *testing.T) {
	ctx := context.Background()
	username := "testuser"

	ctx = WithUsername(ctx, username)
	result := GetUsername(ctx)

	if result != username {
		t.Errorf("GetUsername() = %s, want %s", result, username)
	}
}

func TestGetUsername_Empty(t *testing.T) {
	ctx := context.Background()
	result := GetUsername(ctx)

	if result != "" {
		t.Errorf("GetUsername() from empty context = %s, want empty string", result)
	}
}

func TestWithClientIP(t *testing.T) {
	ctx := context.Background()
	ip := "192.168.1.100"

	ctx = WithClientIP(ctx, ip)
	result := GetClientIP(ctx)

	if result != ip {
		t.Errorf("GetClientIP() = %s, want %s", result, ip)
	}
}

func TestGetClientIP_Empty(t *testing.T) {
	ctx := context.Background()
	result := GetClientIP(ctx)

	if result != "" {
		t.Errorf("GetClientIP() from empty context = %s, want empty string", result)
	}
}

func TestWithBackend(t *testing.T) {
	ctx := context.Background()
	backend := "wireguard-1"

	ctx = WithBackend(ctx, backend)
	result := GetBackend(ctx)

	if result != backend {
		t.Errorf("GetBackend() = %s, want %s", result, backend)
	}
}

func TestGetBackend_Empty(t *testing.T) {
	ctx := context.Background()
	result := GetBackend(ctx)

	if result != "" {
		t.Errorf("GetBackend() from empty context = %s, want empty string", result)
	}
}

// The remaining context values must not clobber one another when layered on a
// single context. The start-time and domain values were dropped because
// nothing ever read them back.
func TestMultipleContextValues(t *testing.T) {
	ctx := context.Background()

	ctx = WithRequestID(ctx, "req-123")
	ctx = WithUsername(ctx, "alice")
	ctx = WithClientIP(ctx, "10.0.0.1")
	ctx = WithBackend(ctx, "direct")

	if GetRequestID(ctx) != "req-123" {
		t.Error("RequestID not preserved")
	}
	if GetUsername(ctx) != "alice" {
		t.Error("Username not preserved")
	}
	if GetClientIP(ctx) != "10.0.0.1" {
		t.Error("ClientIP not preserved")
	}
	if GetBackend(ctx) != "direct" {
		t.Error("Backend not preserved")
	}
}
