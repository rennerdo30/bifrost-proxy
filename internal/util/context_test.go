package util

import (
	"context"
	"testing"
	"time"
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

func TestWithStartTime(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now()

	ctx = WithStartTime(ctx, startTime)
	result := GetStartTime(ctx)

	if !result.Equal(startTime) {
		t.Errorf("GetStartTime() = %v, want %v", result, startTime)
	}
}

func TestGetStartTime_Empty(t *testing.T) {
	ctx := context.Background()
	result := GetStartTime(ctx)

	if !result.IsZero() {
		t.Errorf("GetStartTime() from empty context should be zero time, got: %v", result)
	}
}

func TestGetDuration(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-100 * time.Millisecond)

	ctx = WithStartTime(ctx, startTime)
	duration := GetDuration(ctx)

	if duration < 100*time.Millisecond {
		t.Errorf("GetDuration() = %v, expected >= 100ms", duration)
	}
}

func TestGetDuration_NoStartTime(t *testing.T) {
	ctx := context.Background()
	duration := GetDuration(ctx)

	if duration != 0 {
		t.Errorf("GetDuration() without start time = %v, want 0", duration)
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

func TestWithDomain(t *testing.T) {
	ctx := context.Background()
	domain := "example.com"

	ctx = WithDomain(ctx, domain)
	result := GetDomain(ctx)

	if result != domain {
		t.Errorf("GetDomain() = %s, want %s", result, domain)
	}
}

func TestGetDomain_Empty(t *testing.T) {
	ctx := context.Background()
	result := GetDomain(ctx)

	if result != "" {
		t.Errorf("GetDomain() from empty context = %s, want empty string", result)
	}
}

func TestMultipleContextValues(t *testing.T) {
	ctx := context.Background()

	// Add multiple values
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithUsername(ctx, "alice")
	ctx = WithClientIP(ctx, "10.0.0.1")
	ctx = WithBackend(ctx, "direct")
	ctx = WithDomain(ctx, "test.com")
	ctx = WithStartTime(ctx, time.Now())

	// Verify all values are accessible
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
	if GetDomain(ctx) != "test.com" {
		t.Error("Domain not preserved")
	}
	if GetStartTime(ctx).IsZero() {
		t.Error("StartTime not preserved")
	}
}
