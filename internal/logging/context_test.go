package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestFromContext_NoLogger(t *testing.T) {
	ctx := context.Background()
	logger := FromContext(ctx)

	if logger == nil {
		t.Error("FromContext() should return default logger when no logger in context")
	}
}

func TestFromContext_WithLogger(t *testing.T) {
	ctx := context.Background()
	customLogger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	ctx = WithContext(ctx, customLogger)
	logger := FromContext(ctx)

	if logger != customLogger {
		t.Error("FromContext() should return the logger from context")
	}
}

func TestWithContext(t *testing.T) {
	ctx := context.Background()
	customLogger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	newCtx := WithContext(ctx, customLogger)

	// Original context should not have the logger
	if logger, ok := ctx.Value(contextKey{}).(*slog.Logger); ok {
		t.Errorf("Original context should not have logger, got: %v", logger)
	}

	// New context should have the logger
	if logger, ok := newCtx.Value(contextKey{}).(*slog.Logger); !ok || logger != customLogger {
		t.Error("New context should have the custom logger")
	}
}

func TestContextWith(t *testing.T) {
	ctx := context.Background()

	// Add attributes to the context logger
	newCtx := ContextWith(ctx, "request_id", "123", "user", "alice")

	logger := FromContext(newCtx)
	if logger == nil {
		t.Error("ContextWith() should return context with logger")
	}
}

func TestDebugContext(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	customLogger := slog.New(handler)

	ctx := WithContext(context.Background(), customLogger)

	DebugContext(ctx, "debug message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "debug message") {
		t.Error("DebugContext() output not found")
	}
	if !strings.Contains(output, "key") {
		t.Error("DebugContext() key not found in output")
	}
}

func TestInfoContext(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	customLogger := slog.New(handler)

	ctx := WithContext(context.Background(), customLogger)

	InfoContext(ctx, "info message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "info message") {
		t.Error("InfoContext() output not found")
	}
}

func TestWarnContext(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	customLogger := slog.New(handler)

	ctx := WithContext(context.Background(), customLogger)

	WarnContext(ctx, "warn message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "warn message") {
		t.Error("WarnContext() output not found")
	}
}

func TestErrorContext(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelError,
	})
	customLogger := slog.New(handler)

	ctx := WithContext(context.Background(), customLogger)

	ErrorContext(ctx, "error message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "error message") {
		t.Error("ErrorContext() output not found")
	}
}

func TestContextLogging_DefaultLogger(t *testing.T) {
	// Test that context logging functions work with default logger
	ctx := context.Background()

	// These should not panic
	DebugContext(ctx, "debug")
	InfoContext(ctx, "info")
	WarnContext(ctx, "warn")
	ErrorContext(ctx, "error")
}
