package logging

import (
	"context"
	"log/slog"
)

type contextKey struct{}

// FromContext returns the logger from the context.
// If no logger is present, returns the default logger.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(contextKey{}).(*slog.Logger); ok {
		return logger
	}
	return Default()
}

// WithContext returns a new context with the given logger.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// ContextWith returns a new context with additional attributes added to the logger.
func ContextWith(ctx context.Context, args ...any) context.Context {
	logger := FromContext(ctx).With(args...)
	return WithContext(ctx, logger)
}

// DebugContext logs at debug level using the context logger.
func DebugContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Debug(msg, args...)
}

// InfoContext logs at info level using the context logger.
func InfoContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Info(msg, args...)
}

// WarnContext logs at warn level using the context logger.
func WarnContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Warn(msg, args...)
}

// ErrorContext logs at error level using the context logger.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Error(msg, args...)
}
