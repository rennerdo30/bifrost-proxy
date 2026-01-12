package util

import (
	"context"
	"time"
)

type contextKey string

const (
	requestIDKey  contextKey = "request_id"
	usernameKey   contextKey = "username"
	clientIPKey   contextKey = "client_ip"
	startTimeKey  contextKey = "start_time"
	backendKey    contextKey = "backend"
	domainKey     contextKey = "domain"
)

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// WithUsername adds a username to the context.
func WithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username)
}

// GetUsername retrieves the username from the context.
func GetUsername(ctx context.Context) string {
	if username, ok := ctx.Value(usernameKey).(string); ok {
		return username
	}
	return ""
}

// WithClientIP adds a client IP to the context.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// GetClientIP retrieves the client IP from the context.
func GetClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPKey).(string); ok {
		return ip
	}
	return ""
}

// WithStartTime adds a start time to the context.
func WithStartTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, startTimeKey, t)
}

// GetStartTime retrieves the start time from the context.
func GetStartTime(ctx context.Context) time.Time {
	if t, ok := ctx.Value(startTimeKey).(time.Time); ok {
		return t
	}
	return time.Time{}
}

// GetDuration returns the duration since the start time in the context.
func GetDuration(ctx context.Context) time.Duration {
	startTime := GetStartTime(ctx)
	if startTime.IsZero() {
		return 0
	}
	return time.Since(startTime)
}

// WithBackend adds a backend name to the context.
func WithBackend(ctx context.Context, backend string) context.Context {
	return context.WithValue(ctx, backendKey, backend)
}

// GetBackend retrieves the backend name from the context.
func GetBackend(ctx context.Context) string {
	if backend, ok := ctx.Value(backendKey).(string); ok {
		return backend
	}
	return ""
}

// WithDomain adds a domain to the context.
func WithDomain(ctx context.Context, domain string) context.Context {
	return context.WithValue(ctx, domainKey, domain)
}

// GetDomain retrieves the domain from the context.
func GetDomain(ctx context.Context) string {
	if domain, ok := ctx.Value(domainKey).(string); ok {
		return domain
	}
	return ""
}
