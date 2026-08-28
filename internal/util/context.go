package util

import (
	"context"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	usernameKey  contextKey = "username"
	clientIPKey  contextKey = "client_ip"
	backendKey   contextKey = "backend"
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
