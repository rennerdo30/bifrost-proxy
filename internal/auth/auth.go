// Package auth provides authentication for Bifrost.
package auth

import (
	"context"
	"net/http"
)

// Authenticator is the interface for authentication providers.
type Authenticator interface {
	// Authenticate validates credentials and returns user info.
	Authenticate(ctx context.Context, username, password string) (*UserInfo, error)

	// Name returns the authenticator name.
	Name() string

	// Type returns the authenticator type.
	Type() string
}

// UserInfo contains information about an authenticated user.
type UserInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups,omitempty"`
	Email    string   `json:"email,omitempty"`
	FullName string   `json:"full_name,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Result represents an authentication result.
type Result struct {
	Authenticated bool
	User          *UserInfo
	Error         error
}

// HTTPCredentials extracts credentials from an HTTP request.
type HTTPCredentials struct {
	Username string
	Password string
	Token    string
}

// ExtractBasicAuth extracts Basic auth credentials from a request.
func ExtractBasicAuth(r *http.Request) (username, password string, ok bool) {
	return r.BasicAuth()
}

// ExtractProxyAuth extracts Proxy-Authorization credentials from a request.
func ExtractProxyAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}

	// Create a fake request with the header as Authorization
	fakeReq := &http.Request{Header: http.Header{}}
	fakeReq.Header.Set("Authorization", auth)
	return fakeReq.BasicAuth()
}

// Mode represents an authentication mode.
type Mode string

const (
	// ModeNone disables authentication.
	ModeNone Mode = "none"
	// ModeNative uses native username/password authentication.
	ModeNative Mode = "native"
	// ModeSystem uses system authentication (PAM on Linux, etc.)
	ModeSystem Mode = "system"
	// ModeLDAP uses LDAP authentication.
	ModeLDAP Mode = "ldap"
	// ModeOAuth uses OAuth/OIDC authentication.
	ModeOAuth Mode = "oauth"
)
