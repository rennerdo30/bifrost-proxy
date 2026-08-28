package auth

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the cost factor for bcrypt hashing.
// Per security guidelines, this should be at least 12.
const bcryptCost = 12

// HashPassword creates a bcrypt hash of a password.
// This is a convenience function for creating password hashes.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ExtractProxyBearerToken extracts a Bearer token from the Proxy-Authorization
// header. The HTTP proxy handler uses it to accept a bearer credential on the
// proxy hop (internal/proxy/http.go).
//
// It previously lived in middleware.go beside an unused Authorization-header
// twin; that file was removed as dead code, but this function is on the live
// proxy authentication path and moved here rather than being deleted with it.
func ExtractProxyBearerToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Proxy-Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), true
	}
	return "", false
}
