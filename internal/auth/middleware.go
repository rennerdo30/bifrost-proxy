package auth

import (
	"context"
	"net/http"

	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// Middleware provides HTTP authentication middleware.
type Middleware struct {
	authenticator Authenticator
	realm         string
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(authenticator Authenticator, realm string) *Middleware {
	if realm == "" {
		realm = "Bifrost Proxy"
	}
	return &Middleware{
		authenticator: authenticator,
		realm:         realm,
	}
}

// Handler wraps an HTTP handler with authentication.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for none mode
		if _, ok := m.authenticator.(*NoneAuthenticator); ok {
			next.ServeHTTP(w, r)
			return
		}

		// Extract credentials
		username, password, ok := r.BasicAuth()
		if !ok {
			m.sendUnauthorized(w)
			return
		}

		// Authenticate
		userInfo, err := m.authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			m.sendUnauthorized(w)
			return
		}

		// Add user info to context
		ctx := util.WithUsername(r.Context(), userInfo.Username)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// ProxyHandler wraps an HTTP handler with proxy authentication.
func (m *Middleware) ProxyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for none mode
		if _, ok := m.authenticator.(*NoneAuthenticator); ok {
			next.ServeHTTP(w, r)
			return
		}

		// Extract proxy credentials
		username, password, ok := ExtractProxyAuth(r)
		if !ok {
			m.sendProxyAuthRequired(w)
			return
		}

		// Authenticate
		userInfo, err := m.authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			m.sendProxyAuthRequired(w)
			return
		}

		// Add user info to context
		ctx := util.WithUsername(r.Context(), userInfo.Username)
		r = r.WithContext(ctx)

		// Remove the proxy auth header before forwarding
		r.Header.Del("Proxy-Authorization")

		next.ServeHTTP(w, r)
	})
}

// Authenticate performs authentication and returns the user info.
func (m *Middleware) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	return m.authenticator.Authenticate(ctx, username, password)
}

// sendUnauthorized sends a 401 Unauthorized response.
func (m *Middleware) sendUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+m.realm+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// sendProxyAuthRequired sends a 407 Proxy Authentication Required response.
func (m *Middleware) sendProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+m.realm+`"`)
	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
}

// AuthenticateForProxy authenticates for proxy use (returns user or anonymous).
func (m *Middleware) AuthenticateForProxy(ctx context.Context, username, password string) (*UserInfo, error) {
	// If no auth is required, return anonymous user
	if _, ok := m.authenticator.(*NoneAuthenticator); ok {
		return &UserInfo{Username: "anonymous"}, nil
	}

	return m.authenticator.Authenticate(ctx, username, password)
}
