package auth

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// ContextKey is a type for context keys used by the auth package.
type ContextKey string

const (
	// UserInfoContextKey is the context key for user information.
	UserInfoContextKey ContextKey = "auth_user_info"
	// ClientCertContextKey is the context key for client certificate.
	ClientCertContextKey ContextKey = "auth_client_cert"
)

// Middleware provides HTTP authentication middleware.
type Middleware struct {
	authenticator Authenticator
	realm         string
	// apiKeyHeader is the header name for API key authentication.
	apiKeyHeader string
	// apiKeyAuth is the optional API key authenticator.
	apiKeyAuth Authenticator
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
		if m.authenticator.Type() == "none" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract credentials
		username, password, ok := r.BasicAuth()
		if !ok {
			m.logAuthFailure(r, "", "no_credentials", nil)
			m.sendUnauthorized(w)
			return
		}

		// Authenticate
		userInfo, err := m.authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			m.logAuthFailure(r, username, "invalid_credentials", err)
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
		if m.authenticator.Type() == "none" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract proxy credentials
		username, password, ok := ExtractProxyAuth(r)
		if !ok {
			m.logAuthFailure(r, "", "no_proxy_credentials", nil)
			m.sendProxyAuthRequired(w)
			return
		}

		// Authenticate
		userInfo, err := m.authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			m.logAuthFailure(r, username, "invalid_proxy_credentials", err)
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

// logAuthFailure logs authentication failures for audit purposes.
func (m *Middleware) logAuthFailure(r *http.Request, username, reason string, err error) {
	clientIP := r.RemoteAddr
	// Check for X-Forwarded-For header (if behind a proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first IP in the chain (original client)
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	}
	attrs := []any{
		"client_ip", clientIP,
		"reason", reason,
		"path", r.URL.Path,
		"method", r.Method,
	}
	if username != "" {
		attrs = append(attrs, "username", username)
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	slog.Warn("authentication failed", attrs...)
}

// sendProxyAuthRequired sends a 407 Proxy Authentication Required response.
func (m *Middleware) sendProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+m.realm+`"`)
	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
}

// AuthenticateForProxy authenticates for proxy use (returns user or anonymous).
func (m *Middleware) AuthenticateForProxy(ctx context.Context, username, password string) (*UserInfo, error) {
	// If no auth is required, return anonymous user
	if m.authenticator.Type() == "none" {
		return &UserInfo{Username: "anonymous"}, nil
	}

	return m.authenticator.Authenticate(ctx, username, password)
}

// SetAPIKeyAuth sets an API key authenticator and header name.
func (m *Middleware) SetAPIKeyAuth(auth Authenticator, headerName string) {
	m.apiKeyAuth = auth
	m.apiKeyHeader = headerName
}

// MultiAuthHandler wraps an HTTP handler with multiple authentication methods.
// It supports: Basic auth, Bearer tokens, API keys, and client certificates.
func (m *Middleware) MultiAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for none mode
		if m.authenticator.Type() == "none" {
			next.ServeHTTP(w, r)
			return
		}

		var userInfo *UserInfo
		var err error

		// Try client certificate first (if TLS)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			userInfo, err = m.tryClientCert(r.Context(), r.TLS.PeerCertificates[0])
			if err == nil && userInfo != nil {
				ctx := m.setUserContext(r.Context(), userInfo, r.TLS.PeerCertificates[0])
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}
		}

		// Try API key header
		if m.apiKeyAuth != nil && m.apiKeyHeader != "" {
			apiKey := r.Header.Get(m.apiKeyHeader)
			if apiKey != "" {
				userInfo, err = m.apiKeyAuth.Authenticate(r.Context(), "", apiKey)
				if err == nil && userInfo != nil {
					ctx := m.setUserContext(r.Context(), userInfo, nil)
					r = r.WithContext(ctx)
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Try Bearer token
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			userInfo, err = m.authenticator.Authenticate(r.Context(), "", token)
			if err == nil && userInfo != nil {
				ctx := m.setUserContext(r.Context(), userInfo, nil)
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}
		}

		// Try Basic auth
		username, password, ok := r.BasicAuth()
		if ok {
			userInfo, err = m.authenticator.Authenticate(r.Context(), username, password)
			if err == nil && userInfo != nil {
				ctx := m.setUserContext(r.Context(), userInfo, nil)
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}
		}

		// No valid authentication - log failure
		m.logAuthFailure(r, username, "all_methods_failed", err)
		m.sendUnauthorized(w)
	})
}

// MultiProxyAuthHandler wraps an HTTP handler with multiple proxy authentication methods.
func (m *Middleware) MultiProxyAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for none mode
		if m.authenticator.Type() == "none" {
			next.ServeHTTP(w, r)
			return
		}

		var userInfo *UserInfo
		var err error

		// Try client certificate first (if TLS)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			userInfo, err = m.tryClientCert(r.Context(), r.TLS.PeerCertificates[0])
			if err == nil && userInfo != nil {
				ctx := m.setUserContext(r.Context(), userInfo, r.TLS.PeerCertificates[0])
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}
		}

		// Try API key header
		if m.apiKeyAuth != nil && m.apiKeyHeader != "" {
			apiKey := r.Header.Get(m.apiKeyHeader)
			if apiKey != "" {
				userInfo, err = m.apiKeyAuth.Authenticate(r.Context(), "", apiKey)
				if err == nil && userInfo != nil {
					ctx := m.setUserContext(r.Context(), userInfo, nil)
					r = r.WithContext(ctx)
					r.Header.Del(m.apiKeyHeader) // Remove before forwarding
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Try Proxy-Authorization header
		proxyAuth := r.Header.Get("Proxy-Authorization")
		if proxyAuth != "" {
			// Try Bearer token in Proxy-Authorization
			if strings.HasPrefix(proxyAuth, "Bearer ") {
				token := strings.TrimPrefix(proxyAuth, "Bearer ")
				userInfo, err = m.authenticator.Authenticate(r.Context(), "", token)
				if err == nil && userInfo != nil {
					ctx := m.setUserContext(r.Context(), userInfo, nil)
					r = r.WithContext(ctx)
					r.Header.Del("Proxy-Authorization")
					next.ServeHTTP(w, r)
					return
				}
			}

			// Try Basic auth in Proxy-Authorization
			username, password, ok := ExtractProxyAuth(r)
			if ok {
				userInfo, err = m.authenticator.Authenticate(r.Context(), username, password)
				if err == nil && userInfo != nil {
					ctx := m.setUserContext(r.Context(), userInfo, nil)
					r = r.WithContext(ctx)
					r.Header.Del("Proxy-Authorization")
					next.ServeHTTP(w, r)
					return
				}
				// Log failure for basic auth attempt in proxy context
				m.logAuthFailure(r, username, "proxy_all_methods_failed", err)
				m.sendProxyAuthRequired(w)
				return
			}
		}

		// No valid authentication
		m.logAuthFailure(r, "", "proxy_no_credentials", nil)
		m.sendProxyAuthRequired(w)
	})
}

// tryClientCert attempts to authenticate using a client certificate.
func (m *Middleware) tryClientCert(ctx context.Context, cert *x509.Certificate) (*UserInfo, error) {
	// Check if authenticator supports mTLS
	if m.authenticator.Type() == "mtls" {
		// Pass certificate via context
		ctx = context.WithValue(ctx, ClientCertContextKey, cert)
		return m.authenticator.Authenticate(ctx, "", "")
	}
	return nil, ErrAuthMethodUnsupported
}

// setUserContext adds user information to the context.
func (m *Middleware) setUserContext(ctx context.Context, userInfo *UserInfo, cert *x509.Certificate) context.Context {
	ctx = util.WithUsername(ctx, userInfo.Username)
	ctx = context.WithValue(ctx, UserInfoContextKey, userInfo)
	if cert != nil {
		ctx = context.WithValue(ctx, ClientCertContextKey, cert)
	}
	return ctx
}

// GetUserInfo retrieves user information from the context.
func GetUserInfo(ctx context.Context) *UserInfo {
	userInfo, _ := ctx.Value(UserInfoContextKey).(*UserInfo)
	return userInfo
}

// GetClientCert retrieves the client certificate from the context.
func GetClientCert(ctx context.Context) *x509.Certificate {
	cert, _ := ctx.Value(ClientCertContextKey).(*x509.Certificate)
	return cert
}

// ExtractBearerToken extracts a Bearer token from the Authorization header.
func ExtractBearerToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), true
	}
	return "", false
}

// ExtractProxyBearerToken extracts a Bearer token from the Proxy-Authorization header.
func ExtractProxyBearerToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Proxy-Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), true
	}
	return "", false
}
