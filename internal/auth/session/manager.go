// Package session provides session token storage and management for Bifrost.
package session

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// ManagerConfig configures the session manager.
type ManagerConfig struct {
	// SessionDuration is the default session lifetime.
	SessionDuration time.Duration
	// MaxSessionsPerUser limits concurrent sessions per user (0 = unlimited).
	MaxSessionsPerUser int
	// SecureCookies requires HTTPS for session cookies.
	SecureCookies bool
	// CookieName is the name of the session cookie.
	CookieName string
	// CookiePath is the path for the session cookie.
	CookiePath string
	// CookieDomain is the domain for the session cookie.
	CookieDomain string
	// RotateOnUse regenerates session ID on each use.
	RotateOnUse bool
	// ExtendOnUse extends session expiration on each use.
	ExtendOnUse bool
}

// DefaultManagerConfig returns sensible default configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		SessionDuration:    8 * time.Hour,
		MaxSessionsPerUser: 10,
		SecureCookies:      true,
		CookieName:         "bifrost_session",
		CookiePath:         "/",
		ExtendOnUse:        true,
	}
}

// Manager manages session lifecycle.
type Manager struct {
	store  Store
	config ManagerConfig
}

// NewManager creates a new session manager.
func NewManager(store Store, config ManagerConfig) *Manager {
	return &Manager{
		store:  store,
		config: config,
	}
}

// CreateSession creates a new session for an authenticated user.
func (m *Manager) CreateSession(userInfo *auth.UserInfo, ipAddress, userAgent string) (*Session, error) {
	// Check session limit
	if m.config.MaxSessionsPerUser > 0 {
		existing, err := m.store.ListByUser(userInfo.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to check existing sessions: %w", err)
		}

		if len(existing) >= m.config.MaxSessionsPerUser {
			// Delete oldest session
			var oldest *Session
			for _, s := range existing {
				if oldest == nil || s.CreatedAt.Before(oldest.CreatedAt) {
					oldest = s
				}
			}
			if oldest != nil {
				if err := m.store.Delete(oldest.ID); err != nil {
					slog.Warn("failed to delete oldest session",
						"session_id", oldest.ID,
						"error", err,
					)
				}
			}
		}
	}

	now := time.Now()
	session := &Session{
		UserInfo:  userInfo,
		CreatedAt: now,
		ExpiresAt: now.Add(m.config.SessionDuration),
		LastUsed:  now,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Metadata:  make(map[string]string),
	}

	id, err := m.store.Create(session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	session.ID = id

	slog.Debug("session created",
		"session_id", id,
		"username", userInfo.Username,
		"expires_at", session.ExpiresAt,
	)

	return session, nil
}

// GetSession retrieves and validates a session.
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	session, err := m.store.Get(sessionID)
	if err != nil {
		return nil, err
	}

	// Update last used time
	session.LastUsed = time.Now()

	// Extend expiration if configured
	if m.config.ExtendOnUse {
		session.ExpiresAt = time.Now().Add(m.config.SessionDuration)
	}

	if err := m.store.Update(session); err != nil {
		slog.Warn("failed to update session",
			"session_id", sessionID,
			"error", err,
		)
	}

	return session, nil
}

// ValidateSession validates a session token and returns user info.
func (m *Manager) ValidateSession(sessionID string) (*auth.UserInfo, error) {
	session, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	return session.UserInfo, nil
}

// DestroySession invalidates a session.
func (m *Manager) DestroySession(sessionID string) error {
	if err := m.store.Delete(sessionID); err != nil {
		return fmt.Errorf("failed to destroy session: %w", err)
	}

	slog.Debug("session destroyed", "session_id", sessionID)
	return nil
}

// DestroyUserSessions invalidates all sessions for a user.
func (m *Manager) DestroyUserSessions(username string) error {
	if err := m.store.DeleteByUser(username); err != nil {
		return fmt.Errorf("failed to destroy user sessions: %w", err)
	}

	slog.Debug("user sessions destroyed", "username", username)
	return nil
}

// ListUserSessions returns all active sessions for a user.
func (m *Manager) ListUserSessions(username string) ([]*Session, error) {
	return m.store.ListByUser(username)
}

// SetSessionCookie sets the session cookie on an HTTP response.
func (m *Manager) SetSessionCookie(w http.ResponseWriter, session *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.config.CookieName,
		Value:    session.ID,
		Path:     m.config.CookiePath,
		Domain:   m.config.CookieDomain,
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
		HttpOnly: true,
		Secure:   m.config.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie removes the session cookie.
func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.config.CookieName,
		Value:    "",
		Path:     m.config.CookiePath,
		Domain:   m.config.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.config.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// GetSessionFromRequest extracts the session ID from an HTTP request.
func (m *Manager) GetSessionFromRequest(r *http.Request) (string, error) {
	// Try cookie first
	cookie, err := r.Cookie(m.config.CookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	// Try Authorization header with Bearer token
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && subtle.ConstantTimeCompare([]byte(authHeader[:7]), []byte("Bearer ")) == 1 {
		return authHeader[7:], nil
	}

	// Try X-Session-Token header
	sessionHeader := r.Header.Get("X-Session-Token")
	if sessionHeader != "" {
		return sessionHeader, nil
	}

	return "", ErrSessionNotFound
}

// ValidateRequestSession validates the session from an HTTP request.
func (m *Manager) ValidateRequestSession(r *http.Request) (*Session, error) {
	sessionID, err := m.GetSessionFromRequest(r)
	if err != nil {
		return nil, err
	}

	return m.GetSession(sessionID)
}

// Middleware returns an HTTP middleware that validates sessions.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.ValidateRequestSession(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add session to context
		ctx := context.WithValue(r.Context(), SessionContextKey, session)
		ctx = context.WithValue(ctx, UserInfoContextKey, session.UserInfo)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// OptionalMiddleware returns middleware that attaches session if present but doesn't require it.
func (m *Manager) OptionalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.ValidateRequestSession(r)
		if err == nil && session != nil {
			ctx := context.WithValue(r.Context(), SessionContextKey, session)
			ctx = context.WithValue(ctx, UserInfoContextKey, session.UserInfo)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// Context keys for session middleware.
type contextKey string

const (
	// SessionContextKey is the context key for the session.
	SessionContextKey contextKey = "session"
	// UserInfoContextKey is the context key for the user info.
	UserInfoContextKey contextKey = "user_info"
)

// GetSessionFromContext retrieves the session from context.
func GetSessionFromContext(ctx context.Context) *Session {
	session, _ := ctx.Value(SessionContextKey).(*Session)
	return session
}

// GetUserInfoFromContext retrieves the user info from context.
func GetUserInfoFromContext(ctx context.Context) *auth.UserInfo {
	userInfo, _ := ctx.Value(UserInfoContextKey).(*auth.UserInfo)
	return userInfo
}

// Close closes the manager and its store.
func (m *Manager) Close() error {
	return m.store.Close()
}
