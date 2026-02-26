package protonvpn

import (
	"sync"
	"time"
)

// Session represents an authenticated ProtonVPN session.
type Session struct {
	UID          string
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	mu           sync.RWMutex
}

// NewSession creates a new session from API response.
func NewSession(resp *SessionResponse) *Session {
	return &Session{
		UID:          resp.UID,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		TokenType:    resp.TokenType,
		// ProtonVPN tokens typically expire after 24 hours
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

// IsValid checks if the session has valid tokens.
func (s *Session) IsValid() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AccessToken != "" && s.UID != ""
}

// IsExpired checks if the session token has expired.
func (s *Session) IsExpired() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Now().After(s.ExpiresAt)
}

// NeedsRefresh checks if the token should be refreshed (within 1 hour of expiry).
func (s *Session) NeedsRefresh() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Until(s.ExpiresAt) < time.Hour
}

// GetAuthHeader returns the Authorization header value.
func (s *Session) GetAuthHeader() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.TokenType != "" {
		return s.TokenType + " " + s.AccessToken
	}
	return "Bearer " + s.AccessToken
}

// GetUID returns the session UID.
func (s *Session) GetUID() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.UID
}

// Update updates the session with new tokens.
func (s *Session) Update(resp *SessionResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.UID = resp.UID
	s.AccessToken = resp.AccessToken
	s.RefreshToken = resp.RefreshToken
	s.TokenType = resp.TokenType
	s.ExpiresAt = time.Now().Add(24 * time.Hour)
}

// SessionStore provides persistent storage for sessions.
// This interface allows different storage backends (file, keychain, etc.).
type SessionStore interface {
	// Save persists the session.
	Save(session *Session) error
	// Load retrieves a saved session.
	Load() (*Session, error)
	// Clear removes the saved session.
	Clear() error
}

// MemorySessionStore stores sessions in memory (non-persistent).
type MemorySessionStore struct {
	session *Session
	mu      sync.RWMutex
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{}
}

// Save stores the session in memory.
func (m *MemorySessionStore) Save(session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = session
	return nil
}

// Load retrieves the stored session.
func (m *MemorySessionStore) Load() (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.session, nil
}

// Clear removes the stored session.
func (m *MemorySessionStore) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = nil
	return nil
}

// ManualCredentials holds credentials for manual authentication mode.
// In this mode, users provide their OpenVPN credentials directly
// (obtained from account.protonvpn.com/account#openvpn).
type ManualCredentials struct {
	// OpenVPNUsername is the ProtonVPN OpenVPN/IKEv2 username
	// (different from the Proton account username).
	OpenVPNUsername string

	// OpenVPNPassword is the ProtonVPN OpenVPN/IKEv2 password.
	OpenVPNPassword string

	// Tier indicates the user's subscription tier (0=free, 1=basic, 2=plus).
	// This is used to filter available servers.
	Tier int
}

// IsValid checks if the manual credentials are set.
func (m *ManualCredentials) IsValid() bool {
	return m.OpenVPNUsername != "" && m.OpenVPNPassword != ""
}

// AuthMode represents the authentication mode for the provider.
type AuthMode int

const (
	// AuthModeManual uses manually provided OpenVPN credentials.
	// This is the recommended mode as it doesn't require implementing
	// ProtonVPN's complex SRP authentication protocol.
	AuthModeManual AuthMode = iota

	// AuthModeAPI uses the ProtonVPN API with full authentication.
	// This mode is required for WireGuard key registration.
	AuthModeAPI
)

// String returns the string representation of the auth mode.
func (m AuthMode) String() string {
	switch m {
	case AuthModeManual:
		return "manual"
	case AuthModeAPI:
		return "api"
	default:
		return "unknown"
	}
}

// ParseAuthMode parses an auth mode string.
func ParseAuthMode(s string) AuthMode {
	switch s {
	case "api":
		return AuthModeAPI
	default:
		return AuthModeManual
	}
}
