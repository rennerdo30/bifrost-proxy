// Package session provides session token storage and management for Bifrost.
// It supports in-memory storage with TTL and optional persistent backends.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// Session represents an authenticated session.
type Session struct {
	ID        string         `json:"id"`
	UserInfo  *auth.UserInfo `json:"user_info"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	LastUsed  time.Time      `json:"last_used"`
	IPAddress string         `json:"ip_address,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Store is the interface for session storage backends.
type Store interface {
	// Get retrieves a session by ID.
	Get(id string) (*Session, error)

	// Create creates a new session and returns its ID.
	Create(session *Session) (string, error)

	// Update updates an existing session.
	Update(session *Session) error

	// Delete removes a session by ID.
	Delete(id string) error

	// DeleteByUser removes all sessions for a user.
	DeleteByUser(username string) error

	// ListByUser returns all sessions for a user.
	ListByUser(username string) ([]*Session, error)

	// Cleanup removes expired sessions.
	Cleanup() error

	// Close closes the store and releases resources.
	Close() error
}

// MemoryStore provides in-memory session storage.
type MemoryStore struct {
	sessions   map[string]*Session
	userIndex  map[string]map[string]bool // username -> session IDs
	mu         sync.RWMutex
	stopCh     chan struct{}
	cleanupInt time.Duration
}

// NewMemoryStore creates a new in-memory session store.
func NewMemoryStore(cleanupInterval time.Duration) *MemoryStore {
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}

	store := &MemoryStore{
		sessions:   make(map[string]*Session),
		userIndex:  make(map[string]map[string]bool),
		stopCh:     make(chan struct{}),
		cleanupInt: cleanupInterval,
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// Get retrieves a session by ID.
func (s *MemoryStore) Get(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[id]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// Create creates a new session and returns its ID.
func (s *MemoryStore) Create(session *Session) (string, error) {
	if session.ID == "" {
		id, err := generateSessionID()
		if err != nil {
			return "", err
		}
		session.ID = id
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.ID] = session

	// Update user index
	if session.UserInfo != nil {
		username := session.UserInfo.Username
		if s.userIndex[username] == nil {
			s.userIndex[username] = make(map[string]bool)
		}
		s.userIndex[username][session.ID] = true
	}

	return session.ID, nil
}

// Update updates an existing session.
func (s *MemoryStore) Update(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.ID]; !exists {
		return ErrSessionNotFound
	}

	s.sessions[session.ID] = session
	return nil
}

// Delete removes a session by ID.
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[id]
	if !exists {
		return nil // Already deleted
	}

	// Remove from user index
	if session.UserInfo != nil {
		delete(s.userIndex[session.UserInfo.Username], id)
		if len(s.userIndex[session.UserInfo.Username]) == 0 {
			delete(s.userIndex, session.UserInfo.Username)
		}
	}

	delete(s.sessions, id)
	return nil
}

// DeleteByUser removes all sessions for a user.
func (s *MemoryStore) DeleteByUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionIDs, exists := s.userIndex[username]
	if !exists {
		return nil
	}

	for id := range sessionIDs {
		delete(s.sessions, id)
	}
	delete(s.userIndex, username)

	return nil
}

// ListByUser returns all sessions for a user.
func (s *MemoryStore) ListByUser(username string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionIDs, exists := s.userIndex[username]
	if !exists {
		return nil, nil
	}

	sessions := make([]*Session, 0, len(sessionIDs))
	for id := range sessionIDs {
		if session, exists := s.sessions[id]; exists && !session.IsExpired() {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// Cleanup removes expired sessions.
func (s *MemoryStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, session := range s.sessions {
		if session.IsExpired() {
			// Remove from user index
			if session.UserInfo != nil {
				delete(s.userIndex[session.UserInfo.Username], id)
				if len(s.userIndex[session.UserInfo.Username]) == 0 {
					delete(s.userIndex, session.UserInfo.Username)
				}
			}
			delete(s.sessions, id)
		}
	}

	return nil
}

// Close stops the cleanup goroutine and releases resources.
func (s *MemoryStore) Close() error {
	close(s.stopCh)
	return nil
}

// cleanupLoop periodically removes expired sessions.
func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(s.cleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = s.Cleanup()
		case <-s.stopCh:
			return
		}
	}
}

// Count returns the number of active sessions.
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// generateSessionID generates a secure random session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Session store errors
var (
	ErrSessionNotFound = fmt.Errorf("session not found")
	ErrSessionExpired  = fmt.Errorf("session expired")
)
