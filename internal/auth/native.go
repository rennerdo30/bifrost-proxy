package auth

import (
	"context"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// NativeAuthenticator provides username/password authentication with bcrypt hashes.
type NativeAuthenticator struct {
	users map[string]nativeUser
	mu    sync.RWMutex
}

type nativeUser struct {
	Username     string
	PasswordHash string
	Groups       []string
	Email        string
	FullName     string
	Disabled     bool
}

// NativeConfig holds configuration for native authentication.
type NativeConfig struct {
	Users []NativeUserConfig `yaml:"users"`
}

// NativeUserConfig represents a user in native auth config.
type NativeUserConfig struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"`
	Groups       []string `yaml:"groups,omitempty"`
	Email        string   `yaml:"email,omitempty"`
	FullName     string   `yaml:"full_name,omitempty"`
	Disabled     bool     `yaml:"disabled,omitempty"`
}

// NewNativeAuthenticator creates a new native authenticator.
func NewNativeAuthenticator(cfg NativeConfig) *NativeAuthenticator {
	auth := &NativeAuthenticator{
		users: make(map[string]nativeUser),
	}

	for _, u := range cfg.Users {
		auth.users[u.Username] = nativeUser{
			Username:     u.Username,
			PasswordHash: u.PasswordHash,
			Groups:       u.Groups,
			Email:        u.Email,
			FullName:     u.FullName,
			Disabled:     u.Disabled,
		}
	}

	return auth
}

// Authenticate validates a username and password.
func (a *NativeAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return nil, NewAuthError("native", "authenticate", ErrUserNotFound)
	}

	if user.Disabled {
		return nil, NewAuthError("native", "authenticate", ErrUserDisabled)
	}

	// Compare password with hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, NewAuthError("native", "authenticate", ErrInvalidCredentials)
	}

	return &UserInfo{
		Username: user.Username,
		Groups:   user.Groups,
		Email:    user.Email,
		FullName: user.FullName,
	}, nil
}

// Name returns the authenticator name.
func (a *NativeAuthenticator) Name() string {
	return "native"
}

// Type returns the authenticator type.
func (a *NativeAuthenticator) Type() string {
	return "native"
}

// AddUser adds a user.
func (a *NativeAuthenticator) AddUser(cfg NativeUserConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.users[cfg.Username] = nativeUser{
		Username:     cfg.Username,
		PasswordHash: cfg.PasswordHash,
		Groups:       cfg.Groups,
		Email:        cfg.Email,
		FullName:     cfg.FullName,
		Disabled:     cfg.Disabled,
	}

	return nil
}

// RemoveUser removes a user.
func (a *NativeAuthenticator) RemoveUser(username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.users, username)
	return nil
}

// HashPassword creates a bcrypt hash of a password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
