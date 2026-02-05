// Package native provides username/password authentication with bcrypt hashes.
package native

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("native", &plugin{})
}

// plugin implements the auth.Plugin interface for native authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "native"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "Native username/password authentication with bcrypt hashes"
}

// Create creates a new NativeAuthenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	users, err := parseUsersConfig(config)
	if err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		users: make(map[string]user),
	}

	for _, u := range users {
		authenticator.users[u.Username] = u
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseUsersConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"users": []map[string]any{
			{
				"username":      "admin",
				"password_hash": "$2a$12$example...",
				"groups":        []string{"admins"},
				"email":         "admin@example.com",
				"full_name":     "Administrator",
				"disabled":      false,
			},
		},
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "users": {
      "type": "array",
      "description": "List of user configurations",
      "items": {
        "type": "object",
        "properties": {
          "username": {
            "type": "string",
            "description": "Username for authentication"
          },
          "password_hash": {
            "type": "string",
            "description": "bcrypt hash of the password (minimum cost 12)"
          },
          "groups": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Groups the user belongs to"
          },
          "email": {
            "type": "string",
            "description": "User's email address"
          },
          "full_name": {
            "type": "string",
            "description": "User's full name"
          },
          "disabled": {
            "type": "boolean",
            "description": "Whether the user is disabled"
          }
        },
        "required": ["username", "password_hash"]
      }
    }
  },
  "required": ["users"]
}`
}

// user represents an internal user record.
type user struct {
	Username     string
	PasswordHash string
	Groups       []string
	Email        string
	FullName     string
	Disabled     bool
}

// parseUsersConfig parses the users configuration from the config map.
func parseUsersConfig(config map[string]any) ([]user, error) {
	if config == nil {
		return nil, fmt.Errorf("native auth config is required")
	}

	usersAny, ok := config["users"]
	if !ok {
		return nil, fmt.Errorf("native auth config: 'users' field is required")
	}

	usersSlice, ok := usersAny.([]any)
	if !ok {
		// Try as []map[string]any directly
		if usersMap, ok := usersAny.([]map[string]any); ok {
			return parseUsersList(usersMap)
		}
		return nil, fmt.Errorf("native auth config: 'users' must be an array")
	}

	// Convert []any to []map[string]any
	users := make([]map[string]any, 0, len(usersSlice))
	for i, u := range usersSlice {
		userMap, ok := u.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("native auth config: user at index %d must be an object", i)
		}
		users = append(users, userMap)
	}

	return parseUsersList(users)
}

// parseUsersList parses a list of user maps into user structs.
func parseUsersList(users []map[string]any) ([]user, error) {
	result := make([]user, 0, len(users))

	for i, u := range users {
		username, _ := u["username"].(string) //nolint:errcheck // Type assertion - empty string is valid if missing
		if username == "" {
			return nil, fmt.Errorf("native auth config: user at index %d: 'username' is required", i)
		}

		passwordHash, _ := u["password_hash"].(string) //nolint:errcheck // Type assertion - empty string is valid if missing
		if passwordHash == "" {
			return nil, fmt.Errorf("native auth config: user %q: 'password_hash' is required", username)
		}

		var groups []string
		if groupsAny, ok := u["groups"]; ok {
			if groupsSlice, ok := groupsAny.([]any); ok {
				for _, g := range groupsSlice {
					if gs, ok := g.(string); ok {
						groups = append(groups, gs)
					}
				}
			} else if groupsStr, ok := groupsAny.([]string); ok {
				groups = groupsStr
			}
		}

		email, _ := u["email"].(string)       //nolint:errcheck // Type assertion - empty string is valid if missing
		fullName, _ := u["full_name"].(string) //nolint:errcheck // Type assertion - empty string is valid if missing
		disabled, _ := u["disabled"].(bool)   //nolint:errcheck // Type assertion - false is valid if missing

		result = append(result, user{
			Username:     username,
			PasswordHash: passwordHash,
			Groups:       groups,
			Email:        email,
			FullName:     fullName,
			Disabled:     disabled,
		})
	}

	return result, nil
}

// Authenticator provides username/password authentication with bcrypt hashes.
type Authenticator struct {
	users map[string]user
	mu    sync.RWMutex
}

// Authenticate validates a username and password.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	a.mu.RLock()
	u, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return nil, auth.NewAuthError("native", "authenticate", auth.ErrUserNotFound)
	}

	if u.Disabled {
		return nil, auth.NewAuthError("native", "authenticate", auth.ErrUserDisabled)
	}

	// Compare password with hash
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, auth.NewAuthError("native", "authenticate", auth.ErrInvalidCredentials)
	}

	return &auth.UserInfo{
		Username: u.Username,
		Groups:   u.Groups,
		Email:    u.Email,
		FullName: u.FullName,
	}, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "native"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "native"
}

// AddUser adds a user dynamically.
func (a *Authenticator) AddUser(username, passwordHash string, groups []string, email, fullName string, disabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.users[username] = user{
		Username:     username,
		PasswordHash: passwordHash,
		Groups:       groups,
		Email:        email,
		FullName:     fullName,
		Disabled:     disabled,
	}

	return nil
}

// RemoveUser removes a user.
func (a *Authenticator) RemoveUser(username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.users, username)
	return nil
}

// bcryptCost is the cost factor for bcrypt hashing.
// Per security guidelines, this should be at least 12.
const bcryptCost = 12

// HashPassword creates a bcrypt hash of a password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
