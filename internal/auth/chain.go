package auth

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// ChainAuthenticator tries multiple authenticators in priority order.
type ChainAuthenticator struct {
	authenticators []authenticatorEntry
	mu             sync.RWMutex
}

type authenticatorEntry struct {
	name        string
	priority    int
	auth        Authenticator
}

// NewChainAuthenticator creates a new chain authenticator.
func NewChainAuthenticator() *ChainAuthenticator {
	return &ChainAuthenticator{
		authenticators: make([]authenticatorEntry, 0),
	}
}

// AddAuthenticator adds an authenticator to the chain.
func (c *ChainAuthenticator) AddAuthenticator(name string, priority int, auth Authenticator) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authenticators = append(c.authenticators, authenticatorEntry{
		name:     name,
		priority: priority,
		auth:     auth,
	})

	// Sort by priority (lowest first)
	sort.Slice(c.authenticators, func(i, j int) bool {
		return c.authenticators[i].priority < c.authenticators[j].priority
	})
}

// Authenticate tries each authenticator in priority order.
// Returns success on the first successful authentication.
// Returns ErrInvalidCredentials if all authenticators fail.
func (c *ChainAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.authenticators) == 0 {
		return nil, errors.New("no authenticators configured")
	}

	var lastErr error
	for _, entry := range c.authenticators {
		userInfo, err := entry.auth.Authenticate(ctx, username, password)
		if err == nil && userInfo != nil {
			// Add metadata about which provider authenticated the user
			if userInfo.Metadata == nil {
				userInfo.Metadata = make(map[string]string)
			}
			userInfo.Metadata["auth_provider"] = entry.name
			userInfo.Metadata["auth_type"] = entry.auth.Type()
			return userInfo, nil
		}
		lastErr = err
	}

	// All authenticators failed
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrInvalidCredentials
}

// Name returns the chain authenticator name.
func (c *ChainAuthenticator) Name() string {
	return "chain"
}

// Type returns the authenticator type.
func (c *ChainAuthenticator) Type() string {
	return "chain"
}

// Count returns the number of authenticators in the chain.
func (c *ChainAuthenticator) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.authenticators)
}

// Authenticators returns the list of authenticator names in priority order.
func (c *ChainAuthenticator) Authenticators() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := make([]string, len(c.authenticators))
	for i, entry := range c.authenticators {
		names[i] = entry.name
	}
	return names
}
