package session

import (
	"fmt"
	"time"
)

// StoreOptions selects and configures a session Store backend. It is a
// backend-agnostic description that callers (e.g. the server, mapping from
// config.SessionConfig) populate. Keeping it in the session package avoids a
// dependency from config on session.
type StoreOptions struct {
	// Type selects the backend: "memory" (default) or "redis".
	Type string

	// CleanupInterval controls the memory store reaper cadence (memory only).
	CleanupInterval time.Duration

	// Redis holds connection settings used when Type == "redis".
	Redis RedisStoreOptions
}

// NewStore constructs the session Store selected by opts. For "redis" it
// connects and PINGs the server, returning an error if it is unreachable so the
// caller fails closed. For "memory" (or empty) it returns an in-memory store.
func NewStore(opts StoreOptions) (Store, error) {
	switch opts.Type {
	case "", "memory":
		return NewMemoryStore(opts.CleanupInterval), nil
	case "redis":
		store, err := NewRedisStore(opts.Redis)
		if err != nil {
			return nil, fmt.Errorf("create redis session store: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("unknown session store type %q (expected \"memory\" or \"redis\")", opts.Type)
	}
}
