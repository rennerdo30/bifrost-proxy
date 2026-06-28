package session

import (
	"fmt"
	"time"
)

// StoreOptions selects and configures a session Store backend. It is a
// backend-agnostic description that the integrating layer (the server/API,
// mapping from its session configuration) populates before calling NewStore or
// BuildManager. Keeping it in the session package avoids a dependency from
// config on session.
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

// BuildManager constructs the Store selected by opts and wraps it in a Manager
// configured by mcfg. This is the single entry point the integrating server/API
// layer calls to obtain a fully wired session.Manager: it ensures the Redis
// backend (when selected) is actually constructed and reachable, failing closed
// if it is not. The caller owns the returned Manager and must call its Close
// method on shutdown to release the underlying store.
func BuildManager(opts StoreOptions, mcfg ManagerConfig) (*Manager, error) {
	store, err := NewStore(opts)
	if err != nil {
		return nil, fmt.Errorf("build session manager: %w", err)
	}
	return NewManager(store, mcfg), nil
}
