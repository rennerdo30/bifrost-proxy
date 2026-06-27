package config

import "errors"

var errSessionRedisAddrRequired = errors.New("session: redis store selected but redis.addr is empty")

// SessionConfig selects and configures the session storage backend used for
// authenticated Web UI / API sessions.
//
// Store selects the backend:
//   - "" or "memory" -> in-process memory store (default; not shared across
//     replicas, lost on restart).
//   - "redis"        -> Redis-backed store (shared across replicas, survives
//     restarts). Requires the Redis section to be populated.
type SessionConfig struct {
	// Store selects the backend: "memory" (default) or "redis".
	Store string `yaml:"store" json:"store"`

	// Duration is the default session lifetime. Zero falls back to the manager
	// default (8h).
	Duration Duration `yaml:"duration" json:"duration"`

	// MaxSessionsPerUser limits concurrent sessions per user (0 = unlimited).
	MaxSessionsPerUser int `yaml:"max_sessions_per_user" json:"max_sessions_per_user"`

	// CleanupInterval controls how often the memory store reaps expired
	// sessions. Ignored by the Redis store (Redis expires keys via TTL).
	CleanupInterval Duration `yaml:"cleanup_interval" json:"cleanup_interval"`

	// Redis holds connection settings used when Store == "redis".
	Redis RedisSessionConfig `yaml:"redis" json:"redis"`
}

// RedisSessionConfig configures the Redis-backed session store.
type RedisSessionConfig struct {
	// Addr is the Redis server address (host:port), e.g. "127.0.0.1:6379".
	Addr string `yaml:"addr" json:"addr"`

	// Password is the optional Redis AUTH password.
	Password string `yaml:"password" json:"password"`

	// DB is the Redis logical database index.
	DB int `yaml:"db" json:"db"`

	// KeyPrefix namespaces all keys (default "bifrost:session:").
	KeyPrefix string `yaml:"key_prefix" json:"key_prefix"`

	// OpTimeout bounds each individual Redis operation. Zero uses a 5s default.
	OpTimeout Duration `yaml:"op_timeout" json:"op_timeout"`
}

// StoreType returns the normalized session store type ("memory" or "redis").
func (c SessionConfig) StoreType() string {
	switch c.Store {
	case "redis":
		return "redis"
	default:
		return "memory"
	}
}

// Validate checks the session configuration for internal consistency. It
// returns an error if the Redis store is selected without an address so a
// misconfiguration is caught at load time rather than at first request.
func (c SessionConfig) Validate() error {
	if c.StoreType() == "redis" && c.Redis.Addr == "" {
		return errSessionRedisAddrRequired
	}
	return nil
}
