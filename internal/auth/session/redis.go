// Package session provides session token storage and management for Bifrost.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisClient is the subset of the go-redis client API used by RedisStore.
// It is defined as an interface so the store logic can be unit-tested with a
// mock and does not require a live Redis at test time.
type redisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	SAdd(ctx context.Context, key string, members ...any) *redis.IntCmd
	SRem(ctx context.Context, key string, members ...any) *redis.IntCmd
	SMembers(ctx context.Context, key string) *redis.StringSliceCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

// RedisStore provides Redis-backed session storage. Sessions are stored as JSON
// with a per-key TTL matching the session expiry, so expired sessions are
// reaped automatically by Redis. A per-user set tracks the session IDs owned by
// each user to support ListByUser / DeleteByUser.
type RedisStore struct {
	client    redisClient
	keyPrefix string
	// opTimeout bounds each individual Redis operation.
	opTimeout time.Duration
}

// RedisStoreOptions configures a RedisStore.
type RedisStoreOptions struct {
	// Addr is the Redis server address (host:port).
	Addr string
	// Password is the optional Redis AUTH password.
	Password string
	// DB is the Redis database index.
	DB int
	// KeyPrefix namespaces all keys written by this store (default "bifrost:session:").
	KeyPrefix string
	// OpTimeout bounds each Redis operation (default 5s).
	OpTimeout time.Duration
	// TLS, when non-nil, enables TLS to the Redis server.
	// Left as a placeholder for callers that build the client themselves.
}

const (
	defaultRedisKeyPrefix = "bifrost:session:"
	defaultRedisOpTimeout = 5 * time.Second
)

// NewRedisStore creates a RedisStore backed by a real go-redis client and
// verifies connectivity with a PING. It returns an error if the server cannot
// be reached so a misconfigured backend fails closed at startup rather than at
// first request.
func NewRedisStore(opts RedisStoreOptions) (*RedisStore, error) {
	if opts.Addr == "" {
		return nil, errors.New("redis session store requires an address")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     opts.Addr,
		Password: opts.Password,
		DB:       opts.DB,
	})

	store := newRedisStoreWithClient(client, opts)

	ctx, cancel := context.WithTimeout(context.Background(), store.opTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close() //nolint:errcheck // best effort on failed init
		return nil, fmt.Errorf("failed to connect to redis session store at %s: %w", opts.Addr, err)
	}

	return store, nil
}

// newRedisStoreWithClient builds a RedisStore around an arbitrary redisClient.
// It is used by NewRedisStore and by tests with a mock client.
func newRedisStoreWithClient(client redisClient, opts RedisStoreOptions) *RedisStore {
	prefix := opts.KeyPrefix
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	timeout := opts.OpTimeout
	if timeout <= 0 {
		timeout = defaultRedisOpTimeout
	}
	return &RedisStore{
		client:    client,
		keyPrefix: prefix,
		opTimeout: timeout,
	}
}

func (s *RedisStore) sessionKey(id string) string {
	return s.keyPrefix + "id:" + id
}

func (s *RedisStore) userKey(username string) string {
	return s.keyPrefix + "user:" + username
}

func (s *RedisStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.opTimeout)
}

// Get retrieves a session by ID.
func (s *RedisStore) Get(id string) (*Session, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	data, err := s.client.Get(ctx, s.sessionKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("redis get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("redis decode session: %w", err)
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// Create creates a new session and returns its ID.
func (s *RedisStore) Create(session *Session) (string, error) {
	if session.ID == "" {
		id, err := generateSessionID()
		if err != nil {
			return "", err
		}
		session.ID = id
	}

	if err := s.persist(session); err != nil {
		return "", err
	}

	// Index by user.
	if session.UserInfo != nil && session.UserInfo.Username != "" {
		ctx, cancel := s.ctx()
		defer cancel()
		if err := s.client.SAdd(ctx, s.userKey(session.UserInfo.Username), session.ID).Err(); err != nil {
			return "", fmt.Errorf("redis index session by user: %w", err)
		}
	}

	return session.ID, nil
}

// Update updates an existing session. It returns ErrSessionNotFound if the
// session does not currently exist (mirroring MemoryStore semantics).
func (s *RedisStore) Update(session *Session) error {
	ctx, cancel := s.ctx()
	exists, err := s.client.Get(ctx, s.sessionKey(session.ID)).Result()
	cancel()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("redis check session: %w", err)
	}
	_ = exists

	return s.persist(session)
}

// persist writes a session with a TTL derived from its expiry.
func (s *RedisStore) persist(session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("redis encode session: %w", err)
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		// Already expired; don't write a never-expiring key.
		ttl = time.Second
	}

	ctx, cancel := s.ctx()
	defer cancel()
	if err := s.client.Set(ctx, s.sessionKey(session.ID), data, ttl).Err(); err != nil {
		return fmt.Errorf("redis set session: %w", err)
	}
	return nil
}

// Delete removes a session by ID.
func (s *RedisStore) Delete(id string) error {
	// Look up the session first so we can clean the user index.
	session, err := s.Get(id)
	if err != nil && !errors.Is(err, ErrSessionNotFound) && !errors.Is(err, ErrSessionExpired) {
		return err
	}

	ctx, cancel := s.ctx()
	defer cancel()
	if err := s.client.Del(ctx, s.sessionKey(id)).Err(); err != nil {
		return fmt.Errorf("redis delete session: %w", err)
	}

	if session != nil && session.UserInfo != nil && session.UserInfo.Username != "" {
		if err := s.client.SRem(ctx, s.userKey(session.UserInfo.Username), id).Err(); err != nil {
			return fmt.Errorf("redis remove session from user index: %w", err)
		}
	}

	return nil
}

// DeleteByUser removes all sessions for a user.
func (s *RedisStore) DeleteByUser(username string) error {
	ctx, cancel := s.ctx()
	defer cancel()

	ids, err := s.client.SMembers(ctx, s.userKey(username)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("redis list user sessions: %w", err)
	}

	keys := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		keys = append(keys, s.sessionKey(id))
	}
	keys = append(keys, s.userKey(username))

	if len(keys) > 0 {
		if err := s.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("redis delete user sessions: %w", err)
		}
	}

	return nil
}

// ListByUser returns all non-expired sessions for a user. Stale index entries
// (sessions that have expired and been reaped by Redis) are pruned lazily.
func (s *RedisStore) ListByUser(username string) ([]*Session, error) {
	ctx, cancel := s.ctx()
	ids, err := s.client.SMembers(ctx, s.userKey(username)).Result()
	cancel()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis list user sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(ids))
	var stale []any
	for _, id := range ids {
		session, gErr := s.Get(id)
		if gErr != nil {
			if errors.Is(gErr, ErrSessionNotFound) || errors.Is(gErr, ErrSessionExpired) {
				stale = append(stale, id)
				continue
			}
			return nil, gErr
		}
		sessions = append(sessions, session)
	}

	// Prune stale index entries best-effort.
	if len(stale) > 0 {
		pruneCtx, pruneCancel := s.ctx()
		_ = s.client.SRem(pruneCtx, s.userKey(username), stale...).Err() //nolint:errcheck // best effort
		pruneCancel()
	}

	return sessions, nil
}

// Cleanup is a no-op for Redis: per-key TTLs cause Redis to expire sessions
// automatically. Stale user-index entries are pruned lazily in ListByUser.
func (s *RedisStore) Cleanup() error {
	return nil
}

// Close closes the underlying Redis client.
func (s *RedisStore) Close() error {
	if err := s.client.Close(); err != nil {
		return fmt.Errorf("redis close: %w", err)
	}
	return nil
}
