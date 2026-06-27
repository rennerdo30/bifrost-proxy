package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// fakeRedis is an in-memory implementation of the redisClient interface used to
// unit-test RedisStore without a live Redis server. It models string keys with
// optional expiry and set keys.
type fakeRedis struct {
	mu      sync.Mutex
	strings map[string]string
	expiry  map[string]time.Time
	sets    map[string]map[string]struct{}
	closed  bool
	failAll error // when set, every op returns this error
	pingErr error
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{
		strings: make(map[string]string),
		expiry:  make(map[string]time.Time),
		sets:    make(map[string]map[string]struct{}),
	}
}

func (f *fakeRedis) expireIfNeeded(key string) {
	if exp, ok := f.expiry[key]; ok && time.Now().After(exp) {
		delete(f.strings, key)
		delete(f.expiry, key)
	}
}

func (f *fakeRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return redis.NewStringResult("", f.failAll)
	}
	f.expireIfNeeded(key)
	v, ok := f.strings[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(v, nil)
}

func (f *fakeRedis) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return redis.NewStatusResult("", f.failAll)
	}
	switch v := value.(type) {
	case string:
		f.strings[key] = v
	case []byte:
		f.strings[key] = string(v)
	default:
		f.strings[key] = ""
	}
	if expiration > 0 {
		f.expiry[key] = time.Now().Add(expiration)
	} else {
		delete(f.expiry, key)
	}
	return redis.NewStatusResult("OK", nil)
}

func (f *fakeRedis) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return redis.NewIntResult(0, f.failAll)
	}
	var n int64
	for _, k := range keys {
		if _, ok := f.strings[k]; ok {
			n++
		}
		if _, ok := f.sets[k]; ok {
			n++
		}
		delete(f.strings, k)
		delete(f.expiry, k)
		delete(f.sets, k)
	}
	return redis.NewIntResult(n, nil)
}

func (f *fakeRedis) SAdd(ctx context.Context, key string, members ...any) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return redis.NewIntResult(0, f.failAll)
	}
	if f.sets[key] == nil {
		f.sets[key] = make(map[string]struct{})
	}
	for _, m := range members {
		f.sets[key][m.(string)] = struct{}{}
	}
	return redis.NewIntResult(int64(len(members)), nil)
}

func (f *fakeRedis) SRem(ctx context.Context, key string, members ...any) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return redis.NewIntResult(0, f.failAll)
	}
	if s, ok := f.sets[key]; ok {
		for _, m := range members {
			delete(s, m.(string))
		}
	}
	return redis.NewIntResult(int64(len(members)), nil)
}

func (f *fakeRedis) SMembers(ctx context.Context, key string) *redis.StringSliceCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return redis.NewStringSliceResult(nil, f.failAll)
	}
	s, ok := f.sets[key]
	if !ok {
		return redis.NewStringSliceResult(nil, nil)
	}
	out := make([]string, 0, len(s))
	for m := range s {
		out = append(out, m)
	}
	return redis.NewStringSliceResult(out, nil)
}

func (f *fakeRedis) Ping(ctx context.Context) *redis.StatusCmd {
	if f.pingErr != nil {
		return redis.NewStatusResult("", f.pingErr)
	}
	return redis.NewStatusResult("PONG", nil)
}

func (f *fakeRedis) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func newTestRedisStore(t *testing.T) (*RedisStore, *fakeRedis) {
	t.Helper()
	fake := newFakeRedis()
	store := newRedisStoreWithClient(fake, RedisStoreOptions{})
	return store, fake
}

func sampleSession(user string, ttl time.Duration) *Session {
	now := time.Now()
	return &Session{
		UserInfo:  &auth.UserInfo{Username: user, Email: user + "@example.com"},
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		LastUsed:  now,
		IPAddress: "10.0.0.1",
		Metadata:  map[string]string{"k": "v"},
	}
}

func TestRedisStore_CreateAndGet(t *testing.T) {
	store, _ := newTestRedisStore(t)

	id, err := store.Create(sampleSession("alice", time.Hour))
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	got, err := store.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.UserInfo.Username)
	assert.Equal(t, "v", got.Metadata["k"])
}

func TestRedisStore_CreatePreservesProvidedID(t *testing.T) {
	store, _ := newTestRedisStore(t)
	s := sampleSession("bob", time.Hour)
	s.ID = "fixed-id"
	id, err := store.Create(s)
	require.NoError(t, err)
	assert.Equal(t, "fixed-id", id)
}

func TestRedisStore_GetNotFound(t *testing.T) {
	store, _ := newTestRedisStore(t)
	_, err := store.Get("missing")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestRedisStore_GetExpired(t *testing.T) {
	store, fake := newTestRedisStore(t)
	// Write a session whose payload is already expired but key still present.
	s := sampleSession("carol", time.Hour)
	id, err := store.Create(s)
	require.NoError(t, err)

	// Mutate stored payload to be expired without removing the key.
	expired := sampleSession("carol", -time.Minute)
	expired.ID = id
	store2 := newRedisStoreWithClient(fake, RedisStoreOptions{})
	// Force-write via Set bypassing persist's TTL flooring.
	require.NoError(t, store2.persist(expired))

	_, err = store.Get(id)
	assert.ErrorIs(t, err, ErrSessionExpired)
}

func TestRedisStore_Update(t *testing.T) {
	store, _ := newTestRedisStore(t)
	id, err := store.Create(sampleSession("dave", time.Hour))
	require.NoError(t, err)

	got, err := store.Get(id)
	require.NoError(t, err)
	got.Metadata["new"] = "value"
	require.NoError(t, store.Update(got))

	again, err := store.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "value", again.Metadata["new"])
}

func TestRedisStore_UpdateNonexistent(t *testing.T) {
	store, _ := newTestRedisStore(t)
	s := sampleSession("eve", time.Hour)
	s.ID = "nope"
	err := store.Update(s)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestRedisStore_Delete(t *testing.T) {
	store, _ := newTestRedisStore(t)
	id, err := store.Create(sampleSession("frank", time.Hour))
	require.NoError(t, err)

	require.NoError(t, store.Delete(id))
	_, err = store.Get(id)
	assert.ErrorIs(t, err, ErrSessionNotFound)

	// Index cleaned up.
	sessions, err := store.ListByUser("frank")
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestRedisStore_DeleteIdempotent(t *testing.T) {
	store, _ := newTestRedisStore(t)
	assert.NoError(t, store.Delete("never-existed"))
}

func TestRedisStore_ListByUser(t *testing.T) {
	store, _ := newTestRedisStore(t)
	_, err := store.Create(sampleSession("grace", time.Hour))
	require.NoError(t, err)
	_, err = store.Create(sampleSession("grace", time.Hour))
	require.NoError(t, err)

	sessions, err := store.ListByUser("grace")
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
}

func TestRedisStore_ListByUserPrunesStale(t *testing.T) {
	store, fake := newTestRedisStore(t)
	id, err := store.Create(sampleSession("heidi", time.Hour))
	require.NoError(t, err)

	// Remove the session key directly, leaving a stale index entry.
	fake.mu.Lock()
	delete(fake.strings, store.sessionKey(id))
	fake.mu.Unlock()

	sessions, err := store.ListByUser("heidi")
	require.NoError(t, err)
	assert.Empty(t, sessions)

	// Stale index entry should have been pruned.
	fake.mu.Lock()
	_, present := fake.sets[store.userKey("heidi")][id]
	fake.mu.Unlock()
	assert.False(t, present)
}

func TestRedisStore_ListByUserEmpty(t *testing.T) {
	store, _ := newTestRedisStore(t)
	sessions, err := store.ListByUser("nobody")
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestRedisStore_DeleteByUser(t *testing.T) {
	store, _ := newTestRedisStore(t)
	_, err := store.Create(sampleSession("ivan", time.Hour))
	require.NoError(t, err)
	_, err = store.Create(sampleSession("ivan", time.Hour))
	require.NoError(t, err)

	require.NoError(t, store.DeleteByUser("ivan"))
	sessions, err := store.ListByUser("ivan")
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestRedisStore_DeleteByUserNoSessions(t *testing.T) {
	store, _ := newTestRedisStore(t)
	assert.NoError(t, store.DeleteByUser("ghost"))
}

func TestRedisStore_CleanupNoop(t *testing.T) {
	store, _ := newTestRedisStore(t)
	assert.NoError(t, store.Cleanup())
}

func TestRedisStore_Close(t *testing.T) {
	store, fake := newTestRedisStore(t)
	require.NoError(t, store.Close())
	assert.True(t, fake.closed)
}

func TestRedisStore_PropagatesErrors(t *testing.T) {
	store, fake := newTestRedisStore(t)
	fake.failAll = errors.New("boom")

	_, err := store.Get("x")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrSessionNotFound)

	_, err = store.Create(sampleSession("z", time.Hour))
	assert.Error(t, err)

	_, err = store.ListByUser("z")
	assert.Error(t, err)

	err = store.DeleteByUser("z")
	assert.Error(t, err)
}

func TestRedisStore_KeyPrefixOverride(t *testing.T) {
	fake := newFakeRedis()
	store := newRedisStoreWithClient(fake, RedisStoreOptions{KeyPrefix: "x:"})
	id, err := store.Create(sampleSession("p", time.Hour))
	require.NoError(t, err)

	fake.mu.Lock()
	_, present := fake.strings["x:id:"+id]
	fake.mu.Unlock()
	assert.True(t, present)
}

func TestRedisStore_OpTimeoutDefault(t *testing.T) {
	fake := newFakeRedis()
	store := newRedisStoreWithClient(fake, RedisStoreOptions{})
	assert.Equal(t, defaultRedisOpTimeout, store.opTimeout)
}

func TestNewRedisStore_RequiresAddr(t *testing.T) {
	_, err := NewRedisStore(RedisStoreOptions{})
	assert.Error(t, err)
}

func TestNewStore_Memory(t *testing.T) {
	store, err := NewStore(StoreOptions{Type: "memory"})
	require.NoError(t, err)
	require.NotNil(t, store)
	_ = store.Close()

	store2, err := NewStore(StoreOptions{})
	require.NoError(t, err)
	_ = store2.Close()
}

func TestNewStore_UnknownType(t *testing.T) {
	_, err := NewStore(StoreOptions{Type: "cassandra"})
	assert.Error(t, err)
}

func TestNewStore_RedisUnreachable(t *testing.T) {
	// Use an address that should refuse/timeout quickly.
	_, err := NewStore(StoreOptions{
		Type: "redis",
		Redis: RedisStoreOptions{
			Addr:      "127.0.0.1:1",
			OpTimeout: 500 * time.Millisecond,
		},
	})
	assert.Error(t, err)
}

// Ensure RedisStore satisfies the Store interface.
var _ Store = (*RedisStore)(nil)
