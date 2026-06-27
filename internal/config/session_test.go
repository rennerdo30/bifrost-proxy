package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSessionConfig_StoreType(t *testing.T) {
	assert.Equal(t, "memory", SessionConfig{}.StoreType())
	assert.Equal(t, "memory", SessionConfig{Store: "memory"}.StoreType())
	assert.Equal(t, "memory", SessionConfig{Store: "weird"}.StoreType())
	assert.Equal(t, "redis", SessionConfig{Store: "redis"}.StoreType())
}

func TestSessionConfig_Validate(t *testing.T) {
	// Memory store needs no redis addr.
	assert.NoError(t, SessionConfig{}.Validate())
	assert.NoError(t, SessionConfig{Store: "memory"}.Validate())

	// Redis store without an address is rejected.
	err := SessionConfig{Store: "redis"}.Validate()
	assert.ErrorIs(t, err, errSessionRedisAddrRequired)

	// Redis store with an address is fine.
	assert.NoError(t, SessionConfig{
		Store: "redis",
		Redis: RedisSessionConfig{Addr: "127.0.0.1:6379"},
	}.Validate())
}

func TestSessionConfig_YAML(t *testing.T) {
	data := `
store: redis
duration: 4h
max_sessions_per_user: 5
cleanup_interval: 1m
redis:
  addr: redis.internal:6379
  password: secret
  db: 2
  key_prefix: "app:sess:"
  op_timeout: 3s
`
	var cfg SessionConfig
	require.NoError(t, yaml.Unmarshal([]byte(data), &cfg))

	assert.Equal(t, "redis", cfg.StoreType())
	assert.Equal(t, "4h0m0s", cfg.Duration.Duration().String())
	assert.Equal(t, 5, cfg.MaxSessionsPerUser)
	assert.Equal(t, "1m0s", cfg.CleanupInterval.Duration().String())
	assert.Equal(t, "redis.internal:6379", cfg.Redis.Addr)
	assert.Equal(t, "secret", cfg.Redis.Password)
	assert.Equal(t, 2, cfg.Redis.DB)
	assert.Equal(t, "app:sess:", cfg.Redis.KeyPrefix)
	assert.Equal(t, "3s", cfg.Redis.OpTimeout.Duration().String())
	require.NoError(t, cfg.Validate())
}
