package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseValidServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":8080"},
		},
		Backends: []BackendConfig{{Name: "default", Type: "direct"}},
	}
}

func TestServerConfig_SeedRouteWeights(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.Backends = []BackendConfig{
		{Name: "a", Type: "direct", Weight: 3},
		{Name: "b", Type: "direct", Weight: 5},
		{Name: "c", Type: "direct"}, // no weight
	}
	cfg.Routes = []RouteConfig{
		{
			Domains:     []string{"*"},
			Backends:    []string{"a", "b", "c"},
			LoadBalance: "weighted",
			Weights:     map[string]int{"b": 9}, // explicit override
		},
	}

	require.NoError(t, cfg.Validate())

	w := cfg.Routes[0].Weights
	assert.Equal(t, 3, w["a"], "backend weight should seed missing route weight")
	assert.Equal(t, 9, w["b"], "explicit per-route weight must win over backend weight")
	_, hasC := w["c"]
	assert.False(t, hasC, "backend without weight should not be seeded")
}

func TestServerConfig_SeedRouteWeights_OnlyWeightedRoutes(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.Backends = []BackendConfig{
		{Name: "a", Type: "direct", Weight: 3},
		{Name: "b", Type: "direct", Weight: 5},
	}
	cfg.Routes = []RouteConfig{
		{
			Domains:     []string{"*"},
			Backends:    []string{"a", "b"},
			LoadBalance: "round_robin",
		},
	}

	require.NoError(t, cfg.Validate())
	assert.Nil(t, cfg.Routes[0].Weights, "non-weighted routes must not be seeded")
}

func TestServerConfig_SeedRouteWeights_NoBackendWeights(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.Backends = []BackendConfig{
		{Name: "a", Type: "direct"},
		{Name: "b", Type: "direct"},
	}
	cfg.Routes = []RouteConfig{
		{
			Domains:     []string{"*"},
			Backends:    []string{"a", "b"},
			LoadBalance: "weighted",
		},
	}

	require.NoError(t, cfg.Validate())
	assert.Nil(t, cfg.Routes[0].Weights)
}

func TestServerConfig_RequestLogSizeBounds(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.API.RequestLogSize = -1
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request_log_size must be non-negative")

	cfg = baseValidServerConfig()
	cfg.API.RequestLogSize = MaxRingBufferEntries + 1
	err = cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not exceed")

	cfg = baseValidServerConfig()
	cfg.API.RequestLogSize = MaxRingBufferEntries
	require.NoError(t, cfg.Validate())
}
