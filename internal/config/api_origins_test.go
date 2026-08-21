package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAllowedOrigin(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		wantErr string // substring; empty means the entry must be accepted
	}{
		{name: "bare host", origin: "bifrost.example.com"},
		{name: "host with port", origin: "homeassistant.local:8123"},
		{name: "scheme qualified", origin: "https://bifrost.example.com"},
		{name: "scheme qualified with port", origin: "http://127.0.0.1:8080"},
		{name: "wildcard subdomain", origin: "*.example.com"},
		{name: "explicit disable wildcard", origin: "*"},

		{name: "empty", origin: "", wantErr: "must not be empty"},
		{name: "leading whitespace", origin: " example.com", wantErr: "whitespace"},
		{name: "trailing whitespace", origin: "example.com ", wantErr: "whitespace"},
		{name: "missing scheme", origin: "://example.com", wantErr: "missing scheme"},
		{name: "missing host", origin: "https://", wantErr: "missing host"},
		// A path can never match: the matcher only ever sees "host" or
		// "scheme://host", so such an entry is a silent dead allowlist entry.
		{name: "path is rejected", origin: "https://example.com/dashboard", wantErr: "without a path"},
		{name: "bare host with path", origin: "example.com/x", wantErr: "without a path"},
		{name: "bad glob", origin: "exa[mple.com", wantErr: "invalid wildcard pattern"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAllowedOrigin(tc.origin)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestServerConfig_Validate_AllowedOrigins(t *testing.T) {
	base := func() ServerConfig {
		return ServerConfig{
			Server:   ServerSettings{HTTP: ListenerConfig{Listen: ":8080"}},
			Backends: []BackendConfig{{Name: "default", Type: "direct"}},
		}
	}

	t.Run("valid allowlist accepted", func(t *testing.T) {
		cfg := base()
		cfg.API.AllowedOrigins = []string{"https://bifrost.example.com", "homeassistant.local:8123"}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("no allowlist accepted", func(t *testing.T) {
		cfg := base()
		assert.NoError(t, cfg.Validate())
	})

	t.Run("bad entry rejected with its index", func(t *testing.T) {
		cfg := base()
		cfg.API.AllowedOrigins = []string{"ok.example.com", "https://bad.example.com/path"}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api allowed_origins[1]")
		assert.Contains(t, err.Error(), "without a path")
	})
}
