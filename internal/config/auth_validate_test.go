package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AuthConfig
		wantErr bool
	}{
		{
			name:    "empty is valid",
			cfg:     AuthConfig{},
			wantErr: false,
		},
		{
			name:    "providers without legacy is valid",
			cfg:     AuthConfig{Providers: []AuthProvider{{Name: "p", Type: "none", Enabled: true}}},
			wantErr: false,
		},
		{
			name:    "legacy mode rejected",
			cfg:     AuthConfig{Mode: "native"},
			wantErr: true,
		},
		{
			name:    "legacy top-level native rejected",
			cfg:     AuthConfig{Native: &NativeAuth{}},
			wantErr: true,
		},
		{
			name:    "legacy top-level ldap rejected",
			cfg:     AuthConfig{LDAP: &LDAPAuth{}},
			wantErr: true,
		},
		{
			name: "legacy provider type-specific config rejected",
			cfg: AuthConfig{Providers: []AuthProvider{
				{Name: "p", Type: "native", Native: &NativeAuth{}},
			}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServerConfig_Validate_RejectsLegacyAuth(t *testing.T) {
	cfg := ServerConfig{
		Server: ServerSettings{
			HTTP: ListenerConfig{Listen: ":8080"},
		},
		Backends: []BackendConfig{{Name: "default", Type: "direct"}},
		Auth:     AuthConfig{Mode: "native"},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "legacy auth.mode")
}
