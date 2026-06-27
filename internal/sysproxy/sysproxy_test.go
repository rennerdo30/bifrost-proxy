package sysproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	cfg := Config{
		Address: "127.0.0.1:8080",
		Enabled: true,
	}

	assert.Equal(t, "127.0.0.1:8080", cfg.Address)
	assert.True(t, cfg.Enabled)
}

func TestConfig_Disabled(t *testing.T) {
	cfg := Config{
		Address: "",
		Enabled: false,
	}

	assert.Equal(t, "", cfg.Address)
	assert.False(t, cfg.Enabled)
}

func TestNew(t *testing.T) {
	mgr := New()
	assert.NotNil(t, mgr)

	// Verify it implements Manager interface.
	var _ Manager = mgr
}

func TestErrNotSupported(t *testing.T) {
	assert.NotNil(t, ErrNotSupported)
	assert.Contains(t, ErrNotSupported.Error(), "not supported")
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{name: "ipv4", address: "127.0.0.1:8080", wantHost: "127.0.0.1", wantPort: "8080"},
		{name: "hostname", address: "proxy.example.com:3128", wantHost: "proxy.example.com", wantPort: "3128"},
		{name: "ipv6", address: "[::1]:8080", wantHost: "::1", wantPort: "8080"},
		{name: "empty", address: "", wantErr: true},
		{name: "no port", address: "127.0.0.1", wantErr: true},
		{name: "missing host", address: ":8080", wantErr: true},
		{name: "non-numeric port", address: "127.0.0.1:http", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := splitHostPort(tt.address)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}
