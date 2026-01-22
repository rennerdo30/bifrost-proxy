package vpn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigValidate tests Config validation
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "disabled config is always valid",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid enabled config",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Name:    "bifrost0",
					Address: "10.255.0.1/24",
					MTU:     1400,
				},
				SplitTunnel: SplitTunnelConfig{
					Mode: "exclude",
				},
				DNS: DNSConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid TUN config",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Address: "invalid-address",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid split tunnel config",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Name:    "bifrost0",
					Address: "10.255.0.1/24",
					MTU:     1400,
				},
				SplitTunnel: SplitTunnelConfig{
					Mode: "invalid-mode",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid DNS config",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Name:    "bifrost0",
					Address: "10.255.0.1/24",
					MTU:     1400,
				},
				SplitTunnel: SplitTunnelConfig{
					Mode: "exclude",
				},
				DNS: DNSConfig{
					Enabled:       true,
					InterceptMode: "invalid-mode",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDNSConfigValidate tests DNSConfig validation
func TestDNSConfigValidate(t *testing.T) {
	tests := []struct {
		name       string
		config     DNSConfig
		wantErr    bool
		checkAfter func(*testing.T, DNSConfig)
	}{
		{
			name: "disabled DNS is always valid",
			config: DNSConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid enabled DNS",
			config: DNSConfig{
				Enabled:       true,
				Listen:        "10.255.0.1:53",
				Upstream:      []string{"8.8.8.8"},
				CacheTTL:      5 * time.Minute,
				InterceptMode: "all",
			},
			wantErr: false,
		},
		{
			name: "empty listen sets default",
			config: DNSConfig{
				Enabled: true,
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c DNSConfig) {
				assert.Equal(t, "10.255.0.1:53", c.Listen)
			},
		},
		{
			name: "empty upstream sets default",
			config: DNSConfig{
				Enabled: true,
				Listen:  "10.255.0.1:53",
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c DNSConfig) {
				assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, c.Upstream)
			},
		},
		{
			name: "zero cache TTL sets default",
			config: DNSConfig{
				Enabled:  true,
				Listen:   "10.255.0.1:53",
				Upstream: []string{"8.8.8.8"},
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c DNSConfig) {
				assert.Equal(t, 5*time.Minute, c.CacheTTL)
			},
		},
		{
			name: "empty intercept mode sets default",
			config: DNSConfig{
				Enabled:  true,
				Listen:   "10.255.0.1:53",
				Upstream: []string{"8.8.8.8"},
				CacheTTL: 5 * time.Minute,
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c DNSConfig) {
				assert.Equal(t, "all", c.InterceptMode)
			},
		},
		{
			name: "tunnel_only intercept mode is valid",
			config: DNSConfig{
				Enabled:       true,
				Listen:        "10.255.0.1:53",
				Upstream:      []string{"8.8.8.8"},
				CacheTTL:      5 * time.Minute,
				InterceptMode: "tunnel_only",
			},
			wantErr: false,
		},
		{
			name: "invalid intercept mode",
			config: DNSConfig{
				Enabled:       true,
				Listen:        "10.255.0.1:53",
				Upstream:      []string{"8.8.8.8"},
				CacheTTL:      5 * time.Minute,
				InterceptMode: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkAfter != nil {
					tt.checkAfter(t, tt.config)
				}
			}
		})
	}
}

// TestDefaultConfig tests DefaultConfig function
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Check defaults
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "10.255.0.1/24", cfg.TUN.Address)
	assert.Equal(t, 1400, cfg.TUN.MTU)
	assert.Equal(t, "exclude", cfg.SplitTunnel.Mode)
	assert.True(t, cfg.DNS.Enabled)
	assert.Equal(t, "10.255.0.1:53", cfg.DNS.Listen)
	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, cfg.DNS.Upstream)
	assert.Equal(t, 5*time.Minute, cfg.DNS.CacheTTL)
	assert.Equal(t, "all", cfg.DNS.InterceptMode)

	// Check default always bypass
	assert.Contains(t, cfg.SplitTunnel.AlwaysBypass, "10.0.0.0/8")
	assert.Contains(t, cfg.SplitTunnel.AlwaysBypass, "172.16.0.0/12")
	assert.Contains(t, cfg.SplitTunnel.AlwaysBypass, "192.168.0.0/16")

	// Config should be valid
	require.NoError(t, cfg.Validate())
}

// TestExampleConfig tests ExampleConfig function
func TestExampleConfig(t *testing.T) {
	example := ExampleConfig()
	assert.NotEmpty(t, example)
	assert.Contains(t, example, "vpn:")
	assert.Contains(t, example, "enabled: true")
	assert.Contains(t, example, "split_tunnel:")
	assert.Contains(t, example, "dns:")
	assert.Contains(t, example, "tun:")
}

// TestConfigErrorType tests ConfigError
func TestConfigErrorType(t *testing.T) {
	err := &ConfigError{
		Field:   "test.field",
		Message: "test message",
	}
	assert.Equal(t, "config error: test.field: test message", err.Error())
}
