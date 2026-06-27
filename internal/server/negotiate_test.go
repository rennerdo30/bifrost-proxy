package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestBuildNegotiateHandler_Disabled(t *testing.T) {
	h, err := buildNegotiateHandler(config.AuthConfig{})
	require.NoError(t, err)
	assert.Nil(t, h)

	h, err = buildNegotiateHandler(config.AuthConfig{
		Negotiate: &config.NegotiateConfig{Enabled: false},
	})
	require.NoError(t, err)
	assert.Nil(t, h)
}

func TestBuildNegotiateHandler_NTLMOnly(t *testing.T) {
	cfg := config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "ntlm", Type: "ntlm", Enabled: true, Config: map[string]any{"domain": "EXAMPLE"}},
		},
		Negotiate: &config.NegotiateConfig{
			Enabled:      true,
			NTLMProvider: "ntlm",
			AllowNTLM:    true,
		},
	}
	h, err := buildNegotiateHandler(cfg)
	require.NoError(t, err)
	require.NotNil(t, h)
	t.Cleanup(func() { _ = h.Close() })
}

func TestBuildNegotiateHandler_UnknownProvider(t *testing.T) {
	cfg := config.AuthConfig{
		Negotiate: &config.NegotiateConfig{
			Enabled:      true,
			NTLMProvider: "missing",
		},
	}
	_, err := buildNegotiateHandler(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestBuildNegotiateHandler_WrongType(t *testing.T) {
	cfg := config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "ntlm", Type: "native", Enabled: true},
		},
		Negotiate: &config.NegotiateConfig{
			Enabled:      true,
			NTLMProvider: "ntlm",
		},
	}
	_, err := buildNegotiateHandler(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")
}

func TestBuildNegotiateHandler_AllowNTLMWithoutProvider(t *testing.T) {
	cfg := config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "ntlm", Type: "ntlm", Enabled: true, Config: map[string]any{"domain": "EXAMPLE"}},
		},
		Negotiate: &config.NegotiateConfig{
			Enabled:   true,
			AllowNTLM: true,
			// no ntlm_provider despite allow_ntlm
		},
	}
	_, err := buildNegotiateHandler(cfg)
	require.Error(t, err)
}

func TestBuildNegotiateHandler_NoProviders(t *testing.T) {
	cfg := config.AuthConfig{
		Negotiate: &config.NegotiateConfig{Enabled: true},
	}
	_, err := buildNegotiateHandler(cfg)
	require.Error(t, err)
}
