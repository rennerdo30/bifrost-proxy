package server

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/kerberos"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// aes256CTSHMACSHA1 is the Kerberos encryption type used for the test keytab.
const aes256CTSHMACSHA1 = 18

// TestBuildNegotiateHandler_KerberosSucceeds is the success path.
//
// It matters because `ntlm` is now refused outright, and the NTLM-only test that
// used to cover construction became a refusal test — leaving buildNegotiateHandler's
// handler-config wiring (PreferKerberos, AllowNTLM, Realm, NewHandler) untested.
// Kerberos is the only provider type Negotiate still accepts.
func TestBuildNegotiateHandler_KerberosSucceeds(t *testing.T) {
	// A real (if throwaway) keytab: the provider loads and parses it eagerly.
	// This test is about handler wiring, not SPNEGO verification.
	kt := keytab.New()
	require.NoError(t, kt.AddEntry("HTTP/proxy.example.com", "EXAMPLE.COM", "test-password",
		time.Now(), 1, aes256CTSHMACSHA1))
	ktData, err := kt.Marshal()
	require.NoError(t, err)

	cfg := config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "krb", Type: "kerberos", Enabled: true, Config: map[string]any{
				"realm":             "EXAMPLE.COM",
				"service_principal": "HTTP/proxy.example.com",
				"keytab_base64":     base64.StdEncoding.EncodeToString(ktData),
				// Inline krb5.conf so the test does not depend on /etc/krb5.conf
				// existing on the machine running it.
				"krb5_config": "[libdefaults]\n  default_realm = EXAMPLE.COM\n\n" +
					"[realms]\n  EXAMPLE.COM = {\n    kdc = kdc.example.com\n  }\n",
			}},
		},
		Negotiate: &config.NegotiateConfig{
			Enabled:          true,
			KerberosProvider: "krb",
			PreferKerberos:   true,
			Realm:            "EXAMPLE.COM",
		},
	}

	h, err := buildNegotiateHandler(cfg)
	require.NoError(t, err)
	require.NotNil(t, h)
	t.Cleanup(func() { _ = h.Close() })
}

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

// TestBuildNegotiateHandler_NTLMOnlyIsRefused pins the consequence of refusing
// the NTLM provider outright.
//
// An NTLM-only Negotiate setup was previously accepted and started fine, then
// rejected every single client, because the NTLM plugin has no way to verify a
// client's response. That is now a startup failure with an explanation instead of
// a silently non-working SSO deployment. The remedy is Kerberos: the error says
// so, and points at the two settings to change.
func TestBuildNegotiateHandler_NTLMOnlyIsRefused(t *testing.T) {
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
	_, err := buildNegotiateHandler(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
	assert.Contains(t, err.Error(), "allow_ntlm",
		"the error must tell the operator which settings to change")
	assert.Contains(t, err.Error(), "kerberos")
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
