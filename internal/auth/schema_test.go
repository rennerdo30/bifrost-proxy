package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/mfa"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/apikey"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/hotp"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/jwt"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/kerberos"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ldap"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/mtls"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/native"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/none"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/oauth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/system"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/totp"
)

// Every registered plugin must have a key schema and vice versa, so a new
// plugin cannot ship with an unchecked dynamic config block.
func TestProviderSchemas_CoverEveryRegisteredPlugin(t *testing.T) {
	registered := auth.ListPlugins()
	schemas := auth.SchemaTypes()
	assert.ElementsMatch(t, registered, schemas,
		"every registered plugin needs a key schema in internal/auth/schema.go, and no schema may outlive its plugin")
}

// The audit's fail-open probe: `disabledd: true` on a native user was accepted
// by load AND plugin validation, and the supposedly disabled user then
// authenticated. Both validation and creation must reject the typo now.
func TestProviderKeys_NativeDisabledTypoFailsClosed(t *testing.T) {
	hash, err := auth.HashPassword("password")
	require.NoError(t, err)

	cfg := auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "u", "password_hash": hash, "disabledd": true},
			},
		},
	}

	factory := auth.NewFactory()
	err = factory.ValidateProviders([]auth.ProviderConfig{cfg})
	require.Error(t, err, "validation must reject the typo")
	assert.Contains(t, err.Error(), "disabledd")

	_, err = factory.Create(cfg)
	require.Error(t, err, "creation must reject the typo")
	assert.Contains(t, err.Error(), "disabledd")
}

// The correctly-spelled key still works — and actually disables the user.
func TestProviderKeys_NativeDisabledStillWorks(t *testing.T) {
	hash, err := auth.HashPassword("password")
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name: "native", Type: "native", Enabled: true,
		Config: map[string]any{
			"users": []map[string]any{
				{"username": "u", "password_hash": hash, "disabled": true},
			},
		},
	})
	require.NoError(t, err)

	_, err = authenticator.Authenticate(context.Background(), "u", "password")
	assert.Error(t, err, "a disabled user must not authenticate")
}

// One typo per provider type, checked through the same ValidateProviders path
// the dashboard uses. Every registered type must reject its typo.
func TestProviderKeys_TypoRejectedForEveryType(t *testing.T) {
	cases := map[string]map[string]any{
		"native":      {"userz": []map[string]any{}},
		"apikey":      {"header_nane": "X-API-Key"},
		"totp":        {"algorithn": "SHA1"},
		"hotp":        {"look_ahead_windows": 10},
		"jwt":         {"hmac_secrets": "k"},
		"kerberos":    {"realmm": "EXAMPLE.COM"},
		"ldap":        {"base_dnn": "dc=example"},
		"mtls":        {"ca_cert_filee": "/x.pem"},
		"ntlm":        {"domainn": "EXAMPLE"},
		"oauth":       {"client_idd": "id"},
		"system":      {"allowed_userz": []string{"a"}},
		"mfa_wrapper": {"password_formats": "separated"},
		"none":        {"anything": true},
	}

	assert.ElementsMatch(t, auth.SchemaTypes(), keysOf(cases),
		"this table must cover every provider type with a schema")

	for providerType, cfg := range cases {
		t.Run(providerType, func(t *testing.T) {
			err := auth.ValidateProviderKeys(providerType, cfg)
			require.Error(t, err, "type %s must reject its typo key", providerType)
		})
	}
}

// Nested shapes are checked too: a typo inside a list entry or an inline
// mfa_wrapper block cannot hide from the schema.
func TestProviderKeys_NestedTyposRejected(t *testing.T) {
	require.Error(t, auth.ValidateProviderKeys("apikey", map[string]any{
		"keys": []map[string]any{{"name": "k", "key_plain": "v", "expirs_at": "2030-01-01T00:00:00Z"}},
	}), "typo inside a keys[] entry")

	require.Error(t, auth.ValidateProviderKeys("mtls", map[string]any{
		"subject_mapping": map[string]any{"username_fields": "CN"},
	}), "typo inside subject_mapping")

	require.Error(t, auth.ValidateProviderKeys("mfa_wrapper", map[string]any{
		"primary": map[string]any{
			"mode": "native",
			"config": map[string]any{
				"users": []map[string]any{{"username": "u", "password_hash": "h", "disabledd": true}},
			},
		},
	}), "typo inside an inline mfa_wrapper block's inner config")
}

// Valid configs for each type keep validating: the schema must not reject what
// the plugins document.
func TestProviderKeys_ValidConfigsAccepted(t *testing.T) {
	cases := map[string]map[string]any{
		"native": {"users": []map[string]any{{"username": "u", "password_hash": "h", "groups": []string{"g"}, "email": "e@example.com", "full_name": "U", "disabled": false}}},
		"apikey": {"header_name": "X-API-Key", "keys": []map[string]any{{"name": "k", "key_hash": "h", "groups": []string{"g"}, "disabled": false, "expires_at": "2030-01-01T00:00:00Z"}}},
		"totp":   {"algorithm": "SHA1", "digits": 6, "period": 30, "skew": 1, "issuer": "Bifrost", "secrets": []map[string]any{{"username": "u", "secret": "S", "groups": []string{"g"}}}},
		"hotp":   {"algorithm": "SHA1", "digits": 6, "look_ahead": 10, "secrets": []map[string]any{{"username": "u", "secret": "S", "counter": 0}}},
		"jwt":    {"algorithms": []string{"HS256"}, "hmac_secret": "k", "issuer": "i", "audience": "a", "username_claim": "sub", "leeway_seconds": 30},
		"ldap":   {"url": "ldap://x:389", "base_dn": "dc=example", "bind_dn": "cn=svc", "bind_password": "p", "tls": true, "insecure_skip_verify": false, "group_lookup_fail_closed": true},
		"mtls":   {"ca_cert_file": "/ca.pem", "require_client_cert": true, "subject_mapping": map[string]any{"username_field": "CN"}},
		"oauth":  {"provider": "generic", "client_id": "id", "client_secret": "s", "issuer_url": "https://x", "scopes": []string{"openid"}, "required_claims": map[string]any{"hd": "example.com"}},
		"system": {"allowed_users": []string{"a"}, "allowed_groups": []string{"g"}},
		"mfa_wrapper": {
			"primary":         map[string]any{"mode": "native", "config": map[string]any{"users": []map[string]any{{"username": "u", "password_hash": "h"}}}},
			"secondary":       map[string]any{"mode": "totp", "config": map[string]any{"secrets": []map[string]any{{"username": "u", "secret": "S"}}}},
			"mfa_required":    "always",
			"password_format": "separated",
			"separator":       ":",
			"mfa_code_length": 6,
		},
	}

	for providerType, cfg := range cases {
		t.Run(providerType, func(t *testing.T) {
			assert.NoError(t, auth.ValidateProviderKeys(providerType, cfg))
		})
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
