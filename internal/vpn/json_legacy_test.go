package vpn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exports written before these structs had json tags carry Go field names.
// encoding/json's case-insensitive matching quietly covers single-word fields,
// but the multi-word ones were dropped on import — silently inverting
// split-tunnel behavior. Legacy names must decode; output stays canonical.
func TestConfigJSON_AcceptsLegacyFieldNames(t *testing.T) {
	legacy := `{
		"Enabled": true,
		"TUN": {"Name": "bifrost0", "Address": "10.255.0.1/24", "MTU": 1420},
		"SplitTunnel": {
			"Mode": "include",
			"Domains": ["*.corp.example"],
			"AlwaysBypass": ["10.0.0.0/8"]
		},
		"DNS": {
			"Enabled": true,
			"CacheTTL": 600000000000,
			"InterceptMode": "tunnel_only"
		}
	}`

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(legacy), &cfg))

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "bifrost0", cfg.TUN.Name)
	assert.Equal(t, 1420, cfg.TUN.MTU)
	assert.Equal(t, "include", cfg.SplitTunnel.Mode)
	assert.Equal(t, []string{"*.corp.example"}, cfg.SplitTunnel.Domains)
	assert.Equal(t, []string{"10.0.0.0/8"}, cfg.SplitTunnel.AlwaysBypass)
	assert.True(t, cfg.DNS.Enabled)
	assert.Equal(t, 10*time.Minute, cfg.DNS.CacheTTL.Duration())
	assert.Equal(t, InterceptModeTunnelOnly, cfg.DNS.InterceptMode)
}

// import(old export) -> export must be lossless and canonical: re-encoding a
// legacy-keyed document yields only snake_case keys with the same values.
func TestConfigJSON_LegacyImportReExportsCanonical(t *testing.T) {
	legacy := `{"Enabled":true,"SplitTunnel":{"Mode":"include"},"DNS":{"CacheTTL":600000000000,"InterceptMode":"tunnel_only"}}`

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(legacy), &cfg))
	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	assert.Contains(t, string(out), `"split_tunnel"`)
	assert.Contains(t, string(out), `"cache_ttl":"10m0s"`)
	assert.Contains(t, string(out), `"intercept_mode":"tunnel_only"`)
	assert.NotContains(t, string(out), `"SplitTunnel"`)
	assert.NotContains(t, string(out), `"CacheTTL"`)

	var roundTrip Config
	require.NoError(t, json.Unmarshal(out, &roundTrip))
	assert.Equal(t, cfg, roundTrip)
}

// A document naming both spellings with different values is ambiguous and must
// be rejected, never resolved by key order.
func TestConfigJSON_ConflictingLegacyAndCanonicalRejected(t *testing.T) {
	conflicting := `{"SplitTunnel":{"Mode":"include"},"split_tunnel":{"Mode":"exclude"}}`
	var cfg Config
	require.Error(t, json.Unmarshal([]byte(conflicting), &cfg))
}
