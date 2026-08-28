package mesh

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exports written before these structs had json tags carry Go field names;
// the multi-word ones never matched their snake_case tags and were silently
// reset to defaults on import.
func TestConfigJSON_AcceptsLegacyFieldNames(t *testing.T) {
	legacy := `{
		"Enabled": true,
		"NetworkID": "office",
		"NetworkCIDR": "10.42.0.0/16",
		"PeerName": "laptop",
		"Device": {"Type": "tun", "MACAddress": "02:00:00:00:00:01"},
		"Discovery": {
			"Server": "discovery.example:443",
			"HeartbeatInterval": 30000000000,
			"PeerTimeout": 90000000000
		},
		"Connection": {
			"DirectConnect": true,
			"RelayEnabled": true,
			"KeepAliveInterval": 25000000000
		}
	}`

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(legacy), &cfg))

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "office", cfg.NetworkID)
	assert.Equal(t, "10.42.0.0/16", cfg.NetworkCIDR)
	assert.Equal(t, "laptop", cfg.PeerName)
	assert.Equal(t, "02:00:00:00:00:01", cfg.Device.MACAddress)
	assert.Equal(t, "discovery.example:443", cfg.Discovery.Server)
	assert.Equal(t, 30*time.Second, cfg.Discovery.HeartbeatInterval.Duration())
	assert.Equal(t, 90*time.Second, cfg.Discovery.PeerTimeout.Duration())
	assert.True(t, cfg.Connection.DirectConnect)
	assert.Equal(t, 25*time.Second, cfg.Connection.KeepAliveInterval.Duration())
}

func TestConfigJSON_LegacyImportReExportsCanonical(t *testing.T) {
	legacy := `{"NetworkID":"office","Discovery":{"HeartbeatInterval":30000000000}}`

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(legacy), &cfg))
	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	assert.Contains(t, string(out), `"network_id":"office"`)
	assert.Contains(t, string(out), `"heartbeat_interval":"30s"`)
	assert.NotContains(t, string(out), `"NetworkID"`)
	assert.NotContains(t, string(out), `"HeartbeatInterval"`)
}

func TestConfigJSON_ConflictingKeysRejected(t *testing.T) {
	conflicting := `{"NetworkID":"a","network_id":"b"}`
	var cfg Config
	require.Error(t, json.Unmarshal([]byte(conflicting), &cfg))
}
