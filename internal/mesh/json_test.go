package mesh

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/duration"
)

// Mesh config already carried json tags, but its duration fields were plain
// time.Duration, so they serialized as nanosecond integers. The client dashboard
// feeds them to a duration input that calls String.match(), which threw a
// TypeError and took the entire Settings page down with it. These tests pin the
// duration fields to strings.

// meshDurationJSONKeys lists every duration in the mesh config, by the JSON path
// the dashboards read, together with the value each should serialize to.
func meshDurationJSONKeys(t *testing.T, raw []byte) {
	t.Helper()

	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &top))

	for _, tc := range []struct {
		section string
		key     string
		want    string
	}{
		{"discovery", "heartbeat_interval", "30s"},
		{"discovery", "peer_timeout", "1m30s"},
		{"stun", "timeout", "5s"},
		{"connection", "connect_timeout", "30s"},
		{"connection", "keep_alive_interval", "25s"},
	} {
		rawSection, ok := top[tc.section]
		require.True(t, ok, "missing section %q", tc.section)

		var section map[string]any
		require.NoError(t, json.Unmarshal(rawSection, &section))

		value, ok := section[tc.key]
		require.True(t, ok, "missing key %s.%s", tc.section, tc.key)
		assert.Equal(t, tc.want, value, "%s.%s must be a duration string", tc.section, tc.key)
	}
}

func TestConfigJSONDurationsAreStrings(t *testing.T) {
	b, err := json.Marshal(DefaultConfig())
	require.NoError(t, err)
	meshDurationJSONKeys(t, b)
}

// TestConnectionConfigKeepAliveJSONKey pins the wire name to the documented YAML
// key. The dashboard used to read "keepalive_interval", which matched nothing.
func TestConnectionConfigKeepAliveJSONKey(t *testing.T) {
	b, err := json.Marshal(DefaultConfig().Connection)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))

	assert.Contains(t, got, "keep_alive_interval")
	assert.NotContains(t, got, "keepalive_interval")
	assert.Equal(t, "25s", got["keep_alive_interval"])
}

func TestConfigJSONRoundTrip(t *testing.T) {
	original := DefaultConfig()
	original.Enabled = true
	original.NetworkID = "test-net"
	original.Discovery.Server = "discovery.example.com:8080"
	original.Discovery.HeartbeatInterval = duration.Duration(45 * time.Second)
	original.Connection.KeepAliveInterval = duration.Duration(90 * time.Second)

	b, err := json.Marshal(original)
	require.NoError(t, err)

	var back Config
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, original, back)
}

// TestConfigAcceptsLegacyNanosecondDurations covers a client that read the old
// numeric shape and posts it back verbatim.
func TestConfigAcceptsLegacyNanosecondDurations(t *testing.T) {
	payload := `{"discovery":{"heartbeat_interval":30000000000,"peer_timeout":90000000000},` +
		`"connection":{"connect_timeout":30000000000,"keep_alive_interval":25000000000}}`

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(payload), &cfg))

	assert.Equal(t, 30*time.Second, cfg.Discovery.HeartbeatInterval.Duration())
	assert.Equal(t, 90*time.Second, cfg.Discovery.PeerTimeout.Duration())
	assert.Equal(t, 30*time.Second, cfg.Connection.ConnectTimeout.Duration())
	assert.Equal(t, 25*time.Second, cfg.Connection.KeepAliveInterval.Duration())
}
