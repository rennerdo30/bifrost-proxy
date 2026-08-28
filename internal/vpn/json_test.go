package vpn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/duration"
)

// The client dashboard and the mobile app read the VPN config over JSON using the
// same snake_case names the YAML file uses. These tests pin that contract: without
// json tags Go emits its field names ("Enabled", "TUN", "SplitTunnel", ...) and the
// whole VPN subtree is invisible to every consumer, which made the Settings form
// write-only and left the split-tunnel panel unable to read its own mode.

func TestConfigJSONKeys(t *testing.T) {
	b, err := json.Marshal(DefaultConfig())
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &got))

	assert.ElementsMatch(t, []string{"enabled", "tun", "split_tunnel", "dns"}, keys(got))
}

func TestTUNConfigJSONKeys(t *testing.T) {
	b, err := json.Marshal(TUNConfig{Name: "bifrost0", Address: DefaultTUNAddress, MTU: DefaultTUNMTU})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))

	assert.ElementsMatch(t, []string{"name", "address", "mtu"}, keys(got))
	assert.Equal(t, "bifrost0", got["name"])
	assert.Equal(t, DefaultTUNAddress, got["address"])
	assert.Equal(t, float64(DefaultTUNMTU), got["mtu"])
}

func TestSplitTunnelConfigJSONKeys(t *testing.T) {
	cfg := SplitTunnelConfig{
		Mode:         ModeExclude,
		Apps:         []AppRule{{Name: "slack", Path: "/usr/bin/slack"}},
		Domains:      []string{"*.local"},
		IPs:          []string{"10.0.0.0/8"},
		AlwaysBypass: []string{"127.0.0.0/8"},
	}

	b, err := json.Marshal(cfg)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))

	assert.ElementsMatch(t, []string{"mode", "apps", "domains", "ips", "always_bypass"}, keys(got))

	// The split-tunnel panel keys its mode buttons and its hint text off "mode";
	// without the tag it read undefined and always rendered the include wording.
	assert.Equal(t, ModeExclude, got["mode"])

	apps, ok := got["apps"].([]any)
	require.True(t, ok, "apps must be a JSON array")
	require.Len(t, apps, 1)
	app, ok := apps[0].(map[string]any)
	require.True(t, ok, "app rule must be a JSON object")
	assert.ElementsMatch(t, []string{"name", "path"}, keys(app))
	assert.Equal(t, "slack", app["name"])
	assert.Equal(t, "/usr/bin/slack", app["path"])
}

func TestDNSConfigJSONKeys(t *testing.T) {
	b, err := json.Marshal(DefaultConfig().DNS)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))

	assert.ElementsMatch(t,
		[]string{"enabled", "listen", "upstream", "cache_ttl", "intercept_mode"},
		keys(got))

	// cache_ttl must be a duration string, not a nanosecond count: the form's
	// duration input calls String.match() on whatever arrives.
	assert.Equal(t, "5m0s", got["cache_ttl"])
	assert.Equal(t, DefaultDNSListen, got["listen"])
	assert.Equal(t, InterceptModeAll, got["intercept_mode"])
}

// TestConfigJSONRoundTrip checks the read and write halves agree, so a payload the
// UI reads back can be posted unchanged.
func TestConfigJSONRoundTrip(t *testing.T) {
	original := DefaultConfig()
	original.Enabled = true
	original.DNS.CacheTTL = duration.Duration(90 * time.Second)
	original.SplitTunnel.Mode = ModeInclude

	b, err := json.Marshal(original)
	require.NoError(t, err)

	var back Config
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, original, back)
}

// TestDNSConfigAcceptsLegacyNanosecondCacheTTL covers a client that read the old
// numeric shape and posts it back verbatim.
func TestDNSConfigAcceptsLegacyNanosecondCacheTTL(t *testing.T) {
	var cfg DNSConfig
	require.NoError(t, json.Unmarshal([]byte(`{"cache_ttl":300000000000}`), &cfg))
	assert.Equal(t, 5*time.Minute, cfg.CacheTTL.Duration())
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
