package vpn

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// splitTunnelManager builds a Manager with a live split-tunnel engine, without
// starting the VPN (which needs a TUN device and root).
func splitTunnelManager(t *testing.T) *Manager {
	t.Helper()

	cfg := DefaultConfig()
	cfg.Enabled = false
	cfg.SplitTunnel.Mode = "exclude"

	m, err := New(cfg)
	require.NoError(t, err)

	engine, err := NewSplitTunnelEngine(m.config.SplitTunnel, nil)
	require.NoError(t, err)
	m.splitEngine = engine

	return m
}

// TestAddSplitTunnelApp_EngineRejectionRollsBackConfig is the regression guard
// for the swallowed rule-limit error.
//
// The engine's Add used to discard its error, so Manager.AddSplitTunnelApp
// appended to the stored config and returned nil even when the rule was never
// installed. That left the config and the engine disagreeing about what
// bypasses the tunnel, and the API reporting a rule it was not enforcing.
func TestAddSplitTunnelApp_EngineRejectionRollsBackConfig(t *testing.T) {
	m := splitTunnelManager(t)

	// Fill the engine to its limit directly, leaving the stored config empty,
	// so the next add is refused by the engine rather than by config checks.
	for i := 0; i < MaxAppRules; i++ {
		require.NoError(t, m.splitEngine.AddApp(AppRule{Name: fmt.Sprintf("app-%d", i)}))
	}

	before := len(m.config.SplitTunnel.Apps)

	err := m.AddSplitTunnelApp(AppRule{Name: "one-too-many"})
	require.Error(t, err, "a rule the engine refused must not report success")
	assert.ErrorIs(t, err, ErrAppRulesAtLimit)

	assert.Len(t, m.config.SplitTunnel.Apps, before,
		"the refused rule must not be left in the stored config")
	assert.NotContains(t, m.config.SplitTunnel.Apps, AppRule{Name: "one-too-many"})
}

// TestAddSplitTunnelIP_EngineRejectionRollsBackConfig is the same guard for the
// IP path, which is the one the audit flagged by name.
func TestAddSplitTunnelIP_EngineRejectionRollsBackConfig(t *testing.T) {
	m := splitTunnelManager(t)

	for i := 0; i < MaxIPRules; i++ {
		require.NoError(t, m.splitEngine.AddIP(fmt.Sprintf("10.%d.%d.1/32", i/256, i%256)))
	}

	before := len(m.config.SplitTunnel.IPs)

	err := m.AddSplitTunnelIP("192.0.2.1/32")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIPRulesAtLimit)

	assert.Len(t, m.config.SplitTunnel.IPs, before,
		"the refused entry must not be left in the stored config")
	assert.NotContains(t, m.config.SplitTunnel.IPs, "192.0.2.1/32")
}

// TestAddSplitTunnel_SuccessStillStoresTheRule guards against over-correcting:
// the rollback must only happen on rejection.
func TestAddSplitTunnel_SuccessStillStoresTheRule(t *testing.T) {
	m := splitTunnelManager(t)

	require.NoError(t, m.AddSplitTunnelIP("198.51.100.0/24"))
	assert.Contains(t, m.config.SplitTunnel.IPs, "198.51.100.0/24")

	require.NoError(t, m.AddSplitTunnelApp(AppRule{Name: "browser"}))
	assert.Contains(t, m.config.SplitTunnel.Apps, AppRule{Name: "browser"})

	require.NoError(t, m.AddSplitTunnelDomain("example.com"))
	assert.Contains(t, m.config.SplitTunnel.Domains, "example.com")
}

// TestSplitTunnelEngine_AddReturnsRejections asserts the engine surfaces the
// rejection at all, which is what makes the Manager's rollback reachable.
func TestSplitTunnelEngine_AddReturnsRejections(t *testing.T) {
	engine, err := NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude"}, nil)
	require.NoError(t, err)

	require.NoError(t, engine.AddIP("203.0.113.0/24"))
	assert.Error(t, engine.AddIP("not-an-ip"),
		"a malformed entry must be reported, not silently dropped")
}
