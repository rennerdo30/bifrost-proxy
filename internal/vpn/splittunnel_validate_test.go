package vpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Split-tunnel rules used to be dropped silently at engine construction. In
// include mode the default action is bypass, so a dropped include rule sent
// that traffic OUTSIDE the tunnel in cleartext. Every malformed rule is a
// validation error now.
func TestSplitTunnelConfig_ValidateRejectsMalformedRules(t *testing.T) {
	base := func() SplitTunnelConfig { return SplitTunnelConfig{Mode: "include"} }

	cfg := base()
	cfg.IPs = []string{"10.0.0.0/8", "not-an-ip"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-an-ip")

	cfg = base()
	cfg.AlwaysBypass = []string{"999.999.0.0/16"}
	require.Error(t, cfg.Validate())

	cfg = base()
	cfg.Apps = []AppRule{{Name: ""}}
	require.Error(t, cfg.Validate(), "an app rule with no name matches nothing and must be rejected")

	// A fully valid config still validates.
	cfg = SplitTunnelConfig{
		Mode:         "include",
		IPs:          []string{"10.1.0.0/16", "192.0.2.1"},
		Domains:      []string{"*.corp.example"},
		Apps:         []AppRule{{Name: "slack"}},
		AlwaysBypass: []string{"192.168.0.0/16"},
	}
	assert.NoError(t, cfg.Validate())
}

// The engine refuses to build on a config that validation rejects, so a
// malformed rule can no longer be silently dropped at runtime either.
func TestNewSplitTunnelEngine_RejectsMalformedRules(t *testing.T) {
	_, err := NewSplitTunnelEngine(SplitTunnelConfig{
		Mode: "include",
		IPs:  []string{"bogus"},
	}, nil)
	require.Error(t, err)
}
