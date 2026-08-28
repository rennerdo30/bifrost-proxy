package p2p

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The mesh layer fills TURNConfig/RelayEnabled on ManagerConfig — fields
// nothing read: the relay manager was always built from a zero RelayConfig, so
// with turn.enabled: true no TURN client was ever created and GetBestRelay
// always failed. The bridge must carry the manager-level settings through.
func TestNewP2PManager_BridgesTURNConfigIntoRelayManager(t *testing.T) {
	turn := &TURNConfig{
		Server:   "turn.example.com:3478",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	}

	pm, err := NewP2PManager(ManagerConfig{
		LocalPeerID:      "bridge-test",
		TURNConfig:       turn,
		RelayEnabled:     true,
		PeerRelayEnabled: true,
		ConnectTimeout:   time.Second,
	})
	require.NoError(t, err)
	defer pm.Stop() //nolint:errcheck // test cleanup

	require.NotNil(t, pm.relayManager)
	assert.True(t, pm.relayManager.config.Enabled,
		"relay must be enabled when the manager-level flag is set")
	require.NotNil(t, pm.relayManager.config.TURNConfig,
		"the TURN credentials must reach the relay manager")
	assert.Equal(t, "turn.example.com:3478", pm.relayManager.config.TURNConfig.Server)
}

// An explicitly supplied RelayConfig keeps winning over the bridge.
func TestNewP2PManager_ExplicitRelayConfigWins(t *testing.T) {
	explicit := RelayConfig{Enabled: true, MaxRelayHops: 7, RelayTimeout: time.Second}
	pm, err := NewP2PManager(ManagerConfig{
		LocalPeerID: "explicit-test",
		RelayConfig: explicit,
	})
	require.NoError(t, err)
	defer pm.Stop() //nolint:errcheck // test cleanup
	assert.Equal(t, 7, pm.relayManager.config.MaxRelayHops)
}
