package system_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/system"
)

// TestSystemPlugin_AvailabilityReflectsTheBuild covers the audit finding that
// `system` is offered in the dashboard as "System (PAM)" with a PAM Service
// field while the default `make build` and the Docker image compile the
// fail-closed stub (CGO_ENABLED=0, no `-tags pam`) — so it accepted
// configuration and then rejected every user.
//
// The plugin now reports the build reality, which drives the startup warning,
// the API's /api/v1/auth/plugins response and the dashboard badge.
func TestSystemPlugin_AvailabilityReflectsTheBuild(t *testing.T) {
	plugin, ok := auth.GetPlugin("system")
	require.True(t, ok, "system plugin must be registered")

	availability := auth.PluginAvailability(plugin)

	// Whatever the platform, a plugin that cannot work must explain itself and
	// must never be reported as a permanent dead end: `system` genuinely works
	// on Windows, on macOS via dscl, and in a `-tags pam` Linux build.
	assert.False(t, availability.MustRefuse(),
		"system must never be refused outright — the same config is valid on a PAM-enabled build")

	if availability.Usable() {
		assert.Equal(t, auth.AvailabilityAvailable, availability.State)
		assert.Empty(t, availability.Reason)
		return
	}

	assert.Equal(t, auth.AvailabilityBuildDisabled, availability.State)
	require.NotEmpty(t, availability.Reason, "an unusable provider must say why")
	// The reason has to be actionable: it is the only thing the operator sees.
	assert.Contains(t, availability.Reason, "pam")
	assert.Equal(t, "linux", runtime.GOOS,
		"only a Linux build without the PAM backend should report build_disabled")
}

// TestSystemPlugin_StillValidatesAndCreates asserts the deliberate asymmetry with
// NTLM: `system` is surfaced, not refused, so an operator on a PAM-enabled build
// (or Windows/macOS) can still configure it, and one on a stub build can still
// save a config that mentions it.
func TestSystemPlugin_StillValidatesAndCreates(t *testing.T) {
	plugin, ok := auth.GetPlugin("system")
	require.True(t, ok)

	cfg := map[string]any{"service": "bifrost"}
	require.NoError(t, plugin.ValidateConfig(cfg))

	authenticator, err := plugin.Create(cfg)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	// The factory must not refuse it either, on any platform.
	_, err = auth.NewFactory().Create(auth.ProviderConfig{
		Name:    "sys",
		Type:    "system",
		Enabled: true,
		Config:  cfg,
	})
	assert.NoError(t, err)
}
