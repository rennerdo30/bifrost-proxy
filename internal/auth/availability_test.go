package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAuthenticator is a no-op Authenticator for registry/factory tests.
type stubAuthenticator struct{}

func (stubAuthenticator) Authenticate(_ context.Context, _, _ string) (*UserInfo, error) {
	return &UserInfo{Username: "stub"}, nil
}
func (stubAuthenticator) Type() string   { return "stub" }
func (stubAuthenticator) Close() error   { return nil }
func (stubAuthenticator) Name() string   { return "stub" }
func (stubAuthenticator) Ready() bool    { return true }
func (stubAuthenticator) String() string { return "stub" }

// availabilityPlugin is a test plugin that reports whatever availability the
// test needs.
type availabilityPlugin struct {
	typeName     string
	availability *Availability
}

func (p *availabilityPlugin) Type() string        { return p.typeName }
func (p *availabilityPlugin) Description() string { return "test plugin" }
func (p *availabilityPlugin) Create(_ map[string]any) (Authenticator, error) {
	return stubAuthenticator{}, nil
}
func (p *availabilityPlugin) ValidateConfig(_ map[string]any) error { return nil }
func (p *availabilityPlugin) DefaultConfig() map[string]any         { return nil }
func (p *availabilityPlugin) ConfigSchema() string                  { return "" }

// Availability is only implemented when the test supplies one, so the same type
// also covers the "plugin does not report availability" default.
func (p *availabilityPlugin) Availability() Availability {
	if p.availability == nil {
		return Availability{}
	}
	return *p.availability
}

// plainPlugin implements Plugin but NOT AvailabilityReporter.
type plainPlugin struct{ typeName string }

func (p *plainPlugin) Type() string        { return p.typeName }
func (p *plainPlugin) Description() string { return "plain test plugin" }
func (p *plainPlugin) Create(_ map[string]any) (Authenticator, error) {
	return stubAuthenticator{}, nil
}
func (p *plainPlugin) ValidateConfig(_ map[string]any) error { return nil }
func (p *plainPlugin) DefaultConfig() map[string]any         { return nil }
func (p *plainPlugin) ConfigSchema() string                  { return "" }

func TestPluginAvailability_DefaultsToAvailable(t *testing.T) {
	// A plugin that says nothing about itself is assumed to work; only plugins
	// that know they cannot have to declare it.
	availability := PluginAvailability(&plainPlugin{typeName: "plain"})
	assert.Equal(t, AvailabilityAvailable, availability.State)
	assert.True(t, availability.Usable())
	assert.False(t, availability.MustRefuse())
}

func TestPluginAvailability_EmptyStateIsNormalised(t *testing.T) {
	// A reporter returning a zero Availability must not be read as "unusable
	// with no reason" — failing closed on a programming slip would take out
	// working providers.
	availability := PluginAvailability(&availabilityPlugin{typeName: "zero"})
	assert.Equal(t, AvailabilityAvailable, availability.State)
	assert.True(t, availability.Usable())
}

// TestPluginAvailability_UnknownStateIsNotTreatedAsWorking guards the fail-safe
// direction. A plugin reporting a state this build does not recognize must not be
// read as "available" just because the string did not match — but it must not be
// escalated to a refusal either, since that could take down a config that loads
// fine today.
func TestPluginAvailability_UnknownStateIsNotTreatedAsWorking(t *testing.T) {
	availability := PluginAvailability(&availabilityPlugin{
		typeName:     "weird",
		availability: &Availability{State: AvailabilityState("from-the-future")},
	})

	assert.Equal(t, AvailabilityBuildDisabled, availability.State)
	assert.False(t, availability.Usable())
	assert.False(t, availability.MustRefuse())
	assert.NotEmpty(t, availability.Reason, "an unusable plugin must always carry a reason")
}

func TestAvailability_States(t *testing.T) {
	buildDisabled := Availability{State: AvailabilityBuildDisabled, Reason: "no build tag"}
	assert.False(t, buildDisabled.Usable(), "it cannot authenticate in this binary")
	assert.False(t, buildDisabled.MustRefuse(), "but the same config is correct in a build that has the support")

	unimplemented := Availability{State: AvailabilityUnimplemented, Reason: "no verification path"}
	assert.False(t, unimplemented.Usable())
	assert.True(t, unimplemented.MustRefuse())
}

// TestFactory_RefusesUnimplementedPlugin is the general form of the NTLM case:
// a provider whose plugin can never authenticate must be refused at config
// validation, not created and then made to reject every login.
func TestFactory_RefusesUnimplementedPlugin(t *testing.T) {
	const typeName = "test-unimplemented"
	RegisterPlugin(typeName, &availabilityPlugin{
		typeName: typeName,
		availability: &Availability{
			State:  AvailabilityUnimplemented,
			Reason: "there is no verification path; use something else",
		},
	})
	t.Cleanup(func() { unregisterPluginForTest(typeName) })

	provider := ProviderConfig{Name: "p1", Type: typeName, Enabled: true}
	factory := NewFactory()

	_, err := factory.Create(provider)
	require.Error(t, err)
	var unimplemented *ErrPluginUnimplemented
	require.ErrorAs(t, err, &unimplemented)
	assert.Equal(t, typeName, unimplemented.Type)
	assert.Contains(t, err.Error(), "use something else", "the plugin's own reason must reach the operator")

	// Validate-only path (used by the API's save/validate endpoints).
	require.ErrorAs(t, factory.ValidateProviders([]ProviderConfig{provider}), &unimplemented)

	// And a chain containing it must not come up half-working.
	_, err = factory.CreateChain([]ProviderConfig{provider})
	require.Error(t, err)
}

// TestFactory_AllowsBuildDisabledPlugin pins the deliberate asymmetry: a plugin
// that is merely unavailable in THIS build is surfaced (startup warning + UI
// badge) but not refused, because the identical configuration is correct on a
// build that includes the support. Refusing it would break those deployments and
// would leave an operator unable to save any config that mentions the provider.
func TestFactory_AllowsBuildDisabledPlugin(t *testing.T) {
	const typeName = "test-build-disabled"
	RegisterPlugin(typeName, &availabilityPlugin{
		typeName: typeName,
		availability: &Availability{
			State:  AvailabilityBuildDisabled,
			Reason: "rebuild with -tags something",
		},
	})
	t.Cleanup(func() { unregisterPluginForTest(typeName) })

	provider := ProviderConfig{Name: "p1", Type: typeName, Enabled: true}
	factory := NewFactory()

	_, err := factory.Create(provider)
	assert.NoError(t, err, "a build-disabled provider must still be constructible")
	assert.NoError(t, factory.ValidateProviders([]ProviderConfig{provider}))
}

// TestListPluginInfo_ExposesAvailability covers what the dashboard consumes: the
// UI used to carry a hand-maintained list of provider types with hard-coded
// warnings, which could not express build-dependent truths.
func TestListPluginInfo_ExposesAvailability(t *testing.T) {
	const typeName = "test-info-availability"
	reason := "cannot work here"
	RegisterPlugin(typeName, &availabilityPlugin{
		typeName:     typeName,
		availability: &Availability{State: AvailabilityBuildDisabled, Reason: reason},
	})
	t.Cleanup(func() { unregisterPluginForTest(typeName) })

	info, ok := GetPluginInfo(typeName)
	require.True(t, ok)
	assert.Equal(t, AvailabilityBuildDisabled, info.Availability.State)
	assert.Equal(t, reason, info.Availability.Reason)

	var found bool
	for _, i := range ListPluginInfo() {
		if i.Name == typeName {
			found = true
			assert.Equal(t, AvailabilityBuildDisabled, i.Availability.State)
			assert.Equal(t, reason, i.Availability.Reason)
		}
	}
	assert.True(t, found, "ListPluginInfo must include the plugin")
}

// TestGuidanceForNegotiateProvider covers the "negotiate is not a provider"
// case. SPNEGO/Negotiate is HTTP middleware configured under auth.negotiate.*,
// so `type: negotiate` under auth.providers can never work; the error must say
// so rather than just listing the valid types.
func TestGuidanceForNegotiateProvider(t *testing.T) {
	factory := NewFactory()

	for _, typeName := range []string{"negotiate", "Negotiate", "spnego", " SPNEGO "} {
		t.Run(typeName, func(t *testing.T) {
			_, err := factory.Create(ProviderConfig{Name: "sso", Type: typeName, Enabled: true})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "auth.negotiate",
				"the error must point at the section that does work")

			err = factory.ValidateProviders([]ProviderConfig{{Name: "sso", Type: typeName, Enabled: true}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "auth.negotiate")
		})
	}
}

// unregisterPluginForTest removes a plugin registered by a test so the global
// registry does not leak between tests.
func unregisterPluginForTest(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(plugins, name)
}
