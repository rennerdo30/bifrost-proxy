package auth

import "fmt"

// AvailabilityState classifies whether a registered auth plugin can actually
// authenticate anyone.
//
// Registration alone says nothing about that. Some plugins are registered,
// configurable, and documented, yet reject every single login: NTLM has no
// credential source to verify a client response against, and the `system` (PAM)
// backend compiles to a stub unless the binary was built with the `pam` tag.
// Both used to accept configuration happily and then fail every user, which is
// the worst of both worlds — closed, but silently.
//
// Plugins in that position report it here so the server can say so at startup,
// the API can tell the dashboard, and configuration validation can refuse the
// cases that can never work at all.
type AvailabilityState string

const (
	// AvailabilityAvailable means the plugin can authenticate normally. This is
	// the default for any plugin that does not implement AvailabilityReporter.
	AvailabilityAvailable AvailabilityState = "available"

	// AvailabilityBuildDisabled means this particular binary lacks the support
	// the plugin needs — a build tag, cgo, or a platform library — so it fails
	// closed here but works in a build that includes it.
	//
	// These are reported loudly (startup warning + UI badge) but NOT refused at
	// config validation: the same configuration is correct on a build that has
	// the support, so rejecting it would break those deployments and would turn
	// a warning into a hard startup failure for anyone merely listing the
	// provider in a chain.
	AvailabilityBuildDisabled AvailabilityState = "build_disabled"

	// AvailabilityUnimplemented means the plugin cannot authenticate anyone in
	// any build, because the verification path does not exist.
	//
	// These ARE refused at config validation. Offering a full configuration form
	// for a provider that rejects 100% of logins is worse than not offering it:
	// the operator has no way to tell a misconfiguration from a dead end.
	AvailabilityUnimplemented AvailabilityState = "unimplemented"
)

// Availability is a plugin's self-report of whether it can authenticate.
type Availability struct {
	// State classifies the plugin's usability. See AvailabilityState.
	State AvailabilityState `json:"state"`

	// Reason explains, in operator-facing terms, why the plugin cannot work and
	// what to do instead. Required whenever State is not AvailabilityAvailable;
	// it is the text shown at startup, in validation errors and in the UI.
	Reason string `json:"reason,omitempty"`
}

// Usable reports whether the plugin can authenticate in this binary.
func (a Availability) Usable() bool {
	return a.State == AvailabilityAvailable
}

// MustRefuse reports whether a configuration selecting this plugin should be
// rejected outright rather than merely flagged.
func (a Availability) MustRefuse() bool {
	return a.State == AvailabilityUnimplemented
}

// AvailabilityReporter is implemented by plugins that may be unable to
// authenticate. Plugins that always work simply do not implement it and are
// treated as AvailabilityAvailable.
type AvailabilityReporter interface {
	// Availability reports whether this plugin can authenticate in the running
	// binary. It must not panic and should be cheap: it is called during config
	// validation and to build API responses.
	Availability() Availability
}

// PluginAvailability returns p's availability, defaulting to available for
// plugins that do not report one.
func PluginAvailability(p Plugin) Availability {
	if reporter, ok := p.(AvailabilityReporter); ok {
		a := reporter.Availability()
		if a.State == "" {
			a.State = AvailabilityAvailable
		}
		return a
	}
	return Availability{State: AvailabilityAvailable}
}

// ErrPluginUnimplemented is returned when a configuration selects an auth
// plugin that can never authenticate anyone. Callers can match it with
// errors.Is to distinguish "this provider is a dead end" from "this provider is
// misconfigured".
type ErrPluginUnimplemented struct {
	// Type is the plugin type from the provider configuration.
	Type string
	// Reason is the plugin's own explanation.
	Reason string
}

func (e *ErrPluginUnimplemented) Error() string {
	return fmt.Sprintf("auth provider type %q cannot authenticate anyone and is refused: %s", e.Type, e.Reason)
}
