package server

import (
	"net/http"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// authSection is the config section name reported on auth validation errors.
const authSection = "auth"

// validateAuthProviders runs plugin-aware validation over the configured auth
// providers and returns a validation error per problem found.
//
// config.AuthConfig.Validate() only rejects the legacy `auth.mode` shapes — it
// knows nothing about provider types, because internal/config cannot reach the
// plugin registry without an import cycle. The consequence was that the Web UI's
// save and validate endpoints happily accepted a provider type that can never
// work (`ntlm`), a type that is not a provider at all (`negotiate`, which is
// SPNEGO middleware configured under auth.negotiate.*), or an `mfa_wrapper`
// using the unsupported by-name format. The config was written to disk, reported
// as valid, and only failed later at restart — the operator's dashboard said
// "Saved" and their server would not come back up.
//
// Routing the API through auth.Factory.ValidateProviders closes that gap. That
// method already existed and had no non-test callers.
//
// Only ENABLED providers are checked, matching runtime behaviour: CreateChain
// skips disabled providers, so a disabled one cannot break the server. It also
// preserves the escape route — an operator whose saved config contains an
// `ntlm` provider can disable it in the UI and save successfully, which would be
// impossible if disabled providers were refused too.
func validateAuthProviders(cfg *config.ServerConfig) []ValidationError {
	enabled := make([]auth.ProviderConfig, 0, len(cfg.Auth.Providers))
	for _, p := range cfg.Auth.Providers {
		if !p.Enabled {
			continue
		}
		enabled = append(enabled, auth.ProviderConfig{
			Name:     p.Name,
			Type:     p.Type,
			Enabled:  p.Enabled,
			Priority: p.Priority,
			Config:   p.Config,
		})
	}
	if len(enabled) == 0 {
		return nil
	}

	if err := auth.NewFactory().ValidateProviders(enabled); err != nil {
		return []ValidationError{{Section: authSection, Message: err.Error()}}
	}
	return nil
}

// handleListAuthPlugins reports every registered auth plugin together with
// whether it can actually authenticate in this binary.
//
// The dashboard used to carry a hand-maintained list of provider types with
// hard-coded warning strings, which drifted from the code (it was missing
// `mfa_wrapper`) and could not express build-dependent truths: whether `system`
// works depends on whether this binary was built with `-tags pam`, which the
// frontend has no way to know. Serving the registry's own view means the UI can
// label providers honestly instead of guessing.
func (a *API) handleListAuthPlugins(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]interface{}{
		"plugins": auth.ListPluginInfo(),
	})
}
