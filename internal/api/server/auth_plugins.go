package server

import (
	"fmt"
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
// Only ENABLED providers are checked, matching runtime behavior: CreateChain
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
	if len(enabled) > 0 {
		if err := auth.NewFactory().ValidateProviders(enabled); err != nil {
			return []ValidationError{{Section: authSection, Message: err.Error()}}
		}
	}

	// Checked even when no provider is enabled: an enabled negotiate block
	// pointing at a provider that does not exist (or is disabled) is precisely the
	// case where the provider loop above has nothing to look at.
	if err := validateNegotiate(cfg.Auth); err != nil {
		return []ValidationError{{Section: authSection, Message: err.Error()}}
	}
	return nil
}

// validateNegotiate checks the auth.negotiate block, which is the one part of
// the auth config that does not go through auth.Factory: SPNEGO/Negotiate is
// HTTP middleware wired separately from the provider chain.
//
// Without this the save path still accepted a negotiate block that fails at
// startup — pointing at a provider that does not exist, is disabled, or has the
// wrong type — which is the same defect as the provider gap, in the one corner
// the provider check does not reach. The conditions mirror
// server.buildNegotiateHandler so the two cannot disagree.
func validateNegotiate(authCfg config.AuthConfig) error {
	nc := authCfg.Negotiate
	if nc == nil || !nc.Enabled {
		return nil
	}

	if nc.KerberosProvider == "" && nc.NTLMProvider == "" {
		return fmt.Errorf("auth.negotiate is enabled but neither kerberos_provider nor ntlm_provider is set")
	}
	if nc.AllowNTLM && nc.NTLMProvider == "" {
		return fmt.Errorf("auth.negotiate.allow_ntlm is set but ntlm_provider is not configured")
	}

	for _, ref := range []struct {
		field    string
		name     string
		wantType string
	}{
		{"kerberos_provider", nc.KerberosProvider, "kerberos"},
		{"ntlm_provider", nc.NTLMProvider, "ntlm"},
	} {
		if ref.name == "" {
			continue
		}
		if err := checkNegotiateProviderRef(authCfg.Providers, ref.field, ref.name, ref.wantType); err != nil {
			return err
		}
	}
	return nil
}

// checkNegotiateProviderRef resolves one auth.negotiate provider reference
// against the configured providers.
func checkNegotiateProviderRef(providers []config.AuthProvider, field, name, wantType string) error {
	for _, p := range providers {
		if p.Name != name {
			continue
		}
		if p.Type != wantType {
			return fmt.Errorf("auth.negotiate.%s references provider %q of type %q, expected %q",
				field, name, p.Type, wantType)
		}
		if !p.Enabled {
			return fmt.Errorf("auth.negotiate.%s references provider %q, which is not enabled", field, name)
		}
		// The referenced provider's own type must still be usable. This is what
		// makes an NTLM-backed negotiate block fail here rather than at startup.
		if plugin, ok := auth.GetPlugin(p.Type); ok {
			if availability := auth.PluginAvailability(plugin); availability.MustRefuse() {
				return fmt.Errorf("auth.negotiate.%s references provider %q: %w", field, name,
					&auth.ErrPluginUnimplemented{Type: p.Type, Reason: availability.Reason})
			}
		}
		return nil
	}
	return fmt.Errorf("auth.negotiate.%s references unknown provider %q", field, name)
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
