package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/negotiate"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/proxy"
)

// buildNegotiateHandler constructs a negotiate.Handler (SPNEGO/Kerberos with
// optional NTLM fallback) from the auth configuration. It resolves the
// referenced kerberos/ntlm auth providers and instantiates their authenticators
// via the public auth factory. Returns (nil, nil) when Negotiate is not enabled.
//
// negotiate.Handler is middleware, not an auth.Plugin, so it is wired
// separately from the provider chain.
func buildNegotiateHandler(cfg config.AuthConfig) (*negotiate.Handler, error) {
	nc := cfg.Negotiate
	if nc == nil || !nc.Enabled {
		return nil, nil
	}

	factory := auth.NewFactory()

	var kerberosAuth auth.Authenticator
	if nc.KerberosProvider != "" {
		a, err := authenticatorByName(factory, cfg.Providers, nc.KerberosProvider, "kerberos")
		if err != nil {
			return nil, err
		}
		kerberosAuth = a
	}

	var ntlmAuth auth.Authenticator
	if nc.NTLMProvider != "" {
		a, err := authenticatorByName(factory, cfg.Providers, nc.NTLMProvider, "ntlm")
		if err != nil {
			return nil, err
		}
		ntlmAuth = a
	}

	if kerberosAuth == nil && ntlmAuth == nil {
		return nil, fmt.Errorf("negotiate enabled but no kerberos_provider or ntlm_provider configured")
	}
	if nc.AllowNTLM && ntlmAuth == nil {
		return nil, fmt.Errorf("negotiate allow_ntlm is set but ntlm_provider is not configured")
	}

	hc := negotiate.DefaultHandlerConfig()
	hc.PreferKerberos = nc.PreferKerberos
	hc.AllowNTLM = nc.AllowNTLM
	if nc.Realm != "" {
		hc.Realm = nc.Realm
	}

	return negotiate.NewHandler(hc, kerberosAuth, ntlmAuth), nil
}

// negotiateAuthHook adapts the server's negotiate.Handler to the proxy's
// NegotiateAuth hook signature. It returns nil when Negotiate is not configured,
// so the proxy falls back to Basic/Bearer/mTLS authentication.
func (s *Server) negotiateAuthHook() func(ctx context.Context, req *http.Request) (*proxy.NegotiateResult, error) {
	if s.negotiateHandler == nil {
		return nil
	}
	h := s.negotiateHandler
	return func(ctx context.Context, req *http.Request) (*proxy.NegotiateResult, error) {
		userInfo, resp, err := h.Authenticate(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp != nil {
			return &proxy.NegotiateResult{
				Challenge:        true,
				ChallengeStatus:  resp.StatusCode,
				ChallengeHeaders: resp.Headers,
			}, nil
		}
		return &proxy.NegotiateResult{UserInfo: userInfo}, nil
	}
}

// authenticatorByName looks up the named provider in the provider list,
// validates its type and that it is enabled, and instantiates its
// authenticator.
func authenticatorByName(factory *auth.Factory, providers []config.AuthProvider, name, wantType string) (auth.Authenticator, error) {
	for _, p := range providers {
		if p.Name != name {
			continue
		}
		if !p.Enabled {
			return nil, fmt.Errorf("negotiate references provider %q which is not enabled", name)
		}
		if p.Type != wantType {
			return nil, fmt.Errorf("negotiate provider %q has type %q, expected %q", name, p.Type, wantType)
		}
		a, err := factory.Create(auth.ProviderConfig{
			Name:    p.Name,
			Type:    p.Type,
			Enabled: p.Enabled,
			Config:  p.Config,
		})
		if err != nil {
			return nil, fmt.Errorf("create negotiate provider %q: %w", name, err)
		}
		return a, nil
	}
	return nil, fmt.Errorf("negotiate references unknown provider %q", name)
}
