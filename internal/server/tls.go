package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// clientAuthPolicy maps a config string to a tls.ClientAuthType. The boolean
// reports whether a client-CA pool is needed (i.e. the policy verifies the
// chain). An empty/"none" policy returns tls.NoClientCert.
func clientAuthPolicy(s string) (tls.ClientAuthType, bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return tls.NoClientCert, false, nil
	case "request":
		return tls.RequestClientCert, false, nil
	case "require_any", "require-any":
		return tls.RequireAnyClientCert, false, nil
	case "verify_if_given", "verify-if-given", "optional":
		return tls.VerifyClientCertIfGiven, true, nil
	case "require", "require_and_verify", "require-and-verify":
		return tls.RequireAndVerifyClientCert, true, nil
	default:
		return tls.NoClientCert, false, fmt.Errorf("unknown tls client_auth policy: %q", s)
	}
}

// buildListenerTLSConfig constructs a *tls.Config for a proxy listener from the
// listener TLS settings. When the configured client-auth policy verifies the
// certificate chain, a client CA pool is required: it is sourced from
// tlsCfg.ClientCAFile if set, otherwise from caPoolFallback (typically the mTLS
// auth provider's CA pool). It fails closed if verification is requested but no
// CA pool is available.
//
// Returns (nil, nil) when TLS is not enabled.
func buildListenerTLSConfig(tlsCfg *config.TLSConfig, caPoolFallback *x509.CertPool) (*tls.Config, error) {
	if tlsCfg == nil || !tlsCfg.Enabled {
		return nil, nil
	}
	if tlsCfg.CertFile == "" || tlsCfg.KeyFile == "" {
		return nil, fmt.Errorf("tls enabled but cert_file/key_file not configured")
	}

	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}

	policy, needsPool, err := clientAuthPolicy(tlsCfg.ClientAuth)
	if err != nil {
		return nil, err
	}

	out := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   policy,
	}

	if policy != tls.NoClientCert {
		pool, poolErr := clientCAPool(tlsCfg.ClientCAFile, caPoolFallback)
		if poolErr != nil {
			return nil, poolErr
		}
		if needsPool && pool == nil {
			// Fail closed: verifying without a CA pool would reject every
			// client, but more importantly silently accepting would be unsafe.
			return nil, fmt.Errorf("tls client_auth %q requires a client CA pool (set tls.client_ca_file or configure an mtls auth provider)", tlsCfg.ClientAuth)
		}
		out.ClientCAs = pool
	}

	return out, nil
}

// mtlsCAPoolFromAuth builds an x509 CA pool from the first enabled auth
// provider of type "mtls". The pool is assembled from the provider's
// ca_cert_pem and/or ca_cert_file config so the proxy TLS listener can verify
// client certificates with the same trust anchors the mTLS authenticator uses.
//
// Returns (nil, nil) when no mTLS provider is configured.
func mtlsCAPoolFromAuth(cfg config.AuthConfig) (*x509.CertPool, error) {
	for _, p := range cfg.Providers {
		if !p.Enabled || p.Type != "mtls" || p.Config == nil {
			continue
		}

		pool := x509.NewCertPool()
		added := false

		if pem, ok := p.Config["ca_cert_pem"].(string); ok && strings.TrimSpace(pem) != "" {
			if !pool.AppendCertsFromPEM([]byte(pem)) {
				return nil, fmt.Errorf("mtls provider %q: ca_cert_pem contained no valid certificates", p.Name)
			}
			added = true
		}

		if file, ok := p.Config["ca_cert_file"].(string); ok && strings.TrimSpace(file) != "" {
			data, err := os.ReadFile(file) //nolint:gosec // operator-supplied config path
			if err != nil {
				return nil, fmt.Errorf("mtls provider %q: read ca_cert_file: %w", p.Name, err)
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("mtls provider %q: ca_cert_file %q contained no valid certificates", p.Name, file)
			}
			added = true
		}

		if !added {
			return nil, fmt.Errorf("mtls provider %q: neither ca_cert_pem nor ca_cert_file configured", p.Name)
		}
		return pool, nil
	}
	return nil, nil
}

// clientCAPool returns the CA pool to use for client-certificate verification.
// If caFile is set it is loaded from disk; otherwise the supplied fallback pool
// (e.g. the mTLS auth provider's pool) is used.
func clientCAPool(caFile string, fallback *x509.CertPool) (*x509.CertPool, error) {
	if strings.TrimSpace(caFile) == "" {
		return fallback, nil
	}
	pem, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("read client_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("client_ca_file %q contained no valid certificates", caFile)
	}
	return pool, nil
}
