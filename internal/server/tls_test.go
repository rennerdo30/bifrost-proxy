package server

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestClientAuthPolicy(t *testing.T) {
	cases := []struct {
		in        string
		want      tls.ClientAuthType
		needsPool bool
		wantErr   bool
	}{
		{"", tls.NoClientCert, false, false},
		{"none", tls.NoClientCert, false, false},
		{"request", tls.RequestClientCert, false, false},
		{"require_any", tls.RequireAnyClientCert, false, false},
		{"verify_if_given", tls.VerifyClientCertIfGiven, true, false},
		{"require", tls.RequireAndVerifyClientCert, true, false},
		{"bogus", tls.NoClientCert, false, true},
	}
	for _, c := range cases {
		policy, needsPool, err := clientAuthPolicy(c.in)
		if c.wantErr {
			assert.Error(t, err, "input %q", c.in)
			continue
		}
		require.NoError(t, err, "input %q", c.in)
		assert.Equal(t, c.want, policy, "input %q", c.in)
		assert.Equal(t, c.needsPool, needsPool, "input %q", c.in)
	}
}

func TestBuildListenerTLSConfig_Disabled(t *testing.T) {
	cfg, err := buildListenerTLSConfig(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, cfg)

	cfg, err = buildListenerTLSConfig(&config.TLSConfig{Enabled: false}, nil)
	require.NoError(t, err)
	assert.Nil(t, cfg)
}

func TestBuildListenerTLSConfig_RequireWithoutPoolFailsClosed(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerKeypair(t, dir)

	_, err := buildListenerTLSConfig(&config.TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "require",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client CA pool")
}

func TestBuildListenerTLSConfig_RequireWithPool(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerKeypair(t, dir)

	pool := x509.NewCertPool()
	out, err := buildListenerTLSConfig(&config.TLSConfig{
		Enabled:    true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientAuth: "require",
	}, pool)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, tls.RequireAndVerifyClientCert, out.ClientAuth)
	assert.Equal(t, pool, out.ClientCAs)
}

func TestMTLSCAPoolFromAuth(t *testing.T) {
	// No mtls provider -> nil pool, no error.
	pool, err := mtlsCAPoolFromAuth(config.AuthConfig{})
	require.NoError(t, err)
	assert.Nil(t, pool)

	caPEM := generateCAPEM(t)
	pool, err = mtlsCAPoolFromAuth(config.AuthConfig{
		Providers: []config.AuthProvider{
			{
				Name:    "mtls",
				Type:    "mtls",
				Enabled: true,
				Config: map[string]any{
					"ca_cert_pem": caPEM,
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, pool)

	// Invalid PEM -> error.
	_, err = mtlsCAPoolFromAuth(config.AuthConfig{
		Providers: []config.AuthProvider{
			{
				Name:    "mtls",
				Type:    "mtls",
				Enabled: true,
				Config:  map[string]any{"ca_cert_pem": "not a cert"},
			},
		},
	})
	require.Error(t, err)
}

func TestClientCAPool_FromFile(t *testing.T) {
	dir := t.TempDir()
	caPEM := generateCAPEM(t)
	caFile := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte(caPEM), 0o600))

	pool, err := clientCAPool(caFile, nil)
	require.NoError(t, err)
	require.NotNil(t, pool)

	// Empty file path returns fallback.
	fallback := x509.NewCertPool()
	pool, err = clientCAPool("", fallback)
	require.NoError(t, err)
	assert.Equal(t, fallback, pool)

	// Bad file contents -> error.
	bad := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(bad, []byte("garbage"), 0o600))
	_, err = clientCAPool(bad, nil)
	require.Error(t, err)
}
