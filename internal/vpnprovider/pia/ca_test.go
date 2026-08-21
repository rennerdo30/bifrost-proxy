package pia

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// piaCASHA256Fingerprint pins the SHA-256 fingerprint of PIA's published
// OpenVPN root CA (ca.rsa.4096.crt). It is here so any edit to the embedded
// constant — including a partial/corrupted paste, the bug this replaces — fails
// the test suite instead of shipping.
const piaCASHA256Fingerprint = "1fd25658456eab3041fba77ccd398ab8124edcc1b8b2fc1d55fdf6b1bbfc9d70"

// TestEmbeddedCACertIsUsable is the regression guard for the class of bug that
// shipped unusable embedded CA material: it fails if piaOpenVPNCA stops being a
// parseable, self-consistent X.509 CA certificate, if its fingerprint changes,
// or if it has expired (in which case the constant must be refreshed from PIA's
// published CA).
func TestEmbeddedCACertIsUsable(t *testing.T) {
	certs, err := vpnprovider.ParseCACertPEM(piaOpenVPNCA)
	require.NoError(t, err, "embedded PIA CA must parse as X.509")
	require.Len(t, certs, 1)

	ca := certs[0]
	assert.True(t, ca.IsCA, "embedded PIA CA must be a CA certificate")
	assert.NotEmpty(t, ca.Subject.CommonName)
	assert.NoError(t, vpnprovider.ValidateCACertPEMAt(piaOpenVPNCA, time.Now()),
		"embedded PIA CA is outside its validity window; refresh it from PIA")

	// It must also be self-signed: PIA ships a single root, and a profile whose
	// <ca> block cannot verify its own chain root is useless.
	assert.NoError(t, ca.CheckSignatureFrom(ca), "embedded PIA CA must be self-signed")

	sum := sha256.Sum256(ca.Raw)
	assert.Equal(t, piaCASHA256Fingerprint, hex.EncodeToString(sum[:]),
		"embedded PIA CA fingerprint changed; verify the new certificate against PIA's published ca.rsa.4096.crt")
}

func TestMustParsePIACertPool(t *testing.T) {
	pool := mustParsePIACertPool()
	require.NotNil(t, pool)
	assert.Len(t, pool.Subjects(), 1) //nolint:staticcheck // pool is built from explicit certs

	// The package-level pool is the one used for TLS and must be equivalent.
	require.NotNil(t, piaCertPool)
	assert.True(t, piaCertPool.Equal(pool))
}

// TestGeneratedProfileCarriesValidCA asserts the emitted profile embeds CA
// material that OpenVPN can actually load: the <ca> block is re-parsed here.
func TestGeneratedProfileCarriesValidCA(t *testing.T) {
	client := NewClient("testuser", "testpass")

	server := &vpnprovider.Server{
		ID:   "us-test",
		Name: "US Test",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  DefaultOpenVPNUDPPort,
		},
	}

	config, err := client.buildOpenVPNConfig(server, nil)
	require.NoError(t, err)

	caPEM := extractPEMBlock(t, config, "<ca>", "</ca>")
	certs, err := vpnprovider.ParseCACertPEM(caPEM)
	require.NoError(t, err, "generated <ca> block must be a parseable CA certificate")
	require.Len(t, certs, 1)

	pool := x509.NewCertPool()
	pool.AddCert(certs[0])
	assert.True(t, pool.Equal(piaCertPool))
}

// extractPEMBlock returns the text between the given delimiters.
func extractPEMBlock(t *testing.T, config, openTag, closeTag string) string {
	t.Helper()

	start := strings.Index(config, openTag)
	require.GreaterOrEqual(t, start, 0, "config must contain %s", openTag)
	start += len(openTag)

	end := strings.Index(config[start:], closeTag)
	require.GreaterOrEqual(t, end, 0, "config must contain %s", closeTag)

	return config[start : start+end]
}
