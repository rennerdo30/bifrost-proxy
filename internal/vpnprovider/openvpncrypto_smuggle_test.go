package vpnprovider

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNormalizeCACertPEMStripsSmuggledDirectives is the regression test for
// <ca> element smuggling.
//
// ParseCACertPEM stops at the first non-PEM byte and ignores the remainder, so a
// ca_cert holding a valid certificate followed by "</ca>" and further OpenVPN
// directives validates cleanly. A provider that then wrote the operator string
// into the profile verbatim would close the <ca> element early and promote those
// lines to top-level directives — including ones that run programs, such as
// "up". Emitting the re-encoded certificates instead makes the profile contain
// exactly what was validated.
func TestNormalizeCACertPEMStripsSmuggledDirectives(t *testing.T) {
	now := time.Now()
	valid := testCertPEM(t, "Smuggle CA", true, now.Add(-time.Hour), now.Add(time.Hour))

	smuggled := valid + "</ca>\nscript-security 2\nup /tmp/attacker.sh\n<ca>\n"

	// The smuggling payload is deliberately invisible to validation.
	require.NoError(t, ValidateCACertPEM(smuggled),
		"precondition: trailing content after the PEM is ignored by validation")

	normalized, err := NormalizeCACertPEM(smuggled)
	require.NoError(t, err)

	for _, forbidden := range []string{"</ca>", "script-security", "up /tmp/attacker.sh", "<ca>"} {
		assert.NotContains(t, normalized, forbidden,
			"normalized CA must not carry smuggled profile content")
	}

	// What remains must still be the certificate that was validated.
	certs, err := ParseCACertPEM(normalized)
	require.NoError(t, err)
	require.Len(t, certs, 1)

	original, err := ParseCACertPEM(valid)
	require.NoError(t, err)
	assert.Equal(t, original[0].Raw, certs[0].Raw,
		"normalization must preserve the certificate bytes exactly")
}

// TestNormalizeCACertPEMPreservesBundleOrder guards the multi-certificate case:
// a bundle must survive normalization intact and in file order, since OpenVPN
// walks it as a chain.
func TestNormalizeCACertPEMPreservesBundleOrder(t *testing.T) {
	now := time.Now()
	first := testCertPEM(t, "Bundle Root", true, now.Add(-time.Hour), now.Add(time.Hour))
	second := testCertPEM(t, "Bundle Second", true, now.Add(-time.Hour), now.Add(time.Hour))

	normalized, err := NormalizeCACertPEM(first + second)
	require.NoError(t, err)

	certs, err := ParseCACertPEM(normalized)
	require.NoError(t, err)
	require.Len(t, certs, 2)

	want, err := ParseCACertPEM(first + second)
	require.NoError(t, err)
	assert.Equal(t, want[0].Raw, certs[0].Raw)
	assert.Equal(t, want[1].Raw, certs[1].Raw)
	assert.Equal(t, 2, strings.Count(normalized, "-----BEGIN CERTIFICATE-----"))
}

// TestNormalizeCACertPEMRejectsInvalid confirms normalization is not a way to
// launder material that validation would refuse.
func TestNormalizeCACertPEMRejectsInvalid(t *testing.T) {
	for name, input := range map[string]string{
		"empty":         "",
		"whitespace":    "   \n\t ",
		"not PEM":       "definitely not a certificate",
		"malformed DER": "-----BEGIN CERTIFICATE-----\nbm90IERFUg==\n-----END CERTIFICATE-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NormalizeCACertPEM(input)
			assert.Error(t, err)
		})
	}
}
