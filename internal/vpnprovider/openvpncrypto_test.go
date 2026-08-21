package vpnprovider

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertPEM issues a self-signed certificate with the given validity window
// and CA flag, returning it PEM-encoded.
func testCertPEM(t *testing.T, commonName string, isCA bool, notBefore, notAfter time.Time) string {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testStaticKey formats material as an OpenVPN static key block.
func testStaticKey(material []byte) string {
	var sb strings.Builder
	sb.WriteString(TLSAuthKeyHeader + "\n")
	encoded := hex.EncodeToString(material)
	for i := 0; i < len(encoded); i += TLSAuthKeyHexCharsPerLine {
		end := i + TLSAuthKeyHexCharsPerLine
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end] + "\n")
	}
	sb.WriteString(TLSAuthKeyFooter + "\n")
	return sb.String()
}

func TestParseCACertPEM(t *testing.T) {
	now := time.Now()
	validCA := testCertPEM(t, "Test CA", true, now.Add(-time.Hour), now.Add(24*time.Hour))
	leaf := testCertPEM(t, "Test Leaf", false, now.Add(-time.Hour), now.Add(24*time.Hour))

	// A PEM block whose body is valid base64 but not valid DER. pem.Decode
	// accepts it; x509 does not. This is exactly the shape of the malformed CA
	// material that used to be embedded for ProtonVPN and Mullvad, so it must
	// be rejected.
	malformed := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not DER at all"),
	}))
	require.NotEmpty(t, malformed)

	privateKeyBlock := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte{0x01, 0x02, 0x03},
	}))

	tests := []struct {
		name      string
		input     string
		wantErr   error
		wantCerts int
	}{
		{name: "valid CA", input: validCA, wantCerts: 1},
		{name: "bundle", input: validCA + testCertPEM(t, "Second CA", true, now.Add(-time.Hour), now.Add(24*time.Hour)), wantCerts: 2},
		{name: "empty", input: "   \n ", wantErr: ErrCACertMissing},
		{name: "not PEM", input: "definitely not a certificate", wantErr: ErrCACertNotPEM},
		{name: "malformed DER", input: malformed, wantErr: ErrCACertMalformed},
		{name: "private key block", input: privateKeyBlock, wantErr: ErrCACertWrongPEMType},
		{name: "leaf certificate", input: leaf, wantErr: ErrCACertNotCA},
		{
			name: "base64 without PEM armor",
			// Raw base64 of a certificate is not accepted: OpenVPN needs the
			// armored form inside <ca>.
			input:   base64.StdEncoding.EncodeToString([]byte("MIIB")),
			wantErr: ErrCACertNotPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := ParseCACertPEM(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, certs)
				assert.ErrorIs(t, ValidateCACertPEM(tt.input), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, certs, tt.wantCerts)
			assert.NoError(t, ValidateCACertPEM(tt.input))
		})
	}
}

// TestParseCACertPEMRejectsBrokenSelfSignature covers the failure mode that
// shipped as the embedded PIA CA: a certificate that parses cleanly, names
// itself as issuer, but whose signature does not verify under its own key
// because part of the DER was spliced or invented. OpenVPN only rejects such a
// CA during the TLS handshake, so it has to be caught here.
func TestParseCACertPEMRejectsBrokenSelfSignature(t *testing.T) {
	now := time.Now()
	valid := testCertPEM(t, "Tampered CA", true, now.Add(-time.Hour), now.Add(time.Hour))

	block, _ := pem.Decode([]byte(valid))
	require.NotNil(t, block)

	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0xFF // flip a signature byte
	tampered := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	_, err := ParseCACertPEM(tampered)
	assert.ErrorIs(t, err, ErrCACertBadSelfSignature)
	assert.ErrorIs(t, ValidateCACertPEMAt(tampered, now), ErrCACertBadSelfSignature)
}

func TestValidateCACertPEMAt(t *testing.T) {
	now := time.Now()

	t.Run("valid now", func(t *testing.T) {
		ca := testCertPEM(t, "Current CA", true, now.Add(-time.Hour), now.Add(time.Hour))
		assert.NoError(t, ValidateCACertPEMAt(ca, now))
	})

	t.Run("expired", func(t *testing.T) {
		ca := testCertPEM(t, "Old CA", true, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
		err := ValidateCACertPEMAt(ca, now)
		assert.ErrorIs(t, err, ErrCACertExpired)
		// Structural validation still passes: only the clock check fails.
		assert.NoError(t, ValidateCACertPEM(ca))
	})

	t.Run("not yet valid", func(t *testing.T) {
		ca := testCertPEM(t, "Future CA", true, now.Add(24*time.Hour), now.Add(48*time.Hour))
		assert.ErrorIs(t, ValidateCACertPEMAt(ca, now), ErrCACertNotYetValid)
	})

	t.Run("propagates structural errors", func(t *testing.T) {
		assert.ErrorIs(t, ValidateCACertPEMAt("", now), ErrCACertMissing)
	})
}

func TestValidateTLSAuthKey(t *testing.T) {
	random := make([]byte, TLSAuthKeySize)
	_, err := rand.Read(random)
	require.NoError(t, err)

	repeatedLine := strings.Repeat("0123456789abcdef0123456789abcdef\n", TLSAuthKeySize*2/TLSAuthKeyHexCharsPerLine)

	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{name: "empty is allowed", input: ""},
		{name: "valid random key", input: testStaticKey(random)},
		{name: "valid key with comment", input: strings.Replace(testStaticKey(random), TLSAuthKeyHeader+"\n", "#\n# 2048 bit OpenVPN static key\n#\n"+TLSAuthKeyHeader+"\n", 1)},
		{name: "missing header", input: hex.EncodeToString(random), wantErr: ErrTLSAuthKeyMalformed},
		{name: "missing footer", input: TLSAuthKeyHeader + "\n" + hex.EncodeToString(random) + "\n", wantErr: ErrTLSAuthKeyMalformed},
		{name: "too short", input: testStaticKey(random[:16]), wantErr: ErrTLSAuthKeyMalformed},
		{name: "not hex", input: TLSAuthKeyHeader + "\nnot hex material\n" + TLSAuthKeyFooter + "\n", wantErr: ErrTLSAuthKeyMalformed},
		{
			// The fabricated key that used to ship for ProtonVPN was a single
			// placeholder line repeated to the right length.
			name:    "repeated placeholder line",
			input:   TLSAuthKeyHeader + "\n" + repeatedLine + TLSAuthKeyFooter + "\n",
			wantErr: ErrTLSAuthKeyPlaceholder,
		},
		{name: "all zero", input: testStaticKey(make([]byte, TLSAuthKeySize)), wantErr: ErrTLSAuthKeyPlaceholder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTLSAuthKey(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestMustParseEmbeddedCACertPool(t *testing.T) {
	now := time.Now()

	t.Run("valid material", func(t *testing.T) {
		ca := testCertPEM(t, "Embedded CA", true, now.Add(-time.Hour), now.Add(time.Hour))
		pool := MustParseEmbeddedCACertPool("test", ca)
		require.NotNil(t, pool)
		assert.Len(t, pool.Subjects(), 1) //nolint:staticcheck // Subjects() is fine for a pool built from explicit certs
	})

	t.Run("expired material still loads", func(t *testing.T) {
		// Expiry must not panic at init: the binary has to keep starting.
		ca := testCertPEM(t, "Expired CA", true, now.Add(-48*time.Hour), now.Add(-time.Hour))
		assert.NotPanics(t, func() { MustParseEmbeddedCACertPool("test", ca) })
	})

	t.Run("malformed material panics", func(t *testing.T) {
		malformed := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))
		assert.Panics(t, func() { MustParseEmbeddedCACertPool("test", malformed) })
	})
}
