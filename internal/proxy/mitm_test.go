package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genTestCA returns PEM cert+key for a self-signed CA. keyType selects the
// private-key encoding to exercise the parser ("pkcs8", "ec", "pkcs1").
func genTestCA(t *testing.T, keyType string) (certPEM, keyPEM []byte) {
	t.Helper()

	var (
		pub     any
		signer  any
		keyDER  []byte
		keyKind string
	)

	switch keyType {
	case "pkcs1":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub, signer = &k.PublicKey, k
		keyDER = x509.MarshalPKCS1PrivateKey(k)
		keyKind = "RSA PRIVATE KEY"
	case "ec":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub, signer = &k.PublicKey, k
		keyDER, err = x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
		keyKind = "EC PRIVATE KEY"
	default: // pkcs8
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub, signer = &k.PublicKey, k
		keyDER, err = x509.MarshalPKCS8PrivateKey(k)
		require.NoError(t, err)
		keyKind = "PRIVATE KEY"
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bifrost Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: keyKind, Bytes: keyDER})
	return certPEM, keyPEM
}

func TestNewCertMinter_Disabled(t *testing.T) {
	_, err := NewCertMinter(MITMConfig{Enabled: false})
	assert.ErrorIs(t, err, errMITMDisabled)
}

func TestNewCertMinter_MissingCA(t *testing.T) {
	_, err := NewCertMinter(MITMConfig{Enabled: true})
	assert.Error(t, err)
}

func TestNewCertMinter_InvalidPEM(t *testing.T) {
	_, err := NewCertMinter(MITMConfig{
		Enabled:   true,
		CACertPEM: []byte("not pem"),
		CAKeyPEM:  []byte("not pem"),
	})
	assert.Error(t, err)
}

func TestNewCertMinter_NotACA(t *testing.T) {
	// Build a leaf (non-CA) cert and try to use it as the signing CA.
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, err = NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM})
	assert.Error(t, err)
}

func TestCertMinter_KeyFormats(t *testing.T) {
	for _, kt := range []string{"pkcs8", "ec", "pkcs1"} {
		t.Run(kt, func(t *testing.T) {
			certPEM, keyPEM := genTestCA(t, kt)
			m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM})
			require.NoError(t, err)
			cert, err := m.GetCertificate("example.com")
			require.NoError(t, err)
			require.NotNil(t, cert.Leaf)
			assert.Equal(t, "example.com", cert.Leaf.Subject.CommonName)
		})
	}
}

func TestCertMinter_MintAndVerify(t *testing.T) {
	certPEM, keyPEM := genTestCA(t, "pkcs8")
	m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM, LeafTTL: time.Hour})
	require.NoError(t, err)

	cert, err := m.GetCertificate("secure.example.com:443")
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)

	// Port should be stripped from the host used in the leaf.
	assert.Equal(t, "secure.example.com", cert.Leaf.Subject.CommonName)
	assert.Contains(t, cert.Leaf.DNSNames, "secure.example.com")

	// Leaf must verify against the CA.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM))
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "secure.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err)

	// Chain should include the CA cert.
	assert.Len(t, cert.Certificate, 2)
}

func TestCertMinter_IPSAN(t *testing.T) {
	certPEM, keyPEM := genTestCA(t, "pkcs8")
	m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM})
	require.NoError(t, err)

	cert, err := m.GetCertificate("10.1.2.3")
	require.NoError(t, err)
	require.Len(t, cert.Leaf.IPAddresses, 1)
	assert.Equal(t, "10.1.2.3", cert.Leaf.IPAddresses[0].String())
	assert.Empty(t, cert.Leaf.DNSNames)
}

func TestCertMinter_Caching(t *testing.T) {
	certPEM, keyPEM := genTestCA(t, "pkcs8")
	m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM})
	require.NoError(t, err)

	c1, err := m.GetCertificate("cache.example.com")
	require.NoError(t, err)
	c2, err := m.GetCertificate("cache.example.com")
	require.NoError(t, err)
	// Same cached pointer.
	assert.Same(t, c1, c2)
}

func TestCertMinter_CacheEviction(t *testing.T) {
	certPEM, keyPEM := genTestCA(t, "pkcs8")
	m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM, MaxCachedCerts: 2})
	require.NoError(t, err)

	_, err = m.GetCertificate("a.example.com")
	require.NoError(t, err)
	_, err = m.GetCertificate("b.example.com")
	require.NoError(t, err)
	// Third insertion triggers a cache clear (simple bound).
	_, err = m.GetCertificate("c.example.com")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(m.cache), 2)
}

func TestCertMinter_EmptyServerName(t *testing.T) {
	certPEM, keyPEM := genTestCA(t, "pkcs8")
	m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM})
	require.NoError(t, err)
	_, err = m.GetCertificate("")
	assert.Error(t, err)
}

func TestCertMinter_TLSConfigGetCertificate(t *testing.T) {
	certPEM, keyPEM := genTestCA(t, "pkcs8")
	m, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: certPEM, CAKeyPEM: keyPEM})
	require.NoError(t, err)

	cfg := m.TLSConfig()
	require.NotNil(t, cfg.GetCertificate)
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "tls.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "tls.example.com", cert.Leaf.Subject.CommonName)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestNormalizeHost(t *testing.T) {
	assert.Equal(t, "", normalizeHost(""))
	assert.Equal(t, "example.com", normalizeHost("example.com"))
	assert.Equal(t, "example.com", normalizeHost("example.com:443"))
}
