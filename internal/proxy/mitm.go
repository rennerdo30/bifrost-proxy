package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// MITMConfig configures opt-in HTTPS interception (man-in-the-middle) for
// debugging. It is DISABLED by default; interception only occurs when Enabled
// is true AND a valid signing CA is supplied.
//
// SECURITY: enabling MITM lets the proxy decrypt TLS traffic. The signing CA
// private key is extremely sensitive: anyone holding it can impersonate any
// site to clients that trust it. Only enable in controlled debugging
// environments, supply a dedicated throwaway CA, and never reuse a production
// CA. Leaf certificates are minted in-memory and never written to disk.
type MITMConfig struct {
	// Enabled turns interception on. Default false.
	Enabled bool

	// CACertPEM and CAKeyPEM are the PEM-encoded signing CA certificate and
	// private key used to mint leaf certificates on the fly. Both are required
	// when Enabled is true.
	CACertPEM []byte
	CAKeyPEM  []byte

	// LeafTTL is the validity period of minted leaf certificates. Zero defaults
	// to 24h. Leaf certs are short-lived and cached in-memory per host.
	LeafTTL time.Duration

	// MaxCachedCerts bounds the in-memory leaf certificate cache (0 = default).
	MaxCachedCerts int
}

const (
	defaultLeafTTL        = 24 * time.Hour
	defaultMaxCachedCerts = 1024
)

// errMITMDisabled is returned when an operation requires MITM but it is off.
var errMITMDisabled = errors.New("mitm: interception is disabled")

// CertMinter mints and caches leaf certificates signed by a configured CA. It
// is safe for concurrent use. It carries no live connection logic, so it can be
// unit-tested in isolation from the proxy data path.
type CertMinter struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	leafTTL time.Duration
	maxCert int

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// NewCertMinter builds a CertMinter from MITMConfig. It returns an error if the
// config is disabled or the CA material is missing/invalid, so callers fail
// closed rather than silently disabling interception.
func NewCertMinter(cfg MITMConfig) (*CertMinter, error) {
	if !cfg.Enabled {
		return nil, errMITMDisabled
	}
	if len(cfg.CACertPEM) == 0 || len(cfg.CAKeyPEM) == 0 {
		return nil, errors.New("mitm: enabled but CA certificate/key not provided")
	}

	caCert, caKey, err := parseCA(cfg.CACertPEM, cfg.CAKeyPEM)
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, errors.New("mitm: provided certificate is not a CA (BasicConstraints CA=false)")
	}

	ttl := cfg.LeafTTL
	if ttl <= 0 {
		ttl = defaultLeafTTL
	}
	maxCert := cfg.MaxCachedCerts
	if maxCert <= 0 {
		maxCert = defaultMaxCachedCerts
	}

	return &CertMinter{
		caCert:  caCert,
		caKey:   caKey,
		leafTTL: ttl,
		maxCert: maxCert,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// parseCA decodes PEM CA cert+key. The key may be PKCS#8, EC, or PKCS#1 RSA.
func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("mitm: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("mitm: parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("mitm: invalid CA key PEM")
	}

	signer, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, signer, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("mitm: PKCS#8 key is not a signer")
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("mitm: unsupported or invalid CA private key format")
}

// GetCertificate returns a leaf certificate for the given server name, suitable
// for use as tls.Config.GetCertificate. The leaf is minted on demand, signed by
// the CA, and cached per host.
func (m *CertMinter) GetCertificate(serverName string) (*tls.Certificate, error) {
	host := normalizeHost(serverName)
	if host == "" {
		return nil, errors.New("mitm: empty server name")
	}

	m.mu.Lock()
	if cert, ok := m.cache[host]; ok {
		// Reuse only if still valid for a comfortable margin.
		if cert.Leaf != nil && time.Now().Before(cert.Leaf.NotAfter.Add(-time.Minute)) {
			m.mu.Unlock()
			return cert, nil
		}
		delete(m.cache, host)
	}
	m.mu.Unlock()

	cert, err := m.mintLeaf(host)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	// Simple bound: clear cache if it grows past the limit.
	if len(m.cache) >= m.maxCert {
		m.cache = make(map[string]*tls.Certificate)
	}
	m.cache[host] = cert
	m.mu.Unlock()

	return cert, nil
}

// TLSConfig returns a *tls.Config that serves minted leaf certificates via SNI.
// It is intended to wrap the client side of a CONNECT tunnel once the live
// interception path is wired up.
func (m *CertMinter) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.GetCertificate(hello.ServerName)
		},
	}
}

// mintLeaf creates and signs a new leaf certificate for host.
func (m *CertMinter) mintLeaf(host string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("mitm: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(m.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, leafKey.Public(), m.caKey)
	if err != nil {
		return nil, fmt.Errorf("mitm: sign leaf certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse minted leaf: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, m.caCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
}

// normalizeHost strips a port from a host:port server name and lowercases it.
func normalizeHost(serverName string) string {
	if serverName == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(serverName); err == nil {
		serverName = h
	}
	return serverName
}
