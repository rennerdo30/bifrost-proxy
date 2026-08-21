package vpnprovider

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Validation of OpenVPN crypto material (CA certificate, tls-auth static key).
//
// Providers must never emit an .ovpn profile containing material that OpenVPN
// will reject, and must never fall back to disabling server verification. A
// bare `pem.Decode` is not enough: a PEM block whose body is valid base64 but
// not valid DER decodes fine and only blows up inside the OpenVPN subprocess
// with an opaque "cannot load CA certificate" error. Every provider therefore
// runs the operator-supplied material through the checks below *before* a
// profile is generated (and, where possible, at config-load time), so a
// misconfiguration surfaces as an actionable error instead of a failed tunnel.
//
// The same rules guard compile-time embedded CA material (see
// MustParseEmbeddedCACertPool), which makes a malformed embedded certificate a
// build-time/test-time failure rather than a runtime surprise.

// PEM block types accepted in a CA certificate bundle.
const (
	// pemTypeCertificate is the only PEM block type allowed in a CA bundle.
	pemTypeCertificate = "CERTIFICATE"
)

// OpenVPN tls-auth static key format (see OpenVPN's --secret / --tls-auth).
const (
	// TLSAuthKeyHeader opens an OpenVPN static key block.
	TLSAuthKeyHeader = "-----BEGIN OpenVPN Static key V1-----"
	// TLSAuthKeyFooter closes an OpenVPN static key block.
	TLSAuthKeyFooter = "-----END OpenVPN Static key V1-----"
	// TLSAuthKeySize is the size in bytes of an OpenVPN static key (2048 bits).
	TLSAuthKeySize = 256
	// TLSAuthKeyHexCharsPerLine is the canonical hex line width inside the block.
	TLSAuthKeyHexCharsPerLine = 32
	// TLSAuthKeyMinDistinctLines is the minimum number of distinct hex lines a
	// genuine random key has. Placeholder/fabricated keys are typically a single
	// repeated line, which this rejects.
	TLSAuthKeyMinDistinctLines = 2
)

// Errors returned by the OpenVPN material validators. They are wrapped in
// ErrConfigGenerationFailed by callers so provider code can keep using
// errors.Is(err, ErrConfigGenerationFailed).
var (
	// ErrCACertMissing indicates no CA certificate was supplied.
	ErrCACertMissing = errors.New("CA certificate is empty")

	// ErrCACertNotPEM indicates the CA certificate is not PEM-encoded.
	ErrCACertNotPEM = errors.New("CA certificate is not valid PEM")

	// ErrCACertWrongPEMType indicates a PEM block other than CERTIFICATE was
	// found (a private key pasted into ca_cert, a CSR, ...).
	ErrCACertWrongPEMType = errors.New("CA certificate bundle contains a non-certificate PEM block")

	// ErrCACertMalformed indicates the DER inside the PEM block is not a
	// parseable X.509 certificate. This is the failure mode that previously
	// shipped as embedded provider material.
	ErrCACertMalformed = errors.New("CA certificate is not a parseable X.509 certificate")

	// ErrCACertNotCA indicates the certificate is not a CA certificate.
	ErrCACertNotCA = errors.New("certificate is not a CA certificate (basic constraints CA:FALSE)")

	// ErrCACertBadSelfSignature indicates a self-issued certificate whose
	// signature does not verify against its own public key. Such a certificate
	// still parses, so this check is what distinguishes genuine CA material from
	// bytes that merely look like a certificate.
	ErrCACertBadSelfSignature = errors.New("self-issued CA certificate has an invalid signature")

	// ErrCACertExpired indicates the CA certificate validity window has passed.
	ErrCACertExpired = errors.New("CA certificate has expired")

	// ErrCACertNotYetValid indicates the CA certificate is not valid yet.
	ErrCACertNotYetValid = errors.New("CA certificate is not valid yet")

	// ErrTLSAuthKeyMalformed indicates the tls-auth static key is not a
	// well-formed OpenVPN static key block.
	ErrTLSAuthKeyMalformed = errors.New("tls-auth key is not a valid OpenVPN static key block")

	// ErrTLSAuthKeyPlaceholder indicates the tls-auth key looks fabricated
	// (all-zero or a single repeated line) rather than random key material.
	ErrTLSAuthKeyPlaceholder = errors.New("tls-auth key looks like placeholder material, not random key bytes")
)

// ValidateCACertPEM checks the structure of a PEM CA bundle: it must contain at
// least one CERTIFICATE block, every block must parse as X.509, and the first
// certificate must be a CA. It deliberately does not look at the clock so it can
// also guard compile-time embedded material, where a time-dependent panic would
// be worse than useless. Use ValidateCACertPEMAt for operator-supplied material.
func ValidateCACertPEM(caCertPEM string) error {
	_, err := ParseCACertPEM(caCertPEM)
	return err
}

// ValidateCACertPEMAt runs ValidateCACertPEM and additionally rejects a bundle
// whose leading certificate is expired or not yet valid at now. OpenVPN would
// reject such a CA during the TLS handshake, so failing here turns a mid-connect
// error into a config-time one.
func ValidateCACertPEMAt(caCertPEM string, now time.Time) error {
	certs, err := ParseCACertPEM(caCertPEM)
	if err != nil {
		return err
	}

	ca := certs[0]
	if now.After(ca.NotAfter) {
		return fmt.Errorf("%w (expired %s)", ErrCACertExpired, ca.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(ca.NotBefore) {
		return fmt.Errorf("%w (valid from %s)", ErrCACertNotYetValid, ca.NotBefore.UTC().Format(time.RFC3339))
	}

	return nil
}

// ParseCACertPEM parses a PEM CA bundle and returns the certificates it
// contains, in file order. It returns an error unless every PEM block is a
// CERTIFICATE that parses as X.509, every self-issued certificate carries a
// signature that verifies under its own public key, and the first certificate
// is a CA.
func ParseCACertPEM(caCertPEM string) ([]*x509.Certificate, error) {
	trimmed := strings.TrimSpace(caCertPEM)
	if trimmed == "" {
		return nil, ErrCACertMissing
	}

	var certs []*x509.Certificate
	rest := []byte(trimmed)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			return nil, fmt.Errorf("%w: %q", ErrCACertWrongPEMType, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCACertMalformed, err)
		}
		// A self-issued certificate carries its own proof of integrity: its
		// signature must verify under its own public key. Checking it catches
		// material that parses but has been truncated, spliced or invented —
		// which OpenSSL/OpenVPN would only reject deep inside the handshake.
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			// CheckSignature (rather than CheckSignatureFrom) verifies the
			// signature bytes alone, so a self-issued leaf still reports the
			// more useful "not a CA" error below.
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				return nil, fmt.Errorf("%w: subject %q: %w", ErrCACertBadSelfSignature, cert.Subject.String(), err)
			}
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrCACertNotPEM
	}
	if !certs[0].IsCA {
		return nil, fmt.Errorf("%w: subject %q", ErrCACertNotCA, certs[0].Subject.String())
	}

	return certs, nil
}

// ValidateTLSAuthKey checks that key is a well-formed OpenVPN static key block
// carrying TLSAuthKeySize bytes of key material, and that the material does not
// look fabricated. An empty key is valid: tls-auth is optional and callers omit
// the directive entirely when no key is configured.
func ValidateTLSAuthKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return nil
	}

	body, ok := staticKeyBody(trimmed)
	if !ok {
		return fmt.Errorf("%w: expected %q ... %q", ErrTLSAuthKeyMalformed, TLSAuthKeyHeader, TLSAuthKeyFooter)
	}

	lines := make([]string, 0, TLSAuthKeySize*2/TLSAuthKeyHexCharsPerLine)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}

	material, err := hex.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return fmt.Errorf("%w: key material is not hex: %w", ErrTLSAuthKeyMalformed, err)
	}
	if len(material) != TLSAuthKeySize {
		return fmt.Errorf("%w: expected %d bytes of key material, got %d",
			ErrTLSAuthKeyMalformed, TLSAuthKeySize, len(material))
	}

	distinct := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		distinct[strings.ToLower(line)] = struct{}{}
	}
	if len(distinct) < TLSAuthKeyMinDistinctLines || isAllZero(material) {
		return ErrTLSAuthKeyPlaceholder
	}

	return nil
}

// staticKeyBody extracts the text between the OpenVPN static key header and
// footer, reporting whether both delimiters were present and in order.
func staticKeyBody(key string) (string, bool) {
	start := strings.Index(key, TLSAuthKeyHeader)
	if start < 0 {
		return "", false
	}
	start += len(TLSAuthKeyHeader)

	end := strings.Index(key[start:], TLSAuthKeyFooter)
	if end < 0 {
		return "", false
	}

	return key[start : start+end], true
}

// isAllZero reports whether every byte of b is zero.
func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// MustParseEmbeddedCACertPool builds an x509 pool from CA material embedded in
// the binary at compile time, panicking if that material is malformed.
//
// This is intentionally fail-closed and intentionally loud: because the input is
// a compile-time constant, a failure can only be a source/build regression (the
// class of bug that shipped an unparseable provider CA), never a runtime
// condition. Panicking at package init keeps TLS verification from silently
// degrading to InsecureSkipVerify. Validity dates are NOT checked here — a
// certificate expiring would otherwise stop the whole binary from loading; the
// expiry check belongs at use time (see ValidateCACertPEMAt).
func MustParseEmbeddedCACertPool(provider, caCertPEM string) *x509.CertPool {
	certs, err := ParseCACertPEM(caCertPEM)
	if err != nil {
		panic(fmt.Sprintf("%s: embedded CA certificate is unusable (%v); refusing to start to avoid fail-open TLS", provider, err))
	}

	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
