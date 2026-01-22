// Package mtls provides mutual TLS (client certificate) authentication for Bifrost.
// It supports X.509 client certificates, including smart cards and PIV tokens.
package mtls

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// ContextKey is a type for context keys used by this package.
type ContextKey string

const (
	// ClientCertContextKey is the context key for the client certificate.
	ClientCertContextKey ContextKey = "mtls_client_cert"
)

func init() {
	auth.RegisterPlugin("mtls", &plugin{})
}

// plugin implements the auth.Plugin interface for mTLS authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "mtls"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "Mutual TLS client certificate authentication (X.509, smart cards, PIV)"
}

// Create creates a new mTLS authenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		config:         cfg,
		revokedSerials: make(map[string]bool),
	}

	// Load CA certificates
	if err := authenticator.loadCACerts(); err != nil {
		return nil, err
	}

	// Load CRL if specified
	if cfg.CRLFile != "" {
		if err := authenticator.loadCRL(); err != nil {
			slog.Warn("failed to load CRL", "file", cfg.CRLFile, "error", err)
		}
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"ca_cert_file":        "/etc/bifrost/ca.crt",
		"require_client_cert": true,
		"subject_mapping": map[string]any{
			"username_field": "CN",
			"groups_field":   "OU",
		},
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "ca_cert_file": {
      "type": "string",
      "description": "Path to CA certificate file (PEM format)"
    },
    "ca_cert_pem": {
      "type": "string",
      "description": "CA certificate in PEM format (inline)"
    },
    "require_client_cert": {
      "type": "boolean",
      "description": "Whether client certificate is required",
      "default": true
    },
    "subject_mapping": {
      "type": "object",
      "description": "Mapping from certificate fields to user info",
      "properties": {
        "username_field": {
          "type": "string",
          "description": "Certificate field for username (CN, emailAddress, UID)",
          "default": "CN"
        },
        "groups_field": {
          "type": "string",
          "description": "Certificate field for groups (OU)",
          "default": "OU"
        },
        "email_field": {
          "type": "string",
          "description": "Certificate field for email (emailAddress, SAN)",
          "default": "emailAddress"
        }
      }
    },
    "allowed_subjects": {
      "type": "array",
      "description": "List of allowed subject patterns (regex)",
      "items": {"type": "string"}
    },
    "allowed_issuers": {
      "type": "array",
      "description": "List of allowed issuer patterns (regex)",
      "items": {"type": "string"}
    },
    "crl_file": {
      "type": "string",
      "description": "Path to Certificate Revocation List (PEM or DER)"
    },
    "verify_time": {
      "type": "boolean",
      "description": "Verify certificate validity period",
      "default": true
    }
  }
}`
}

// mtlsConfig represents the parsed configuration.
type mtlsConfig struct {
	CACertFile        string
	CACertPEM         string
	RequireClientCert bool
	SubjectMapping    subjectMapping
	AllowedSubjects   []*regexp.Regexp
	AllowedIssuers    []*regexp.Regexp
	CRLFile           string
	VerifyTime        bool
}

// subjectMapping defines how to extract user info from certificate fields.
type subjectMapping struct {
	UsernameField string
	GroupsField   string
	EmailField    string
}

// parseConfig parses the configuration map.
func parseConfig(config map[string]any) (*mtlsConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("mtls auth config is required")
	}

	cfg := &mtlsConfig{
		RequireClientCert: true,
		VerifyTime:        true,
		SubjectMapping: subjectMapping{
			UsernameField: "CN",
			GroupsField:   "OU",
			EmailField:    "emailAddress",
		},
	}

	if caCertFile, ok := config["ca_cert_file"].(string); ok {
		cfg.CACertFile = caCertFile
	}

	if caCertPEM, ok := config["ca_cert_pem"].(string); ok {
		cfg.CACertPEM = caCertPEM
	}

	if cfg.CACertFile == "" && cfg.CACertPEM == "" {
		return nil, fmt.Errorf("mtls config: either 'ca_cert_file' or 'ca_cert_pem' is required")
	}

	if requireClientCert, ok := config["require_client_cert"].(bool); ok {
		cfg.RequireClientCert = requireClientCert
	}

	if verifyTime, ok := config["verify_time"].(bool); ok {
		cfg.VerifyTime = verifyTime
	}

	if crlFile, ok := config["crl_file"].(string); ok {
		cfg.CRLFile = crlFile
	}

	// Parse subject mapping
	if sm, ok := config["subject_mapping"].(map[string]any); ok {
		if uf, ok := sm["username_field"].(string); ok && uf != "" {
			cfg.SubjectMapping.UsernameField = uf
		}
		if gf, ok := sm["groups_field"].(string); ok && gf != "" {
			cfg.SubjectMapping.GroupsField = gf
		}
		if ef, ok := sm["email_field"].(string); ok && ef != "" {
			cfg.SubjectMapping.EmailField = ef
		}
	}

	// Parse allowed subjects
	if subjects, ok := config["allowed_subjects"].([]any); ok {
		for _, s := range subjects {
			if pattern, ok := s.(string); ok {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("mtls config: invalid allowed_subjects pattern %q: %w", pattern, err)
				}
				cfg.AllowedSubjects = append(cfg.AllowedSubjects, re)
			}
		}
	}

	// Parse allowed issuers
	if issuers, ok := config["allowed_issuers"].([]any); ok {
		for _, i := range issuers {
			if pattern, ok := i.(string); ok {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("mtls config: invalid allowed_issuers pattern %q: %w", pattern, err)
				}
				cfg.AllowedIssuers = append(cfg.AllowedIssuers, re)
			}
		}
	}

	return cfg, nil
}

// Authenticator provides mTLS client certificate authentication.
type Authenticator struct {
	config         *mtlsConfig
	caPool         *x509.CertPool
	revokedSerials map[string]bool
	mu             sync.RWMutex
}

// Authenticate validates a client certificate.
// This method expects the certificate to be passed via context (set by TLS middleware).
// The username and password parameters are ignored for mTLS auth.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	// Get certificate from context
	cert, ok := ctx.Value(ClientCertContextKey).(*x509.Certificate)
	if !ok || cert == nil {
		if a.config.RequireClientCert {
			return nil, auth.NewAuthError("mtls", "authenticate", auth.ErrAuthRequired)
		}
		// No cert but not required - allow anonymous
		return &auth.UserInfo{
			Username: "anonymous",
			Metadata: map[string]string{
				"auth_type": "mtls",
				"cert_auth": "none",
			},
		}, nil
	}

	// Validate the certificate
	return a.validateCertificate(cert)
}

// AuthenticateCertificate validates a client certificate directly.
func (a *Authenticator) AuthenticateCertificate(cert *x509.Certificate) (*auth.UserInfo, error) {
	return a.validateCertificate(cert)
}

// validateCertificate validates a client certificate and extracts user info.
func (a *Authenticator) validateCertificate(cert *x509.Certificate) (*auth.UserInfo, error) {
	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots: a.caPool,
		// Verify for client authentication, not server authentication
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if a.config.VerifyTime {
		opts.CurrentTime = time.Now()
	}

	if _, err := cert.Verify(opts); err != nil {
		return nil, auth.NewAuthError("mtls", "verify", fmt.Errorf("certificate verification failed: %w", err))
	}

	// Check revocation
	a.mu.RLock()
	revoked := a.revokedSerials[cert.SerialNumber.String()]
	a.mu.RUnlock()

	if revoked {
		return nil, auth.NewAuthError("mtls", "revocation", fmt.Errorf("certificate has been revoked"))
	}

	// Check allowed subjects
	if len(a.config.AllowedSubjects) > 0 {
		subjectDN := cert.Subject.String()
		allowed := false
		for _, re := range a.config.AllowedSubjects {
			if re.MatchString(subjectDN) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, auth.NewAuthError("mtls", "policy", fmt.Errorf("subject not allowed: %s", subjectDN))
		}
	}

	// Check allowed issuers
	if len(a.config.AllowedIssuers) > 0 {
		issuerDN := cert.Issuer.String()
		allowed := false
		for _, re := range a.config.AllowedIssuers {
			if re.MatchString(issuerDN) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, auth.NewAuthError("mtls", "policy", fmt.Errorf("issuer not allowed: %s", issuerDN))
		}
	}

	// Extract user info from certificate
	userInfo := a.extractUserInfo(cert)

	slog.Debug("mTLS authentication successful",
		"username", userInfo.Username,
		"subject", cert.Subject.String(),
		"issuer", cert.Issuer.String(),
		"serial", cert.SerialNumber.String(),
	)

	return userInfo, nil
}

// extractUserInfo extracts user information from a certificate.
func (a *Authenticator) extractUserInfo(cert *x509.Certificate) *auth.UserInfo {
	userInfo := &auth.UserInfo{
		Metadata: map[string]string{
			"auth_type":    "mtls",
			"cert_subject": cert.Subject.String(),
			"cert_issuer":  cert.Issuer.String(),
			"cert_serial":  cert.SerialNumber.String(),
		},
	}

	// Extract username
	userInfo.Username = a.extractField(cert.Subject, a.config.SubjectMapping.UsernameField, cert)

	// Extract groups
	groupValues := a.extractFieldMulti(cert.Subject, a.config.SubjectMapping.GroupsField, cert)
	userInfo.Groups = groupValues

	// Extract email
	userInfo.Email = a.extractField(cert.Subject, a.config.SubjectMapping.EmailField, cert)

	// Extract full name from CN if username is not CN
	if a.config.SubjectMapping.UsernameField != "CN" && cert.Subject.CommonName != "" {
		userInfo.FullName = cert.Subject.CommonName
	}

	return userInfo
}

// extractField extracts a single value from a certificate field.
func (a *Authenticator) extractField(subject pkix.Name, field string, cert *x509.Certificate) string {
	switch strings.ToUpper(field) {
	case "CN", "COMMONNAME":
		return subject.CommonName
	case "O", "ORGANIZATION":
		if len(subject.Organization) > 0 {
			return subject.Organization[0]
		}
	case "OU", "ORGANIZATIONALUNIT":
		if len(subject.OrganizationalUnit) > 0 {
			return subject.OrganizationalUnit[0]
		}
	case "L", "LOCALITY":
		if len(subject.Locality) > 0 {
			return subject.Locality[0]
		}
	case "C", "COUNTRY":
		if len(subject.Country) > 0 {
			return subject.Country[0]
		}
	case "ST", "STATE", "PROVINCE":
		if len(subject.Province) > 0 {
			return subject.Province[0]
		}
	case "SERIALNUMBER":
		return subject.SerialNumber
	case "EMAILADDRESS", "EMAIL":
		// Check SAN email addresses
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0]
		}
	case "UID", "USERID":
		// UID is not standard in pkix.Name, check ExtraNames
		for _, attr := range subject.Names {
			// UID OID is 0.9.2342.19200300.100.1.1
			if attr.Type.String() == "0.9.2342.19200300.100.1.1" {
				if s, ok := attr.Value.(string); ok {
					return s
				}
			}
		}
	case "SAN", "SUBJECTALTNAME":
		// Return first SAN (DNS or email)
		if len(cert.DNSNames) > 0 {
			return cert.DNSNames[0]
		}
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0]
		}
	}

	return ""
}

// extractFieldMulti extracts multiple values from a certificate field (for groups).
func (a *Authenticator) extractFieldMulti(subject pkix.Name, field string, cert *x509.Certificate) []string {
	switch strings.ToUpper(field) {
	case "OU", "ORGANIZATIONALUNIT":
		return subject.OrganizationalUnit
	case "O", "ORGANIZATION":
		return subject.Organization
	case "SAN", "SUBJECTALTNAME":
		// Return all SANs
		result := make([]string, 0, len(cert.DNSNames)+len(cert.EmailAddresses))
		result = append(result, cert.DNSNames...)
		result = append(result, cert.EmailAddresses...)
		return result
	}

	// For single-value fields, return as slice
	if val := a.extractField(subject, field, cert); val != "" {
		return []string{val}
	}

	return nil
}

// loadCACerts loads CA certificates for verification.
func (a *Authenticator) loadCACerts() error {
	a.caPool = x509.NewCertPool()

	var pemData []byte

	if a.config.CACertPEM != "" {
		pemData = []byte(a.config.CACertPEM)
	} else {
		var err error
		pemData, err = os.ReadFile(a.config.CACertFile)
		if err != nil {
			return fmt.Errorf("failed to read CA cert file: %w", err)
		}
	}

	if !a.caPool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("failed to parse CA certificates")
	}

	return nil
}

// loadCRL loads a Certificate Revocation List.
func (a *Authenticator) loadCRL() error {
	data, err := os.ReadFile(a.config.CRLFile)
	if err != nil {
		return err
	}

	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, entry := range crl.RevokedCertificateEntries {
		a.revokedSerials[entry.SerialNumber.String()] = true
	}

	slog.Debug("CRL loaded", "revoked_count", len(crl.RevokedCertificateEntries))
	return nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "mtls"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "mtls"
}

// GetCAPool returns the CA certificate pool for TLS configuration.
func (a *Authenticator) GetCAPool() *x509.CertPool {
	return a.caPool
}

// IsRevoked checks if a certificate serial is revoked.
func (a *Authenticator) IsRevoked(serial string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.revokedSerials[serial]
}

// AddRevoked adds a certificate serial to the revocation list.
func (a *Authenticator) AddRevoked(serial string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revokedSerials[serial] = true
}

// RemoveRevoked removes a certificate serial from the revocation list.
func (a *Authenticator) RemoveRevoked(serial string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.revokedSerials, serial)
}

// ReloadCRL reloads the CRL from the configured file.
func (a *Authenticator) ReloadCRL() error {
	if a.config.CRLFile == "" {
		return nil
	}
	return a.loadCRL()
}
