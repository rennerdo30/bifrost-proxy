package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/mtls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA holds a test CA certificate and key
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// testClientCert holds a test client certificate
type testClientCert struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
}

// createTestCA creates a self-signed CA for testing
func createTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}
}

// createTestCAWithSubject creates a self-signed CA with a specific subject
func createTestCAWithSubject(t *testing.T, subject pkix.Name) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}
}

// createTestClientCert creates a client certificate signed by the CA
func createTestClientCert(t *testing.T, ca *testCA, cn string, ou []string) *testClientCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: ou,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &testClientCert{
		cert:    cert,
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
}

// createTestClientCertWithSubject creates a client certificate with a full subject
func createTestClientCertWithSubject(t *testing.T, ca *testCA, subject pkix.Name) *testClientCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &testClientCert{
		cert:    cert,
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
}

// createTestClientCertWithSANs creates a client certificate with DNS names and email addresses
//
//nolint:unparam // cn is always "testuser" in tests but kept for test readability
func createTestClientCertWithSANs(t *testing.T, ca *testCA, cn string, dnsNames []string, emails []string) *testClientCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:       dnsNames,
		EmailAddresses: emails,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &testClientCert{
		cert:    cert,
		certPEM: certPEM,
		keyPEM:  keyPEM,
	}
}

// createTestClientCertWithUID creates a client certificate with UID in subject
func createTestClientCertWithUID(t *testing.T, ca *testCA, cn string, uid string) *testClientCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// UID OID is 0.9.2342.19200300.100.1.1
	uidOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

	subject := pkix.Name{
		CommonName: cn,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  uidOID,
				Value: uid,
			},
		},
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &testClientCert{
		cert:    cert,
		certPEM: certPEM,
	}
}

// createExpiredClientCert creates an expired client certificate
func createExpiredClientCert(t *testing.T, ca *testCA, cn string) *testClientCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   time.Now().Add(-48 * time.Hour),
		NotAfter:    time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &testClientCert{
		cert:    cert,
		certPEM: certPEM,
	}
}

// createCRL creates a Certificate Revocation List
func createCRL(t *testing.T, ca *testCA, revokedSerials []*big.Int) (pemData []byte, derData []byte) {
	t.Helper()

	var revokedCerts []x509.RevocationListEntry
	for _, serial := range revokedSerials {
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		})
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: revokedCerts,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.key)
	require.NoError(t, err)

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return crlPEM, crlDER
}

// ===================
// Plugin Tests
// ===================

func TestMTLSPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("mtls")
	require.True(t, ok, "mtls plugin not registered")
	assert.Equal(t, "mtls", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

func TestMTLSPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("mtls")
	require.True(t, ok)

	// Create temp CA file for testing
	ca := createTestCA(t)
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{
			name:    "nil config should error",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "missing ca_cert_file should error",
			config:  map[string]any{},
			wantErr: true,
		},
		{
			name: "valid config with ca_cert_file",
			config: map[string]any{
				"ca_cert_file": caFile,
			},
			wantErr: false,
		},
		{
			name: "valid config with ca_cert_pem",
			config: map[string]any{
				"ca_cert_pem": string(ca.certPEM),
			},
			wantErr: false,
		},
		{
			name: "ca_cert_file path validation happens at create time",
			config: map[string]any{
				"ca_cert_file": "/nonexistent/ca.crt",
			},
			wantErr: false, // ValidateConfig only checks config structure, not file existence
		},
		{
			name: "invalid allowed_subjects regex",
			config: map[string]any{
				"ca_cert_file":     caFile,
				"allowed_subjects": []any{"[invalid regex"},
			},
			wantErr: true,
		},
		{
			name: "invalid allowed_issuers regex",
			config: map[string]any{
				"ca_cert_file":    caFile,
				"allowed_issuers": []any{"(unclosed paren"},
			},
			wantErr: true,
		},
		{
			name: "valid allowed_subjects regex",
			config: map[string]any{
				"ca_cert_file":     caFile,
				"allowed_subjects": []any{"CN=.*admin.*", "OU=IT"},
			},
			wantErr: false,
		},
		{
			name: "valid allowed_issuers regex",
			config: map[string]any{
				"ca_cert_file":    caFile,
				"allowed_issuers": []any{"O=Trusted Corp"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMTLSPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("mtls")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, "/etc/bifrost/ca.crt", defaults["ca_cert_file"])
	assert.Equal(t, true, defaults["require_client_cert"])

	// Check nested subject_mapping
	subjectMapping, ok := defaults["subject_mapping"].(map[string]any)
	assert.True(t, ok, "subject_mapping should be a map")
	assert.Equal(t, "CN", subjectMapping["username_field"])
	assert.Equal(t, "OU", subjectMapping["groups_field"])
}

func TestMTLSPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("mtls")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "ca_cert_file")
	assert.Contains(t, schema, "ca_cert_pem")
	assert.Contains(t, schema, "username_field")
	assert.Contains(t, schema, "groups_field")
	assert.Contains(t, schema, "email_field")
	assert.Contains(t, schema, "allowed_subjects")
	assert.Contains(t, schema, "allowed_issuers")
	assert.Contains(t, schema, "crl_file")
	assert.Contains(t, schema, "verify_time")
}

// ===================
// Authenticator Creation Tests
// ===================

func TestMTLSAuthenticator_CreateWithCAFile(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

func TestMTLSAuthenticator_CreateWithCAPEM(t *testing.T) {
	ca := createTestCA(t)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_pem": string(ca.certPEM),
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

func TestMTLSAuthenticator_CreateWithInvalidCAFile(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": "/nonexistent/ca.crt",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA cert file")
}

func TestMTLSAuthenticator_CreateWithInvalidCAPEM(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_pem": "not a valid PEM",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificates")
}

func TestMTLSAuthenticator_CreateWithCRLFile(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", nil)

	crlPEM, _ := createCRL(t, ca, []*big.Int{clientCert.cert.SerialNumber})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	crlFile := filepath.Join(tmpDir, "crl.pem")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(crlFile, crlPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"crl_file":     crlFile,
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

func TestMTLSAuthenticator_CreateWithInvalidCRLFile(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	// CRL file doesn't exist - should still create (with warning)
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"crl_file":     "/nonexistent/crl.pem",
		},
	})
	// CRL loading failure is just a warning, not an error
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

func TestMTLSAuthenticator_CreateWithCRLDERFormat(t *testing.T) {
	ca := createTestCA(t)
	_, crlDER := createCRL(t, ca, []*big.Int{})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	crlFile := filepath.Join(tmpDir, "crl.der")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(crlFile, crlDER, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"crl_file":     crlFile,
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

// ===================
// Authentication Tests
// ===================

func TestMTLSAuthenticator_Success(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", []string{"admin", "users"})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "CN",
				"groups_field":   "OU",
			},
		},
	})
	require.NoError(t, err)

	// Create context with client certificate
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Contains(t, user.Groups, "admin")
	assert.Contains(t, user.Groups, "users")
	assert.Equal(t, "mtls", user.Metadata["auth_type"])
	assert.NotEmpty(t, user.Metadata["cert_subject"])
	assert.NotEmpty(t, user.Metadata["cert_issuer"])
	assert.NotEmpty(t, user.Metadata["cert_serial"])
}

func TestMTLSAuthenticator_NoCertificate(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	// No certificate in context
	_, err = authenticator.Authenticate(context.Background(), "", "")
	assert.Error(t, err)
}

func TestMTLSAuthenticator_NilCertificate(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	// Nil certificate in context
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, (*x509.Certificate)(nil))
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestMTLSAuthenticator_WrongTypeInContext(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	// Wrong type in context
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, "not a certificate")
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestMTLSAuthenticator_ExpiredCertificate(t *testing.T) {
	ca := createTestCA(t)
	expiredCert := createExpiredClientCert(t, ca, "expireduser")

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, expiredCert.cert)

	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestMTLSAuthenticator_ExpiredCertificateWithVerifyTimeDisabled(t *testing.T) {
	ca := createTestCA(t)
	expiredCert := createExpiredClientCert(t, ca, "expireduser")

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"verify_time":  false, // Disable time verification
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, expiredCert.cert)

	// With verify_time=false, expired cert should still fail because
	// x509.VerifyOptions still checks validity by default
	// The verify_time option only sets CurrentTime when true
	_, err = authenticator.Authenticate(ctx, "", "")
	// This will still fail because the certificate chain verification
	// includes validity period checking
	assert.Error(t, err)
}

func TestMTLSAuthenticator_UntrustedCA(t *testing.T) {
	ca1 := createTestCA(t)
	ca2 := createTestCA(t) // Different CA
	clientCert := createTestClientCert(t, ca2, "testuser", nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca1.certPEM, 0644) // Use ca1
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	// Certificate signed by ca2, but authenticator trusts ca1
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestMTLSAuthenticator_OptionalCert(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file":        caFile,
			"require_client_cert": false, // Cert not required
		},
	})
	require.NoError(t, err)

	// No certificate in context - should succeed with anonymous
	user, err := authenticator.Authenticate(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "anonymous", user.Username)
	assert.Equal(t, "none", user.Metadata["cert_auth"])
}

// ===================
// Certificate Revocation Tests
// ===================

func TestMTLSAuthenticator_RevokedCertificate(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "revokeduser", nil)

	crlPEM, _ := createCRL(t, ca, []*big.Int{clientCert.cert.SerialNumber})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	crlFile := filepath.Join(tmpDir, "crl.pem")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(crlFile, crlPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"crl_file":     crlFile,
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestMTLSAuthenticator_RevocationManagement(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authIface, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	// Cast to *mtls.Authenticator to access revocation methods
	authenticator, ok := authIface.(*mtls.Authenticator)
	require.True(t, ok)

	serial := clientCert.cert.SerialNumber.String()

	// Initially not revoked
	assert.False(t, authenticator.IsRevoked(serial))

	// Add to revocation list
	authenticator.AddRevoked(serial)
	assert.True(t, authenticator.IsRevoked(serial))

	// Try to authenticate - should fail
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	// Remove from revocation list
	authenticator.RemoveRevoked(serial)
	assert.False(t, authenticator.IsRevoked(serial))

	// Should authenticate successfully now
	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestMTLSAuthenticator_ReloadCRL(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", nil)

	// Create initial empty CRL
	crlPEM, _ := createCRL(t, ca, []*big.Int{})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	crlFile := filepath.Join(tmpDir, "crl.pem")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(crlFile, crlPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authIface, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"crl_file":     crlFile,
		},
	})
	require.NoError(t, err)

	authenticator, ok := authIface.(*mtls.Authenticator)
	require.True(t, ok)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	// Should authenticate successfully
	_, err = authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)

	// Update CRL to revoke the certificate
	newCRLPEM, _ := createCRL(t, ca, []*big.Int{clientCert.cert.SerialNumber})
	err = os.WriteFile(crlFile, newCRLPEM, 0644)
	require.NoError(t, err)

	// Reload CRL
	err = authenticator.ReloadCRL()
	require.NoError(t, err)

	// Should now fail
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestMTLSAuthenticator_ReloadCRL_NoCRLConfigured(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authIface, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			// No CRL file configured
		},
	})
	require.NoError(t, err)

	authenticator, ok := authIface.(*mtls.Authenticator)
	require.True(t, ok)

	// ReloadCRL should return nil when no CRL is configured
	err = authenticator.ReloadCRL()
	assert.NoError(t, err)
}

// ===================
// Allowed Subjects/Issuers Tests
// ===================

func TestMTLSAuthenticator_AllowedSubjects(t *testing.T) {
	ca := createTestCA(t)
	allowedCert := createTestClientCert(t, ca, "admin-user", []string{"IT"})
	deniedCert := createTestClientCert(t, ca, "regular-user", []string{"Sales"})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file":     caFile,
			"allowed_subjects": []any{"CN=admin-.*"},
		},
	})
	require.NoError(t, err)

	// Allowed subject
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, allowedCert.cert)
	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "admin-user", user.Username)

	// Denied subject
	ctx = context.WithValue(context.Background(), mtls.ClientCertContextKey, deniedCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subject not allowed")
}

func TestMTLSAuthenticator_MultipleAllowedSubjects(t *testing.T) {
	ca := createTestCA(t)
	adminCert := createTestClientCert(t, ca, "admin-user", nil)
	serviceCert := createTestClientCert(t, ca, "service-account", nil)
	deniedCert := createTestClientCert(t, ca, "regular-user", nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file":     caFile,
			"allowed_subjects": []any{"CN=admin-.*", "CN=service-.*"},
		},
	})
	require.NoError(t, err)

	// First pattern match
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, adminCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)

	// Second pattern match
	ctx = context.WithValue(context.Background(), mtls.ClientCertContextKey, serviceCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)

	// No pattern match
	ctx = context.WithValue(context.Background(), mtls.ClientCertContextKey, deniedCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestMTLSAuthenticator_AllowedIssuers(t *testing.T) {
	trustedCA := createTestCAWithSubject(t, pkix.Name{
		CommonName:   "Trusted CA",
		Organization: []string{"Trusted Corp"},
	})
	untrustedCA := createTestCAWithSubject(t, pkix.Name{
		CommonName:   "Untrusted CA",
		Organization: []string{"Untrusted Corp"},
	})

	trustedCert := createTestClientCert(t, trustedCA, "user1", nil)
	untrustedCert := createTestClientCert(t, untrustedCA, "user2", nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	// Write both CA certs to the same file
	bothCerts := append(trustedCA.certPEM, untrustedCA.certPEM...)
	err := os.WriteFile(caFile, bothCerts, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file":    caFile,
			"allowed_issuers": []any{"O=Trusted Corp"},
		},
	})
	require.NoError(t, err)

	// Allowed issuer
	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, trustedCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)

	// Denied issuer
	ctx = context.WithValue(context.Background(), mtls.ClientCertContextKey, untrustedCert.cert)
	_, err = authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer not allowed")
}

// ===================
// Subject Mapping Tests
// ===================

func TestMTLSAuthenticator_UsernameFromEmail(t *testing.T) {
	ca := createTestCA(t)

	// Create client cert with email in SAN
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "testuser",
		},
		EmailAddresses: []string{"user@example.com"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	clientCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err = os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "emailAddress",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", user.Username)
}

func TestMTLSAuthenticator_UsernameFromOrganization(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName:   "testuser",
		Organization: []string{"MyOrg"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "O",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "MyOrg", user.Username)
}

func TestMTLSAuthenticator_UsernameFromLocality(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName: "testuser",
		Locality:   []string{"New York"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "L",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "New York", user.Username)
}

func TestMTLSAuthenticator_UsernameFromCountry(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName: "testuser",
		Country:    []string{"US"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "C",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "US", user.Username)
}

func TestMTLSAuthenticator_UsernameFromState(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName: "testuser",
		Province:   []string{"California"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "ST",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "California", user.Username)
}

func TestMTLSAuthenticator_UsernameFromSerialNumber(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName:   "testuser",
		SerialNumber: "12345",
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "SERIALNUMBER",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "12345", user.Username)
}

func TestMTLSAuthenticator_UsernameFromUID(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithUID(t, ca, "testuser", "uid123")

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "UID",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "uid123", user.Username)
}

func TestMTLSAuthenticator_UsernameFromSAN(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSANs(t, ca, "testuser", []string{"host.example.com"}, nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "SAN",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "host.example.com", user.Username)
}

func TestMTLSAuthenticator_SANFallsBackToEmail(t *testing.T) {
	ca := createTestCA(t)
	// No DNS names, only email
	clientCert := createTestClientCertWithSANs(t, ca, "testuser", nil, []string{"user@example.com"})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "SAN",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", user.Username)
}

func TestMTLSAuthenticator_GroupsFromOrganization(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName:   "testuser",
		Organization: []string{"Org1", "Org2"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"groups_field": "O",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "Org1")
	assert.Contains(t, user.Groups, "Org2")
}

func TestMTLSAuthenticator_GroupsFromSAN(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSANs(t, ca, "testuser",
		[]string{"dns1.example.com", "dns2.example.com"},
		[]string{"user@example.com"})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"groups_field": "SAN",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "dns1.example.com")
	assert.Contains(t, user.Groups, "dns2.example.com")
	assert.Contains(t, user.Groups, "user@example.com")
}

func TestMTLSAuthenticator_GroupsFromSingleValueField(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName: "testuser",
		Country:    []string{"US"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"groups_field": "C",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Contains(t, user.Groups, "US")
}

func TestMTLSAuthenticator_FullNameExtraction(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName:   "John Doe",
		SerialNumber: "12345",
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "SERIALNUMBER", // Not CN
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "12345", user.Username)
	assert.Equal(t, "John Doe", user.FullName) // CN should be used as FullName
}

func TestMTLSAuthenticator_EmptyFieldReturnsEmpty(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", nil) // No OU

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "CN",
				"groups_field":   "OU",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Empty(t, user.Groups) // No groups because no OU
}

func TestMTLSAuthenticator_UnknownFieldReturnsEmpty(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "UNKNOWNFIELD",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Empty(t, user.Username) // Unknown field returns empty
}

// ===================
// Direct Authentication Tests
// ===================

func TestMTLSAuthenticator_AuthenticateCertificate(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "directuser", []string{"group1"})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authIface, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	authenticator, ok := authIface.(*mtls.Authenticator)
	require.True(t, ok)

	// Use AuthenticateCertificate directly
	user, err := authenticator.AuthenticateCertificate(clientCert.cert)
	require.NoError(t, err)
	assert.Equal(t, "directuser", user.Username)
	assert.Contains(t, user.Groups, "group1")
}

// ===================
// Helper Methods Tests
// ===================

func TestMTLSAuthenticator_NameAndType(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "mtls", authenticator.Name())
	assert.Equal(t, "mtls", authenticator.Type())
}

func TestMTLSAuthenticator_GetCAPool(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authIface, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	authenticator, ok := authIface.(*mtls.Authenticator)
	require.True(t, ok)

	caPool := authenticator.GetCAPool()
	assert.NotNil(t, caPool)
}

// ===================
// Edge Cases and Error Handling
// ===================

func TestMTLSAuthenticator_CRLParseError(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	crlFile := filepath.Join(tmpDir, "crl.pem")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)
	// Write invalid CRL data
	err = os.WriteFile(crlFile, []byte("not a valid CRL"), 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	// Should still create (CRL error is just a warning)
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"crl_file":     crlFile,
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

func TestMTLSAuthenticator_CaseSensitiveFieldMapping(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName:   "testuser",
		Organization: []string{"MyOrg"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	// Test various case combinations
	testCases := []struct {
		field    string
		expected string
	}{
		{"cn", "testuser"},
		{"CN", "testuser"},
		{"Cn", "testuser"},
		{"commonname", "testuser"},
		{"COMMONNAME", "testuser"},
		{"CommonName", "testuser"},
		{"o", "MyOrg"},
		{"O", "MyOrg"},
		{"organization", "MyOrg"},
		{"ORGANIZATION", "MyOrg"},
	}

	for _, tc := range testCases {
		t.Run("field_"+tc.field, func(t *testing.T) {
			factory := auth.NewFactory()
			authenticator, err := factory.Create(auth.ProviderConfig{
				Name:    "mtls-test",
				Type:    "mtls",
				Enabled: true,
				Config: map[string]any{
					"ca_cert_file": caFile,
					"subject_mapping": map[string]any{
						"username_field": tc.field,
					},
				},
			})
			require.NoError(t, err)

			ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)
			user, err := authenticator.Authenticate(ctx, "", "")
			require.NoError(t, err)
			assert.Equal(t, tc.expected, user.Username)
		})
	}
}

func TestMTLSAuthenticator_FieldAliases(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSubject(t, ca, pkix.Name{
		CommonName: "testuser",
		Province:   []string{"California"},
		Locality:   []string{"San Francisco"},
	})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	testCases := []struct {
		field    string
		expected string
	}{
		{"ST", "California"},
		{"STATE", "California"},
		{"PROVINCE", "California"},
		{"L", "San Francisco"},
		{"LOCALITY", "San Francisco"},
	}

	for _, tc := range testCases {
		t.Run("field_"+tc.field, func(t *testing.T) {
			factory := auth.NewFactory()
			authenticator, err := factory.Create(auth.ProviderConfig{
				Name:    "mtls-test",
				Type:    "mtls",
				Enabled: true,
				Config: map[string]any{
					"ca_cert_file": caFile,
					"subject_mapping": map[string]any{
						"username_field": tc.field,
					},
				},
			})
			require.NoError(t, err)

			ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)
			user, err := authenticator.Authenticate(ctx, "", "")
			require.NoError(t, err)
			assert.Equal(t, tc.expected, user.Username)
		})
	}
}

func TestMTLSAuthenticator_EmptyOrganizationalUnit(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCert(t, ca, "testuser", nil) // No OU

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"username_field": "OU",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Empty(t, user.Username) // Empty because no OU
}

func TestMTLSAuthenticator_EmailFromSAN(t *testing.T) {
	ca := createTestCA(t)
	clientCert := createTestClientCertWithSANs(t, ca, "testuser", nil, []string{"user@example.com"})

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"email_field": "EMAIL",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", user.Email)
}

func TestMTLSAuthenticator_GroupsFromEmptyField(t *testing.T) {
	ca := createTestCA(t)
	// Cert with no SANs
	clientCert := createTestClientCert(t, ca, "testuser", nil)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
			"subject_mapping": map[string]any{
				"groups_field": "SAN",
			},
		},
	})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), mtls.ClientCertContextKey, clientCert.cert)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Empty(t, user.Groups)
}

func TestMTLSAuthenticator_ConcurrentRevocationAccess(t *testing.T) {
	ca := createTestCA(t)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	err := os.WriteFile(caFile, ca.certPEM, 0644)
	require.NoError(t, err)

	factory := auth.NewFactory()
	authIface, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls-test",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_file": caFile,
		},
	})
	require.NoError(t, err)

	authenticator, ok := authIface.(*mtls.Authenticator)
	require.True(t, ok)

	// Test concurrent access to revocation list
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			serial := "12345"
			authenticator.AddRevoked(serial)
			_ = authenticator.IsRevoked(serial)
			authenticator.RemoveRevoked(serial)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
