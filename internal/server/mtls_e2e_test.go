package server

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	_ "github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/mtls"
	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/proxy"
)

// --- certificate test helpers ---

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue creates a leaf certificate signed by the CA. serverCert toggles
// server vs client extended key usage.
func (ca *testCA) issue(t *testing.T, cn string, serverCert bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if serverCert {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	if serverCert {
		tmpl.DNSNames = []string{"127.0.0.1", "localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	return tlsCert
}

// generateCAPEM returns a self-signed CA certificate PEM (used by tls_test.go).
func generateCAPEM(t *testing.T) string {
	t.Helper()
	return string(newTestCA(t).certPEM)
}

// writeServerKeypair writes a server cert+key signed by a throwaway CA into dir
// and returns their paths (used by tls_test.go).
func writeServerKeypair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	ca := newTestCA(t)
	leaf := ca.issue(t, "127.0.0.1", true)

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")

	certOut, err := os.Create(certFile) //nolint:gosec // test temp path
	require.NoError(t, err)
	for _, der := range leaf.Certificate {
		require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	require.NoError(t, certOut.Close())

	keyDER, err := x509.MarshalECPrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	keyOut, err := os.Create(keyFile) //nolint:gosec // test temp path
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyOut.Close())

	return certFile, keyFile
}

// --- end-to-end mTLS proxy test ---

// TestMTLSProxyEndToEnd exercises the full mTLS path: the proxy TLS listener is
// configured with the mTLS auth provider's CA pool and RequireAndVerifyClientCert,
// and the proxy request path authenticates the verified client certificate.
func TestMTLSProxyEndToEnd(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issue(t, "127.0.0.1", true)
	clientCert := ca.issue(t, "alice", false)

	// mTLS authenticator from the auth factory using the same CA.
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "mtls",
		Type:    "mtls",
		Enabled: true,
		Config: map[string]any{
			"ca_cert_pem":         string(ca.certPEM),
			"require_client_cert": true,
		},
	})
	require.NoError(t, err)

	// Listener TLS config sourcing the client CA pool from the mTLS provider.
	mtlsPool, err := mtlsCAPoolFromAuth(config.AuthConfig{
		Providers: []config.AuthProvider{
			{Name: "mtls", Type: "mtls", Enabled: true, Config: map[string]any{"ca_cert_pem": string(ca.certPEM)}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, mtlsPool)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    mtlsPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	// Backend manager with a direct backend the proxy can route to.
	mgr := backend.NewManager()
	direct := backend.NewDirectBackend(backend.DirectConfig{Name: "direct"})
	require.NoError(t, mgr.Add(direct))
	require.NoError(t, direct.Start(context.Background()))

	// A trivial upstream TCP server the proxy will CONNECT to.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstream.Close()
	go func() {
		for {
			c, aerr := upstream.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	handler := proxy.NewHTTPHandler(proxy.HTTPHandlerConfig{
		GetBackend: func(_, _ string) backend.Backend { return direct },
		Authenticate: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return authenticator.Authenticate(ctx, username, password)
		},
		AuthRequired: true,
		DialTimeout:  3 * time.Second,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	tlsLn := tls.NewListener(ln, tlsConf)

	connCh := make(chan net.Conn, 2)
	go func() {
		for {
			c, aerr := tlsLn.Accept()
			if aerr != nil {
				return
			}
			connCh <- c
		}
	}()
	go func() {
		for c := range connCh {
			go handler.ServeConn(context.Background(), c)
		}
	}()

	addr := ln.Addr().String()

	// Case 1: verified client certificate -> CONNECT succeeds.
	t.Run("verified cert authenticated", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      mustPool(t, ca.certPEM),
			ServerName:   "127.0.0.1",
			MinVersion:   tls.VersionTLS12,
		}
		conn, derr := tls.Dial("tcp", addr, clientTLS)
		require.NoError(t, derr)
		defer conn.Close()

		_, werr := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		require.NoError(t, werr)

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		resp, rerr := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		require.NoError(t, rerr)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Case 2: no client certificate -> TLS handshake rejected by the listener.
	t.Run("no cert rejected at handshake", func(t *testing.T) {
		clientTLS := &tls.Config{
			RootCAs:    mustPool(t, ca.certPEM),
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		}
		conn, derr := tls.Dial("tcp", addr, clientTLS)
		if derr == nil {
			// Some stacks defer the alert until first I/O.
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, werr := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"))
			_ = werr
			buf := make([]byte, 1)
			_, rerr := conn.Read(buf)
			conn.Close()
			require.Error(t, rerr, "expected handshake/read failure without client cert")
			return
		}
		require.Error(t, derr)
	})

	// Case 3: certificate from an unknown CA -> handshake rejected.
	t.Run("unknown ca rejected at handshake", func(t *testing.T) {
		otherCA := newTestCA(t)
		badClient := otherCA.issue(t, "mallory", false)
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{badClient},
			RootCAs:      mustPool(t, ca.certPEM),
			ServerName:   "127.0.0.1",
			MinVersion:   tls.VersionTLS12,
		}
		conn, derr := tls.Dial("tcp", addr, clientTLS)
		if derr == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"))
			buf := make([]byte, 1)
			_, rerr := conn.Read(buf)
			conn.Close()
			require.Error(t, rerr, "expected handshake/read failure with unknown CA cert")
			return
		}
		require.Error(t, derr)
	})
}

func mustPool(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes))
	return pool
}
