package pia

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPIACertPoolFailsClosed verifies the package refuses to fall back to
// InsecureSkipVerify: the compile-time CA must parse into the shared pool.
func TestPIACertPoolFailsClosed(t *testing.T) {
	require.NotNil(t, piaCertPool, "PIA CA pool must be built at init")

	cfg := piaTLSConfig()
	assert.False(t, cfg.InsecureSkipVerify, "piaTLSConfig must never disable verification")
	assert.NotNil(t, cfg.RootCAs, "piaTLSConfig must pin the PIA CA pool")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// newCNTLSServer starts an HTTPS server whose certificate is issued for the
// given CN (and 127.0.0.1 SAN so the dial succeeds). It returns the server, its
// listen IP, and a cert pool trusting it.
func newCNTLSServer(t *testing.T, cn string, handler http.Handler) (*httptest.Server, string, *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))

	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	return srv, host, pool
}

// TestRegisterWireGuardKeyVerifiesAgainstCN confirms /addKey verifies the server
// certificate against the WireGuard CN (not the dialed IP) without
// InsecureSkipVerify, dialing the server IP while validating the CN.
func TestRegisterWireGuardKeyVerifiesAgainstCN(t *testing.T) {
	const cn = "pia-wg.example-region.privateinternetaccess.com"

	var gotHost, gotPath, gotPubkey, gotToken string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		require.NoError(t, r.ParseForm())
		gotPubkey = r.Form.Get("pubkey")
		gotToken = r.Form.Get("pt")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WireGuardKeyResponse{
			Status:     "OK",
			ServerKey:  "server-pub",
			ServerIP:   "10.0.0.1",
			ServerPort: 1337,
			ServerVIP:  "10.0.0.2",
			PeerIP:     "10.64.0.5",
			DNSServers: []string{"10.0.0.243"},
		})
	})

	srv, serverIP, pool := newCNTLSServer(t, cn, handler)

	// Build a transport identical in shape to production (CN-pinned ServerName,
	// dial forced to the server IP), but trusting the test CA so we exercise the
	// real verification path without InsecureSkipVerify.
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	target := net.JoinHostPort(serverIP, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: cn,
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, target)
		},
	}

	client := NewClient("user", "pass", WithAddKeyTransport(transport))

	region := &Region{
		ID:   "example-region",
		Name: "Example",
		Servers: RegionServers{
			WireGuard: []WGServer{{IP: serverIP, CN: cn}},
		},
	}

	resp, err := client.registerWireGuardKey(context.Background(), region, "client-pub", "tok-123")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, "10.64.0.5", resp.PeerIP)
	assert.Equal(t, "10.0.0.2", resp.ServerVIP)

	// The request must target the CN host (so TLS verified against it) and the
	// /addKey path, carrying the supplied pubkey/token.
	assert.Contains(t, gotHost, cn)
	assert.Equal(t, AddKeyPath, gotPath)
	assert.Equal(t, "client-pub", gotPubkey)
	assert.Equal(t, "tok-123", gotToken)
}

// TestRegisterWireGuardKeyMissingCNFailsClosed verifies that a region without a
// WireGuard CN is rejected rather than dialing the IP with verification off.
func TestRegisterWireGuardKeyMissingCNFailsClosed(t *testing.T) {
	client := NewClient("user", "pass")
	region := &Region{
		ID: "no-cn",
		Servers: RegionServers{
			WireGuard: []WGServer{{IP: "1.2.3.4"}}, // CN empty
		},
	}

	_, err := client.registerWireGuardKey(context.Background(), region, "pub", "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CN")
}

// TestAddKeyRoundTripperPinsCN verifies the production transport builder pins the
// ServerName to the CN and never disables verification.
func TestAddKeyRoundTripperPinsCN(t *testing.T) {
	client := NewClient("user", "pass")
	rt := client.addKeyRoundTripper("9.9.9.9", "wg.example.com")

	tr, ok := rt.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.TLSClientConfig)
	assert.Equal(t, "wg.example.com", tr.TLSClientConfig.ServerName)
	assert.False(t, tr.TLSClientConfig.InsecureSkipVerify)
	assert.NotNil(t, tr.TLSClientConfig.RootCAs)
	assert.NotNil(t, tr.DialContext)
}
