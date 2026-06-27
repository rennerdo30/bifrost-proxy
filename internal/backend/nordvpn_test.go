package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

func nordTestCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test NordVPN CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestNordVPNBackend_OpenVPNDelegate_RequiresCA verifies that building an
// OpenVPN delegate fails closed when no CA certificate is configured and
// succeeds (config generation) when a valid CA is supplied.
func TestNordVPNBackend_OpenVPNDelegate_RequiresCA(t *testing.T) {
	server := &vpnprovider.Server{
		Hostname:    "de123.nordvpn.com",
		CountryCode: "DE",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de123.nordvpn.com",
			UDPPort:  1194,
		},
	}

	// Without CA: fail closed.
	bNoCA := NewNordVPNBackend(NordVPNConfig{
		Name:     "nord-ovpn",
		Protocol: "openvpn",
		Username: "u",
		Password: "p",
	})
	_, err := bNoCA.buildDelegate(context.Background(), server, vpnprovider.Credentials{
		Username: "u",
		Password: "p",
	})
	require.Error(t, err)

	// With a valid CA: config generation succeeds and produces an OpenVPN
	// delegate backend.
	bWithCA := NewNordVPNBackend(NordVPNConfig{
		Name:     "nord-ovpn",
		Protocol: "openvpn",
		Username: "u",
		Password: "p",
		CACert:   nordTestCAPEM(t),
	})
	delegate, err := bWithCA.buildDelegate(context.Background(), server, vpnprovider.Credentials{
		Username: "u",
		Password: "p",
		CACert:   nordTestCAPEM(t),
	})
	require.NoError(t, err)
	require.NotNil(t, delegate)
	assert.Equal(t, "openvpn", delegate.Type())
}

func TestNewNordVPNBackend(t *testing.T) {
	cfg := NordVPNConfig{
		Name:    "test-nordvpn",
		Country: "US",
	}

	b := NewNordVPNBackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-nordvpn", b.Name())
	assert.Equal(t, "nordvpn", b.Type())
}

func TestNewNordVPNBackend_Defaults(t *testing.T) {
	cfg := NordVPNConfig{
		Name: "test",
	}

	b := NewNordVPNBackend(cfg)

	// Check defaults are applied
	assert.Equal(t, "wireguard", b.config.Protocol)
	assert.Equal(t, 70, b.config.MaxLoad)
	assert.Equal(t, 30*time.Minute, b.config.RefreshInterval)
}

func TestNewNordVPNBackend_CustomConfig(t *testing.T) {
	cfg := NordVPNConfig{
		Name:            "custom",
		Country:         "DE",
		City:            "Berlin",
		Protocol:        "openvpn",
		MaxLoad:         50,
		RefreshInterval: 1 * time.Hour,
		Features:        []string{"p2p"},
	}

	b := NewNordVPNBackend(cfg)

	assert.Equal(t, "openvpn", b.config.Protocol)
	assert.Equal(t, 50, b.config.MaxLoad)
	assert.Equal(t, 1*time.Hour, b.config.RefreshInterval)
	assert.Equal(t, []string{"p2p"}, b.config.Features)
}

func TestNordVPNBackend_Dial_NotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestNordVPNBackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestNordVPNBackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	assert.False(t, b.IsHealthy())
}

func TestNordVPNBackend_Stats(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test-nordvpn"})

	stats := b.Stats()
	assert.Equal(t, "test-nordvpn", stats.Name)
	assert.Equal(t, "nordvpn", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestNordVPNBackend_Stop_NotRunning(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestNordVPNBackend_SelectedServer_NilWhenNotStarted(t *testing.T) {
	b := NewNordVPNBackend(NordVPNConfig{Name: "test"})

	server := b.SelectedServer()
	assert.Nil(t, server)
}
