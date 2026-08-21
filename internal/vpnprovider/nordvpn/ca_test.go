package nordvpn

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// tamperPEMSignature returns certPEM with one signature byte flipped: the
// certificate still parses, but its self-signature no longer verifies.
func tamperPEMSignature(t *testing.T, certPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)

	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0xFF

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// pemWithGarbageDER is a PEM block that decodes fine but holds no X.509
// certificate. Config generation must reject it.
func pemWithGarbageDER() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}))
}

// TestOpenVPNConfigRefusesUnusableCryptoMaterial asserts config generation fails
// closed for every flavour of unusable CA / tls-auth material instead of
// emitting a profile the OpenVPN subprocess would reject.
func TestOpenVPNConfigRefusesUnusableCryptoMaterial(t *testing.T) {
	client := NewClient()

	tests := []struct {
		name    string
		creds   vpnprovider.Credentials
		wantErr error
	}{
		{name: "no CA", creds: vpnprovider.Credentials{}, wantErr: vpnprovider.ErrCACertMissing},
		{name: "not PEM", creds: vpnprovider.Credentials{CACert: "not a valid pem"}, wantErr: vpnprovider.ErrCACertNotPEM},
		{name: "garbage DER", creds: vpnprovider.Credentials{CACert: pemWithGarbageDER()}, wantErr: vpnprovider.ErrCACertMalformed},
		{
			name:    "broken self-signature",
			creds:   vpnprovider.Credentials{CACert: tamperPEMSignature(t, testCACertPEM)},
			wantErr: vpnprovider.ErrCACertBadSelfSignature,
		},
		{
			name:    "truncated tls-auth key",
			creds:   vpnprovider.Credentials{CACert: testCACertPEM, TLSAuthKey: vpnprovider.TLSAuthKeyHeader + "\ndeadbeef\n" + vpnprovider.TLSAuthKeyFooter},
			wantErr: vpnprovider.ErrTLSAuthKeyMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := client.generateOpenVPNConfigContent("us1234.nordvpn.com", "udp", 1194, tt.creds)
			require.Error(t, err, "generation must fail closed")
			assert.Empty(t, config)
			assert.ErrorIs(t, err, vpnprovider.ErrConfigGenerationFailed)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestOpenVPNConfigEmitsUsableCA re-parses the <ca> block of a generated profile
// so a regression that emits unusable material is caught here rather than by
// OpenVPN at connect time.
func TestOpenVPNConfigEmitsUsableCA(t *testing.T) {
	client := NewClient()

	config, err := client.generateOpenVPNConfigContent("us1234.nordvpn.com", "udp", 1194, vpnprovider.Credentials{
		CACert:     testCACertPEM,
		TLSAuthKey: testTLSAuthKey,
	})
	require.NoError(t, err)

	start := strings.Index(config, "<ca>")
	end := strings.Index(config, "</ca>")
	require.Greater(t, end, start)

	certs, err := vpnprovider.ParseCACertPEM(config[start+len("<ca>") : end])
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}
