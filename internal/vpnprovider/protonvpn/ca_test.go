package protonvpn

import (
	"encoding/pem"
	"fmt"
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
// certificate — the shape of the ProtonVPN CA material that used to be embedded
// in this package. Config generation must reject it.
func pemWithGarbageDER() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}))
}

func testOpenVPNServer() *vpnprovider.Server {
	return &vpnprovider.Server{
		Name:     "US#1",
		Hostname: "test.protonvpn.net",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.protonvpn.net",
			UDPPort:  OpenVPNUDPPort,
			TCPPort:  OpenVPNTCPPort,
		},
	}
}

// TestNoEmbeddedCAMaterial documents the deliberate absence of embedded
// ProtonVPN crypto material: without an operator-supplied CA there is nothing to
// fall back on, and generation must fail closed.
func TestNoEmbeddedCAMaterial(t *testing.T) {
	client := NewClient(WithManualCredentials("user", "pass", TierPlus))

	_, err := client.generateOpenVPNConfigContent(testOpenVPNServer(), "udp", vpnprovider.Credentials{})
	require.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrConfigGenerationFailed)
	assert.ErrorIs(t, err, vpnprovider.ErrCACertMissing)
}

// TestOpenVPNConfigRefusesUnusableCryptoMaterial asserts config generation fails
// closed for every flavor of unusable CA / tls-auth material instead of
// emitting a profile the OpenVPN subprocess would reject.
func TestOpenVPNConfigRefusesUnusableCryptoMaterial(t *testing.T) {
	client := NewClient(WithManualCredentials("user", "pass", TierPlus))

	fabricatedTLSAuth := vpnprovider.TLSAuthKeyHeader + "\n" +
		strings.Repeat("0123456789abcdef0123456789abcdef\n", vpnprovider.TLSAuthKeySize*2/vpnprovider.TLSAuthKeyHexCharsPerLine) +
		vpnprovider.TLSAuthKeyFooter + "\n"

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
			// A repeated placeholder line of the right total length is exactly
			// what the fabricated tls-auth key in this package looked like.
			name:    "fabricated tls-auth key",
			creds:   vpnprovider.Credentials{CACert: testCACertPEM, TLSAuthKey: fabricatedTLSAuth},
			wantErr: vpnprovider.ErrTLSAuthKeyPlaceholder,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := client.generateOpenVPNConfigContent(testOpenVPNServer(), "udp", tt.creds)
			require.Error(t, err, "generation must fail closed")
			assert.Empty(t, config)
			assert.ErrorIs(t, err, vpnprovider.ErrConfigGenerationFailed)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestOpenVPNConfigEmitsUsableCA re-parses the <ca> block of a generated profile
// so a regression that emits unusable material is caught here rather than by
// OpenVPN at connect time. It also asserts the profile does not enable
// script-security / host resolv.conf hooks, which would rewrite the host's
// global DNS configuration on tunnel-up.
func TestOpenVPNConfigEmitsUsableCA(t *testing.T) {
	client := NewClient(WithManualCredentials("user", "pass", TierPlus))

	config, err := client.generateOpenVPNConfigContent(testOpenVPNServer(), "udp", vpnprovider.Credentials{
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

	assert.Contains(t, config, "<tls-auth>")
	assert.Contains(t, config, "key-direction 1")

	assert.NotContains(t, config, "script-security")
	assert.NotContains(t, config, "update-resolv-conf")
	assert.NotContains(t, config, "/etc/openvpn")
}

// TestImportOpenVPNConfigValidatesInlineCA asserts an imported profile carrying
// an unusable inline <ca> block is rejected, while a profile whose CA is
// referenced out of line is passed through.
func TestImportOpenVPNConfigValidatesInlineCA(t *testing.T) {
	client := NewClient(WithManualCredentials("user", "pass", TierPlus))
	const header = "client\ndev tun\nproto udp\nremote test.protonvpn.net 1194\n"

	t.Run("valid inline CA", func(t *testing.T) {
		profile := header + "<ca>\n" + testCACertPEM + "\n</ca>\n"

		config, err := client.ImportOpenVPNConfig(profile, "user", "pass")
		require.NoError(t, err)
		assert.Equal(t, profile, config.ConfigContent)
	})

	t.Run("malformed inline CA", func(t *testing.T) {
		profile := header + "<ca>\n" + pemWithGarbageDER() + "</ca>\n"

		_, err := client.ImportOpenVPNConfig(profile, "user", "pass")
		require.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrConfigGenerationFailed)
		assert.ErrorIs(t, err, vpnprovider.ErrCACertMalformed)
	})

	t.Run("out-of-line CA is passed through", func(t *testing.T) {
		profile := header + "ca /etc/openvpn/proton.crt\n"

		config, err := client.ImportOpenVPNConfig(profile, "user", "pass")
		require.NoError(t, err)
		assert.Equal(t, profile, config.ConfigContent)
	})
}

// TestOpenVPNConfigProtocolSelection covers the TCP variant of the template,
// which selects the TCP port instead of the UDP one.
func TestOpenVPNConfigProtocolSelection(t *testing.T) {
	client := NewClient(WithManualCredentials("user", "pass", TierPlus))
	creds := vpnprovider.Credentials{CACert: testCACertPEM}

	udpConfig, err := client.generateOpenVPNConfigContent(testOpenVPNServer(), "udp", creds)
	require.NoError(t, err)
	assert.Contains(t, udpConfig, "proto udp")
	assert.Contains(t, udpConfig, fmt.Sprintf("remote test.protonvpn.net %d", OpenVPNUDPPort))

	tcpConfig, err := client.generateOpenVPNConfigContent(testOpenVPNServer(), "tcp", creds)
	require.NoError(t, err)
	assert.Contains(t, tcpConfig, "proto tcp")
	assert.Contains(t, tcpConfig, fmt.Sprintf("remote test.protonvpn.net %d", OpenVPNTCPPort))
}
