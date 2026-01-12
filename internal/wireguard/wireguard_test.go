package wireguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	// Create a temporary config file
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24, fd00::2/64
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420
ListenPort = 51820

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)

	// Check interface
	assert.Equal(t, "WGExample1234567890123456789012345678901234=", config.Interface.PrivateKey)
	assert.Equal(t, []string{"10.0.0.2/24", "fd00::2/64"}, config.Interface.Address)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, config.Interface.DNS)
	assert.Equal(t, 1420, config.Interface.MTU)
	assert.Equal(t, 51820, config.Interface.ListenPort)

	// Check peer
	require.Len(t, config.Peers, 1)
	peer := config.Peers[0]
	assert.Equal(t, "WGExample1234567890123456789012345678901234=", peer.PublicKey)
	assert.Equal(t, "vpn.example.com:51820", peer.Endpoint)
	assert.Equal(t, []string{"0.0.0.0/0", "::/0"}, peer.AllowedIPs)
	assert.Equal(t, 25, peer.PersistentKeepalive)
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid key", "WGExample1234567890123456789012345678901234=", false},
		{"invalid base64", "not-valid-base64!", true},
		{"wrong length", "dG9vIHNob3J0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Interface: InterfaceConfig{
					PrivateKey: "WGExample1234567890123456789012345678901234=",
					Address:    []string{"10.0.0.2/24"},
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "WGExample1234567890123456789012345678901234=",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing private key",
			config: Config{
				Interface: InterfaceConfig{
					Address: []string{"10.0.0.2/24"},
				},
				Peers: []PeerConfig{
					{
						PublicKey:  "WGExample1234567890123456789012345678901234=",
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no peers",
			config: Config{
				Interface: InterfaceConfig{
					PrivateKey: "WGExample1234567890123456789012345678901234=",
					Address:    []string{"10.0.0.2/24"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
