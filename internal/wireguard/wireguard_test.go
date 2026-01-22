package wireguard

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorReader is a reader that returns an error after reading some content
type errorReader struct {
	content   string
	readCount int
	errAfter  int
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	r.readCount++
	if r.readCount > r.errAfter {
		return 0, errors.New("simulated read error")
	}
	if r.content == "" {
		return 0, io.EOF
	}
	n = copy(p, r.content)
	r.content = r.content[n:]
	return n, nil
}

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
		{
			name: "missing interface address",
			config: Config{
				Interface: InterfaceConfig{
					PrivateKey: "WGExample1234567890123456789012345678901234=",
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
			name: "peer missing public key",
			config: Config{
				Interface: InterfaceConfig{
					PrivateKey: "WGExample1234567890123456789012345678901234=",
					Address:    []string{"10.0.0.2/24"},
				},
				Peers: []PeerConfig{
					{
						AllowedIPs: []string{"0.0.0.0/0"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "peer missing allowed IPs",
			config: Config{
				Interface: InterfaceConfig{
					PrivateKey: "WGExample1234567890123456789012345678901234=",
					Address:    []string{"10.0.0.2/24"},
				},
				Peers: []PeerConfig{
					{
						PublicKey: "WGExample1234567890123456789012345678901234=",
					},
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

func TestConfig_ToIPC(t *testing.T) {
	config := Config{
		Interface: InterfaceConfig{
			PrivateKey: "WGExample1234567890123456789012345678901234=",
			ListenPort: 51820,
		},
		Peers: []PeerConfig{
			{
				PublicKey:           "WGExample1234567890123456789012345678901234=",
				PresharedKey:        "WGExample1234567890123456789012345678901234=",
				Endpoint:            "vpn.example.com:51820",
				AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
				PersistentKeepalive: 25,
			},
		},
	}

	ipc := config.ToIPC()

	// Check that IPC contains expected keys
	assert.Contains(t, ipc, "private_key=")
	assert.Contains(t, ipc, "listen_port=51820")
	assert.Contains(t, ipc, "public_key=")
	assert.Contains(t, ipc, "preshared_key=")
	assert.Contains(t, ipc, "endpoint=vpn.example.com:51820")
	assert.Contains(t, ipc, "allowed_ip=0.0.0.0/0")
	assert.Contains(t, ipc, "allowed_ip=::/0")
	assert.Contains(t, ipc, "persistent_keepalive_interval=25")
}

func TestConfig_ToIPC_MinimalConfig(t *testing.T) {
	config := Config{
		Interface: InterfaceConfig{
			PrivateKey: "WGExample1234567890123456789012345678901234=",
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "WGExample1234567890123456789012345678901234=",
				AllowedIPs: []string{"10.0.0.0/8"},
			},
		},
	}

	ipc := config.ToIPC()

	assert.Contains(t, ipc, "private_key=")
	assert.Contains(t, ipc, "public_key=")
	assert.Contains(t, ipc, "allowed_ip=10.0.0.0/8")
	// Should not contain optional fields
	assert.NotContains(t, ipc, "listen_port=")
	assert.NotContains(t, ipc, "preshared_key=")
	assert.NotContains(t, ipc, "endpoint=")
	assert.NotContains(t, ipc, "persistent_keepalive_interval=")
}

func TestParseFile_WithHooks(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
Table = auto
PreUp = echo pre-up
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PreDown = echo pre-down
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, "auto", config.Interface.Table)
	assert.Equal(t, "echo pre-up", config.Interface.PreUp)
	assert.Equal(t, "iptables -A FORWARD -i wg0 -j ACCEPT", config.Interface.PostUp)
	assert.Equal(t, "echo pre-down", config.Interface.PreDown)
	assert.Equal(t, "iptables -D FORWARD -i wg0 -j ACCEPT", config.Interface.PostDown)
}

func TestParseFile_WithPresharedKey(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
PresharedKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "WGExample1234567890123456789012345678901234=", config.Peers[0].PresharedKey)
}

func TestParseFile_InvalidFormat(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
InvalidLine without equals sign
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid format")
}

func TestParseFile_InvalidAddress(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = not-an-ip-address
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address")
}

func TestParseFile_InvalidListenPort(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
ListenPort = invalid
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid listen port")
}

func TestParseFile_InvalidMTU(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
MTU = 100
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MTU")
}

func TestParseFile_InvalidPrivateKey(t *testing.T) {
	content := `[Interface]
PrivateKey = not-a-valid-key
Address = 10.0.0.2/24
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}

func TestParseFile_InvalidPeerPublicKey(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = invalid-key
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key")
}

func TestParseFile_InvalidAllowedIP(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = not-an-ip
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid allowed IP")
}

func TestParseFile_InvalidPersistentKeepalive(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = invalid
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid persistent keepalive")
}

func TestParseFile_MultiplePeers(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 10.0.0.0/8
Endpoint = vpn1.example.com:51820

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 192.168.0.0/16
Endpoint = vpn2.example.com:51820
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)

	require.Len(t, config.Peers, 2)
	assert.Equal(t, "vpn1.example.com:51820", config.Peers[0].Endpoint)
	assert.Equal(t, "vpn2.example.com:51820", config.Peers[1].Endpoint)
}

func TestParseFile_FileNotFound(t *testing.T) {
	_, err := ParseFile("/nonexistent/path/wg0.conf")
	assert.Error(t, err)
}

func TestParseFile_PeerKeyWithoutSection(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
PublicKey = WGExample1234567890123456789012345678901234=
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	// PublicKey in Interface section should be ignored (unknown key)
	config, err := ParseFile(configPath)
	require.NoError(t, err)
	assert.Len(t, config.Peers, 0)
}

func TestInterfaceConfig_Struct(t *testing.T) {
	iface := InterfaceConfig{
		PrivateKey: "test-key",
		Address:    []string{"10.0.0.2/24", "fd00::2/64"},
		ListenPort: 51820,
		DNS:        []string{"1.1.1.1", "8.8.8.8"},
		MTU:        1420,
		Table:      "auto",
		PreUp:      "pre-up",
		PostUp:     "post-up",
		PreDown:    "pre-down",
		PostDown:   "post-down",
	}

	assert.Equal(t, "test-key", iface.PrivateKey)
	assert.Len(t, iface.Address, 2)
	assert.Equal(t, 51820, iface.ListenPort)
	assert.Len(t, iface.DNS, 2)
	assert.Equal(t, 1420, iface.MTU)
	assert.Equal(t, "auto", iface.Table)
}

func TestPeerConfig_Struct(t *testing.T) {
	peer := PeerConfig{
		PublicKey:           "pub-key",
		PresharedKey:        "psk-key",
		Endpoint:            "vpn.example.com:51820",
		AllowedIPs:          []string{"0.0.0.0/0"},
		PersistentKeepalive: 25,
	}

	assert.Equal(t, "pub-key", peer.PublicKey)
	assert.Equal(t, "psk-key", peer.PresharedKey)
	assert.Equal(t, "vpn.example.com:51820", peer.Endpoint)
	assert.Len(t, peer.AllowedIPs, 1)
	assert.Equal(t, 25, peer.PersistentKeepalive)
}

func TestParseFile_InvalidPresharedKey(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
PresharedKey = invalid-psk-key
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid preshared key")
}

func TestParseFile_InvalidListenPortOutOfRange(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
ListenPort = 70000
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid listen port")
}

func TestParseFile_InvalidMTUOutOfRange(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
MTU = 70000
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MTU")
}

func TestParseFile_InvalidPersistentKeepaliveOutOfRange(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = -1
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid persistent keepalive")
}

func TestParseFile_PlainIPAddress(t *testing.T) {
	// Test parsing an IP address without CIDR notation
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2"}, config.Interface.Address)
}

func TestParseFile_CommentsAndEmptyLines(t *testing.T) {
	content := `# This is a comment
[Interface]
# Another comment
PrivateKey = WGExample1234567890123456789012345678901234=

# Empty lines above and below
Address = 10.0.0.2/24

[Peer]
# Peer comment
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "WGExample1234567890123456789012345678901234=", config.Interface.PrivateKey)
}

func TestParseFile_NoInterface(t *testing.T) {
	// Config with only a Peer section (no Interface)
	content := `[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)
	// Interface will have zero values but peers should be parsed
	assert.Len(t, config.Peers, 1)
}

func TestParseFile_UnknownSection(t *testing.T) {
	// Config with an unknown section
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Unknown]
SomeKey = SomeValue

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	config, err := ParseFile(configPath)
	require.NoError(t, err)
	assert.Len(t, config.Peers, 1)
}

func TestParseFile_NegativeListenPort(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
ListenPort = -1
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wg0.conf")
	err := os.WriteFile(configPath, []byte(content), 0600)
	require.NoError(t, err)

	_, err = ParseFile(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid listen port")
}

func TestHexKey(t *testing.T) {
	// Test the hexKey function with a valid base64 key
	key := "WGExample1234567890123456789012345678901234="
	result := hexKey(key)
	assert.NotEmpty(t, result)
	// The result should be a hex string (64 characters for 32 bytes)
	assert.Len(t, result, 64)
}

func TestHexKey_InvalidBase64(t *testing.T) {
	// Test hexKey with invalid base64 - should return empty hex
	key := "not-valid-base64!"
	result := hexKey(key)
	// When base64 decode fails, decoded will be empty, so hex will be empty
	assert.Equal(t, "", result)
}

func TestConfig_ToIPC_MultiplePeers(t *testing.T) {
	config := Config{
		Interface: InterfaceConfig{
			PrivateKey: "WGExample1234567890123456789012345678901234=",
			ListenPort: 51820,
		},
		Peers: []PeerConfig{
			{
				PublicKey:  "WGExample1234567890123456789012345678901234=",
				AllowedIPs: []string{"10.0.0.0/8"},
			},
			{
				PublicKey:           "WGExample1234567890123456789012345678901234=",
				PresharedKey:        "WGExample1234567890123456789012345678901234=",
				Endpoint:            "vpn2.example.com:51820",
				AllowedIPs:          []string{"192.168.0.0/16", "172.16.0.0/12"},
				PersistentKeepalive: 30,
			},
		},
	}

	ipc := config.ToIPC()

	// Check that all expected keys are present
	assert.Contains(t, ipc, "private_key=")
	assert.Contains(t, ipc, "listen_port=51820")
	// First peer
	assert.Contains(t, ipc, "allowed_ip=10.0.0.0/8")
	// Second peer
	assert.Contains(t, ipc, "endpoint=vpn2.example.com:51820")
	assert.Contains(t, ipc, "allowed_ip=192.168.0.0/16")
	assert.Contains(t, ipc, "allowed_ip=172.16.0.0/12")
	assert.Contains(t, ipc, "persistent_keepalive_interval=30")
}

func TestParse_FromReader(t *testing.T) {
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24

[Peer]
PublicKey = WGExample1234567890123456789012345678901234=
AllowedIPs = 0.0.0.0/0
`
	reader := strings.NewReader(content)
	config, err := Parse(reader)
	require.NoError(t, err)
	assert.Equal(t, "WGExample1234567890123456789012345678901234=", config.Interface.PrivateKey)
	assert.Len(t, config.Peers, 1)
}

func TestParse_ScannerError(t *testing.T) {
	// Create a reader that returns an error after reading some content
	// This tests the scanner.Err() branch
	content := `[Interface]
PrivateKey = WGExample1234567890123456789012345678901234=
Address = 10.0.0.2/24
`
	reader := &errorReader{content: content, errAfter: 1}
	_, err := Parse(reader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan config")
}

func TestParse_EmptyReader(t *testing.T) {
	reader := strings.NewReader("")
	config, err := Parse(reader)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Empty(t, config.Interface.PrivateKey)
	assert.Empty(t, config.Peers)
}
