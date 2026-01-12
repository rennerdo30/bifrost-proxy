package openvpn

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigFile(t *testing.T) {
	// Create a temp config file
	content := `# OpenVPN config
client
dev tun
proto udp
remote vpn.example.com 1194 udp
remote backup.example.com 443 tcp
cipher AES-256-GCM
auth SHA256
tls-auth ta.key 1
ca ca.crt
cert client.crt
key client.key
compress lz4
verb 3
management 127.0.0.1 7505
auth-user-pass auth.txt
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, configPath, cfg.ConfigFile)
	assert.Equal(t, "udp", cfg.Protocol)
	assert.Equal(t, "tun", cfg.Dev)
	assert.Equal(t, "AES-256-GCM", cfg.Cipher)
	assert.Equal(t, "SHA256", cfg.Auth)
	assert.Equal(t, "ta.key", cfg.TLSAuth)
	assert.Equal(t, "ca.crt", cfg.CA)
	assert.Equal(t, "client.crt", cfg.Cert)
	assert.Equal(t, "client.key", cfg.Key)
	assert.Equal(t, "lz4", cfg.Compress)
	assert.Equal(t, 3, cfg.Verb)
	assert.Equal(t, "127.0.0.1", cfg.Management.Address)
	assert.Equal(t, 7505, cfg.Management.Port)
	assert.Equal(t, "auth.txt", cfg.AuthFile)

	// Check remotes
	require.Len(t, cfg.Remote, 2)
	assert.Equal(t, "vpn.example.com", cfg.Remote[0].Host)
	assert.Equal(t, 1194, cfg.Remote[0].Port)
	assert.Equal(t, "udp", cfg.Remote[0].Protocol)
	assert.Equal(t, "backup.example.com", cfg.Remote[1].Host)
	assert.Equal(t, 443, cfg.Remote[1].Port)
	assert.Equal(t, "tcp", cfg.Remote[1].Protocol)
}

func TestParseConfigFile_WithProto(t *testing.T) {
	content := `proto tcp
remote server.example.com
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, "tcp", cfg.Protocol)
	// Remote should inherit protocol from proto directive
	require.Len(t, cfg.Remote, 1)
	assert.Equal(t, "tcp", cfg.Remote[0].Protocol)
}

func TestParseConfigFile_WithPort(t *testing.T) {
	content := `port 443
remote server.example.com
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, 443, cfg.Port)
}

func TestParseConfigFile_CompLzo(t *testing.T) {
	content := `comp-lzo
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, "lzo", cfg.Compress)
}

func TestParseConfigFile_CompressNoArg(t *testing.T) {
	content := `compress
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, "lzo", cfg.Compress)
}

func TestParseConfigFile_ManagementWithPassword(t *testing.T) {
	content := `management 127.0.0.1 7505 secret
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", cfg.Management.Address)
	assert.Equal(t, 7505, cfg.Management.Port)
	assert.Equal(t, "secret", cfg.Management.Password)
}

func TestParseConfigFile_SkipComments(t *testing.T) {
	content := `# This is a comment
; This is also a comment
dev tun

# Another comment
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Equal(t, "tun", cfg.Dev)
}

func TestParseConfigFile_FileNotFound(t *testing.T) {
	_, err := ParseConfigFile("/nonexistent/path/config.ovpn")
	assert.Error(t, err)
}

func TestConfig_Validate(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.ovpn")
	err := os.WriteFile(configPath, []byte("dev tun"), 0644)
	require.NoError(t, err)

	cfg := &Config{ConfigFile: configPath}
	err = cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_NoConfigFile(t *testing.T) {
	cfg := &Config{}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config file path is required")
}

func TestConfig_Validate_FileNotAccessible(t *testing.T) {
	cfg := &Config{ConfigFile: "/nonexistent/path/config.ovpn"}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
}

func TestConfig_GetPrimaryRemote(t *testing.T) {
	cfg := &Config{
		Remote: []RemoteServer{
			{Host: "vpn.example.com", Port: 1194, Protocol: "udp"},
			{Host: "backup.example.com", Port: 443, Protocol: "tcp"},
		},
	}

	primary := cfg.GetPrimaryRemote()
	assert.Equal(t, "vpn.example.com:1194", primary)
}

func TestConfig_GetPrimaryRemote_Empty(t *testing.T) {
	cfg := &Config{}
	primary := cfg.GetPrimaryRemote()
	assert.Equal(t, "", primary)
}

func TestNewProcess(t *testing.T) {
	cfg := &Config{ConfigFile: "/tmp/test.ovpn"}
	procCfg := ProcessConfig{
		Config: cfg,
	}

	proc := NewProcess(procCfg)
	assert.NotNil(t, proc)
	assert.Equal(t, StateDisconnected, proc.State())
}

func TestProcess_State(t *testing.T) {
	proc := &Process{state: StateConnected}
	assert.Equal(t, StateConnected, proc.State())
}

func TestProcess_LocalIP(t *testing.T) {
	proc := &Process{localIP: "10.8.0.2"}
	assert.Equal(t, "10.8.0.2", proc.LocalIP())
}

func TestProcess_RemoteIP(t *testing.T) {
	proc := &Process{remoteIP: "1.2.3.4"}
	assert.Equal(t, "1.2.3.4", proc.RemoteIP())
}

func TestProcess_StateChan(t *testing.T) {
	proc := NewProcess(ProcessConfig{
		Config: &Config{},
	})

	ch := proc.StateChan()
	assert.NotNil(t, ch)
}

func TestProcess_setState(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
	}

	proc.setState(StateConnecting)
	assert.Equal(t, StateConnecting, proc.state)

	// Check state was sent to channel
	select {
	case s := <-proc.stateCh:
		assert.Equal(t, StateConnecting, s)
	default:
		t.Fatal("expected state on channel")
	}
}

func TestProcess_parseManagementLine_Connected(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
	}

	proc.parseManagementLine(">STATE:1234567890,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4")

	assert.Equal(t, StateConnected, proc.state)
	assert.Equal(t, "10.8.0.2", proc.localIP)
	assert.Equal(t, "1.2.3.4", proc.remoteIP)
}

func TestProcess_parseManagementLine_Connecting(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
	}

	testCases := []string{
		">STATE:1234567890,CONNECTING,,,",
		">STATE:1234567890,WAIT,,,",
		">STATE:1234567890,AUTH,,,",
		">STATE:1234567890,GET_CONFIG,,,",
		">STATE:1234567890,ASSIGN_IP,,,",
		">STATE:1234567890,ADD_ROUTES,,,",
	}

	for _, line := range testCases {
		proc.state = StateDisconnected
		proc.parseManagementLine(line)
		assert.Equal(t, StateConnecting, proc.state, "for line: %s", line)
	}
}

func TestProcess_parseManagementLine_Reconnecting(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
	}

	proc.parseManagementLine(">STATE:1234567890,RECONNECTING,,,")
	assert.Equal(t, StateReconnecting, proc.state)
}

func TestProcess_parseManagementLine_Exiting(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
	}

	proc.parseManagementLine(">STATE:1234567890,EXITING,,,")
	assert.Equal(t, StateExiting, proc.state)
}

func TestProcess_parseManagementLine_NonState(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
		state:   StateDisconnected,
	}

	// Non-state lines should be ignored
	proc.parseManagementLine(">INFO:OpenVPN Management Interface")
	assert.Equal(t, StateDisconnected, proc.state)
}

func TestCreateAuthFile(t *testing.T) {
	path, err := CreateAuthFile("testuser", "testpass")
	require.NoError(t, err)
	defer os.Remove(path)

	// Read and verify contents
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "testuser\ntestpass\n", string(content))

	// Verify permissions
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestLogWriter_Write(t *testing.T) {
	w := &logWriter{prefix: "test"}

	n, err := w.Write([]byte("line1\nline2\n"))
	assert.NoError(t, err)
	assert.Equal(t, 12, n)
}

func TestLogWriter_Write_EmptyLines(t *testing.T) {
	w := &logWriter{prefix: "test"}

	n, err := w.Write([]byte("\n\n\n"))
	assert.NoError(t, err)
	assert.Equal(t, 3, n)
}

func TestState_Constants(t *testing.T) {
	assert.Equal(t, State("disconnected"), StateDisconnected)
	assert.Equal(t, State("connecting"), StateConnecting)
	assert.Equal(t, State("connected"), StateConnected)
	assert.Equal(t, State("reconnecting"), StateReconnecting)
	assert.Equal(t, State("exiting"), StateExiting)
}

func TestRemoteServer_Struct(t *testing.T) {
	r := RemoteServer{
		Host:     "vpn.example.com",
		Port:     1194,
		Protocol: "udp",
	}

	assert.Equal(t, "vpn.example.com", r.Host)
	assert.Equal(t, 1194, r.Port)
	assert.Equal(t, "udp", r.Protocol)
}

func TestManagementConfig_Struct(t *testing.T) {
	m := ManagementConfig{
		Address:  "127.0.0.1",
		Port:     7505,
		Password: "secret",
	}

	assert.Equal(t, "127.0.0.1", m.Address)
	assert.Equal(t, 7505, m.Port)
	assert.Equal(t, "secret", m.Password)
}

func TestProcessConfig_Struct(t *testing.T) {
	cfg := ProcessConfig{
		Config:        &Config{},
		OnStateChange: func(s State) {},
	}

	assert.NotNil(t, cfg.Config)
	assert.NotNil(t, cfg.OnStateChange)
}
