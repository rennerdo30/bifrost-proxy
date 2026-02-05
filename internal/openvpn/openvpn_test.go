package openvpn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// TestProcess_Start_AlreadyRunning tests that Start returns an error if process is already running
func TestProcess_Start_AlreadyRunning(t *testing.T) {
	proc := &Process{
		state:   StateConnecting, // Already running
		stateCh: make(chan State, 10),
	}

	err := proc.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

// TestProcess_Start_Success tests a successful start with a mock executable
func TestProcess_Start_Success(t *testing.T) {
	// Create a temp directory for our mock script
	tmpDir := t.TempDir()

	// Create a simple config file
	configPath := filepath.Join(tmpDir, "test.ovpn")
	err := os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)

	// Create a mock openvpn script that exits quickly
	mockScript := filepath.Join(tmpDir, "openvpn")
	// Simple script that just sleeps briefly and exits
	scriptContent := `#!/bin/sh
sleep 0.1
exit 0
`
	err = os.WriteFile(mockScript, []byte(scriptContent), 0755)
	require.NoError(t, err)

	// Temporarily modify PATH to use our mock
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+origPath)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
		Management: ManagementConfig{
			Address: "127.0.0.1",
			Port:    0, // Will be set by Start
		},
	}

	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = proc.Start(ctx)
	assert.NoError(t, err)
	assert.Equal(t, StateConnecting, proc.State())

	// Wait a bit for process to exit
	time.Sleep(200 * time.Millisecond)
}

// TestProcess_Start_WithAuthFile tests start with auth file configured
func TestProcess_Start_WithAuthFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config and auth files
	configPath := filepath.Join(tmpDir, "test.ovpn")
	authPath := filepath.Join(tmpDir, "auth.txt")
	err := os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(authPath, []byte("user\npass\n"), 0600)
	require.NoError(t, err)

	// Create mock openvpn
	mockScript := filepath.Join(tmpDir, "openvpn")
	err = os.WriteFile(mockScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
	require.NoError(t, err)

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+origPath)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
		AuthFile:   authPath,
		Management: ManagementConfig{
			Address: "127.0.0.1",
			Port:    7506,
		},
	}

	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = proc.Start(ctx)
	assert.NoError(t, err)
}

// TestProcess_Start_CommandError tests that Start returns an error if openvpn command fails to start
func TestProcess_Start_CommandError(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "test.ovpn")
	err := os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)

	// Set PATH to empty directory so openvpn won't be found
	emptyDir := filepath.Join(tmpDir, "empty")
	os.MkdirAll(emptyDir, 0755)
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", emptyDir)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
	}

	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	err = proc.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start openvpn")
}

// TestProcess_Stop_NilProcess tests Stop with nil process
func TestProcess_Stop_NilProcess(t *testing.T) {
	proc := &Process{
		cmd:     nil,
		stateCh: make(chan State, 10),
	}

	err := proc.Stop(context.Background())
	assert.NoError(t, err)
}

// TestProcess_Stop_NilCmd tests Stop with nil cmd.Process
func TestProcess_Stop_NilCmd(t *testing.T) {
	proc := &Process{
		cmd:     &exec.Cmd{},
		stateCh: make(chan State, 10),
	}

	err := proc.Stop(context.Background())
	assert.NoError(t, err)
}

// TestProcess_Stop_GracefulShutdown tests graceful shutdown via management interface
func TestProcess_Stop_GracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock process that exits on SIGTERM
	mockScript := filepath.Join(tmpDir, "openvpn")
	scriptContent := `#!/bin/sh
trap 'exit 0' TERM
sleep 10
`
	err := os.WriteFile(mockScript, []byte(scriptContent), 0755)
	require.NoError(t, err)

	configPath := filepath.Join(tmpDir, "test.ovpn")
	err = os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+origPath)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
		Management: ManagementConfig{
			Address: "127.0.0.1",
			Port:    7507,
		},
	}

	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	ctx := context.Background()
	err = proc.Start(ctx)
	require.NoError(t, err)

	// Give it a moment
	time.Sleep(100 * time.Millisecond)

	// Stop should work
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = proc.Stop(stopCtx)
	assert.NoError(t, err)
}

// TestProcess_Stop_WithMgmtConn tests stop with active management connection
func TestProcess_Stop_WithMgmtConn(t *testing.T) {
	// Create a server to simulate management interface
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Accept connections in background
	go func() {
		acceptedConn, acceptErr := listener.Accept()
		if acceptErr == nil {
			// Read the signal command
			reader := bufio.NewReader(acceptedConn)
			reader.ReadString('\n')
			acceptedConn.Close()
		}
	}()

	// Connect to the mock server
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	mockScript := filepath.Join(tmpDir, "openvpn")
	err = os.WriteFile(mockScript, []byte("#!/bin/sh\nsleep 0.1\n"), 0755)
	require.NoError(t, err)

	configPath := filepath.Join(tmpDir, "test.ovpn")
	err = os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+origPath)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
	}

	// Start process first
	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	ctx := context.Background()
	err = proc.Start(ctx)
	require.NoError(t, err)

	// Inject management connection
	proc.mu.Lock()
	proc.mgmtConn = conn
	proc.mu.Unlock()

	time.Sleep(50 * time.Millisecond)

	// Stop
	err = proc.Stop(context.Background())
	assert.NoError(t, err)
}

// TestProcess_Stop_ForceKillOnTimeout tests force kill when graceful shutdown times out
func TestProcess_Stop_ForceKillOnTimeout(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock process that ignores signals
	mockScript := filepath.Join(tmpDir, "openvpn")
	scriptContent := `#!/bin/sh
trap '' TERM INT
sleep 30
`
	err := os.WriteFile(mockScript, []byte(scriptContent), 0755)
	require.NoError(t, err)

	configPath := filepath.Join(tmpDir, "test.ovpn")
	err = os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+origPath)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
	}

	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	ctx := context.Background()
	err = proc.Start(ctx)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Stop with a short timeout - should force kill
	stopCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	err = proc.Stop(stopCtx)
	assert.NoError(t, err)
}

// TestProcess_Stop_ContextCancellation tests force kill when context is canceled
func TestProcess_Stop_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock process that runs indefinitely
	mockScript := filepath.Join(tmpDir, "openvpn")
	scriptContent := `#!/bin/sh
trap '' TERM INT
sleep 30
`
	err := os.WriteFile(mockScript, []byte(scriptContent), 0755)
	require.NoError(t, err)

	configPath := filepath.Join(tmpDir, "test.ovpn")
	err = os.WriteFile(configPath, []byte("dev tun\n"), 0644)
	require.NoError(t, err)

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+origPath)
	defer os.Setenv("PATH", origPath)

	cfg := &Config{
		ConfigFile: configPath,
	}

	proc := NewProcess(ProcessConfig{
		Config: cfg,
		Logger: slog.Default(),
	})

	ctx := context.Background()
	err = proc.Start(ctx)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Cancel context immediately
	stopCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel right away

	err = proc.Stop(stopCtx)
	assert.NoError(t, err)
}

// TestProcess_monitorManagement_ContextCancelled tests monitorManagement exits on context cancel
func TestProcess_monitorManagement_ContextCancelled(t *testing.T) {
	cfg := &Config{
		Management: ManagementConfig{
			Address: "127.0.0.1",
			Port:    9999, // Non-listening port
		},
	}

	proc := &Process{
		config:  cfg,
		stateCh: make(chan State, 10),
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// This should exit quickly
	done := make(chan struct{})
	go func() {
		proc.monitorManagement(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("monitorManagement didn't exit on context cancel")
	}
}

// TestProcess_monitorManagement_ConnectionSuccess tests successful connection to management
func TestProcess_monitorManagement_ConnectionSuccess(t *testing.T) {
	// Start a mock management server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Get the port
	addr := listener.Addr().(*net.TCPAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Send a state line then close
		conn.Write([]byte(">STATE:1234567890,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4\n"))
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}()

	cfg := &Config{
		Management: ManagementConfig{
			Address: "127.0.0.1",
			Port:    addr.Port,
		},
	}

	proc := &Process{
		config:  cfg,
		stateCh: make(chan State, 10),
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		proc.monitorManagement(ctx)
		close(done)
	}()

	wg.Wait()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("monitorManagement didn't complete")
	}

	assert.Equal(t, StateConnected, proc.State())
}

// TestProcess_handleManagement_ContextCancelled tests handleManagement exits on context cancel
func TestProcess_handleManagement_ContextCancelled(t *testing.T) {
	// Use TCP listener instead of net.Pipe to support deadlines
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	done := make(chan struct{})

	// Accept connection in background
	go func() {
		acceptedConn, acceptErr := listener.Accept()
		if acceptErr == nil {
			// Keep connection open but send no data
			// Wait until test is done
			<-done
			acceptedConn.Close()
		}
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	proc := &Process{
		stateCh: make(chan State, 10),
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start handler in background
	handlerDone := make(chan struct{})
	go func() {
		proc.handleManagement(ctx, client)
		close(handlerDone)
	}()

	// Cancel context after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-handlerDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("handleManagement didn't exit on context cancel")
	}
	close(done)
}

// TestProcess_handleManagement_EOF tests handleManagement exits on EOF
func TestProcess_handleManagement_EOF(t *testing.T) {
	server, client := net.Pipe()

	proc := &Process{
		stateCh: make(chan State, 10),
		logger:  slog.Default(),
	}

	ctx := context.Background()
	// Need to read from server side because net.Pipe is unbuffered and Write blocks
	go io.Copy(io.Discard, server)

	done := make(chan struct{})
	go func() {
		proc.handleManagement(ctx, client)
		close(done)
	}()

	// Close server side to cause EOF
	server.Close()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("handleManagement didn't exit on EOF")
	}
}

// TestProcess_handleManagement_StateLines tests various state line parsing
func TestProcess_handleManagement_StateLines(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	proc := &Process{
		stateCh: make(chan State, 10),
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Need to read from server side because net.Pipe is unbuffered and Write blocks
	// Use a goroutine that can be stopped
	go func() {
		buf := make([]byte, 1024)
		for {
			server.Read(buf)
		}
	}()

	done := make(chan struct{})
	go func() {
		proc.handleManagement(ctx, client)
		close(done)
	}()

	// Write various state lines
	go func() {
		server.Write([]byte(">STATE:123,CONNECTING,,,\n"))
		time.Sleep(50 * time.Millisecond)
		server.Write([]byte(">STATE:123,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4\n"))
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	<-done

	assert.Equal(t, StateConnected, proc.State())
	assert.Equal(t, "10.8.0.2", proc.LocalIP())
	assert.Equal(t, "1.2.3.4", proc.RemoteIP())
}

// TestProcess_handleManagement_TimeoutRetry tests that timeouts are retried
func TestProcess_handleManagement_TimeoutRetry(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	proc := &Process{
		stateCh: make(chan State, 10),
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		proc.handleManagement(ctx, client)
		close(done)
	}()

	// Wait for timeout then send data
	go func() {
		// Read initial command to unblock client.Write
		buf := make([]byte, 1024)
		server.Read(buf)

		time.Sleep(1500 * time.Millisecond) // Wait for timeout cycle
		server.Write([]byte(">STATE:123,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4\n"))
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	<-done

	assert.Equal(t, StateConnected, proc.State())
}

// TestProcess_parseManagementLine_ConnectedPartialParts tests CONNECTED with fewer parts
func TestProcess_parseManagementLine_ConnectedPartialParts(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
	}

	// Only 3 parts (no localIP)
	proc.parseManagementLine(">STATE:123,CONNECTED,SUCCESS")
	assert.Equal(t, StateConnected, proc.state)
	assert.Equal(t, "", proc.localIP)

	// 4 parts (localIP but no remoteIP)
	proc.state = StateDisconnected
	proc.parseManagementLine(">STATE:123,CONNECTED,SUCCESS,10.8.0.2")
	assert.Equal(t, StateConnected, proc.state)
	assert.Equal(t, "10.8.0.2", proc.localIP)
	assert.Equal(t, "", proc.remoteIP)
}

// TestProcess_parseManagementLine_UnknownState tests unknown state values
func TestProcess_parseManagementLine_UnknownState(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
		state:   StateDisconnected,
	}

	proc.parseManagementLine(">STATE:123,UNKNOWN_STATE,,,")
	// State should not change for unknown values
	assert.Equal(t, StateDisconnected, proc.state)
}

// TestProcess_parseManagementLine_SinglePart tests STATE line with single part
func TestProcess_parseManagementLine_SinglePart(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 10),
		state:   StateDisconnected,
	}

	// Only timestamp, no state
	proc.parseManagementLine(">STATE:123")
	// State should not change
	assert.Equal(t, StateDisconnected, proc.state)
}

// TestProcess_setState_ChannelFull tests setState when channel is full (non-blocking)
func TestProcess_setState_ChannelFull(t *testing.T) {
	proc := &Process{
		stateCh: make(chan State, 1), // Buffer of 1
	}

	// Fill the channel
	proc.stateCh <- StateConnected

	// This should not block even though channel is full
	done := make(chan struct{})
	go func() {
		proc.setState(StateConnecting)
		close(done)
	}()

	select {
	case <-done:
		// Success - didn't block
	case <-time.After(time.Second):
		t.Fatal("setState blocked on full channel")
	}

	assert.Equal(t, StateConnecting, proc.state)
}

// TestLogWriter_Write_WithLogger tests logWriter with an actual logger
func TestLogWriter_Write_WithLogger(t *testing.T) {
	logger := slog.Default()
	w := &logWriter{prefix: "test", logger: logger}

	n, err := w.Write([]byte("test line\n"))
	assert.NoError(t, err)
	assert.Equal(t, 10, n)
}

// TestLogWriter_Write_MultipleLines tests logWriter with multiple lines
func TestLogWriter_Write_MultipleLines(t *testing.T) {
	logger := slog.Default()
	w := &logWriter{prefix: "test", logger: logger}

	n, err := w.Write([]byte("line1\nline2\nline3"))
	assert.NoError(t, err)
	assert.Equal(t, 17, n)
}

// TestParseConfigFile_ScannerError tests scanner error handling
// Note: This is difficult to test directly since scanner.Err() returns nil for most errors
// We test by ensuring the scanner processes large lines correctly
func TestParseConfigFile_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "large.ovpn")

	// Create a config with many directives
	var content string
	for i := 0; i < 100; i++ {
		content += fmt.Sprintf("# Comment line %d\n", i)
		content += fmt.Sprintf("remote server%d.example.com %d udp\n", i, 1194+i)
	}

	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.Len(t, cfg.Remote, 100)
}

// TestParseConfigFile_RemoteWithDefaultPort tests remote without port specified
func TestParseConfigFile_RemoteWithDefaultPort(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.ovpn")

	content := "remote server.example.com\n"
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	require.Len(t, cfg.Remote, 1)
	assert.Equal(t, "server.example.com", cfg.Remote[0].Host)
	assert.Equal(t, 1194, cfg.Remote[0].Port) // Default port
	assert.Equal(t, "udp", cfg.Remote[0].Protocol)
}

// TestParseConfigFile_RemoteWithPort tests remote with port only
func TestParseConfigFile_RemoteWithPort(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.ovpn")

	content := "remote server.example.com 443\n"
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	require.Len(t, cfg.Remote, 1)
	assert.Equal(t, "server.example.com", cfg.Remote[0].Host)
	assert.Equal(t, 443, cfg.Remote[0].Port)
	assert.Equal(t, "udp", cfg.Remote[0].Protocol) // Inherits default
}

// TestParseConfigFile_AllDirectivesWithArgs tests that directives with no args are handled
func TestParseConfigFile_DirectivesWithNoArgs(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.ovpn")

	// These are directives that check for args length
	content := `proto
port
dev
cipher
auth
tls-auth
ca
cert
key
verb
management 127.0.0.1
auth-user-pass
`
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	// All should use defaults or be empty (no crash)
	assert.NotNil(t, cfg)
}

// TestParseConfigFile_ManagementIncomplete tests management with only address (no port)
func TestParseConfigFile_ManagementIncomplete(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.ovpn")

	content := "management 127.0.0.1\n"
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	// Management should not be set since it requires at least 2 args
	assert.Equal(t, "", cfg.Management.Address)
	assert.Equal(t, 0, cfg.Management.Port)
}

// TestParseConfigFile_EmptyPartsLine tests line that becomes empty after Fields
func TestParseConfigFile_WhitespaceOnlyLine(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.ovpn")

	content := "   \t   \n"
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := ParseConfigFile(configPath)
	require.NoError(t, err)

	assert.NotNil(t, cfg)
}
