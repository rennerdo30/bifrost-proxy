package backend

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenVPNBackend(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-openvpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)
	assert.NotNil(t, b)
	assert.Equal(t, "test-openvpn", b.Name())
	assert.Equal(t, "openvpn", b.Type())
}

func TestNewOpenVPNBackend_Defaults(t *testing.T) {
	cfg := OpenVPNConfig{
		Name: "test",
	}

	b := NewOpenVPNBackend(cfg)
	assert.Equal(t, "openvpn", b.config.Binary)
	assert.Equal(t, "127.0.0.1", b.config.ManagementAddr)
	assert.Equal(t, 7505, b.config.ManagementPort)
	assert.Equal(t, 60*time.Second, b.config.ConnectTimeout)
}

func TestNewOpenVPNBackend_CustomConfig(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:           "test",
		Binary:         "/custom/openvpn",
		ManagementAddr: "192.168.1.1",
		ManagementPort: 8000,
		ConnectTimeout: 30 * time.Second,
	}

	b := NewOpenVPNBackend(cfg)
	assert.Equal(t, "/custom/openvpn", b.config.Binary)
	assert.Equal(t, "192.168.1.1", b.config.ManagementAddr)
	assert.Equal(t, 8000, b.config.ManagementPort)
	assert.Equal(t, 30*time.Second, b.config.ConnectTimeout)
}

func TestOpenVPNBackend_Dial_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	_, err := b.Dial(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestOpenVPNBackend_DialTimeout_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	_, err := b.DialTimeout(context.Background(), "tcp", "example.com:80", 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestOpenVPNBackend_IsHealthy_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	assert.False(t, b.IsHealthy())
}

func TestOpenVPNBackend_Stats(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test-openvpn"})

	stats := b.Stats()
	assert.Equal(t, "test-openvpn", stats.Name)
	assert.Equal(t, "openvpn", stats.Type)
	assert.False(t, stats.Healthy)
	assert.Equal(t, int64(0), stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
}

func TestOpenVPNBackend_Stop_NotStarted(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	// Stop should be safe to call even when not started
	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestOpenVPNBackend_Start_MissingConfigFile(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test",
		ConfigFile: "/nonexistent/path/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)
	err := b.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config file")
}

func TestOpenVPNBackend_recordError(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	assert.Equal(t, int64(0), b.stats.errors.Load())
	assert.Equal(t, "", b.stats.lastError)

	b.recordError(assert.AnError)

	assert.Equal(t, int64(1), b.stats.errors.Load())
	assert.Equal(t, assert.AnError.Error(), b.stats.lastError)
	assert.False(t, b.stats.lastErrorTime.IsZero())
}

func TestOpenVPNBackend_cleanupTempFiles(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "test"})

	// Set temp file paths (not real files, just test cleanup logic)
	b.tempConfigFile = "/tmp/test-config"
	b.tempAuthFile = "/tmp/test-auth"

	// Cleanup should clear the paths (actual file removal will fail silently for non-existent files)
	b.cleanupTempFiles()

	assert.Equal(t, "", b.tempConfigFile)
	assert.Equal(t, "", b.tempAuthFile)
}

func TestOpenVPNConfig_InlineContent(t *testing.T) {
	cfg := OpenVPNConfig{
		Name: "inline-test",
		ConfigContent: `
client
dev tun
proto udp
remote vpn.example.com 1194
`,
		Username: "testuser",
		Password: "testpass",
	}

	assert.Equal(t, "inline-test", cfg.Name)
	assert.Contains(t, cfg.ConfigContent, "client")
	assert.Contains(t, cfg.ConfigContent, "remote vpn.example.com 1194")
	assert.Equal(t, "testuser", cfg.Username)
	assert.Equal(t, "testpass", cfg.Password)
}

func TestOpenVPNConfig_Struct(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:           "my-vpn",
		ConfigFile:     "/path/to/config.ovpn",
		ConfigContent:  "content",
		AuthFile:       "/path/to/auth",
		Username:       "user",
		Password:       "pass",
		ManagementAddr: "127.0.0.1",
		ManagementPort: 7505,
		Binary:         "/usr/sbin/openvpn",
		ExtraArgs:      []string{"--verb", "3"},
		ConnectTimeout: 60 * time.Second,
	}

	assert.Equal(t, "my-vpn", cfg.Name)
	assert.Equal(t, "/path/to/config.ovpn", cfg.ConfigFile)
	assert.Equal(t, "content", cfg.ConfigContent)
	assert.Equal(t, "/path/to/auth", cfg.AuthFile)
	assert.Equal(t, "user", cfg.Username)
	assert.Equal(t, "pass", cfg.Password)
	assert.Equal(t, "127.0.0.1", cfg.ManagementAddr)
	assert.Equal(t, 7505, cfg.ManagementPort)
	assert.Equal(t, "/usr/sbin/openvpn", cfg.Binary)
	assert.Equal(t, []string{"--verb", "3"}, cfg.ExtraArgs)
	assert.Equal(t, 60*time.Second, cfg.ConnectTimeout)
}

func TestOpenVPNBackend_Start_AlreadyRunning(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Manually set as running
	b.mu.Lock()
	b.running = true
	b.mu.Unlock()

	// Start should be idempotent
	err := b.Start(context.Background())
	assert.NoError(t, err)
}

func TestOpenVPNBackend_Stop_AlreadyStopped(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)
	// Backend is not running by default

	// Stop should be safe
	err := b.Stop(context.Background())
	assert.NoError(t, err)
}

func TestOpenVPNBackend_queryLocalAddress_NoConnection(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Call with no management connection
	err := b.queryLocalAddress()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "management connection not available")
}

func TestOpenVPNBackend_waitForManagement_ContextCanceled(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:           "test-vpn",
		ConfigFile:     "/path/to/config.ovpn",
		ManagementAddr: "127.0.0.1",
		ManagementPort: 19999, // Unused port
		ConnectTimeout: 5 * time.Second,
	}

	b := NewOpenVPNBackend(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := b.waitForManagement(ctx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestOpenVPNBackend_waitForManagement_Timeout(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:           "test-vpn",
		ConfigFile:     "/path/to/config.ovpn",
		ManagementAddr: "127.0.0.1",
		ManagementPort: 19998, // Unused port
		ConnectTimeout: 100 * time.Millisecond,
	}

	b := NewOpenVPNBackend(cfg)

	err := b.waitForManagement(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestOpenVPNBackend_waitForManagement_Success(t *testing.T) {
	// Start a mock management server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	cfg := OpenVPNConfig{
		Name:           "test-vpn",
		ConfigFile:     "/path/to/config.ovpn",
		ManagementAddr: "127.0.0.1",
		ManagementPort: addr.Port,
		ConnectTimeout: 5 * time.Second,
	}

	b := NewOpenVPNBackend(cfg)

	// Accept connection in background
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			// Keep connection open briefly
			time.Sleep(100 * time.Millisecond)
			conn.Close()
		}
	}()

	err = b.waitForManagement(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, b.mgmtConn)

	// Clean up
	if b.mgmtConn != nil {
		b.mgmtConn.Close()
	}
}

func TestOpenVPNBackend_queryLocalAddress_Connected(t *testing.T) {
	// Start a mock management server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			defer conn.Close()
			// Read state command
			buf := make([]byte, 100)
			conn.Read(buf)
			// Send connected state response
			conn.Write([]byte("1234567890,CONNECTED,SUCCESS,10.8.0.2,\nEND\n"))
		}
	}()

	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Connect to mock server
	b.mgmtConn, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	err = b.queryLocalAddress()
	assert.NoError(t, err)
	assert.Equal(t, "10.8.0.2", b.localAddr)

	b.mgmtConn.Close()
}

func TestOpenVPNBackend_queryLocalAddress_NotConnected(t *testing.T) {
	// Start a mock management server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 100)
			conn.Read(buf)
			// Send state response without CONNECTED status
			conn.Write([]byte("1234567890,CONNECTING,Connecting to VPN,,\nEND\n"))
		}
	}()

	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	b.mgmtConn, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	err = b.queryLocalAddress()
	assert.NoError(t, err) // Should not error, just not set localAddr
	assert.Empty(t, b.localAddr)

	b.mgmtConn.Close()
}

func TestOpenVPNBackend_Dial_WithLocalAddr(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Set running and localAddr
	b.mu.Lock()
	b.running = true
	b.localAddr = "127.0.0.1"
	b.mu.Unlock()

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	ctx := context.Background()
	conn, err := b.Dial(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	assert.NotNil(t, conn)

	buf := make([]byte, 5)
	conn.Read(buf)
	conn.Close()

	stats := b.Stats()
	assert.Equal(t, int64(1), stats.TotalConnections)
}

func TestOpenVPNBackend_Dial_WithoutLocalAddr(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Set running but no localAddr
	b.mu.Lock()
	b.running = true
	b.mu.Unlock()

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	ctx := context.Background()
	conn, err := b.Dial(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	assert.NotNil(t, conn)

	buf := make([]byte, 5)
	conn.Read(buf)
	conn.Close()
}

func TestOpenVPNBackend_Dial_Error(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Set running
	b.mu.Lock()
	b.running = true
	b.mu.Unlock()

	ctx := context.Background()
	// Try to connect to unreachable address
	_, err := b.Dial(ctx, "tcp", "192.0.2.1:12345")
	assert.Error(t, err)

	stats := b.Stats()
	assert.Greater(t, stats.Errors, int64(0))
}

func TestOpenVPNBackend_TrackedConn_OnClose(t *testing.T) {
	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	b.mu.Lock()
	b.running = true
	b.mu.Unlock()

	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			time.Sleep(50 * time.Millisecond)
			conn.Close()
		}
	}()

	ctx := context.Background()
	conn, err := b.Dial(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)

	stats := b.Stats()
	assert.Equal(t, int64(1), stats.ActiveConnections)

	// Read and close
	buf := make([]byte, 5)
	conn.Read(buf)
	conn.Close()

	time.Sleep(10 * time.Millisecond)
	stats = b.Stats()
	assert.Equal(t, int64(0), stats.ActiveConnections)
}

func TestOpenVPNBackend_Stop_WithManagementConn(t *testing.T) {
	// Start a mock management server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverDone := make(chan struct{})
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			// Read any data
			buf := make([]byte, 1024)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					break
				}
			}
			conn.Close()
		}
		close(serverDone)
	}()

	cfg := OpenVPNConfig{
		Name:       "test-vpn",
		ConfigFile: "/path/to/config.ovpn",
	}

	b := NewOpenVPNBackend(cfg)

	// Set up state
	b.mu.Lock()
	b.running = true
	b.healthy.Store(true)
	// Connect to mock server
	mgmtConn, _ := net.Dial("tcp", listener.Addr().String())
	b.mgmtConn = mgmtConn
	b.mu.Unlock()

	// Stop should close mgmtConn
	err = b.Stop(context.Background())
	assert.NoError(t, err)
	assert.False(t, b.IsHealthy())

	listener.Close()
	<-serverDone
}

func TestOpenVPNBackend_Start_InlineConfigContent(t *testing.T) {
	cfg := OpenVPNConfig{
		Name: "test-vpn",
		ConfigContent: `client
dev tun
proto udp
remote vpn.example.com 1194
`,
		Binary:         "/nonexistent/openvpn", // Will fail to start
		ConnectTimeout: 100 * time.Millisecond,
	}

	b := NewOpenVPNBackend(cfg)

	// Start will fail because binary doesn't exist, but it tests the temp file creation path
	err := b.Start(context.Background())
	assert.Error(t, err)
	// Temp file should be cleaned up on error
	assert.Empty(t, b.tempConfigFile)
}

func TestOpenVPNBackend_Start_InlineAuth(t *testing.T) {
	// Create a temp config file that exists
	tmpConfig, err := os.CreateTemp("", "test-config-*.ovpn")
	require.NoError(t, err)
	tmpConfig.WriteString("client\n")
	tmpConfig.Close()
	defer os.Remove(tmpConfig.Name())

	cfg := OpenVPNConfig{
		Name:           "test-vpn",
		ConfigFile:     tmpConfig.Name(),
		Username:       "testuser",
		Password:       "testpass",
		Binary:         "/nonexistent/openvpn", // Will fail
		ConnectTimeout: 100 * time.Millisecond,
	}

	b := NewOpenVPNBackend(cfg)

	err = b.Start(context.Background())
	assert.Error(t, err)
	// Temp auth file should be cleaned up on error
	assert.Empty(t, b.tempAuthFile)
}
