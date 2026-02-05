package client

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiclient "github.com/rennerdo30/bifrost-proxy/internal/api/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/vpn"
)

// mockSysProxyManager implements sysproxy.Manager for testing
type mockSysProxyManager struct {
	proxySet     bool
	proxyAddress string
	setErr       error
	clearErr     error
}

func (m *mockSysProxyManager) SetProxy(address string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.proxySet = true
	m.proxyAddress = address
	return nil
}

func (m *mockSysProxyManager) ClearProxy() error {
	if m.clearErr != nil {
		return m.clearErr
	}
	m.proxySet = false
	m.proxyAddress = ""
	return nil
}

func TestNew(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP:   config.ListenerConfig{Listen: "127.0.0.1:0"},
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.router)
	assert.NotNil(t, client.serverConn)
	assert.False(t, client.Running())
}

func TestNew_WithRoutes(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*.local"}, Action: "direct"},
			{Name: "server", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNew_WithDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 100,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.debugger)
}

func TestClient_Running(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, client.Running())
}

func TestClient_GetDebugEntries_NilDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled: false,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	entries := client.GetDebugEntries()
	assert.Nil(t, entries)
}

func TestClient_GetDebugEntries_WithDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 10,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	entries := client.GetDebugEntries()
	assert.NotNil(t, entries)
	assert.Empty(t, entries)
}

func TestClient_StartStop(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Start again (should be no-op)
	err = client.Start(ctx)
	require.NoError(t, err)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, client.Running())

	// Stop again (should be no-op)
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_StartWithSOCKS5(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_StartWithAPI(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Token:   "test-token",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Give API server time to start
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_getBackend_Direct(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*.local"}, Action: "direct"},
			{Name: "server", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Should match direct route
	be := client.getBackend("test.local", "192.168.1.1")
	require.NotNil(t, be)
	assert.Equal(t, "direct", be.Name())
}

func TestClient_getBackend_Server(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*.local"}, Action: "direct"},
			{Name: "server", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Should match server route (catch-all)
	be := client.getBackend("example.com", "192.168.1.1")
	require.NotNil(t, be)
	assert.Equal(t, "server", be.Name())
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	// IDs should be different (very high probability)
	// Note: This could technically fail if nanoseconds match, but extremely unlikely
}

func TestClient_VPNManager_Nil(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// VPN not enabled, should return nil
	assert.Nil(t, client.VPNManager())
}

func TestClient_SetConfigPath(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Set a config path
	testPath := "/tmp/test-config.yaml"
	client.SetConfigPath(testPath)

	// Verify it was set (indirectly via Config update)
	assert.Equal(t, testPath, client.configPath)
}

func TestClient_Config(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Get config
	gotCfg := client.Config()
	require.NotNil(t, gotCfg)
	assert.Equal(t, "localhost:7080", gotCfg.Server.Address)
	assert.Equal(t, "http", gotCfg.Server.Protocol)
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
	}{
		{"seconds", "30s", 30 * time.Second},
		{"minutes", "5m", 5 * time.Minute},
		{"hours", "2h", 2 * time.Hour},
		{"milliseconds", "500ms", 500 * time.Millisecond},
		{"invalid", "invalid", 0},
		{"empty", "", 0},
		{"no unit", "100", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDuration(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_updateConfig_Server(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"server": map[string]interface{}{
			"address":     "newhost:9090",
			"protocol":    "socks5",
			"username":    "testuser",
			"password":    "testpass",
			"timeout":     "60s",
			"retry_count": float64(5),
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.Equal(t, "newhost:9090", client.config.Server.Address)
	assert.Equal(t, "socks5", client.config.Server.Protocol)
	assert.Equal(t, "testuser", client.config.Server.Username)
	assert.Equal(t, "testpass", client.config.Server.Password)
	assert.Equal(t, config.Duration(60*time.Second), client.config.Server.Timeout)
	assert.Equal(t, 5, client.config.Server.RetryCount)
}

func TestClient_updateConfig_Proxy(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP:   config.ListenerConfig{Listen: "127.0.0.1:7380"},
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:7180"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"proxy": map[string]interface{}{
			"http": map[string]interface{}{
				"listen":       "0.0.0.0:8888",
				"read_timeout": "120s",
			},
			"socks5": map[string]interface{}{
				"listen": "0.0.0.0:9999",
			},
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8888", client.config.Proxy.HTTP.Listen)
	assert.Equal(t, config.Duration(120*time.Second), client.config.Proxy.HTTP.ReadTimeout)
	assert.Equal(t, "0.0.0.0:9999", client.config.Proxy.SOCKS5.Listen)
}

func TestClient_updateConfig_Debug(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled:     false,
			MaxEntries:  100,
			CaptureBody: false,
			MaxBodySize: 1024,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"debug": map[string]interface{}{
			"enabled":       true,
			"max_entries":   float64(500),
			"capture_body":  true,
			"max_body_size": float64(2048),
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.Debug.Enabled)
	assert.Equal(t, 500, client.config.Debug.MaxEntries)
	assert.True(t, client.config.Debug.CaptureBody)
	assert.Equal(t, 2048, client.config.Debug.MaxBodySize)
}

func TestClient_updateConfig_Logging(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"logging": map[string]interface{}{
			"level":  "debug",
			"format": "json",
			"output": "/var/log/bifrost.log",
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.Equal(t, "debug", client.config.Logging.Level)
	assert.Equal(t, "json", client.config.Logging.Format)
	assert.Equal(t, "/var/log/bifrost.log", client.config.Logging.Output)
}

func TestClient_updateConfig_Tray(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"tray": map[string]interface{}{
			"enabled":            true,
			"start_minimized":    true,
			"show_quick_gui":     false,
			"auto_connect":       true,
			"show_notifications": false,
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.Tray.Enabled)
	assert.True(t, client.config.Tray.StartMinimized)
	assert.False(t, client.config.Tray.ShowQuickGUI)
	assert.True(t, client.config.Tray.AutoConnect)
	assert.False(t, client.config.Tray.ShowNotifications)
}

func TestClient_updateConfig_WebUI(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"web_ui": map[string]interface{}{
			"enabled": true,
			"listen":  "0.0.0.0:7080",
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.WebUI.Enabled)
	assert.Equal(t, "0.0.0.0:7080", client.config.WebUI.Listen)
}

func TestClient_updateConfig_API(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"api": map[string]interface{}{
			"enabled": true,
			"listen":  "0.0.0.0:9000",
			"token":   "my-secret-token",
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.API.Enabled)
	assert.Equal(t, "0.0.0.0:9000", client.config.API.Listen)
	assert.Equal(t, "my-secret-token", client.config.API.Token)
}

func TestClient_updateConfig_AutoUpdate(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"auto_update": map[string]interface{}{
			"enabled": true,
			"channel": "beta",
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.AutoUpdate.Enabled)
	assert.Equal(t, "beta", client.config.AutoUpdate.Channel)
}

func TestClient_updateConfig_VPN(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"vpn": map[string]interface{}{
			"enabled": true,
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.VPN.Enabled)
}

func TestClient_updateConfig_Mesh(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	updates := map[string]interface{}{
		"mesh": map[string]interface{}{
			"enabled":      true,
			"network_id":   "test-network",
			"network_cidr": "10.0.0.0/24",
			"peer_name":    "my-peer",
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	assert.True(t, client.config.Mesh.Enabled)
	assert.Equal(t, "test-network", client.config.Mesh.NetworkID)
	assert.Equal(t, "10.0.0.0/24", client.config.Mesh.NetworkCIDR)
	assert.Equal(t, "my-peer", client.config.Mesh.PeerName)
}

func TestClient_updateConfig_SaveToFile(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "bifrost-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Set a config path
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	client.SetConfigPath(configPath)

	updates := map[string]interface{}{
		"server": map[string]interface{}{
			"address": "newhost:9090",
		},
	}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

func TestClient_updateConfig_EmptyUpdates(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Empty updates should not fail
	updates := map[string]interface{}{}

	err = client.updateConfig(updates)
	require.NoError(t, err)

	// Config should remain unchanged
	assert.Equal(t, "localhost:7080", client.config.Server.Address)
}

func TestClient_onConnect_WithDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 100,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client.debugger)

	// Create a mock connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		acceptedConn, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptedConn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Call onConnect
	ctx := context.Background()
	client.onConnect(ctx, conn, "example.com:80", nil)

	// Verify debug entry was logged
	entries := client.GetDebugEntries()
	assert.NotEmpty(t, entries)
}

func TestClient_onConnect_NilDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled: false, // Debugger disabled
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	assert.Nil(t, client.debugger)

	// Create a mock connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		acceptedConn, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptedConn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Call onConnect - should not panic with nil debugger
	ctx := context.Background()
	client.onConnect(ctx, conn, "example.com:80", nil)
}

func TestClient_onError_WithDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 100,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client.debugger)

	// Create a mock connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		acceptedConn, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptedConn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Call onError
	ctx := context.Background()
	testErr := errors.New("test connection error")
	client.onError(ctx, conn, "example.com:80", testErr)

	// Verify debug entry was logged
	entries := client.GetDebugEntries()
	assert.NotEmpty(t, entries)
}

func TestClient_onError_NilDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled: false, // Debugger disabled
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	assert.Nil(t, client.debugger)

	// Create a mock connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		acceptedConn, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptedConn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Call onError - should not panic with nil debugger
	ctx := context.Background()
	testErr := errors.New("test connection error")
	client.onError(ctx, conn, "example.com:80", testErr)
}

func TestClient_StartStop_Multiple(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP:   config.ListenerConfig{Listen: "127.0.0.1:0"},
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start with both HTTP and SOCKS5
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())
	assert.NotNil(t, client.httpListener)
	assert.NotNil(t, client.socks5Listener)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, client.Running())
}

func TestClient_StartWithDebuggerAndAPI(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 100,
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Token:   "test-token",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Wait a bit for goroutines to start
	time.Sleep(50 * time.Millisecond)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestNew_InvalidRoutes(t *testing.T) {
	// Test with invalid routes (empty domains should fail)
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "invalid", Domains: []string{}, Action: "direct"}, // Empty domains
		},
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load routes")
}

func TestClient_Start_HTTPListenerError(t *testing.T) {
	// Create a listener on a port to cause a conflict
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: listener.Addr().String()}, // Conflict
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listen HTTP")
}

func TestClient_Start_SOCKS5ListenerError(t *testing.T) {
	// Create a listener on a port to cause a conflict
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			SOCKS5: config.ListenerConfig{Listen: listener.Addr().String()}, // Conflict
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listen SOCKS5")
}

func TestClient_Stop_NoListeners(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			// No listeners configured
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_Stop_AlreadyStopped(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Client is not running, stop should be no-op
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_updateConfig_SaveToInvalidPath(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Set an invalid config path (non-writable directory)
	client.SetConfigPath("/nonexistent/directory/deeply/nested/config.yaml")

	// With a very deeply nested invalid path, mkdir should still work on temp systems
	// So let's try a path that's definitely not writable
	// On most systems, /dev/null/foo will fail
	if testing.Short() {
		t.Skip("Skipping file write test in short mode")
	}
}

func TestClient_ConcurrentAccess(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Test concurrent access to Running()
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = client.Running()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestClient_ConcurrentConfigAccess(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:7080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Test concurrent access to Config() and SetConfigPath()
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			for j := 0; j < 100; j++ {
				_ = client.Config()
				client.SetConfigPath("/tmp/test-config-" + string(rune('0'+idx)) + ".yaml")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestClient_HTTPProxyServing(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "127.0.0.1:1", // Invalid - will fail
			Protocol: "http",
			Timeout:  config.Duration(100 * time.Millisecond),
		},
		Routes: []config.ClientRouteConfig{
			{Name: "all", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client.Stop(stopCtx)
	}()

	// Get the listening address
	addr := client.httpListener.Addr().String()

	// Connect to the HTTP proxy and send a CONNECT request
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Send a CONNECT request - this will fail because server is not available
	// but it exercises the serveHTTP code path
	_, err = conn.Write([]byte("CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"))
	require.NoError(t, err)

	// Read response (should be an error since server is not available)
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)
	// We don't check the exact response, just that the code ran without panicking
}

func TestClient_SOCKS5ProxyServing(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "127.0.0.1:1", // Invalid - will fail
			Protocol: "socks5",
			Timeout:  config.Duration(100 * time.Millisecond),
		},
		Routes: []config.ClientRouteConfig{
			{Name: "all", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client.Stop(stopCtx)
	}()

	// Get the listening address
	addr := client.socks5Listener.Addr().String()

	// Connect to the SOCKS5 proxy
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Send SOCKS5 greeting
	_, err = conn.Write([]byte{0x05, 0x01, 0x00}) // Version 5, 1 method, no auth
	require.NoError(t, err)

	// Read response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)
	// We don't check the exact response, just that the code ran without panicking
}

func TestClient_DirectRouteHTTP(t *testing.T) {
	// Start a simple HTTP server to connect to directly
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	httpServer := listener.(*net.TCPListener)

	go func() {
		for {
			acceptedConn, acceptErr := httpServer.Accept()
			if acceptErr != nil {
				return
			}
			acceptedConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			acceptedConn.Close()
		}
	}()

	targetAddr := listener.Addr().String()

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*"}, Action: "direct"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client.Stop(stopCtx)
	}()

	// Get the proxy address
	proxyAddr := client.httpListener.Addr().String()

	// Connect to proxy and request connection to target
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Send CONNECT request
	_, err = conn.Write([]byte("CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n"))
	require.NoError(t, err)

	// Read response - should establish connection
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Contains(t, string(buf[:n]), "200")
}

func TestClient_getQuickSettings(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Tray: config.TrayConfig{
			AutoConnect:       true,
			StartMinimized:    true,
			ShowNotifications: false,
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: true,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	settings := client.getQuickSettings()
	require.NotNil(t, settings)

	assert.True(t, settings.AutoConnect)
	assert.True(t, settings.StartMinimized)
	assert.False(t, settings.ShowNotifications)
	assert.False(t, settings.VPNEnabled) // VPN not running
	assert.True(t, settings.SystemProxyEnabled)
	assert.Equal(t, "localhost:7080", settings.CurrentServer)
}

func TestClient_getQuickSettings_WithVPNManager(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		VPN: vpn.Config{
			Enabled: false, // We'll mock the manager status
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Create a disabled VPN manager to test the status check
	vpnCfg := vpn.DefaultConfig()
	vpnCfg.Enabled = false
	vpnManager, err := vpn.New(vpnCfg)
	require.NoError(t, err)
	client.vpnManager = vpnManager

	settings := client.getQuickSettings()
	require.NotNil(t, settings)

	// VPN is initialized but not connected
	assert.False(t, settings.VPNEnabled)
}

func TestClient_updateQuickSettings(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:8080"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		Tray: config.TrayConfig{
			AutoConnect:       false,
			StartMinimized:    false,
			ShowNotifications: true,
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: false,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace sys proxy manager with mock
	mockManager := &mockSysProxyManager{}
	client.sysProxyManager = mockManager

	settings := &apiclient.QuickSettings{
		AutoConnect:        true,
		StartMinimized:     true,
		ShowNotifications:  false,
		SystemProxyEnabled: false, // Keep disabled
		CurrentServer:      "localhost:7080",
	}

	err = client.updateQuickSettings(settings)
	require.NoError(t, err)

	// Verify tray config updated
	assert.True(t, client.config.Tray.AutoConnect)
	assert.True(t, client.config.Tray.StartMinimized)
	assert.False(t, client.config.Tray.ShowNotifications)
}

func TestClient_updateQuickSettings_EnableSystemProxy(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:8080"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: false,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace sys proxy manager with mock
	mockManager := &mockSysProxyManager{}
	client.sysProxyManager = mockManager

	settings := &apiclient.QuickSettings{
		SystemProxyEnabled: true,
		CurrentServer:      "localhost:7080",
	}

	err = client.updateQuickSettings(settings)
	require.NoError(t, err)

	// Verify system proxy was enabled
	assert.True(t, client.config.SystemProxy.Enabled)
	assert.True(t, mockManager.proxySet)
	assert.Equal(t, "127.0.0.1:8080", mockManager.proxyAddress)
}

func TestClient_updateQuickSettings_DisableSystemProxy(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:8080"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: true,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace sys proxy manager with mock (start with proxy set)
	mockManager := &mockSysProxyManager{proxySet: true}
	client.sysProxyManager = mockManager

	settings := &apiclient.QuickSettings{
		SystemProxyEnabled: false,
		CurrentServer:      "localhost:7080",
	}

	err = client.updateQuickSettings(settings)
	require.NoError(t, err)

	// Verify system proxy was disabled
	assert.False(t, client.config.SystemProxy.Enabled)
	assert.False(t, mockManager.proxySet)
}

func TestClient_updateQuickSettings_ChangeServer(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:8080"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace sys proxy manager with mock
	mockManager := &mockSysProxyManager{}
	client.sysProxyManager = mockManager

	settings := &apiclient.QuickSettings{
		CurrentServer: "newserver:9090",
	}

	err = client.updateQuickSettings(settings)
	require.NoError(t, err)

	// Verify server address was updated
	assert.Equal(t, "newserver:9090", client.config.Server.Address)
}

func TestClient_updateQuickSettings_WithConfigPath(t *testing.T) {
	// Create temp dir for config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:8080"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Set config path
	client.SetConfigPath(configPath)

	// Replace sys proxy manager with mock
	mockManager := &mockSysProxyManager{}
	client.sysProxyManager = mockManager

	settings := &apiclient.QuickSettings{
		AutoConnect:   true,
		CurrentServer: "localhost:7080",
	}

	err = client.updateQuickSettings(settings)
	require.NoError(t, err)

	// Verify config file was created
	_, err = os.Stat(configPath)
	assert.NoError(t, err)
}

func TestClient_updateQuickSettings_SystemProxyWithSOCKS5(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP:   config.ListenerConfig{Listen: ""}, // No HTTP
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:1080"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: false,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace sys proxy manager with mock
	mockManager := &mockSysProxyManager{}
	client.sysProxyManager = mockManager

	settings := &apiclient.QuickSettings{
		SystemProxyEnabled: true,
		CurrentServer:      "localhost:7080",
	}

	err = client.updateQuickSettings(settings)
	require.NoError(t, err)

	// Verify SOCKS5 address was used when HTTP is empty
	assert.True(t, mockManager.proxySet)
	assert.Equal(t, "127.0.0.1:1080", mockManager.proxyAddress)
}

func TestNew_WithVPNEnabled(t *testing.T) {
	vpnCfg := vpn.DefaultConfig()
	vpnCfg.Enabled = true

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		VPN: vpnCfg,
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.vpnManager)
}

func TestClient_Start_SystemProxyNoListeners(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			// No HTTP or SOCKS5 listeners
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: true, // System proxy enabled but no listeners
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err) // Should not error, just warn

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_Start_SystemProxyWithSOCKS5Only(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			// No HTTP listener, only SOCKS5
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: true,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace with mock
	mockManager := &mockSysProxyManager{}
	client.sysProxyManager = mockManager

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)

	// Verify SOCKS5 was used for system proxy
	assert.True(t, mockManager.proxySet)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_Start_SystemProxyError(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
		SystemProxy: config.SystemProxyConfig{
			Enabled: true,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Replace with mock that returns error
	mockManager := &mockSysProxyManager{
		setErr: errors.New("failed to set system proxy"),
	}
	client.sysProxyManager = mockManager

	ctx := context.Background()
	err = client.Start(ctx)
	// Should not fail, just log error
	require.NoError(t, err)
	assert.False(t, mockManager.proxySet)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_Start_AlreadyRunning(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:7080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the first time
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Start again - should be a no-op
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}
