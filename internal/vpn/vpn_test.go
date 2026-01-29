package vpn

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/device"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTUNDevice implements TUNDevice interface for testing
type mockTUNDevice struct {
	name      string
	mtu       int
	readData  []byte
	readErr   error
	writeData []byte
	writeErr  error
	closed    bool
	mu        sync.Mutex
	readChan  chan []byte
}

func newMockTUNDevice(name string, mtu int) *mockTUNDevice {
	return &mockTUNDevice{
		name:     name,
		mtu:      mtu,
		readChan: make(chan []byte, 10),
	}
}

func (m *mockTUNDevice) Name() string {
	return m.name
}

func (m *mockTUNDevice) MTU() int {
	return m.mtu
}

func (m *mockTUNDevice) Type() device.DeviceType {
	return device.DeviceTUN
}

func (m *mockTUNDevice) Read(b []byte) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, io.EOF
	}
	if m.readErr != nil {
		err := m.readErr
		m.mu.Unlock()
		return 0, err
	}
	m.mu.Unlock()

	select {
	case data := <-m.readChan:
		n := copy(b, data)
		return n, nil
	case <-time.After(100 * time.Millisecond):
		return 0, io.EOF
	}
}

func (m *mockTUNDevice) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.EOF
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = make([]byte, len(b))
	copy(m.writeData, b)
	return len(b), nil
}

func (m *mockTUNDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	close(m.readChan)
	return nil
}

// mockServerConnector implements ServerConnector for testing
type mockServerConnector struct {
	connectFunc func(ctx context.Context, target string) (net.Conn, error)
}

func (m *mockServerConnector) Connect(ctx context.Context, target string) (net.Conn, error) {
	if m.connectFunc != nil {
		return m.connectFunc(ctx, target)
	}
	return nil, errors.New("connect not implemented")
}

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	readErr   error
	writeData []byte
	writeErr  error
	closed    bool
	mu        sync.Mutex
}

func (m *mockConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readErr != nil {
		return 0, m.readErr
	}
	n := copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = make([]byte, len(b))
	copy(m.writeData, b)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestNew tests creating a new Manager
func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid disabled config",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid enabled config",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Name:    "bifrost0",
					Address: "10.255.0.1/24",
					MTU:     1400,
				},
				SplitTunnel: SplitTunnelConfig{
					Mode: "exclude",
				},
				DNS: DNSConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid TUN address",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Name:    "bifrost0",
					Address: "invalid",
					MTU:     1400,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid split tunnel mode",
			config: Config{
				Enabled: true,
				TUN: TUNConfig{
					Name:    "bifrost0",
					Address: "10.255.0.1/24",
					MTU:     1400,
				},
				SplitTunnel: SplitTunnelConfig{
					Mode: "invalid",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, m)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, m)
				assert.Equal(t, StatusDisabled, m.status.Load().(Status))
			}
		})
	}
}

// TestManagerConfigure tests the Configure method
func TestManagerConfigure(t *testing.T) {
	cfg := Config{
		Enabled: false,
	}
	m, err := New(cfg)
	require.NoError(t, err)

	connector := &mockServerConnector{}
	m.Configure(WithServerConnector(connector))
	assert.Equal(t, connector, m.serverConn)

	// Test WithLogger (no-op for now but should not panic)
	m.Configure(WithLogger(nil))
}

// TestManagerEnabled tests the Enabled method
func TestManagerEnabled(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{"enabled", true, true},
		{"disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = tt.enabled
			m, err := New(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, m.Enabled())
		})
	}
}

// TestManagerStatus tests the Status method
func TestManagerStatus(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	m, err := New(cfg)
	require.NoError(t, err)

	status := m.Status()
	assert.Equal(t, StatusDisabled, status.Status)
	assert.Zero(t, status.Uptime)
	assert.Zero(t, status.BytesSent)
	assert.Zero(t, status.BytesReceived)
	assert.Zero(t, status.PacketsSent)
	assert.Zero(t, status.PacketsReceived)
	assert.Zero(t, status.ActiveConnections)
	assert.Empty(t, status.LastError)
}

// TestManagerStatusWithError tests status with recorded error
func TestManagerStatusWithError(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	// Set an error
	m.setError(errors.New("test error"))

	status := m.Status()
	assert.Equal(t, "test error", status.LastError)
	assert.False(t, status.LastErrorTime.IsZero())
}

// TestManagerConnections tests the Connections method
func TestManagerConnections(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	// Without connTracker initialized
	conns := m.Connections()
	assert.Nil(t, conns)

	// Initialize connTracker
	m.connTracker = NewConnTracker()
	defer m.connTracker.Close()

	// Add a connection
	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
		ProxyConn: &mockConn{},
	}
	m.connTracker.Add(conn)

	conns = m.Connections()
	assert.Len(t, conns, 1)
	assert.Equal(t, "tcp", conns[0].Protocol)
	assert.Equal(t, uint16(12345), conns[0].LocalAddr.Port())
	assert.Equal(t, uint16(443), conns[0].RemoteAddr.Port())
}

// TestManagerSplitTunnelRules tests the SplitTunnelRules method
func TestManagerSplitTunnelRules(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SplitTunnel.Mode = "exclude"
	cfg.SplitTunnel.Apps = []AppRule{{Name: "test"}}
	cfg.SplitTunnel.Domains = []string{"*.example.com"}
	cfg.SplitTunnel.IPs = []string{"10.0.0.0/8"}

	m, err := New(cfg)
	require.NoError(t, err)

	rules := m.SplitTunnelRules()
	assert.Equal(t, "exclude", rules.Mode)
	assert.Len(t, rules.Apps, 1)
	assert.Len(t, rules.Domains, 1)
	assert.Len(t, rules.IPs, 1)
}

// TestManagerAddSplitTunnelApp tests adding apps to split tunnel
func TestManagerAddSplitTunnelApp(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	// Add app without engine
	err = m.AddSplitTunnelApp(AppRule{Name: "test"})
	assert.NoError(t, err)
	assert.Len(t, m.config.SplitTunnel.Apps, 1)

	// Add duplicate
	err = m.AddSplitTunnelApp(AppRule{Name: "test"})
	assert.Error(t, err)

	// Initialize split engine and add another app
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude"}, nil)
	err = m.AddSplitTunnelApp(AppRule{Name: "another"})
	assert.NoError(t, err)
	assert.Len(t, m.config.SplitTunnel.Apps, 2)
}

// TestManagerRemoveSplitTunnelApp tests removing apps from split tunnel
func TestManagerRemoveSplitTunnelApp(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SplitTunnel.Apps = []AppRule{{Name: "test"}}
	m, err := New(cfg)
	require.NoError(t, err)

	// Remove non-existent
	err = m.RemoveSplitTunnelApp("nonexistent")
	assert.Error(t, err)

	// Remove existing
	err = m.RemoveSplitTunnelApp("test")
	assert.NoError(t, err)
	assert.Len(t, m.config.SplitTunnel.Apps, 0)

	// Initialize split engine and test removal
	m.config.SplitTunnel.Apps = []AppRule{{Name: "test2"}}
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude", Apps: []AppRule{{Name: "test2"}}}, nil)
	err = m.RemoveSplitTunnelApp("test2")
	assert.NoError(t, err)
}

// TestManagerAddSplitTunnelDomain tests adding domains to split tunnel
func TestManagerAddSplitTunnelDomain(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	// Add domain
	err = m.AddSplitTunnelDomain("*.example.com")
	assert.NoError(t, err)
	assert.Contains(t, m.config.SplitTunnel.Domains, "*.example.com")

	// Add duplicate
	err = m.AddSplitTunnelDomain("*.example.com")
	assert.Error(t, err)

	// With split engine
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude"}, nil)
	err = m.AddSplitTunnelDomain("*.test.com")
	assert.NoError(t, err)
}

// TestManagerAddSplitTunnelIP tests adding IPs to split tunnel
func TestManagerAddSplitTunnelIP(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	// Add valid CIDR
	err = m.AddSplitTunnelIP("10.0.0.0/8")
	assert.NoError(t, err)
	assert.Contains(t, m.config.SplitTunnel.IPs, "10.0.0.0/8")

	// Add valid single IP
	err = m.AddSplitTunnelIP("192.168.1.1")
	assert.NoError(t, err)

	// Add duplicate
	err = m.AddSplitTunnelIP("10.0.0.0/8")
	assert.Error(t, err)

	// Add invalid
	err = m.AddSplitTunnelIP("invalid")
	assert.Error(t, err)

	// With split engine
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude"}, nil)
	err = m.AddSplitTunnelIP("172.16.0.0/12")
	assert.NoError(t, err)
}

// TestManagerStopNotRunning tests stopping when not running
func TestManagerStopNotRunning(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = m.Stop(ctx)
	assert.NoError(t, err)
}

// TestStatusConstants tests status constants
func TestStatusConstants(t *testing.T) {
	assert.Equal(t, Status("disabled"), StatusDisabled)
	assert.Equal(t, Status("connecting"), StatusConnecting)
	assert.Equal(t, Status("connected"), StatusConnected)
	assert.Equal(t, Status("disconnected"), StatusDisconnected)
	assert.Equal(t, Status("error"), StatusError)
}

// TestVPNStats tests VPNStats struct
func TestVPNStats(t *testing.T) {
	stats := VPNStats{
		Status:            StatusConnected,
		Uptime:            time.Hour,
		BytesSent:         1000,
		BytesReceived:     2000,
		PacketsSent:       10,
		PacketsReceived:   20,
		ActiveConnections: 5,
		TunneledConns:     3,
		BypassedConns:     2,
		DNSQueries:        100,
		DNSCacheHits:      80,
		LastError:         "test",
		LastErrorTime:     time.Now(),
	}

	assert.Equal(t, StatusConnected, stats.Status)
	assert.Equal(t, time.Hour, stats.Uptime)
	assert.Equal(t, int64(1000), stats.BytesSent)
	assert.Equal(t, int64(2000), stats.BytesReceived)
}

// TestConnectionInfo tests ConnectionInfo struct
func TestConnectionInfo(t *testing.T) {
	info := ConnectionInfo{
		ID:           "test-id",
		Protocol:     "tcp",
		LocalAddr:    netip.MustParseAddrPort("192.168.1.100:12345"),
		RemoteAddr:   netip.MustParseAddrPort("93.184.216.34:443"),
		RemoteHost:   "example.com",
		Action:       ActionTunnel,
		MatchedBy:    "default",
		StartTime:    time.Now(),
		BytesSent:    100,
		BytesReceived: 200,
	}

	assert.Equal(t, "test-id", info.ID)
	assert.Equal(t, "tcp", info.Protocol)
	assert.Equal(t, ActionTunnel, info.Action)
}

// TestHandleBypassPacket tests handling bypass packets
func TestHandleBypassPacket(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	packet := &IPPacket{
		DstIP:   netip.MustParseAddr("192.168.1.1"),
		DstPort: 80,
	}
	decision := Decision{
		Action:    ActionBypass,
		Reason:    "test",
		MatchedBy: "ip",
	}

	// Should not panic
	m.handleBypassPacket(packet, decision)
}

// TestHandleTunnelPacketNoConnector tests tunnel handling without connector
func TestHandleTunnelPacketNoConnector(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	packet := &IPPacket{
		Protocol: ProtocolTCP,
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		DstPort:  443,
	}
	decision := Decision{
		Action:    ActionTunnel,
		Reason:    "test",
		MatchedBy: "default",
	}

	// Should not panic, just log and return
	m.handleTunnelPacket(packet, decision)
}

// TestHandleUDPPacket tests UDP packet handling
func TestHandleUDPPacket(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	m.serverConn = &mockServerConnector{}

	packet := &IPPacket{
		Protocol: ProtocolUDP,
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		DstPort:  53,
	}

	// Should not panic
	m.handleUDPPacket(packet)
}

// TestForwardOnConnection tests forwarding on an existing connection
func TestForwardOnConnection(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	m.connTracker = NewConnTracker()
	defer m.connTracker.Close()

	mc := &mockConn{}
	conn := &TrackedConnection{
		Key: ConnKey{
			SrcIP:    netip.MustParseAddr("192.168.1.100"),
			DstIP:    netip.MustParseAddr("93.184.216.34"),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: ProtocolTCP,
		},
		ProxyConn: mc,
	}
	m.connTracker.Add(conn)

	// Empty payload
	packet := &IPPacket{
		Payload: nil,
	}
	m.forwardOnConnection(conn, packet)
	assert.Nil(t, mc.writeData)

	// With payload
	packet = &IPPacket{
		Payload: []byte("test data"),
	}
	m.forwardOnConnection(conn, packet)
	assert.Equal(t, []byte("test data"), mc.writeData)

	// With write error
	mc.writeErr = errors.New("write error")
	m.forwardOnConnection(conn, packet)
	// Connection should be removed
	assert.Nil(t, m.connTracker.Get(conn.Key))
}

// TestHandleTCPPacketNotSYN tests TCP handling for non-SYN packets
func TestHandleTCPPacketNotSYN(t *testing.T) {
	cfg := DefaultConfig()
	m, err := New(cfg)
	require.NoError(t, err)

	m.connTracker = NewConnTracker()
	defer m.connTracker.Close()

	m.serverConn = &mockServerConnector{}

	// Non-SYN packet without existing connection
	packet := &IPPacket{
		Protocol: ProtocolTCP,
		SrcIP:    netip.MustParseAddr("192.168.1.100"),
		DstIP:    netip.MustParseAddr("93.184.216.34"),
		SrcPort:  12345,
		DstPort:  443,
		TCPFlags: TCPFlagACK, // ACK only, not SYN
	}

	// Should not create new connection
	m.handleTCPPacket(packet)
	assert.Zero(t, m.connTracker.Count())
}

// TestManagerRemoveSplitTunnelDomain tests removing domains from split tunnel
func TestManagerRemoveSplitTunnelDomain(t *testing.T) {
	tests := []struct {
		name           string
		initialDomains []string
		removePattern  string
		wantErr        bool
		remaining      int
	}{
		{
			name:           "remove existing domain",
			initialDomains: []string{"*.example.com", "*.test.com"},
			removePattern:  "*.example.com",
			wantErr:        false,
			remaining:      1,
		},
		{
			name:           "remove non-existent domain",
			initialDomains: []string{"*.example.com"},
			removePattern:  "*.nonexistent.com",
			wantErr:        true,
			remaining:      1,
		},
		{
			name:           "remove from empty list",
			initialDomains: []string{},
			removePattern:  "*.example.com",
			wantErr:        true,
			remaining:      0,
		},
		{
			name:           "remove last domain",
			initialDomains: []string{"*.example.com"},
			removePattern:  "*.example.com",
			wantErr:        false,
			remaining:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SplitTunnel.Domains = tt.initialDomains
			m, err := New(cfg)
			require.NoError(t, err)

			err = m.RemoveSplitTunnelDomain(tt.removePattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Len(t, m.config.SplitTunnel.Domains, tt.remaining)
		})
	}
}

// TestManagerRemoveSplitTunnelDomain_WithEngine tests domain removal with split engine
func TestManagerRemoveSplitTunnelDomain_WithEngine(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SplitTunnel.Domains = []string{"*.example.com", "*.test.com"}
	m, err := New(cfg)
	require.NoError(t, err)

	// Initialize split engine
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{
		Mode:    "exclude",
		Domains: cfg.SplitTunnel.Domains,
	}, nil)

	err = m.RemoveSplitTunnelDomain("*.example.com")
	assert.NoError(t, err)
	assert.Len(t, m.config.SplitTunnel.Domains, 1)
	assert.NotContains(t, m.config.SplitTunnel.Domains, "*.example.com")
}

// TestManagerRemoveSplitTunnelDomain_NilManager tests nil manager
func TestManagerRemoveSplitTunnelDomain_NilManager(t *testing.T) {
	var m *Manager
	err := m.RemoveSplitTunnelDomain("*.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestManagerRemoveSplitTunnelIP tests removing IPs from split tunnel
func TestManagerRemoveSplitTunnelIP(t *testing.T) {
	tests := []struct {
		name       string
		initialIPs []string
		removeCIDR string
		wantErr    bool
		remaining  int
	}{
		{
			name:       "remove existing CIDR",
			initialIPs: []string{"10.0.0.0/8", "192.168.0.0/16"},
			removeCIDR: "10.0.0.0/8",
			wantErr:    false,
			remaining:  1,
		},
		{
			name:       "remove non-existent CIDR",
			initialIPs: []string{"10.0.0.0/8"},
			removeCIDR: "172.16.0.0/12",
			wantErr:    true,
			remaining:  1,
		},
		{
			name:       "remove from empty list",
			initialIPs: []string{},
			removeCIDR: "10.0.0.0/8",
			wantErr:    true,
			remaining:  0,
		},
		{
			name:       "remove last IP",
			initialIPs: []string{"10.0.0.0/8"},
			removeCIDR: "10.0.0.0/8",
			wantErr:    false,
			remaining:  0,
		},
		{
			name:       "remove single IP",
			initialIPs: []string{"192.168.1.1", "10.0.0.1"},
			removeCIDR: "192.168.1.1",
			wantErr:    false,
			remaining:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SplitTunnel.IPs = tt.initialIPs
			m, err := New(cfg)
			require.NoError(t, err)

			err = m.RemoveSplitTunnelIP(tt.removeCIDR)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Len(t, m.config.SplitTunnel.IPs, tt.remaining)
		})
	}
}

// TestManagerRemoveSplitTunnelIP_WithEngine tests IP removal with split engine
func TestManagerRemoveSplitTunnelIP_WithEngine(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SplitTunnel.IPs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	m, err := New(cfg)
	require.NoError(t, err)

	// Initialize split engine
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{
		Mode: "exclude",
		IPs:  cfg.SplitTunnel.IPs,
	}, nil)

	err = m.RemoveSplitTunnelIP("10.0.0.0/8")
	assert.NoError(t, err)
	assert.Len(t, m.config.SplitTunnel.IPs, 1)
	assert.NotContains(t, m.config.SplitTunnel.IPs, "10.0.0.0/8")
}

// TestManagerRemoveSplitTunnelIP_NilManager tests nil manager
func TestManagerRemoveSplitTunnelIP_NilManager(t *testing.T) {
	var m *Manager
	err := m.RemoveSplitTunnelIP("10.0.0.0/8")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestManagerSetSplitTunnelMode tests setting split tunnel mode
func TestManagerSetSplitTunnelMode(t *testing.T) {
	tests := []struct {
		name        string
		initialMode string
		newMode     string
		wantErr     bool
	}{
		{
			name:        "exclude to include",
			initialMode: "exclude",
			newMode:     "include",
			wantErr:     false,
		},
		{
			name:        "include to exclude",
			initialMode: "include",
			newMode:     "exclude",
			wantErr:     false,
		},
		{
			name:        "same mode",
			initialMode: "exclude",
			newMode:     "exclude",
			wantErr:     false,
		},
		{
			name:        "invalid mode",
			initialMode: "exclude",
			newMode:     "invalid",
			wantErr:     true,
		},
		{
			name:        "empty mode",
			initialMode: "exclude",
			newMode:     "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SplitTunnel.Mode = tt.initialMode
			m, err := New(cfg)
			require.NoError(t, err)

			err = m.SetSplitTunnelMode(tt.newMode)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.initialMode, m.config.SplitTunnel.Mode)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.newMode, m.config.SplitTunnel.Mode)
			}
		})
	}
}

// TestManagerSetSplitTunnelMode_WithEngine tests mode change with split engine
func TestManagerSetSplitTunnelMode_WithEngine(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SplitTunnel.Mode = "exclude"
	m, err := New(cfg)
	require.NoError(t, err)

	// Initialize split engine
	m.splitEngine, _ = NewSplitTunnelEngine(SplitTunnelConfig{Mode: "exclude"}, nil)

	err = m.SetSplitTunnelMode("include")
	assert.NoError(t, err)
	assert.Equal(t, "include", m.config.SplitTunnel.Mode)
}

// TestManagerSetSplitTunnelMode_NilManager tests nil manager
func TestManagerSetSplitTunnelMode_NilManager(t *testing.T) {
	var m *Manager
	err := m.SetSplitTunnelMode("exclude")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}
