package backend

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OpenVPNBackend provides connections through an OpenVPN tunnel.
type OpenVPNBackend struct {
	name           string
	config         OpenVPNConfig
	cmd            *exec.Cmd
	mgmtConn       net.Conn
	localAddr      string
	startTime      time.Time
	healthy        atomic.Bool
	stats          openvpnStats
	mu             sync.RWMutex
	running        bool
	stopChan       chan struct{}
	tempConfigFile string // Temporary config file created from ConfigContent
	tempAuthFile   string // Temporary auth file created from Username/Password
}

type openvpnStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// OpenVPNConfig holds configuration for an OpenVPN backend.
type OpenVPNConfig struct {
	Name           string        `yaml:"name"`
	ConfigFile     string        `yaml:"config_file"`     // Path to .ovpn file
	ConfigContent  string        `yaml:"config_content"`  // Inline OpenVPN config content (alternative to ConfigFile)
	AuthFile       string        `yaml:"auth_file"`       // Path to auth credentials file
	Username       string        `yaml:"username"`        // Inline username (alternative to AuthFile)
	Password       string        `yaml:"password"`        // Inline password (alternative to AuthFile)
	ManagementAddr string        `yaml:"management_addr"` // Management interface address
	ManagementPort int           `yaml:"management_port"` // Management interface port
	Binary         string        `yaml:"binary"`          // Path to openvpn binary
	ExtraArgs      []string      `yaml:"extra_args"`      // Extra command line arguments
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// NewOpenVPNBackend creates a new OpenVPN backend.
func NewOpenVPNBackend(cfg OpenVPNConfig) *OpenVPNBackend {
	if cfg.Binary == "" {
		cfg.Binary = "openvpn"
	}
	if cfg.ManagementAddr == "" {
		cfg.ManagementAddr = "127.0.0.1"
	}
	if cfg.ManagementPort == 0 {
		cfg.ManagementPort = 7505
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 60 * time.Second
	}

	return &OpenVPNBackend{
		name:     cfg.Name,
		config:   cfg,
		stopChan: make(chan struct{}),
	}
}

// Name returns the backend name.
func (b *OpenVPNBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *OpenVPNBackend) Type() string {
	return "openvpn"
}

// Dial creates a connection through the OpenVPN tunnel.
// Note: OpenVPN typically works at the OS network level, so this uses
// the system's routing table. For proper isolation, use a network namespace
// or ensure the routing is configured correctly.
func (b *OpenVPNBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.RLock()
	if !b.running {
		b.mu.RUnlock()
		return nil, NewBackendError(b.name, "dial", ErrBackendNotStarted)
	}
	localAddr := b.localAddr
	b.mu.RUnlock()

	// Create a dialer that uses the VPN interface
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// If we have a local address from the VPN, use it
	if localAddr != "" {
		hostPort := net.JoinHostPort(localAddr, "0")
		laddr, err := net.ResolveTCPAddr(network, hostPort)
		if err == nil {
			dialer.LocalAddr = laddr
		}
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		b.recordError(err)
		return nil, NewBackendError(b.name, "dial", err)
	}

	b.stats.activeConns.Add(1)
	b.stats.totalConns.Add(1)

	// Wrap connection to track stats
	tracked := &TrackedConn{
		Conn: conn,
		OnClose: func(bytesRead, bytesWritten int64) {
			b.stats.activeConns.Add(-1)
			b.stats.bytesRecv.Add(bytesRead)
			b.stats.bytesSent.Add(bytesWritten)
		},
	}

	return tracked, nil
}

// DialTimeout creates a connection with a specific timeout.
func (b *OpenVPNBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes and starts the OpenVPN process.
func (b *OpenVPNBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	// Determine config file path
	configFile := b.config.ConfigFile
	if b.config.ConfigContent != "" {
		// Create temp config file from inline content
		tmpFile, err := os.CreateTemp("", "bifrost-ovpn-*.conf")
		if err != nil {
			return NewBackendError(b.name, "create temp config", err)
		}
		if _, err := tmpFile.WriteString(b.config.ConfigContent); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return NewBackendError(b.name, "write temp config", err)
		}
		tmpFile.Close()
		configFile = tmpFile.Name()
		b.tempConfigFile = configFile
	}

	// Verify config file exists
	if _, err := os.Stat(configFile); err != nil {
		return NewBackendError(b.name, "config file", err)
	}

	// Determine auth file path
	authFile := b.config.AuthFile
	if b.config.Username != "" && b.config.Password != "" {
		// Create temp auth file from inline credentials
		tmpFile, err := os.CreateTemp("", "bifrost-ovpn-auth-*")
		if err != nil {
			return NewBackendError(b.name, "create temp auth", err)
		}
		content := fmt.Sprintf("%s\n%s\n", b.config.Username, b.config.Password)
		if _, err := tmpFile.WriteString(content); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return NewBackendError(b.name, "write temp auth", err)
		}
		if err := tmpFile.Chmod(0600); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return NewBackendError(b.name, "chmod temp auth", err)
		}
		tmpFile.Close()
		authFile = tmpFile.Name()
		b.tempAuthFile = authFile
	}

	// Build command arguments
	args := []string{
		"--config", configFile,
		"--management", b.config.ManagementAddr, fmt.Sprintf("%d", b.config.ManagementPort),
		"--management-query-passwords",
		"--daemon",
	}

	if authFile != "" {
		args = append(args, "--auth-user-pass", authFile)
	}

	args = append(args, b.config.ExtraArgs...)

	// Start OpenVPN process
	b.cmd = exec.CommandContext(ctx, b.config.Binary, args...)
	// Set working directory to config file location (for relative paths in config)
	if b.config.ConfigFile != "" {
		b.cmd.Dir = filepath.Dir(b.config.ConfigFile)
	} else if b.tempConfigFile != "" {
		b.cmd.Dir = filepath.Dir(b.tempConfigFile)
	}

	if err := b.cmd.Start(); err != nil {
		// Clean up temp files on failure to prevent credential leakage
		b.cleanupTempFiles()
		return NewBackendError(b.name, "start openvpn", err)
	}

	// Wait for management interface to be available
	if err := b.waitForManagement(ctx); err != nil {
		b.cmd.Process.Kill()
		// Clean up temp files on failure to prevent credential leakage
		b.cleanupTempFiles()
		return NewBackendError(b.name, "connect management", err)
	}

	// Get local IP address from OpenVPN
	if err := b.queryLocalAddress(); err != nil {
		// Non-fatal, but log warning
		b.recordError(err)
	}

	b.running = true
	b.startTime = time.Now()
	b.healthy.Store(true)

	// Start health monitoring goroutine
	go b.monitor()

	return nil
}

func (b *OpenVPNBackend) waitForManagement(ctx context.Context) error {
	deadline := time.Now().Add(b.config.ConnectTimeout)
	addr := net.JoinHostPort(b.config.ManagementAddr, fmt.Sprintf("%d", b.config.ManagementPort))

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			b.mgmtConn = conn
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for management interface")
}

func (b *OpenVPNBackend) queryLocalAddress() error {
	if b.mgmtConn == nil {
		return fmt.Errorf("management connection not available")
	}

	// Send state command
	fmt.Fprintf(b.mgmtConn, "state\n")

	reader := bufio.NewReader(b.mgmtConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if line == "END" {
			break
		}

		// Parse state line: timestamp,state,description,local_ip,...
		parts := strings.Split(line, ",")
		if len(parts) >= 4 && parts[1] == "CONNECTED" {
			b.localAddr = parts[3]
			return nil
		}
	}

	return nil
}

func (b *OpenVPNBackend) monitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.mu.RLock()
			if !b.running {
				b.mu.RUnlock()
				return
			}
			// Check if process is still running while holding the lock
			cmd := b.cmd
			b.mu.RUnlock()

			// Only check process state if we have a command
			if cmd != nil && cmd.ProcessState != nil && cmd.ProcessState.Exited() {
				b.healthy.Store(false)
				b.recordError(fmt.Errorf("openvpn process exited"))
			}
		}
	}
}

// Stop shuts down the OpenVPN process.
func (b *OpenVPNBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil
	}

	close(b.stopChan)

	// Close management connection
	if b.mgmtConn != nil {
		// Send quit command
		fmt.Fprintf(b.mgmtConn, "signal SIGTERM\n")
		b.mgmtConn.Close()
		b.mgmtConn = nil
	}

	// Wait for process to exit
	if b.cmd != nil && b.cmd.Process != nil {
		done := make(chan error, 1)
		go func() {
			done <- b.cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			b.cmd.Process.Kill()
		case <-ctx.Done():
			b.cmd.Process.Kill()
		}
	}

	b.running = false
	b.healthy.Store(false)
	b.stopChan = make(chan struct{})

	// Clean up temp files containing sensitive credentials
	b.cleanupTempFiles()

	return nil
}

// IsHealthy returns the health status.
func (b *OpenVPNBackend) IsHealthy() bool {
	return b.healthy.Load()
}

// Stats returns backend statistics.
func (b *OpenVPNBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "openvpn",
		Healthy:           b.healthy.Load(),
		ActiveConnections: b.stats.activeConns.Load(),
		TotalConnections:  b.stats.totalConns.Load(),
		BytesSent:         b.stats.bytesSent.Load(),
		BytesReceived:     b.stats.bytesRecv.Load(),
		Errors:            b.stats.errors.Load(),
		LastError:         lastErr,
		LastErrorTime:     lastErrTime,
		Uptime:            time.Since(b.startTime),
	}
}

func (b *OpenVPNBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}

// cleanupTempFiles removes any temporary files created for this backend.
// This is called on both successful Stop() and on Start() failure.
func (b *OpenVPNBackend) cleanupTempFiles() {
	if b.tempConfigFile != "" {
		os.Remove(b.tempConfigFile)
		b.tempConfigFile = ""
	}
	if b.tempAuthFile != "" {
		os.Remove(b.tempAuthFile)
		b.tempAuthFile = ""
	}
}
