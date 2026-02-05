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
	"strings"
	"sync"
	"time"
)

// State represents the OpenVPN connection state.
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateExiting      State = "exiting"
)

// Process manages an OpenVPN process.
type Process struct {
	config   *Config
	cmd      *exec.Cmd
	state    State
	localIP  string
	remoteIP string
	mgmtConn net.Conn
	stopCh   chan struct{}
	waitDone chan struct{}
	stateCh  chan State
	mu       sync.RWMutex
	logger   *slog.Logger
}

// ProcessConfig holds configuration for the OpenVPN process.
type ProcessConfig struct {
	Config        *Config
	Logger        *slog.Logger
	OnStateChange func(State)
}

// NewProcess creates a new OpenVPN process manager.
func NewProcess(cfg ProcessConfig) *Process {
	return &Process{
		config:  cfg.Config,
		state:   StateDisconnected,
		stopCh:  make(chan struct{}),
		stateCh: make(chan State, 10),
		logger:  cfg.Logger,
	}
}

// Start starts the OpenVPN process.
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != StateDisconnected {
		return fmt.Errorf("process already running")
	}

	// Build command arguments
	args := []string{
		"--config", p.config.ConfigFile,
		"--verb", "3",
	}

	// Add management interface if not already configured
	if p.config.Management.Port == 0 {
		p.config.Management.Address = "127.0.0.1"
		p.config.Management.Port = 7505
	}
	args = append(args, "--management", p.config.Management.Address, fmt.Sprintf("%d", p.config.Management.Port))

	// Add auth file if specified
	if p.config.AuthFile != "" {
		args = append(args, "--auth-user-pass", p.config.AuthFile)
	}

	// Create command
	p.cmd = exec.CommandContext(ctx, "openvpn", args...)
	p.cmd.Stdout = &logWriter{prefix: "openvpn", logger: p.logger}
	p.cmd.Stderr = &logWriter{prefix: "openvpn", logger: p.logger}

	// Start process
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn: %w", err)
	}

	p.setState(StateConnecting)

	// Connect to management interface
	go p.monitorManagement(ctx)

	p.waitDone = make(chan struct{})

	// Wait for process in background
	go func() {
		_ = p.cmd.Wait() //nolint:errcheck // Process exit status is signaled via channel
		close(p.waitDone)
		p.mu.Lock()
		p.setState(StateDisconnected)
		p.mu.Unlock()
	}()

	return nil
}

// Stop stops the OpenVPN process.
func (p *Process) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}

	p.setState(StateExiting)

	// Try graceful shutdown via management interface
	if p.mgmtConn != nil {
		_, _ = p.mgmtConn.Write([]byte("signal SIGTERM\n")) //nolint:errcheck // Best effort signal
		p.mgmtConn.Close()
		p.mgmtConn = nil
	}

	// Give it a moment to exit gracefully
	select {
	case <-p.waitDone:
		// Exited gracefully
	case <-time.After(5 * time.Second):
		// Force kill
		_ = p.cmd.Process.Kill() //nolint:errcheck // Best effort kill
	case <-ctx.Done():
		_ = p.cmd.Process.Kill() //nolint:errcheck // Best effort kill
	}

	p.setState(StateDisconnected)
	return nil
}

// State returns the current connection state.
func (p *Process) State() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// LocalIP returns the assigned local IP address.
func (p *Process) LocalIP() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.localIP
}

// RemoteIP returns the remote VPN gateway IP.
func (p *Process) RemoteIP() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.remoteIP
}

// StateChan returns a channel for state change notifications.
func (p *Process) StateChan() <-chan State {
	return p.stateCh
}

func (p *Process) setState(state State) {
	p.state = state
	select {
	case p.stateCh <- state:
	default:
	}
}

func (p *Process) monitorManagement(ctx context.Context) {
	// Wait a bit for OpenVPN to start
	time.Sleep(500 * time.Millisecond)

	addr := net.JoinHostPort(p.config.Management.Address, fmt.Sprintf("%d", p.config.Management.Port))

	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			p.mu.Lock()
			p.mgmtConn = conn
			p.mu.Unlock()
			p.handleManagement(ctx, conn)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (p *Process) handleManagement(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Request state notifications
	_, _ = conn.Write([]byte("state on\n")) //nolint:errcheck // Best effort management command

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			if p.logger != nil {
				configFile := ""
				if p.config != nil {
					configFile = p.config.ConfigFile
				}
				p.logger.Debug("failed to set read deadline on management connection",
					"remote_addr", conn.RemoteAddr(),
					"config_file", configFile,
					"error", err,
				)
			}
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		line = strings.TrimSpace(line)
		p.parseManagementLine(line)
	}
}

func (p *Process) parseManagementLine(line string) {
	// Parse state lines like: >STATE:1234567890,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4
	if strings.HasPrefix(line, ">STATE:") {
		parts := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
		if len(parts) >= 2 {
			state := parts[1]
			p.mu.Lock()
			switch state {
			case "CONNECTING", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES":
				p.setState(StateConnecting)
			case "CONNECTED":
				p.setState(StateConnected)
				if len(parts) >= 4 {
					p.localIP = parts[3]
				}
				if len(parts) >= 5 {
					p.remoteIP = parts[4]
				}
			case "RECONNECTING":
				p.setState(StateReconnecting)
			case "EXITING":
				p.setState(StateExiting)
			}
			p.mu.Unlock()
		}
	}
}

// logWriter writes OpenVPN output to the logger.
type logWriter struct {
	prefix string
	logger *slog.Logger
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(strings.TrimSpace(string(p)), "\n")
	for _, line := range lines {
		if line != "" {
			if w.logger != nil {
				w.logger.Debug(line)
			}
		}
	}
	return len(p), nil
}

// CreateAuthFile creates a temporary auth file with username and password.
func CreateAuthFile(username, password string) (string, error) {
	f, err := os.CreateTemp("", "ovpn-auth-*")
	if err != nil {
		return "", fmt.Errorf("create auth file: %w", err)
	}

	content := fmt.Sprintf("%s\n%s\n", username, password)
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write auth file: %w", err)
	}

	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("chmod auth file: %w", err)
	}

	f.Close()
	return f.Name(), nil
}
