// Package service provides cross-platform system service management.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// ServiceType identifies whether this is a server or client service.
type ServiceType string

const (
	// TypeServer is the bifrost server service.
	TypeServer ServiceType = "server"
	// TypeClient is the bifrost client service.
	TypeClient ServiceType = "client"

	systemctlCommand      = "systemctl"
	launchctlCommand      = "launchctl"
	windowsServiceCommand = "sc"
)

// Config holds service installation configuration.
type Config struct {
	// Type is either "server" or "client"
	Type ServiceType
	// Name is the service name (e.g., "bifrost-server")
	Name string
	// Description is a human-readable service description
	Description string
	// BinaryPath is the absolute path to the executable
	BinaryPath string
	// ConfigPath is the absolute path to the config file
	ConfigPath string
	// WorkingDir is the working directory for the service
	WorkingDir string
}

type controlAction string

const (
	controlStart controlAction = "start"
	controlStop  controlAction = "stop"
)

// Manager handles service installation and management.
type Manager struct {
	config Config

	// runControl executes a platform service-control command. Kept injectable
	// so Start/Stop can be regression-tested without controlling a real host
	// service manager.
	runControl func(*exec.Cmd) ([]byte, error)
}

// New creates a new service manager.
func New(cfg Config) (*Manager, error) {
	// Resolve binary path to absolute
	if !filepath.IsAbs(cfg.BinaryPath) {
		abs, err := filepath.Abs(cfg.BinaryPath)
		if err != nil {
			return nil, fmt.Errorf("resolve binary path: %w", err)
		}
		cfg.BinaryPath = abs
	}

	// Resolve config path to absolute
	if !filepath.IsAbs(cfg.ConfigPath) {
		abs, err := filepath.Abs(cfg.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("resolve config path: %w", err)
		}
		cfg.ConfigPath = abs
	}

	// Default working directory to binary directory
	if cfg.WorkingDir == "" {
		cfg.WorkingDir = filepath.Dir(cfg.BinaryPath)
	}

	// Set default name
	if cfg.Name == "" {
		cfg.Name = "bifrost-" + string(cfg.Type)
	}

	// Set default description
	if cfg.Description == "" {
		if cfg.Type == TypeServer {
			cfg.Description = "Bifrost Proxy Server"
		} else {
			cfg.Description = "Bifrost Proxy Client"
		}
	}

	return &Manager{
		config: cfg,
		runControl: func(cmd *exec.Cmd) ([]byte, error) {
			return cmd.CombinedOutput()
		},
	}, nil
}

// Install installs the service on the current platform.
func (m *Manager) Install() error {
	// Verify binary exists
	if _, err := os.Stat(m.config.BinaryPath); err != nil {
		return fmt.Errorf("binary not found: %s", m.config.BinaryPath)
	}

	// Verify config exists
	if _, err := os.Stat(m.config.ConfigPath); err != nil {
		return fmt.Errorf("config not found: %s", m.config.ConfigPath)
	}

	switch runtime.GOOS {
	case "linux":
		return m.installSystemd()
	case "darwin":
		return m.installLaunchd()
	case "windows":
		return m.installWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Uninstall removes the service from the current platform.
func (m *Manager) Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return m.uninstallSystemd()
	case "darwin":
		return m.uninstallLaunchd()
	case "windows":
		return m.uninstallWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Start starts the installed service on the current platform.
func (m *Manager) Start() error {
	return m.control(controlStart)
}

// Stop stops the installed service without uninstalling it.
func (m *Manager) Stop() error {
	return m.control(controlStop)
}

func (m *Manager) control(action controlAction) error {
	cmd, err := m.controlCommand(runtime.GOOS, action)
	if err != nil {
		return err
	}

	out, err := m.runControl(cmd)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return fmt.Errorf("%s service: %w: %s", action, err, detail)
		}
		return fmt.Errorf("%s service: %w", action, err)
	}

	slog.Info("service control completed", "action", action, "name", m.config.Name)
	return nil
}

func (m *Manager) controlCommand(platform string, action controlAction) (*exec.Cmd, error) {
	switch platform {
	case "linux":
		return exec.Command(systemctlCommand, string(action), m.config.Name), nil //nolint:gosec // G204: service name is from validated config
	case "darwin":
		verb := "load"
		if action == controlStop {
			verb = "unload"
		}
		return exec.Command(launchctlCommand, verb, m.launchdPath()), nil //nolint:gosec // G204: plist path is generated from validated config
	case "windows":
		return exec.Command(windowsServiceCommand, string(action), m.config.Name), nil //nolint:gosec // G204: service name is from validated config
	default:
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
}

// Status returns the current service status.
func (m *Manager) Status() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return m.statusSystemd()
	case "darwin":
		return m.statusLaunchd()
	case "windows":
		return m.statusWindows()
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Platform returns the current platform name.
func Platform() string {
	return runtime.GOOS
}

// --- Linux (systemd) ---

const systemdTemplate = `[Unit]
Description={{.Description}}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} -c {{.ConfigPath}}
ExecReload=/bin/kill -HUP $MAINPID
WorkingDirectory={{.WorkingDir}}
Restart=always
RestartSec=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier={{.Name}}

[Install]
WantedBy=multi-user.target
`

func (m *Manager) systemdPath() string {
	return filepath.Join("/etc/systemd/system", m.config.Name+".service")
}

func (m *Manager) installSystemd() error {
	// Generate unit file
	tmpl, err := template.New("systemd").Parse(systemdTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, m.config); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	// Write unit file
	unitPath := m.systemdPath()
	if err := os.WriteFile(unitPath, buf.Bytes(), 0600); err != nil { //nolint:gosec // G302: Service file permissions are appropriate
		return fmt.Errorf("write unit file: %w (try running with sudo)", err)
	}

	// Reload systemd
	if err := exec.Command(systemctlCommand, "daemon-reload").Run(); err != nil { //nolint:gosec // G204: no user input
		return fmt.Errorf("reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command(systemctlCommand, "enable", m.config.Name).Run(); err != nil { //nolint:gosec // G204: service name is from validated config
		return fmt.Errorf("enable service: %w", err)
	}

	slog.Info("service installed", "unit", unitPath, "start_command", "sudo systemctl start "+m.config.Name)
	return nil
}

func (m *Manager) uninstallSystemd() error {
	// Stop service (ignore errors if not running)
	_ = exec.Command(systemctlCommand, "stop", m.config.Name).Run() //nolint:errcheck,gosec // G204: service name is from validated config; ignoring error as service may not be running

	// Disable service
	_ = exec.Command(systemctlCommand, "disable", m.config.Name).Run() //nolint:errcheck,gosec // G204: service name is from validated config; ignoring error as service may not be enabled

	// Remove unit file
	unitPath := m.systemdPath()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	// Reload systemd
	_ = exec.Command(systemctlCommand, "daemon-reload").Run() //nolint:errcheck,gosec // G204: no user input; best effort reload

	slog.Info("service uninstalled", "name", m.config.Name)
	return nil
}

// commandRan reports whether err means the command executed and returned a
// non-zero status — a meaningful answer from the tool — as opposed to not
// running at all (binary missing, permission denied). The status helpers used
// to launder BOTH cases into confident status strings with a nil error, so
// "systemctl is not on PATH" read exactly like "the service is stopped".
func commandRan(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

func (m *Manager) statusSystemd() (string, error) {
	unitPath := m.systemdPath()
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return "not installed", nil
	}

	out, err := exec.Command(systemctlCommand, "is-active", m.config.Name).Output() //nolint:gosec // G204: service name is from validated config
	if err != nil && !commandRan(err) {
		// systemctl itself could not be executed: that is an unknown state,
		// not an inactive service.
		return "", fmt.Errorf("query systemd status: %w", err)
	}
	// `systemctl is-active` exits non-zero for every non-active state while
	// still printing the state (inactive, failed, activating, ...) on stdout.
	status := strings.TrimSpace(string(out))
	if status == "" {
		status = "inactive"
	}
	return fmt.Sprintf("installed (%s)", status), nil
}

// --- macOS (launchd) ---

const launchdTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Name}}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{{.BinaryPath}}</string>
        <string>-c</string>
        <string>{{.ConfigPath}}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>WorkingDirectory</key>
    <string>{{.WorkingDir}}</string>

    <key>StandardOutPath</key>
    <string>/tmp/{{.Name}}.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/{{.Name}}.error.log</string>
</dict>
</plist>
`

func (m *Manager) launchdPath() string {
	// Use LaunchDaemons for system-wide (requires sudo)
	// Use LaunchAgents for user-level
	home, _ := os.UserHomeDir() //nolint:errcheck // Fall back to empty string if home dir unavailable
	userAgentPath := filepath.Join(home, "Library", "LaunchAgents", m.config.Name+".plist")

	// Prefer LaunchDaemons when running with the privileges to manage it.
	// The old probe CREATED the real plist path and deleted it again — a
	// destructive writability test that could clobber or momentarily remove
	// an installed service's plist. Root can always write there; nothing
	// else can, so the euid check answers the same question harmlessly.
	daemonPath := filepath.Join("/Library/LaunchDaemons", m.config.Name+".plist")
	if os.Geteuid() == 0 {
		return daemonPath
	}

	return userAgentPath
}

func (m *Manager) installLaunchd() error {
	// Generate plist
	tmpl, err := template.New("launchd").Parse(launchdTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, m.config); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	// Ensure directory exists
	plistPath := m.launchdPath()
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil { //nolint:gosec // G301: Service directory permissions are appropriate
		return fmt.Errorf("create directory: %w", err)
	}

	// Write plist file
	if err := os.WriteFile(plistPath, buf.Bytes(), 0600); err != nil { //nolint:gosec // G302: Service file permissions are appropriate
		return fmt.Errorf("write plist: %w", err)
	}

	// Load service
	if err := exec.Command(launchctlCommand, "load", plistPath).Run(); err != nil { //nolint:gosec // G204: plist path is generated from validated config
		return fmt.Errorf("load service: %w", err)
	}

	slog.Info("service installed and running", "plist", plistPath)
	return nil
}

func (m *Manager) uninstallLaunchd() error {
	plistPath := m.launchdPath()

	// Unload service (ignore errors if not loaded)
	_ = exec.Command(launchctlCommand, "unload", plistPath).Run() //nolint:errcheck,gosec // G204: plist path from config; ignoring error as service may not be loaded

	// Remove plist file
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	slog.Info("service uninstalled", "name", m.config.Name)
	return nil
}

func (m *Manager) statusLaunchd() (string, error) {
	plistPath := m.launchdPath()
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return "not installed", nil
	}

	out, err := exec.Command(launchctlCommand, "list", m.config.Name).Output() //nolint:gosec // G204: service name is from validated config
	if err != nil {
		if !commandRan(err) {
			// launchctl itself could not be executed: unknown state, not a
			// stopped service.
			return "", fmt.Errorf("query launchd status: %w", err)
		}
		// launchctl list exits non-zero when the job is not loaded.
		return "installed (not running)", nil
	}

	if strings.Contains(string(out), m.config.Name) {
		return "installed (running)", nil
	}

	return "installed (not running)", nil
}

// --- Windows ---

func (m *Manager) installWindows() error {
	// Create service using sc.exe
	binPath := fmt.Sprintf(`"%s" -c "%s"`, m.config.BinaryPath, m.config.ConfigPath)

	cmd := exec.Command(windowsServiceCommand, "create", m.config.Name, //nolint:gosec // G204: service name and paths are from validated config
		"binPath=", binPath,
		"DisplayName=", m.config.Description,
		"start=", "auto")

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create service: %w\n%s", err, string(out))
	}

	// Set description
	_ = exec.Command(windowsServiceCommand, "description", m.config.Name, m.config.Description).Run() //nolint:errcheck,gosec // G204: service name from config; best effort description set

	slog.Info("service installed", "name", m.config.Name, "start_command", "sc start "+m.config.Name)
	return nil
}

func (m *Manager) uninstallWindows() error {
	// Stop service (ignore errors)
	_ = exec.Command(windowsServiceCommand, "stop", m.config.Name).Run() //nolint:errcheck,gosec // G204: service name from config; ignoring error as service may not be running

	// Delete service
	cmd := exec.Command(windowsServiceCommand, "delete", m.config.Name) //nolint:gosec // G204: service name is from validated config
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("delete service: %w\n%s", err, string(out))
	}

	slog.Info("service uninstalled", "name", m.config.Name)
	return nil
}

func (m *Manager) statusWindows() (string, error) {
	cmd := exec.Command(windowsServiceCommand, "query", m.config.Name) //nolint:gosec // G204: service name is from validated config
	out, err := cmd.Output()
	if err != nil {
		if !commandRan(err) {
			// sc.exe itself could not be executed: unknown state, not an
			// uninstalled service.
			return "", fmt.Errorf("query service status: %w", err)
		}
		// sc query exits non-zero (1060) when the service does not exist.
		return "not installed", nil
	}

	output := string(out)
	if strings.Contains(output, "RUNNING") {
		return "installed (running)", nil
	} else if strings.Contains(output, "STOPPED") {
		return "installed (stopped)", nil
	}

	return "installed", nil
}
