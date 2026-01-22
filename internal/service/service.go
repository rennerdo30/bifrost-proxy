// Package service provides cross-platform system service management.
package service

import (
	"bytes"
	"fmt"
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

// Manager handles service installation and management.
type Manager struct {
	config Config
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

	return &Manager{config: cfg}, nil
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
	if err := os.WriteFile(unitPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write unit file: %w (try running with sudo)", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", m.config.Name).Run(); err != nil {
		return fmt.Errorf("enable service: %w", err)
	}

	fmt.Printf("Service installed: %s\n", unitPath)
	fmt.Printf("Start with: sudo systemctl start %s\n", m.config.Name)
	return nil
}

func (m *Manager) uninstallSystemd() error {
	// Stop service (ignore errors if not running)
	_ = exec.Command("systemctl", "stop", m.config.Name).Run()

	// Disable service
	_ = exec.Command("systemctl", "disable", m.config.Name).Run()

	// Remove unit file
	unitPath := m.systemdPath()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	// Reload systemd
	_ = exec.Command("systemctl", "daemon-reload").Run()

	fmt.Printf("Service uninstalled: %s\n", m.config.Name)
	return nil
}

func (m *Manager) statusSystemd() (string, error) {
	unitPath := m.systemdPath()
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return "not installed", nil
	}

	out, err := exec.Command("systemctl", "is-active", m.config.Name).Output()
	if err != nil {
		return "installed (inactive)", nil
	}

	status := strings.TrimSpace(string(out))
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
	home, _ := os.UserHomeDir()
	userAgentPath := filepath.Join(home, "Library", "LaunchAgents", m.config.Name+".plist")

	// Check if we can write to LaunchDaemons
	daemonPath := filepath.Join("/Library/LaunchDaemons", m.config.Name+".plist")
	if f, err := os.OpenFile(daemonPath, os.O_WRONLY|os.O_CREATE, 0644); err == nil {
		f.Close()
		os.Remove(daemonPath)
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
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Write plist file
	if err := os.WriteFile(plistPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Load service
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("load service: %w", err)
	}

	fmt.Printf("Service installed: %s\n", plistPath)
	fmt.Printf("Service is now running.\n")
	return nil
}

func (m *Manager) uninstallLaunchd() error {
	plistPath := m.launchdPath()

	// Unload service (ignore errors if not loaded)
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist file
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	fmt.Printf("Service uninstalled: %s\n", m.config.Name)
	return nil
}

func (m *Manager) statusLaunchd() (string, error) {
	plistPath := m.launchdPath()
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return "not installed", nil
	}

	out, err := exec.Command("launchctl", "list", m.config.Name).Output()
	if err != nil {
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

	cmd := exec.Command("sc", "create", m.config.Name,
		"binPath=", binPath,
		"DisplayName=", m.config.Description,
		"start=", "auto")

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create service: %w\n%s", err, string(out))
	}

	// Set description
	_ = exec.Command("sc", "description", m.config.Name, m.config.Description).Run()

	fmt.Printf("Service installed: %s\n", m.config.Name)
	fmt.Printf("Start with: sc start %s\n", m.config.Name)
	return nil
}

func (m *Manager) uninstallWindows() error {
	// Stop service (ignore errors)
	_ = exec.Command("sc", "stop", m.config.Name).Run()

	// Delete service
	cmd := exec.Command("sc", "delete", m.config.Name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("delete service: %w\n%s", err, string(out))
	}

	fmt.Printf("Service uninstalled: %s\n", m.config.Name)
	return nil
}

func (m *Manager) statusWindows() (string, error) {
	cmd := exec.Command("sc", "query", m.config.Name)
	out, err := cmd.Output()
	if err != nil {
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
