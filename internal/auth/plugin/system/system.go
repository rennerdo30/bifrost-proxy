//go:build !windows
// +build !windows

// Package system provides system (PAM) authentication for Bifrost.
// On Unix/Darwin, this uses PAM or su for authentication.
// On Windows, see system_windows.go which uses the LogonUser API.
package system

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("system", &plugin{})
}

// plugin implements the auth.Plugin interface for system authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "system"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "System/PAM authentication (Unix/macOS)"
}

// Create creates a new SystemAuthenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	allowedUsers := make(map[string]bool)
	for _, u := range cfg.allowedUsers {
		allowedUsers[u] = true
	}

	allowedGroups := make(map[string]bool)
	for _, g := range cfg.allowedGroups {
		allowedGroups[g] = true
	}

	return &Authenticator{
		service:       cfg.service,
		allowedUsers:  allowedUsers,
		allowedGroups: allowedGroups,
	}, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"service":        "login",
		"allowed_users":  []string{},
		"allowed_groups": []string{},
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "service": {
      "type": "string",
      "description": "PAM service name to use (default: 'login')"
    },
    "allowed_users": {
      "type": "array",
      "items": {"type": "string"},
      "description": "List of allowed usernames (empty = all users)"
    },
    "allowed_groups": {
      "type": "array",
      "items": {"type": "string"},
      "description": "List of allowed groups (user must be in at least one, empty = all groups)"
    }
  }
}`
}

type systemConfig struct {
	service       string
	allowedUsers  []string
	allowedGroups []string
}

func parseConfig(config map[string]any) (*systemConfig, error) {
	cfg := &systemConfig{
		service: "login",
	}

	if config == nil {
		return cfg, nil
	}

	if service, ok := config["service"].(string); ok && service != "" {
		cfg.service = service
	}

	if usersAny, ok := config["allowed_users"]; ok {
		cfg.allowedUsers = parseStringSlice(usersAny)
	}

	if groupsAny, ok := config["allowed_groups"]; ok {
		cfg.allowedGroups = parseStringSlice(groupsAny)
	}

	return cfg, nil
}

func parseStringSlice(v any) []string {
	var result []string
	switch s := v.(type) {
	case []any:
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	case []string:
		result = s
	}
	return result
}

// Authenticator implements system-level authentication.
// On Unix systems, it uses PAM or su to validate credentials.
type Authenticator struct {
	service       string
	allowedUsers  map[string]bool
	allowedGroups map[string]bool
}

// Authenticate validates credentials against the system.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if username == "" || password == "" {
		return nil, auth.ErrInvalidCredentials
	}

	// Check if user is allowed
	if len(a.allowedUsers) > 0 && !a.allowedUsers[username] {
		return nil, auth.ErrInvalidCredentials
	}

	// Look up user to verify they exist
	sysUser, err := user.Lookup(username)
	if err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	// Validate password using platform-specific method
	if !a.validatePassword(ctx, username, password) {
		return nil, auth.ErrInvalidCredentials
	}

	// Get user groups
	groups, err := a.getUserGroups(sysUser)
	if err != nil {
		groups = []string{}
	}

	// Check if user is in allowed groups
	if len(a.allowedGroups) > 0 {
		inAllowedGroup := false
		for _, g := range groups {
			if a.allowedGroups[g] {
				inAllowedGroup = true
				break
			}
		}
		if !inAllowedGroup {
			return nil, auth.ErrInvalidCredentials
		}
	}

	return &auth.UserInfo{
		Username: username,
		FullName: sysUser.Name,
		Groups:   groups,
		Metadata: map[string]string{
			"uid":      sysUser.Uid,
			"gid":      sysUser.Gid,
			"home_dir": sysUser.HomeDir,
		},
	}, nil
}

// validatePassword validates the password using platform-specific methods.
func (a *Authenticator) validatePassword(ctx context.Context, username, password string) bool {
	switch runtime.GOOS {
	case "darwin":
		return a.validateDarwin(ctx, username, password)
	case "linux":
		return a.validateLinux(ctx, username, password)
	default:
		// No supported password validation backend for this platform. Fail
		// closed rather than reporting a false success.
		slog.Warn("system auth: no supported password validation backend for platform",
			"platform", runtime.GOOS)
		return false
	}
}

// validateDarwin validates password on macOS using dscl, which authenticates
// directly against the local directory service without needing a TTY.
func (a *Authenticator) validateDarwin(ctx context.Context, username, password string) bool {
	cmd := exec.CommandContext(ctx, "dscl", ".", "-authonly", username, password) //nolint:gosec // G204: System auth requires OS-level commands
	return cmd.Run() == nil
}

// validateLinux validates a password on Linux.
//
// A real implementation must call into PAM (which also honors the configured
// 'service' field). The previous "su with password on stdin" approach did not
// work: su reads the password from the controlling TTY (/dev/tty), not stdin,
// so feeding the password to stdin authenticates nothing and could even succeed
// spuriously when run from a privileged context. Because this is an
// authentication primitive, we fail closed instead of shipping that unsafe
// behavior.
//
// To enable Linux system auth, build with a cgo-based PAM backend (not yet
// implemented). See the 'system' auth docs.
func (a *Authenticator) validateLinux(_ context.Context, _, _ string) bool {
	slog.Warn("system auth: PAM password validation is not implemented on Linux; " +
		"failing closed (the 'service' field is therefore unused on this platform)")
	return false
}

// getUserGroups gets the groups for a user.
func (a *Authenticator) getUserGroups(sysUser *user.User) ([]string, error) {
	groupIDs, err := sysUser.GroupIds()
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(groupIDs))
	for _, gid := range groupIDs {
		if g, err := user.LookupGroupId(gid); err == nil {
			groups = append(groups, g.Name)
		}
	}

	return groups, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return fmt.Sprintf("system-%s", strings.ToLower(runtime.GOOS))
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "system"
}
