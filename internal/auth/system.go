// Package auth provides system (PAM) authentication for Bifrost.
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// SystemConfig holds system authenticator configuration.
type SystemConfig struct {
	// Service is the PAM service name to use (default: "login")
	Service string

	// AllowedUsers is a list of users allowed to authenticate.
	// If empty, all system users are allowed.
	AllowedUsers []string

	// AllowedGroups is a list of groups allowed to authenticate.
	// Users must be in at least one of these groups.
	// If empty, all groups are allowed.
	AllowedGroups []string
}

// SystemAuthenticator implements system-level authentication.
// On Unix systems, it uses PAM or su to validate credentials.
// Note: Windows is not currently supported. Use native, ldap, or oauth authentication instead.
type SystemAuthenticator struct {
	config        SystemConfig
	allowedUsers  map[string]bool
	allowedGroups map[string]bool
}

// NewSystemAuthenticator creates a new system authenticator.
func NewSystemAuthenticator(cfg SystemConfig) (*SystemAuthenticator, error) {
	// Check for Windows - system auth is not supported
	if runtime.GOOS == "windows" {
		slog.Warn("system authentication is not supported on Windows",
			"platform", runtime.GOOS,
			"recommendation", "use native, ldap, or oauth authentication instead")
		return nil, fmt.Errorf("%w: system authentication is not supported on Windows - use native, ldap, or oauth instead", ErrAuthMethodUnsupported)
	}

	if cfg.Service == "" {
		cfg.Service = "login"
	}

	allowedUsers := make(map[string]bool)
	for _, u := range cfg.AllowedUsers {
		allowedUsers[u] = true
	}

	allowedGroups := make(map[string]bool)
	for _, g := range cfg.AllowedGroups {
		allowedGroups[g] = true
	}

	return &SystemAuthenticator{
		config:        cfg,
		allowedUsers:  allowedUsers,
		allowedGroups: allowedGroups,
	}, nil
}

// Authenticate validates credentials against the system.
func (a *SystemAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	// Check if user is allowed
	if len(a.allowedUsers) > 0 && !a.allowedUsers[username] {
		return nil, ErrInvalidCredentials
	}

	// Look up user to verify they exist
	sysUser, err := user.Lookup(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Validate password using platform-specific method
	if !a.validatePassword(ctx, username, password) {
		return nil, ErrInvalidCredentials
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
			return nil, ErrInvalidCredentials
		}
	}

	return &UserInfo{
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
func (a *SystemAuthenticator) validatePassword(ctx context.Context, username, password string) bool {
	switch runtime.GOOS {
	case "darwin":
		return a.validateDarwin(ctx, username, password)
	case "linux":
		return a.validateLinux(ctx, username, password)
	default:
		// For unsupported platforms, try the su method as fallback
		return a.validateWithSu(ctx, username, password)
	}
}

// validateDarwin validates password on macOS using dscl.
func (a *SystemAuthenticator) validateDarwin(ctx context.Context, username, password string) bool {
	// Use dscl to authenticate
	cmd := exec.CommandContext(ctx, "dscl", ".", "-authonly", username, password)
	if err := cmd.Run(); err == nil {
		return true
	}

	// Fallback to su method
	return a.validateWithSu(ctx, username, password)
}

// validateLinux validates password on Linux using PAM via su.
func (a *SystemAuthenticator) validateLinux(ctx context.Context, username, password string) bool {
	// Try using su to validate (this uses PAM internally)
	return a.validateWithSu(ctx, username, password)
}

// validateWithSu validates password by attempting to run su.
// This method works on most Unix systems as su uses PAM.
func (a *SystemAuthenticator) validateWithSu(ctx context.Context, username, password string) bool {
	// Use expect-like behavior with su
	// Note: This is a simplified version. In production, consider using PAM directly.
	cmd := exec.CommandContext(ctx, "su", "-c", "true", username)

	// Create a pipe to write the password
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false
	}

	if err := cmd.Start(); err != nil {
		return false
	}

	// Write password
	_, _ = stdin.Write([]byte(password + "\n"))
	stdin.Close()

	// Wait for result
	if err := cmd.Wait(); err != nil {
		return false
	}

	return true
}

// getUserGroups gets the groups for a user.
func (a *SystemAuthenticator) getUserGroups(sysUser *user.User) ([]string, error) {
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
func (a *SystemAuthenticator) Name() string {
	return fmt.Sprintf("system-%s", strings.ToLower(runtime.GOOS))
}

// Type returns the authenticator type.
func (a *SystemAuthenticator) Type() string {
	return "system"
}
