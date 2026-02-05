//go:build windows
// +build windows

// Package system provides system authentication for Bifrost.
// On Windows, this uses the LogonUser API.
package system

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// Windows LogonUser constants
const (
	LOGON32_LOGON_NETWORK           = 3
	LOGON32_PROVIDER_DEFAULT        = 0
	LOGON32_LOGON_INTERACTIVE       = 2
	LOGON32_LOGON_BATCH             = 4
	LOGON32_LOGON_SERVICE           = 5
	LOGON32_LOGON_NETWORK_CLEARTEXT = 8
)

var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW          = advapi32.NewProc("LogonUserW")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

func init() {
	auth.RegisterPlugin("system", &plugin{})
}

// plugin implements the auth.Plugin interface for system authentication on Windows.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "system"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "Windows LogonUser API authentication"
}

// Create creates a new SystemAuthenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	allowedUsers := make(map[string]bool)
	for _, u := range cfg.allowedUsers {
		allowedUsers[strings.ToLower(u)] = true
	}

	allowedGroups := make(map[string]bool)
	for _, g := range cfg.allowedGroups {
		allowedGroups[strings.ToLower(g)] = true
	}

	slog.Info("Windows system authentication initialized",
		"allowed_users", len(allowedUsers),
		"allowed_groups", len(allowedGroups),
		"domain", cfg.domain)

	return &Authenticator{
		domain:        cfg.domain,
		logonType:     cfg.logonType,
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
		"domain":         "",
		"logon_type":     "network",
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
    "domain": {
      "type": "string",
      "description": "Windows domain name (empty for local accounts)"
    },
    "logon_type": {
      "type": "string",
      "enum": ["network", "interactive", "batch", "service"],
      "description": "Windows logon type (default: 'network')"
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
	domain        string
	logonType     uint32
	allowedUsers  []string
	allowedGroups []string
}

func parseConfig(config map[string]any) (*systemConfig, error) {
	cfg := &systemConfig{
		domain:    "",
		logonType: LOGON32_LOGON_NETWORK,
	}

	if config == nil {
		return cfg, nil
	}

	if domain, ok := config["domain"].(string); ok {
		cfg.domain = domain
	}

	if logonTypeStr, ok := config["logon_type"].(string); ok {
		switch strings.ToLower(logonTypeStr) {
		case "network":
			cfg.logonType = LOGON32_LOGON_NETWORK
		case "interactive":
			cfg.logonType = LOGON32_LOGON_INTERACTIVE
		case "batch":
			cfg.logonType = LOGON32_LOGON_BATCH
		case "service":
			cfg.logonType = LOGON32_LOGON_SERVICE
		default:
			return nil, fmt.Errorf("invalid logon_type: %s (must be network, interactive, batch, or service)", logonTypeStr)
		}
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

// Authenticator implements Windows system-level authentication using LogonUser API.
type Authenticator struct {
	domain        string
	logonType     uint32
	allowedUsers  map[string]bool
	allowedGroups map[string]bool
}

// Authenticate validates credentials against Windows using LogonUser API.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if username == "" || password == "" {
		return nil, auth.ErrInvalidCredentials
	}

	// Normalize username for comparison
	normalizedUser := strings.ToLower(username)

	// Check if user is allowed
	if len(a.allowedUsers) > 0 && !a.allowedUsers[normalizedUser] {
		slog.Debug("user not in allowed list", "username", username)
		return nil, auth.ErrInvalidCredentials
	}

	// Attempt Windows logon
	token, err := a.logonUser(username, password)
	if err != nil {
		slog.Debug("Windows logon failed", "username", username, "error", err)
		return nil, auth.ErrInvalidCredentials
	}
	defer windows.CloseHandle(token)

	// Get user groups from token
	groups, err := a.getTokenGroups(token)
	if err != nil {
		slog.Warn("failed to get user groups", "username", username, "error", err)
		groups = []string{}
	}

	// Check if user is in allowed groups
	if len(a.allowedGroups) > 0 {
		inAllowedGroup := false
		for _, g := range groups {
			if a.allowedGroups[strings.ToLower(g)] {
				inAllowedGroup = true
				break
			}
		}
		if !inAllowedGroup {
			slog.Debug("user not in any allowed group", "username", username, "groups", groups)
			return nil, auth.ErrInvalidCredentials
		}
	}

	slog.Info("Windows authentication successful", "username", username, "groups", len(groups))

	return &auth.UserInfo{
		Username: username,
		FullName: username, // Windows doesn't easily provide full name from LogonUser
		Groups:   groups,
		Metadata: map[string]string{
			"domain":    a.domain,
			"auth_type": "windows_logon",
		},
	}, nil
}

// logonUser calls the Windows LogonUserW API.
func (a *Authenticator) logonUser(username, password string) (windows.Handle, error) {
	// Convert strings to UTF-16 pointers
	usernamePtr, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, fmt.Errorf("invalid username: %w", err)
	}

	passwordPtr, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return 0, fmt.Errorf("invalid password: %w", err)
	}

	var domainPtr *uint16
	if a.domain != "" {
		domainPtr, err = syscall.UTF16PtrFromString(a.domain)
		if err != nil {
			return 0, fmt.Errorf("invalid domain: %w", err)
		}
	}

	var token windows.Handle
	ret, _, lastErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(a.logonType),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("LogonUser failed: %w", lastErr)
	}

	return token, nil
}

// getTokenGroups retrieves the group memberships from a Windows token.
func (a *Authenticator) getTokenGroups(token windows.Handle) ([]string, error) {
	// Cast Handle to Token for GetTokenInformation
	tokenHandle := windows.Token(token)

	// First call to get required buffer size
	var needed uint32
	windows.GetTokenInformation(tokenHandle, windows.TokenGroups, nil, 0, &needed)

	if needed == 0 {
		return nil, fmt.Errorf("GetTokenInformation returned zero size")
	}

	// Allocate buffer
	buf := make([]byte, needed)
	var returned uint32

	err := windows.GetTokenInformation(tokenHandle, windows.TokenGroups, &buf[0], needed, &returned)
	if err != nil {
		return nil, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	// Parse TOKEN_GROUPS structure
	tokenGroups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	groups := make([]string, 0, tokenGroups.GroupCount)

	for i := uint32(0); i < tokenGroups.GroupCount; i++ {
		group := tokenGroups.Groups[i]

		// Look up the SID to get the group name
		name, domain, _, err := group.Sid.LookupAccount("")
		if err != nil {
			continue // Skip SIDs we can't resolve
		}

		// Format as DOMAIN\Name or just Name for local groups
		if domain != "" && domain != "BUILTIN" && domain != "NT AUTHORITY" {
			groups = append(groups, fmt.Sprintf("%s\\%s", domain, name))
		} else {
			groups = append(groups, name)
		}
	}

	return groups, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	if a.domain != "" {
		return fmt.Sprintf("system-windows-%s", a.domain)
	}
	return "system-windows-local"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "system"
}
