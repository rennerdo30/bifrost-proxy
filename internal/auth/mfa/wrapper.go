// Package mfa provides multi-factor authentication wrapper for Bifrost.
// It wraps a primary authenticator with an MFA factor (TOTP, HOTP, etc.)
// to provide true two-factor authentication.
package mfa

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// MFAMode defines when MFA is required.
type MFAMode string

const (
	// MFAModeAlways requires MFA for all users.
	MFAModeAlways MFAMode = "always"
	// MFAModePerUser requires MFA only for users with MFA enabled.
	MFAModePerUser MFAMode = "per_user"
	// MFAModeGroupBased requires MFA for users in specific groups.
	MFAModeGroupBased MFAMode = "group_based"
)

// PasswordFormat defines how primary password and MFA code are combined.
type PasswordFormat string

const (
	// PasswordFormatConcatenated combines as password+code (e.g., "password123456").
	PasswordFormatConcatenated PasswordFormat = "concatenated"
	// PasswordFormatSeparated combines as password:code (e.g., "password:123456").
	PasswordFormatSeparated PasswordFormat = "separated"
)

// Config represents the MFA wrapper configuration.
type Config struct {
	// PrimaryProvider is the name of the primary authentication provider.
	PrimaryProvider string
	// MFAType is the type of MFA to use (totp, hotp, etc.).
	MFAType string
	// MFARequired determines when MFA is required.
	MFARequired MFAMode
	// MFAGroups is the list of groups that require MFA (for group_based mode).
	MFAGroups []string
	// PasswordFormat defines how password and MFA code are combined.
	PasswordFormat PasswordFormat
	// Separator is the separator for PasswordFormatSeparated (default: ":").
	Separator string
	// MFACodeLength is the expected length of MFA codes (default: 6).
	MFACodeLength int
}

// Wrapper wraps a primary authenticator with MFA.
type Wrapper struct {
	config     *Config
	primary    auth.Authenticator
	mfa        auth.Authenticator
	mfaUsers   map[string]bool // Users with MFA enabled (for per_user mode)
	mfaUsersMu sync.RWMutex
}

// NewWrapper creates a new MFA wrapper.
func NewWrapper(config *Config, primary, mfa auth.Authenticator) (*Wrapper, error) {
	if config == nil {
		return nil, fmt.Errorf("MFA wrapper config is required")
	}

	if primary == nil {
		return nil, fmt.Errorf("primary authenticator is required")
	}

	if mfa == nil {
		return nil, fmt.Errorf("MFA authenticator is required")
	}

	if config.Separator == "" {
		config.Separator = ":"
	}

	if config.MFACodeLength == 0 {
		config.MFACodeLength = 6
	}

	if config.PasswordFormat == "" {
		config.PasswordFormat = PasswordFormatConcatenated
	}

	if config.MFARequired == "" {
		config.MFARequired = MFAModeAlways
	}

	return &Wrapper{
		config:   config,
		primary:  primary,
		mfa:      mfa,
		mfaUsers: make(map[string]bool),
	}, nil
}

// Authenticate performs two-factor authentication.
func (w *Wrapper) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	// Split password into primary password and MFA code
	primaryPassword, mfaCode, err := w.splitPassword(password)
	if err != nil {
		return nil, auth.NewAuthError("mfa", "parse", err)
	}

	// First, authenticate with primary provider
	userInfo, err := w.primary.Authenticate(ctx, username, primaryPassword)
	if err != nil {
		return nil, err // Pass through primary auth errors
	}

	// Check if MFA is required for this user
	if !w.isMFARequired(userInfo) {
		return userInfo, nil
	}

	// If MFA is required but no code provided, return specific error
	if mfaCode == "" {
		return nil, auth.NewAuthError("mfa", "authenticate", ErrMFARequired)
	}

	// Validate MFA code
	_, err = w.mfa.Authenticate(ctx, username, mfaCode)
	if err != nil {
		return nil, auth.NewAuthError("mfa", "validate", auth.ErrInvalidCredentials)
	}

	// Add MFA metadata
	if userInfo.Metadata == nil {
		userInfo.Metadata = make(map[string]string)
	}
	userInfo.Metadata["auth_type"] = "mfa_wrapper"
	userInfo.Metadata["mfa_type"] = w.config.MFAType
	userInfo.Metadata["mfa_verified"] = "true"

	return userInfo, nil
}

// splitPassword splits the password into primary password and MFA code.
func (w *Wrapper) splitPassword(password string) (string, string, error) {
	switch w.config.PasswordFormat {
	case PasswordFormatConcatenated:
		// Password followed by MFA code
		// e.g., "mypassword123456" where 123456 is the TOTP code
		if len(password) < w.config.MFACodeLength {
			// No MFA code in password
			return password, "", nil
		}

		codeStart := len(password) - w.config.MFACodeLength
		primaryPassword := password[:codeStart]
		mfaCode := password[codeStart:]

		// Check if the code looks like a valid OTP (all digits)
		if !isNumeric(mfaCode) {
			// Not a valid code, treat entire string as password
			return password, "", nil
		}

		return primaryPassword, mfaCode, nil

	case PasswordFormatSeparated:
		// Password and MFA code separated by delimiter
		// e.g., "mypassword:123456"
		idx := strings.LastIndex(password, w.config.Separator)
		if idx == -1 {
			// No separator found, no MFA code
			return password, "", nil
		}

		primaryPassword := password[:idx]
		mfaCode := password[idx+len(w.config.Separator):]

		// Validate code length
		if len(mfaCode) != w.config.MFACodeLength {
			// Code wrong length, treat as password without MFA
			return password, "", nil
		}

		return primaryPassword, mfaCode, nil

	default:
		return "", "", fmt.Errorf("unknown password format: %s", w.config.PasswordFormat)
	}
}

// isMFARequired checks if MFA is required for the given user.
func (w *Wrapper) isMFARequired(userInfo *auth.UserInfo) bool {
	switch w.config.MFARequired {
	case MFAModeAlways:
		return true

	case MFAModePerUser:
		w.mfaUsersMu.RLock()
		required := w.mfaUsers[userInfo.Username]
		w.mfaUsersMu.RUnlock()
		return required

	case MFAModeGroupBased:
		// Check if user is in any MFA-required group
		for _, userGroup := range userInfo.Groups {
			for _, mfaGroup := range w.config.MFAGroups {
				if strings.EqualFold(userGroup, mfaGroup) {
					return true
				}
			}
		}
		return false

	default:
		return true // Default to always require MFA
	}
}

// Name returns the authenticator name.
func (w *Wrapper) Name() string {
	return "mfa_wrapper"
}

// Type returns the authenticator type.
func (w *Wrapper) Type() string {
	return "mfa_wrapper"
}

// EnableMFA enables MFA for a user (for per_user mode).
func (w *Wrapper) EnableMFA(username string) {
	w.mfaUsersMu.Lock()
	defer w.mfaUsersMu.Unlock()
	w.mfaUsers[username] = true
}

// DisableMFA disables MFA for a user (for per_user mode).
func (w *Wrapper) DisableMFA(username string) {
	w.mfaUsersMu.Lock()
	defer w.mfaUsersMu.Unlock()
	delete(w.mfaUsers, username)
}

// IsMFAEnabled checks if MFA is enabled for a user (for per_user mode).
func (w *Wrapper) IsMFAEnabled(username string) bool {
	w.mfaUsersMu.RLock()
	defer w.mfaUsersMu.RUnlock()
	return w.mfaUsers[username]
}

// SetMFAUsers sets the list of users with MFA enabled.
func (w *Wrapper) SetMFAUsers(users []string) {
	w.mfaUsersMu.Lock()
	defer w.mfaUsersMu.Unlock()

	w.mfaUsers = make(map[string]bool, len(users))
	for _, u := range users {
		w.mfaUsers[u] = true
	}
}

// GetPrimaryAuthenticator returns the primary authenticator.
func (w *Wrapper) GetPrimaryAuthenticator() auth.Authenticator {
	return w.primary
}

// GetMFAAuthenticator returns the MFA authenticator.
func (w *Wrapper) GetMFAAuthenticator() auth.Authenticator {
	return w.mfa
}

// isNumeric checks if a string contains only digits.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// MFA-specific errors
var (
	// ErrMFARequired is returned when MFA is required but not provided.
	ErrMFARequired = fmt.Errorf("MFA code required")
)
