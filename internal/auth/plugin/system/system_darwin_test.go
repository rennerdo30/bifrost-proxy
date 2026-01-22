//go:build darwin
// +build darwin

// Package system provides system (PAM) authentication for Bifrost.
package system

import (
	"context"
	"os/user"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestValidateDarwinOnDarwin tests the validateDarwin method specifically on macOS.
func TestValidateDarwinOnDarwin(t *testing.T) {
	a := &Authenticator{}
	ctx := context.Background()

	// With invalid credentials, should return false
	result := a.validateDarwin(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestValidateDarwinDsclFails tests validateDarwin when dscl fails and falls back to su.
func TestValidateDarwinDsclFails(t *testing.T) {
	a := &Authenticator{}
	ctx := context.Background()

	// Using a nonexistent user, dscl will fail and fall back to su
	// Both should fail, returning false
	result := a.validateDarwin(ctx, "invalid_user_xyz_99999", "password")
	assert.False(t, result)
}

// TestValidateDarwinWithTimeout tests validateDarwin with a timeout context.
func TestValidateDarwinWithTimeout(t *testing.T) {
	a := &Authenticator{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := a.validateDarwin(ctx, "nonexistent_user_xyz", "password")
	assert.False(t, result)
}

// TestValidatePasswordOnDarwin tests that validatePassword routes to validateDarwin on macOS.
func TestValidatePasswordOnDarwin(t *testing.T) {
	a := &Authenticator{}
	ctx := context.Background()

	// On macOS, validatePassword should call validateDarwin
	result := a.validatePassword(ctx, "nonexistent_user_xyz", "password")
	assert.False(t, result, "should return false for nonexistent user")
}

// TestValidateDarwinCurrentUserWrongPassword tests validation with current user but wrong password.
func TestValidateDarwinCurrentUserWrongPassword(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	a := &Authenticator{}
	ctx := context.Background()

	// Current user exists, but password is wrong
	result := a.validateDarwin(ctx, currentUser.Username, "definitely_wrong_password_xyz_12345")
	assert.False(t, result)
}
