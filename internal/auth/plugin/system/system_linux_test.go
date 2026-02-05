//go:build linux
// +build linux

// Package system provides system (PAM) authentication for Bifrost.
package system

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateLinuxOnLinux tests the validateLinux method on Linux.
func TestValidateLinuxOnLinux(t *testing.T) {
	a := &Authenticator{}
	ctx := context.Background()

	// With invalid credentials, should return false
	result := a.validateLinux(ctx, "nonexistent_user_xyz_12345", "wrong_password")
	assert.False(t, result)
}

// TestValidateLinuxWithCanceledContext tests validateLinux with canceled context.
func TestValidateLinuxWithCanceledContext(t *testing.T) {
	a := &Authenticator{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := a.validateLinux(ctx, "anyuser", "anypassword")
	assert.False(t, result)
}

// TestValidatePasswordOnLinux tests that validatePassword routes to validateLinux on Linux.
func TestValidatePasswordOnLinux(t *testing.T) {
	a := &Authenticator{}
	ctx := context.Background()

	// On Linux, validatePassword should call validateLinux
	result := a.validatePassword(ctx, "nonexistent_user_xyz", "password")
	assert.False(t, result, "should return false for nonexistent user")
}
