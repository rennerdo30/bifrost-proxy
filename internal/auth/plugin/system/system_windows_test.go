//go:build windows
// +build windows

// Package system provides system (PAM) authentication for Bifrost.
package system

import (
	"testing"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginCreateOnWindowsReturnsError tests that Create returns an error on Windows.
func TestPluginCreateOnWindowsReturnsError(t *testing.T) {
	p := &plugin{}
	_, err := p.Create(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrAuthMethodUnsupported)
	assert.Contains(t, err.Error(), "Windows")
}

// TestPluginCreateOnWindowsWithConfig tests that Create returns an error on Windows even with config.
func TestPluginCreateOnWindowsWithConfig(t *testing.T) {
	p := &plugin{}
	_, err := p.Create(map[string]any{
		"service":        "login",
		"allowed_users":  []string{"user1"},
		"allowed_groups": []string{"group1"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrAuthMethodUnsupported)
}

// TestPluginValidateConfigOnWindowsReturnsError tests that ValidateConfig returns an error on Windows.
func TestPluginValidateConfigOnWindowsReturnsError(t *testing.T) {
	p := &plugin{}
	err := p.ValidateConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Windows")
}

// TestPluginValidateConfigOnWindowsWithConfig tests ValidateConfig with config on Windows.
func TestPluginValidateConfigOnWindowsWithConfig(t *testing.T) {
	p := &plugin{}
	err := p.ValidateConfig(map[string]any{
		"service": "sshd",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Windows")
}

// TestFactoryCreateOnWindows tests that factory returns error on Windows.
func TestFactoryCreateOnWindows(t *testing.T) {
	factory := auth.NewFactory()
	_, err := factory.Create(auth.ProviderConfig{
		Name:    "system-test",
		Type:    "system",
		Enabled: true,
		Config:  nil,
	})
	require.Error(t, err)
	// The error will be wrapped by the factory
	assert.Contains(t, err.Error(), "Windows")
}
