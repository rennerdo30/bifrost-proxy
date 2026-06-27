package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMITMConfig_ValidateDisabled(t *testing.T) {
	// Disabled always validates, even with no CA files.
	assert.NoError(t, MITMConfig{}.Validate())
	assert.NoError(t, MITMConfig{Enabled: false}.Validate())
}

func TestMITMConfig_ValidateEnabled(t *testing.T) {
	assert.ErrorIs(t, MITMConfig{Enabled: true}.Validate(), errMITMCACertRequired)
	assert.ErrorIs(t, MITMConfig{Enabled: true, CACertFile: "ca.pem"}.Validate(), errMITMCAKeyRequired)
	assert.NoError(t, MITMConfig{Enabled: true, CACertFile: "ca.pem", CAKeyFile: "ca.key"}.Validate())
}

func TestMITMConfig_LoadCADisabled(t *testing.T) {
	_, _, err := MITMConfig{Enabled: false}.LoadCA()
	assert.Error(t, err)
}

func TestMITMConfig_LoadCAMissingFile(t *testing.T) {
	_, _, err := MITMConfig{Enabled: true, CACertFile: "/nope/ca.pem", CAKeyFile: "/nope/ca.key"}.LoadCA()
	assert.Error(t, err)
}

func TestMITMConfig_LoadCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, []byte("CERT"), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte("KEY"), 0o600))

	cfg := MITMConfig{Enabled: true, CACertFile: certPath, CAKeyFile: keyPath}
	certPEM, keyPEM, err := cfg.LoadCA()
	require.NoError(t, err)
	assert.Equal(t, "CERT", string(certPEM))
	assert.Equal(t, "KEY", string(keyPEM))
}

func TestMITMConfig_LoadCAKeyMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(certPath, []byte("CERT"), 0o600))
	cfg := MITMConfig{Enabled: true, CACertFile: certPath, CAKeyFile: filepath.Join(dir, "missing.key")}
	_, _, err := cfg.LoadCA()
	assert.Error(t, err)
}

func TestMITMConfig_YAML(t *testing.T) {
	data := `
enabled: true
ca_cert_file: /etc/bifrost/mitm-ca.pem
ca_key_file: /etc/bifrost/mitm-ca.key
leaf_ttl: 12h
max_cached_certs: 512
`
	var cfg MITMConfig
	require.NoError(t, yaml.Unmarshal([]byte(data), &cfg))
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "/etc/bifrost/mitm-ca.pem", cfg.CACertFile)
	assert.Equal(t, "/etc/bifrost/mitm-ca.key", cfg.CAKeyFile)
	assert.Equal(t, "12h0m0s", cfg.LeafTTL.Duration().String())
	assert.Equal(t, 512, cfg.MaxCachedCerts)
	require.NoError(t, cfg.Validate())
}
