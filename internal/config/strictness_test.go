package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Everything after a `---` separator used to be silently ignored — one more
// way for a setting to look configured while nothing reads it.
func TestLoad_RejectsMultipleYAMLDocuments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.yaml")
	content := `server:
  http:
    listen: ":7080"
backends:
  - name: direct
    type: direct
    enabled: true
---
server:
  http:
    listen: ":9999"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	var cfg ServerConfig
	err := Load(path, &cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one YAML document")
}

// A single document with a trailing newline or comments stays fine.
func TestLoad_SingleDocumentStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.yaml")
	content := "# comment\nserver:\n  http:\n    listen: \":7080\"\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	var cfg ServerConfig
	require.NoError(t, Load(path, &cfg))
	assert.Equal(t, ":7080", cfg.Server.HTTP.Listen)
}

// The node-preserving save path (LoadNode/UpdateNode/SaveNode — the client
// API's persistence route) must round-trip literal dollars exactly like
// config.Save does: an inserted value containing `${` is escaped on write and
// comes back verbatim after expansion, while pre-existing `${VAR}` references
// in untouched parts of the file keep working.
func TestUpdateNode_EscapesInsertedDollarValues(t *testing.T) {
	t.Setenv("BIFROST_STRICT_TEST_TOKEN", "EXPANDED")
	t.Setenv("BIFROST_STRICT_TEST_PORT", "7380")

	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	seed := `proxy:
  http:
    listen: "127.0.0.1:${BIFROST_STRICT_TEST_PORT}"
server:
  address: "127.0.0.1:39990"
  password: "old"
`
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	node, err := LoadNode(path)
	require.NoError(t, err)
	require.NoError(t, UpdateNode(node, map[string]interface{}{
		"server": map[string]interface{}{
			"password": "a${BIFROST_STRICT_TEST_TOKEN}b",
		},
	}))
	require.NoError(t, SaveNode(path, node))

	var cfg ClientConfig
	require.NoError(t, Load(path, &cfg))
	assert.Equal(t, "a${BIFROST_STRICT_TEST_TOKEN}b", cfg.Server.Password,
		"an inserted literal ${...} must survive save and expansion")
	assert.Equal(t, "127.0.0.1:7380", cfg.Proxy.HTTP.Listen,
		"a pre-existing env reference in an untouched value must keep expanding")
}

// ValidateKnownKeys is the strictness bridge for dynamic map sections.
func TestValidateKnownKeys(t *testing.T) {
	type prototype struct {
		Known string `yaml:"known"`
	}

	assert.NoError(t, ValidateKnownKeys("test", map[string]any{"known": "v"}, &prototype{}))
	assert.NoError(t, ValidateKnownKeys("test", nil, &prototype{}))

	err := ValidateKnownKeys("test", map[string]any{"knwon": "v"}, &prototype{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "knwon")

	// The migration escape hatch downgrades this exactly like file loading.
	t.Setenv(EnvAllowUnknownKeys, "1")
	assert.NoError(t, ValidateKnownKeys("test", map[string]any{"knwon": "v"}, &prototype{}))
}
