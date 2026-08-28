package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// An API update carrying an unknown key used to report success, write the key
// to disk, and brick the next strict reload. It must be rejected up front and
// leave the file untouched.
func TestClientUpdateConfig_UnknownKeyRejectedBeforePersisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	seed := "proxy:\n  http:\n    listen: \"127.0.0.1:0\"\nserver:\n  address: \"127.0.0.1:39990\"\n"
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	cfg := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &cfg))
	client, err := New(&cfg)
	require.NoError(t, err)
	client.SetConfigPath(path)

	err = client.updateConfig(map[string]interface{}{
		"proxy": map[string]interface{}{
			"http": map[string]interface{}{"listem": ":9999"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listem")

	written, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, seed, string(written), "a rejected update must not touch the file")

	// The file remains strictly loadable.
	reloaded := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &reloaded))
}

// A valid partial update still works, and the file still reloads strictly.
func TestClientUpdateConfig_ValidUpdateStillPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	seed := "proxy:\n  http:\n    listen: \"127.0.0.1:0\"\nserver:\n  address: \"127.0.0.1:39990\"\n"
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	cfg := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &cfg))
	client, err := New(&cfg)
	require.NoError(t, err)
	client.SetConfigPath(path)

	require.NoError(t, client.updateConfig(map[string]interface{}{
		"server": map[string]interface{}{"address": "127.0.0.1:39999"},
	}))

	reloaded := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &reloaded))
	assert.Equal(t, "127.0.0.1:39999", reloaded.Server.Address)
}

// The client API's save path escapes inserted dollars, so a literal ${...}
// credential saved from the dashboard survives the next reload.
func TestClientUpdateConfig_LiteralDollarSurvivesReload(t *testing.T) {
	t.Setenv("BIFROST_CLIENT_UPDATE_TOKEN", "EXPANDED")

	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	seed := "proxy:\n  http:\n    listen: \"127.0.0.1:0\"\nserver:\n  address: \"127.0.0.1:39990\"\n  password: \"old\"\n"
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	cfg := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &cfg))
	client, err := New(&cfg)
	require.NoError(t, err)
	client.SetConfigPath(path)

	const literal = "a${BIFROST_CLIENT_UPDATE_TOKEN}b"
	require.NoError(t, client.updateConfig(map[string]interface{}{
		"server": map[string]interface{}{"password": literal},
	}))

	reloaded := config.DefaultClientConfig()
	require.NoError(t, config.LoadAndValidate(path, &reloaded))
	assert.Equal(t, literal, reloaded.Server.Password,
		"the saved password must come back literally, not env-expanded")
}
