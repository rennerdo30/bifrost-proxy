package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestUpdateNode(t *testing.T) {
	yamlInput := `
# Top comment
proxy:
  # HTTP comment
  http:
    listen: "127.0.0.1:7380" # Inline comment
    read_timeout: "30s"
  # SOCKS5 comment
  socks5:
    listen: "127.0.0.1:7381"
`

	var node yaml.Node
	err := yaml.Unmarshal([]byte(yamlInput), &node)
	assert.NoError(t, err)

	updates := map[string]interface{}{
		"proxy": map[string]interface{}{
			"http": map[string]interface{}{
				"listen": "0.0.0.0:8080",
			},
		},
		"new_key": "new_value",
	}

	err = UpdateNode(&node, updates)
	assert.NoError(t, err)

	out, err := yaml.Marshal(&node)
	assert.NoError(t, err)

	outStr := string(out)

	// Verify values updated
	assert.Contains(t, outStr, "listen: \"0.0.0.0:8080\"")
	assert.Contains(t, outStr, "new_key: new_value")

	// Verify comments preserved
	assert.Contains(t, outStr, "# Top comment")
	assert.Contains(t, outStr, "# HTTP comment")
	assert.Contains(t, outStr, "# SOCKS5 comment")
	assert.Contains(t, outStr, "# Inline comment")
}

func TestLoadNode(t *testing.T) {
	// Create a temporary YAML file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.yaml")

	yamlContent := `
name: test-config
version: "1.0"
settings:
  debug: true
  timeout: 30
`
	err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Test loading the file
	node, err := LoadNode(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, node)
	assert.Equal(t, yaml.DocumentNode, node.Kind)
}

func TestLoadNode_FileNotFound(t *testing.T) {
	_, err := LoadNode("/nonexistent/path/config.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoadNode_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yaml")

	invalidYAML := `
name: test
  invalid: indentation
    here: broken
`
	err := os.WriteFile(tmpFile, []byte(invalidYAML), 0644)
	require.NoError(t, err)

	_, err = LoadNode(tmpFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestParseNode(t *testing.T) {
	yamlData := []byte(`
name: test
value: 123
`)
	node, err := ParseNode(yamlData)
	require.NoError(t, err)
	assert.NotNil(t, node)
	assert.Equal(t, yaml.DocumentNode, node.Kind)
}

func TestParseNode_InvalidYAML(t *testing.T) {
	invalidYAML := []byte(`
name: test
  bad indentation:
    more bad:
`)
	_, err := ParseNode(invalidYAML)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse yaml")
}

func TestSaveNode(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "output.yaml")

	// Create a simple node
	var node yaml.Node
	yamlContent := `name: test-output
version: "2.0"
`
	err := yaml.Unmarshal([]byte(yamlContent), &node)
	require.NoError(t, err)

	// Save the node
	err = SaveNode(tmpFile, &node)
	require.NoError(t, err)

	// Verify the file was created and contains expected content
	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "name: test-output")
	assert.Contains(t, string(data), "version: \"2.0\"")
}

func TestSaveNode_InvalidPath(t *testing.T) {
	var node yaml.Node
	yaml.Unmarshal([]byte("test: value"), &node)

	// Try to save to an invalid path (directory doesn't exist)
	err := SaveNode("/nonexistent/directory/output.yaml", &node)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create config file")
}
