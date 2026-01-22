package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
