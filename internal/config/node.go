package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadNode reads a YAML file into a yaml.Node (AST).
func LoadNode(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &node, nil
}

// ParseNode parses YAML bytes into a yaml.Node.
func ParseNode(data []byte) (*yaml.Node, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}
	return &node, nil
}

// SaveNode writes a yaml.Node to a file.
func SaveNode(path string, node *yaml.Node) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer f.Close()

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	defer encoder.Close()

	if err := encoder.Encode(node); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// UpdateNode updates values in a yaml.Node based on a map of updates.
// It supports nested maps and preservation of comments.
func UpdateNode(node *yaml.Node, updates map[string]interface{}) error {
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return fmt.Errorf("empty yaml document")
		}
		return UpdateNode(node.Content[0], updates)
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node, got %v", node.Kind)
	}

	for k, v := range updates {
		found := false
		// node.Content is [key, value, key, value, ...]
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == k {
				found = true
				if nestedUpdates, ok := v.(map[string]interface{}); ok {
					// Recursive update for nested maps
					if err := UpdateNode(node.Content[i+1], nestedUpdates); err != nil {
						return fmt.Errorf("failed to update key %s: %w", k, err)
					}
				} else {
					// Direct value update
					// We need to marshal the new value to a node to handle types correctly
					newNode, err := valueToNode(v)
					if err != nil {
						return fmt.Errorf("failed to convert value for key %s: %w", k, err)
					}
					// Preserve comments/style from original value node
					if node.Content[i+1].Kind == yaml.ScalarNode && newNode.Kind == yaml.ScalarNode {
						newNode.Style = node.Content[i+1].Style
					}
					newNode.HeadComment = node.Content[i+1].HeadComment
					newNode.LineComment = node.Content[i+1].LineComment
					newNode.FootComment = node.Content[i+1].FootComment
					node.Content[i+1] = newNode
				}
				break
			}
		}

		if !found {
			// Add new key-value pair if not found
			// This might lose some formatting context but better than erroring
			// or we could decide to skip fields not in original

			// For now, let's append new keys
			// We need a key node and a value node
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
			valueNode, err := valueToNode(v)
			if err != nil {
				return fmt.Errorf("failed to convert value for new key %s: %w", k, err)
			}

			// Add comment if we have a default comment for this key?
			// That would require a richer update map or a sidecar definition.
			// For now, just append.
			node.Content = append(node.Content, keyNode, valueNode)
		}
	}

	return nil
}

func valueToNode(v interface{}) (*yaml.Node, error) {
	// Convert value to YAML node by marshaling to bytes then unmarshaling.
	// This approach ensures proper YAML node structure for any Go value.
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if len(node.Content) > 0 {
		return node.Content[0], nil
	}
	return nil, fmt.Errorf("failed to convert value to node")
}
