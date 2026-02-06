// Package config provides configuration loading and validation for Bifrost.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a configuration file into the given struct.
func Load(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	data = []byte(os.ExpandEnv(string(data)))

	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

// Save writes a configuration struct to a file.
func Save(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil { //nolint:gosec // G301: Config directory permissions are appropriate
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Use 0600 permissions - config files may contain sensitive data (passwords, tokens)
	if err := os.WriteFile(path, data, 0600); err != nil { //nolint:gosec // G302: Config file permissions are restricted
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the given configuration using validator functions.
type Validator interface {
	Validate() error
}

// ValidateConfig validates a configuration if it implements Validator.
func ValidateConfig(v any) error {
	if validator, ok := v.(Validator); ok {
		return validator.Validate()
	}
	return nil
}

// LoadAndValidate loads and validates a configuration file.
func LoadAndValidate(path string, v any) error {
	if err := Load(path, v); err != nil {
		return err
	}
	return ValidateConfig(v)
}

// Backup creates a timestamped backup of the config file.
func Backup(path string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.backup.%s", path, timestamp)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	// Use 0600 permissions - config files may contain sensitive data (passwords, tokens)
	if err := os.WriteFile(backupPath, data, 0600); err != nil { //nolint:gosec // G302: Config file permissions are restricted
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	return backupPath, nil
}
