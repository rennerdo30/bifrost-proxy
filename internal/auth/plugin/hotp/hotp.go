// Package hotp provides HMAC-based One-Time Password (HOTP) authentication for Bifrost.
// It implements RFC 4226 and is compatible with YubiKey HOTP mode and other hardware tokens.
package hotp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("hotp", &plugin{})
}

// plugin implements the auth.Plugin interface for HOTP authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "hotp"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "HMAC-based One-Time Password (HOTP) authentication (RFC 4226)"
}

// Create creates a new HOTP authenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		config:  cfg,
		secrets: make(map[string]*userSecret),
	}

	// Load secrets from file if specified
	if cfg.SecretsFile != "" {
		if err := authenticator.loadSecretsFile(); err != nil {
			return nil, fmt.Errorf("failed to load secrets file: %w", err)
		}
	}

	// Load inline secrets
	for _, s := range cfg.Secrets {
		authenticator.secrets[s.Username] = s
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"digits":       6,
		"algorithm":    "SHA1",
		"look_ahead":   10,
		"secrets_file": "/etc/bifrost/hotp-secrets.yaml",
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "digits": {
      "type": "integer",
      "description": "Number of digits in OTP code",
      "default": 6,
      "enum": [6, 8]
    },
    "algorithm": {
      "type": "string",
      "description": "Hash algorithm",
      "default": "SHA1",
      "enum": ["SHA1", "SHA256", "SHA512"]
    },
    "look_ahead": {
      "type": "integer",
      "description": "Number of counters to look ahead for resync",
      "default": 10
    },
    "secrets_file": {
      "type": "string",
      "description": "Path to YAML file containing user secrets"
    },
    "secrets": {
      "type": "array",
      "description": "Inline user secrets (use secrets_file in production)",
      "items": {
        "type": "object",
        "properties": {
          "username": {"type": "string"},
          "secret": {"type": "string", "description": "Base32-encoded secret"},
          "counter": {"type": "integer", "description": "Current counter value"},
          "groups": {"type": "array", "items": {"type": "string"}},
          "disabled": {"type": "boolean"}
        },
        "required": ["username", "secret"]
      }
    }
  }
}`
}

// hotpConfig represents the parsed configuration.
type hotpConfig struct {
	Digits      int
	Algorithm   string
	LookAhead   int
	SecretsFile string
	Secrets     []*userSecret
}

// userSecret represents a user's HOTP secret.
type userSecret struct {
	Username string   `yaml:"username"`
	Secret   string   `yaml:"secret"`  // Base32-encoded
	Counter  uint64   `yaml:"counter"` // Current counter value
	Groups   []string `yaml:"groups,omitempty"`
	Disabled bool     `yaml:"disabled,omitempty"`
}

// parseConfig parses the configuration map.
func parseConfig(config map[string]any) (*hotpConfig, error) {
	if config == nil {
		config = make(map[string]any)
	}

	cfg := &hotpConfig{
		Digits:    6,
		Algorithm: "SHA1",
		LookAhead: 10,
	}

	if digits, ok := config["digits"].(int); ok {
		cfg.Digits = digits
	} else if digits, ok := config["digits"].(float64); ok {
		cfg.Digits = int(digits)
	}

	if cfg.Digits != 6 && cfg.Digits != 8 {
		return nil, fmt.Errorf("hotp config: digits must be 6 or 8")
	}

	if algorithm, ok := config["algorithm"].(string); ok && algorithm != "" {
		cfg.Algorithm = strings.ToUpper(algorithm)
	}

	switch cfg.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return nil, fmt.Errorf("hotp config: unsupported algorithm %s", cfg.Algorithm)
	}

	if lookAhead, ok := config["look_ahead"].(int); ok {
		cfg.LookAhead = lookAhead
	} else if lookAhead, ok := config["look_ahead"].(float64); ok {
		cfg.LookAhead = int(lookAhead)
	}

	if cfg.LookAhead < 1 {
		cfg.LookAhead = 1
	}

	if secretsFile, ok := config["secrets_file"].(string); ok {
		cfg.SecretsFile = secretsFile
	}

	// Parse inline secrets
	if secretsAny, ok := config["secrets"]; ok {
		secrets, err := parseSecrets(secretsAny)
		if err != nil {
			return nil, fmt.Errorf("hotp config: %w", err)
		}
		cfg.Secrets = secrets
	}

	return cfg, nil
}

// parseSecrets parses the inline secrets configuration.
func parseSecrets(v any) ([]*userSecret, error) {
	if v == nil {
		return nil, nil
	}

	var secrets []*userSecret

	switch s := v.(type) {
	case []any:
		for i, item := range s {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("secret at index %d must be an object", i)
			}
			secret, err := parseSecret(m)
			if err != nil {
				return nil, fmt.Errorf("secret at index %d: %w", i, err)
			}
			secrets = append(secrets, secret)
		}
	case []map[string]any:
		for i, m := range s {
			secret, err := parseSecret(m)
			if err != nil {
				return nil, fmt.Errorf("secret at index %d: %w", i, err)
			}
			secrets = append(secrets, secret)
		}
	default:
		return nil, fmt.Errorf("secrets must be an array")
	}

	return secrets, nil
}

// parseSecret parses a single secret configuration.
func parseSecret(m map[string]any) (*userSecret, error) {
	username, _ := m["username"].(string)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	secret, _ := m["secret"].(string)
	if secret == "" {
		return nil, fmt.Errorf("secret is required for user %s", username)
	}

	// Validate base32 encoding
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return nil, fmt.Errorf("invalid base32 secret for user %s: %w", username, err)
	}

	var counter uint64
	if c, ok := m["counter"].(int); ok {
		counter = uint64(c)
	} else if c, ok := m["counter"].(float64); ok {
		counter = uint64(c)
	}

	var groups []string
	if groupsAny, ok := m["groups"]; ok {
		groups = toStringSlice(groupsAny)
	}

	disabled, _ := m["disabled"].(bool)

	return &userSecret{
		Username: username,
		Secret:   secret,
		Counter:  counter,
		Groups:   groups,
		Disabled: disabled,
	}, nil
}

// toStringSlice converts an any to []string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}

	if ss, ok := v.([]string); ok {
		return ss
	}

	if slice, ok := v.([]any); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// Authenticator provides HOTP authentication.
type Authenticator struct {
	config  *hotpConfig
	secrets map[string]*userSecret
	mu      sync.RWMutex
}

// Authenticate validates an HOTP code.
// The username is the user identifier and password is the 6 or 8 digit HOTP code.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	secret, exists := a.secrets[username]
	if !exists {
		return nil, auth.NewAuthError("hotp", "authenticate", auth.ErrUserNotFound)
	}

	if secret.Disabled {
		return nil, auth.NewAuthError("hotp", "authenticate", auth.ErrUserDisabled)
	}

	// Validate the HOTP code
	matched, newCounter := a.validateCode(secret, password)
	if !matched {
		return nil, auth.NewAuthError("hotp", "authenticate", auth.ErrInvalidCredentials)
	}

	// Update counter on successful authentication
	secret.Counter = newCounter

	// Persist counter update if using file-based storage
	if a.config.SecretsFile != "" {
		if err := a.saveSecretsFile(); err != nil {
			slog.Error("failed to save updated HOTP counters", "error", err)
		}
	}

	return &auth.UserInfo{
		Username: username,
		Groups:   secret.Groups,
		Metadata: map[string]string{
			"auth_type": "hotp",
		},
	}, nil
}

// validateCode validates an HOTP code against the secret.
func (a *Authenticator) validateCode(secret *userSecret, code string) (bool, uint64) {
	// Remove any whitespace from the code
	code = strings.ReplaceAll(code, " ", "")

	// Check code length
	if len(code) != a.config.Digits {
		return false, 0
	}

	// Decode the secret
	secretStr := strings.ToUpper(strings.TrimSpace(secret.Secret))
	secretStr = strings.ReplaceAll(secretStr, " ", "")
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretStr)
	if err != nil {
		slog.Error("failed to decode HOTP secret", "error", err)
		return false, 0
	}

	// Check current counter and look-ahead window
	for i := 0; i <= a.config.LookAhead; i++ {
		counter := secret.Counter + uint64(i)
		expectedCode := a.generateCode(secretBytes, counter)
		if subtle.ConstantTimeCompare([]byte(code), []byte(expectedCode)) == 1 {
			return true, counter + 1 // Return next counter value
		}
	}

	return false, 0
}

// generateCode generates an HOTP code for the given counter.
func (a *Authenticator) generateCode(secret []byte, counter uint64) string {
	// Convert counter to big-endian bytes
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Create HMAC
	var h func() hash.Hash
	switch a.config.Algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}

	mac := hmac.New(h, secret)
	mac.Write(counterBytes)
	hs := mac.Sum(nil)

	// Dynamic truncation
	offset := hs[len(hs)-1] & 0x0f
	code := int64(hs[offset]&0x7f)<<24 |
		int64(hs[offset+1]&0xff)<<16 |
		int64(hs[offset+2]&0xff)<<8 |
		int64(hs[offset+3]&0xff)

	// Modulo to get the desired number of digits
	mod := int64(1)
	for i := 0; i < a.config.Digits; i++ {
		mod *= 10
	}
	code = code % mod

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", a.config.Digits)
	return fmt.Sprintf(format, code)
}

// loadSecretsFile loads secrets from the configured YAML file.
func (a *Authenticator) loadSecretsFile() error {
	data, err := os.ReadFile(a.config.SecretsFile)
	if err != nil {
		return err
	}

	var secretsFile struct {
		Secrets []*userSecret `yaml:"secrets"`
	}

	if err := yaml.Unmarshal(data, &secretsFile); err != nil {
		return fmt.Errorf("failed to parse secrets file: %w", err)
	}

	for _, s := range secretsFile.Secrets {
		if s.Username == "" || s.Secret == "" {
			continue
		}
		// Normalize secret
		s.Secret = strings.ToUpper(strings.TrimSpace(s.Secret))
		s.Secret = strings.ReplaceAll(s.Secret, " ", "")
		a.secrets[s.Username] = s
	}

	slog.Debug("HOTP secrets loaded", "count", len(secretsFile.Secrets))
	return nil
}

// saveSecretsFile saves secrets to the configured YAML file.
func (a *Authenticator) saveSecretsFile() error {
	if a.config.SecretsFile == "" {
		return nil
	}

	secrets := make([]*userSecret, 0, len(a.secrets))
	for _, s := range a.secrets {
		secrets = append(secrets, s)
	}

	data, err := yaml.Marshal(map[string]any{"secrets": secrets})
	if err != nil {
		return err
	}

	return os.WriteFile(a.config.SecretsFile, data, 0600)
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "hotp"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "hotp"
}

// AddUser adds a user with an HOTP secret.
func (a *Authenticator) AddUser(username, secret string, counter uint64, groups []string) error {
	// Validate base32 encoding
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return fmt.Errorf("invalid base32 secret: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.secrets[username] = &userSecret{
		Username: username,
		Secret:   secret,
		Counter:  counter,
		Groups:   groups,
	}

	return nil
}

// RemoveUser removes a user.
func (a *Authenticator) RemoveUser(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.secrets, username)
}

// GetCounter returns the current counter for a user.
func (a *Authenticator) GetCounter(username string) (uint64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	secret, exists := a.secrets[username]
	if !exists {
		return 0, fmt.Errorf("user not found")
	}

	return secret.Counter, nil
}

// SetCounter sets the counter for a user (for resynchronization).
func (a *Authenticator) SetCounter(username string, counter uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	secret, exists := a.secrets[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	secret.Counter = counter
	return nil
}

// GenerateSecret generates a new HOTP secret for enrollment.
func (a *Authenticator) GenerateSecret() (string, error) {
	// Generate 20 random bytes (160 bits) for SHA1, more for other algorithms
	secretLen := 20
	switch a.config.Algorithm {
	case "SHA256":
		secretLen = 32
	case "SHA512":
		secretLen = 64
	}

	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateProvisioningURI generates an otpauth:// URI for QR code generation.
func (a *Authenticator) GenerateProvisioningURI(username, secret string, counter uint64, issuer string) string {
	if issuer == "" {
		issuer = "Bifrost"
	}
	// otpauth://hotp/ISSUER:USERNAME?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&counter=0
	return fmt.Sprintf("otpauth://hotp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&counter=%d",
		issuer,
		username,
		secret,
		issuer,
		a.config.Algorithm,
		a.config.Digits,
		counter,
	)
}
