// Package totp provides Time-based One-Time Password (TOTP) authentication for Bifrost.
// It implements RFC 6238 and is compatible with Google Authenticator and other TOTP apps.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: SHA1 is required by RFC 6238 (TOTP) for compatibility with authenticator apps
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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("totp", &plugin{})
}

// plugin implements the auth.Plugin interface for TOTP authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "totp"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "Time-based One-Time Password (TOTP) authentication (RFC 6238)"
}

// Create creates a new TOTP authenticator from the configuration.
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
		"issuer":       "Bifrost Proxy",
		"digits":       6,
		"period":       30,
		"algorithm":    "SHA1",
		"skew":         1,
		"secrets_file": "/etc/bifrost/totp-secrets.yaml",
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "issuer": {
      "type": "string",
      "description": "Issuer name shown in authenticator apps",
      "default": "Bifrost Proxy"
    },
    "digits": {
      "type": "integer",
      "description": "Number of digits in OTP code",
      "default": 6,
      "enum": [6, 8]
    },
    "period": {
      "type": "integer",
      "description": "OTP validity period in seconds",
      "default": 30
    },
    "algorithm": {
      "type": "string",
      "description": "Hash algorithm",
      "default": "SHA1",
      "enum": ["SHA1", "SHA256", "SHA512"]
    },
    "skew": {
      "type": "integer",
      "description": "Number of time periods to allow for clock skew",
      "default": 1
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
          "groups": {"type": "array", "items": {"type": "string"}},
          "disabled": {"type": "boolean"}
        },
        "required": ["username", "secret"]
      }
    }
  }
}`
}

// totpConfig represents the parsed configuration.
type totpConfig struct {
	Issuer      string
	Digits      int
	Period      int64
	Algorithm   string
	Skew        int
	SecretsFile string
	Secrets     []*userSecret
}

// userSecret represents a user's TOTP secret.
type userSecret struct {
	Username string   `yaml:"username"`
	Secret   string   `yaml:"secret"` // Base32-encoded
	Groups   []string `yaml:"groups,omitempty"`
	Disabled bool     `yaml:"disabled,omitempty"`
}

// parseConfig parses the configuration map.
func parseConfig(config map[string]any) (*totpConfig, error) {
	if config == nil {
		config = make(map[string]any)
	}

	cfg := &totpConfig{
		Issuer:    "Bifrost Proxy",
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Skew:      1,
	}

	if issuer, ok := config["issuer"].(string); ok && issuer != "" {
		cfg.Issuer = issuer
	}

	if digits, ok := config["digits"].(int); ok {
		cfg.Digits = digits
	} else if digits, ok := config["digits"].(float64); ok {
		cfg.Digits = int(digits)
	}

	if cfg.Digits != 6 && cfg.Digits != 8 {
		return nil, fmt.Errorf("totp config: digits must be 6 or 8")
	}

	if period, ok := config["period"].(int); ok {
		cfg.Period = int64(period)
	} else if period, ok := config["period"].(float64); ok {
		cfg.Period = int64(period)
	}

	if cfg.Period < 1 {
		return nil, fmt.Errorf("totp config: period must be positive")
	}

	if algorithm, ok := config["algorithm"].(string); ok && algorithm != "" {
		cfg.Algorithm = strings.ToUpper(algorithm)
	}

	switch cfg.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return nil, fmt.Errorf("totp config: unsupported algorithm %s", cfg.Algorithm)
	}

	if skew, ok := config["skew"].(int); ok {
		cfg.Skew = skew
	} else if skew, ok := config["skew"].(float64); ok {
		cfg.Skew = int(skew)
	}

	if secretsFile, ok := config["secrets_file"].(string); ok {
		cfg.SecretsFile = secretsFile
	}

	// Parse inline secrets
	if secretsAny, ok := config["secrets"]; ok {
		secrets, err := parseSecrets(secretsAny)
		if err != nil {
			return nil, fmt.Errorf("totp config: %w", err)
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
	username, _ := m["username"].(string) //nolint:errcheck // Type assertion - empty string is valid if missing
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	secret, _ := m["secret"].(string) //nolint:errcheck // Type assertion - empty string is valid if missing
	if secret == "" {
		return nil, fmt.Errorf("secret is required for user %s", username)
	}

	// Validate base32 encoding
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return nil, fmt.Errorf("invalid base32 secret for user %s: %w", username, err)
	}

	var groups []string
	if groupsAny, ok := m["groups"]; ok {
		groups = toStringSlice(groupsAny)
	}

	disabled, _ := m["disabled"].(bool) //nolint:errcheck // Type assertion - false is valid if missing

	return &userSecret{
		Username: username,
		Secret:   secret,
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

// Authenticator provides TOTP authentication.
type Authenticator struct {
	config  *totpConfig
	secrets map[string]*userSecret
	mu      sync.RWMutex
}

// Authenticate validates a TOTP code.
// The username is the user identifier and password is the 6 or 8 digit TOTP code.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	a.mu.RLock()
	secret, exists := a.secrets[username]
	a.mu.RUnlock()

	if !exists {
		return nil, auth.NewAuthError("totp", "authenticate", auth.ErrUserNotFound)
	}

	if secret.Disabled {
		return nil, auth.NewAuthError("totp", "authenticate", auth.ErrUserDisabled)
	}

	// Validate the TOTP code
	if !a.validateCode(secret.Secret, password) {
		return nil, auth.NewAuthError("totp", "authenticate", auth.ErrInvalidCredentials)
	}

	return &auth.UserInfo{
		Username: username,
		Groups:   secret.Groups,
		Metadata: map[string]string{
			"auth_type": "totp",
		},
	}, nil
}

// validateCode validates a TOTP code against the secret.
func (a *Authenticator) validateCode(secretStr, code string) bool {
	// Remove any whitespace from the code
	code = strings.ReplaceAll(code, " ", "")

	// Check code length
	if len(code) != a.config.Digits {
		return false
	}

	// Decode the secret
	secretStr = strings.ToUpper(strings.TrimSpace(secretStr))
	secretStr = strings.ReplaceAll(secretStr, " ", "")
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretStr)
	if err != nil {
		slog.Error("failed to decode TOTP secret", "error", err)
		return false
	}

	// Get current time counter
	now := time.Now().Unix()
	counter := now / a.config.Period

	// Check current time window and skew windows
	for i := -a.config.Skew; i <= a.config.Skew; i++ {
		expectedCode := a.generateCode(secretBytes, counter+int64(i))
		if subtle.ConstantTimeCompare([]byte(code), []byte(expectedCode)) == 1 {
			return true
		}
	}

	return false
}

// generateCode generates a TOTP code for the given counter.
func (a *Authenticator) generateCode(secret []byte, counter int64) string {
	// Convert counter to big-endian bytes
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter)) //nolint:gosec // G115: counter is always non-negative (Unix timestamp / period)

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

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, s := range secretsFile.Secrets {
		if s.Username == "" || s.Secret == "" {
			continue
		}
		// Normalize secret
		s.Secret = strings.ToUpper(strings.TrimSpace(s.Secret))
		s.Secret = strings.ReplaceAll(s.Secret, " ", "")
		a.secrets[s.Username] = s
	}

	slog.Debug("TOTP secrets loaded", "count", len(secretsFile.Secrets))
	return nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "totp"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "totp"
}

// AddUser adds a user with a TOTP secret.
func (a *Authenticator) AddUser(username, secret string, groups []string) error {
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

// GenerateSecret generates a new TOTP secret for enrollment.
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
	if _, err := cryptoRandRead(b); err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateProvisioningURI generates an otpauth:// URI for QR code generation.
func (a *Authenticator) GenerateProvisioningURI(username, secret string) string {
	// otpauth://totp/ISSUER:USERNAME?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		a.config.Issuer,
		username,
		secret,
		a.config.Issuer,
		a.config.Algorithm,
		a.config.Digits,
		a.config.Period,
	)
}

// GetCurrentCode returns the current TOTP code for a user (useful for debugging).
func (a *Authenticator) GetCurrentCode(username string) (string, error) {
	a.mu.RLock()
	secret, exists := a.secrets[username]
	a.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("user not found")
	}

	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret.Secret)
	if err != nil {
		return "", err
	}

	counter := time.Now().Unix() / a.config.Period
	return a.generateCode(secretBytes, counter), nil
}

// cryptoRandRead is a wrapper for crypto/rand.Read to allow testing.
var cryptoRandRead = func(b []byte) (int, error) {
	return rand.Read(b)
}
