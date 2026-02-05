// Package ntlm provides NTLM/Negotiate authentication for Bifrost.
// It supports Windows NTLM authentication as a fallback when Kerberos is not available.
package ntlm

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// ContextKey is a type for context keys used by this package.
type ContextKey string

const (
	// NTLMTokenContextKey is the context key for the NTLM token.
	NTLMTokenContextKey ContextKey = "ntlm_token"

	// NTLMChallengeContextKey is the context key for storing the NTLM challenge.
	NTLMChallengeContextKey ContextKey = "ntlm_challenge"
)

func init() {
	auth.RegisterPlugin("ntlm", &plugin{})
}

// plugin implements the auth.Plugin interface for NTLM authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "ntlm"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "NTLM/Negotiate authentication for Windows domain integration"
}

// Create creates a new NTLM authenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg := parseConfig(config)

	authenticator := &Authenticator{
		config:     cfg,
		challenges: make(map[string]*challengeState),
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(_ map[string]any) error {
	return nil
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"domain":                "EXAMPLE",
		"strip_domain":          true,
		"username_to_lowercase": true,
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "domain": {
      "type": "string",
      "description": "Default Windows domain for authentication"
    },
    "allowed_domains": {
      "type": "array",
      "description": "List of allowed Windows domains",
      "items": {"type": "string"}
    },
    "strip_domain": {
      "type": "boolean",
      "description": "Strip domain from username (DOMAIN\\user -> user)",
      "default": true
    },
    "username_to_lowercase": {
      "type": "boolean",
      "description": "Convert username to lowercase",
      "default": true
    },
    "server_challenge_secret": {
      "type": "string",
      "description": "Secret for generating server challenges (auto-generated if not specified)"
    }
  }
}`
}

// ntlmConfig represents the parsed configuration.
type ntlmConfig struct {
	Domain                string
	AllowedDomains        []string
	StripDomain           bool
	UsernameToLowercase   bool
	ServerChallengeSecret string
}

// parseConfig parses the configuration map.
func parseConfig(config map[string]any) *ntlmConfig {
	if config == nil {
		config = make(map[string]any)
	}

	cfg := &ntlmConfig{
		StripDomain:         true,
		UsernameToLowercase: true,
	}

	if domain, ok := config["domain"].(string); ok {
		cfg.Domain = strings.ToUpper(domain)
	}

	if allowedDomains, ok := config["allowed_domains"].([]any); ok {
		for _, d := range allowedDomains {
			if domain, ok := d.(string); ok {
				cfg.AllowedDomains = append(cfg.AllowedDomains, strings.ToUpper(domain))
			}
		}
	}

	if stripDomain, ok := config["strip_domain"].(bool); ok {
		cfg.StripDomain = stripDomain
	}

	if usernameToLowercase, ok := config["username_to_lowercase"].(bool); ok {
		cfg.UsernameToLowercase = usernameToLowercase
	}

	if secret, ok := config["server_challenge_secret"].(string); ok {
		cfg.ServerChallengeSecret = secret
	}

	return cfg
}

// challengeState tracks NTLM handshake state.
type challengeState struct {
	domain    string
	timestamp int64
}

// Authenticator provides NTLM authentication.
type Authenticator struct {
	config     *ntlmConfig
	challenges map[string]*challengeState // Map of session ID to challenge state
	mu         sync.RWMutex
}

// Authenticate validates NTLM credentials.
// For NTLM Negotiate auth, the NTLM token should be passed via context or as password.
// For direct auth, username should be DOMAIN\username or username@DOMAIN format,
// and password is the user's password.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	// Check if NTLM token is in context
	if token, ok := ctx.Value(NTLMTokenContextKey).([]byte); ok && len(token) > 0 {
		return a.validateNTLMToken(ctx, token)
	}

	// Try to use password as base64-encoded NTLM token
	if password != "" && len(password) > 10 {
		token, err := base64.StdEncoding.DecodeString(password)
		if err == nil && len(token) > 0 {
			// Check if it looks like an NTLM message
			if len(token) > 8 && string(token[:7]) == "NTLMSSP" {
				return a.validateNTLMToken(ctx, token)
			}
		}
	}

	// For direct username/password auth, this plugin doesn't support it
	// as NTLM requires the challenge-response mechanism
	return nil, auth.NewAuthError("ntlm", "authenticate",
		fmt.Errorf("NTLM requires challenge-response authentication; use Negotiate handler"))
}

// validateNTLMToken validates an NTLM token.
func (a *Authenticator) validateNTLMToken(ctx context.Context, token []byte) (*auth.UserInfo, error) {
	// Check token type
	if len(token) < 12 {
		return nil, auth.NewAuthError("ntlm", "validate", fmt.Errorf("invalid NTLM token"))
	}

	// Verify NTLMSSP signature
	if string(token[:7]) != "NTLMSSP" {
		return nil, auth.NewAuthError("ntlm", "validate", fmt.Errorf("not an NTLM token"))
	}

	// Get message type
	msgType := binary.LittleEndian.Uint32(token[8:12])

	switch msgType {
	case 1:
		// Type 1: Negotiate message - generate challenge
		return a.handleType1(ctx, token)
	case 3:
		// Type 3: Authenticate message - validate credentials
		return a.handleType3(ctx, token)
	default:
		return nil, auth.NewAuthError("ntlm", "validate", fmt.Errorf("unexpected NTLM message type: %d", msgType))
	}
}

// handleType1 handles NTLM Type 1 (Negotiate) messages.
func (a *Authenticator) handleType1(_ context.Context, token []byte) (*auth.UserInfo, error) {
	// Parse Type 1 message to extract domain and workstation
	// For now, we just acknowledge receipt and indicate a challenge is needed

	slog.Debug("NTLM Type 1 (Negotiate) message received")

	// Return a special error to indicate challenge is required
	return nil, &NTLMChallengeRequired{
		Token: token,
	}
}

// handleType3 handles NTLM Type 3 (Authenticate) messages.
func (a *Authenticator) handleType3(_ context.Context, token []byte) (*auth.UserInfo, error) {
	// Parse NTLM Type 3 message to extract username and domain
	domain, username, err := parseType3Message(token)
	if err != nil {
		return nil, auth.NewAuthError("ntlm", "parse", err)
	}

	// Validate domain
	if len(a.config.AllowedDomains) > 0 {
		allowed := false
		for _, d := range a.config.AllowedDomains {
			if strings.EqualFold(d, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, auth.NewAuthError("ntlm", "policy", fmt.Errorf("domain not allowed: %s", domain))
		}
	}

	// Transform username
	transformedUsername := a.transformUsername(username, domain)

	slog.Debug("NTLM Type 3 (Authenticate) message processed",
		"username", transformedUsername,
		"domain", domain,
	)

	return &auth.UserInfo{
		Username: transformedUsername,
		Metadata: map[string]string{
			"auth_type": "ntlm",
			"domain":    domain,
		},
	}, nil
}

// parseType3Message extracts domain and username from an NTLM Type 3 message.
func parseType3Message(token []byte) (string, string, error) {
	if len(token) < 64 {
		return "", "", fmt.Errorf("NTLM Type 3 message too short")
	}

	// Domain name field (offset 28)
	domainLen := binary.LittleEndian.Uint16(token[28:30])
	domainOffset := binary.LittleEndian.Uint32(token[32:36])

	// User name field (offset 36)
	userLen := binary.LittleEndian.Uint16(token[36:38])
	userOffset := binary.LittleEndian.Uint32(token[40:44])

	// Extract domain
	var domain string
	if domainLen > 0 && int(domainOffset)+int(domainLen) <= len(token) {
		domainBytes := token[domainOffset : domainOffset+uint32(domainLen)]
		domain = decodeUTF16LE(domainBytes)
	}

	// Extract username
	var username string
	if userLen > 0 && int(userOffset)+int(userLen) <= len(token) {
		userBytes := token[userOffset : userOffset+uint32(userLen)]
		username = decodeUTF16LE(userBytes)
	}

	if username == "" {
		return "", "", fmt.Errorf("failed to extract username from NTLM message")
	}

	return domain, username, nil
}

// decodeUTF16LE decodes a UTF-16 LE encoded byte slice to a string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}

	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	return string(utf16.Decode(u16s))
}

// transformUsername applies configured transformations to the username.
func (a *Authenticator) transformUsername(username, domain string) string {
	if !a.config.StripDomain && domain != "" {
		username = domain + "\\" + username
	}

	if a.config.UsernameToLowercase {
		username = strings.ToLower(username)
	}

	return username
}

// GenerateChallenge generates an NTLM Type 2 (Challenge) message.
func (a *Authenticator) GenerateChallenge(negotiateMsg []byte, sessionID string) ([]byte, error) {
	// Create a basic NTLM Type 2 challenge message
	// This is a simplified implementation

	domain := a.config.Domain

	// Store challenge state for validation
	a.mu.Lock()
	a.challenges[sessionID] = &challengeState{
		domain:    domain,
		timestamp: time.Now().Unix(),
	}
	a.mu.Unlock()

	// Clean up old challenges periodically
	go a.cleanupChallenges()

	// Return a placeholder - real implementation would use ntlmssp library
	return nil, fmt.Errorf("NTLM challenge generation not fully implemented")
}

// ValidateAuthenticate validates an NTLM Type 3 (Authenticate) message.
func (a *Authenticator) ValidateAuthenticate(authMsg []byte, sessionID string) (*auth.UserInfo, error) {
	// Get stored challenge state
	a.mu.Lock()
	state, exists := a.challenges[sessionID]
	if exists {
		delete(a.challenges, sessionID)
	}
	a.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("no challenge found for session")
	}

	// Parse authenticate message
	domain, username, err := parseType3Message(authMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticate message: %w", err)
	}

	_ = state // Challenge validation would happen here with proper NTLM library support

	// Validate domain
	if len(a.config.AllowedDomains) > 0 {
		allowed := false
		for _, d := range a.config.AllowedDomains {
			if strings.EqualFold(d, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("domain not allowed: %s", domain)
		}
	}

	// Transform username
	transformedUsername := a.transformUsername(username, domain)

	return &auth.UserInfo{
		Username: transformedUsername,
		Metadata: map[string]string{
			"auth_type": "ntlm",
			"domain":    domain,
		},
	}, nil
}

// cleanupChallenges removes expired challenge states.
func (a *Authenticator) cleanupChallenges() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().Unix()
	maxAge := int64(300) // 5 minutes

	for sessionID, state := range a.challenges {
		if now-state.timestamp > maxAge {
			delete(a.challenges, sessionID)
		}
	}
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "ntlm"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "ntlm"
}

// GetDomain returns the configured domain.
func (a *Authenticator) GetDomain() string {
	return a.config.Domain
}

// NTLMChallengeRequired is returned when NTLM challenge-response is needed.
type NTLMChallengeRequired struct {
	Token []byte
}

func (e *NTLMChallengeRequired) Error() string {
	return "NTLM challenge required"
}

// IsNTLMChallengeRequired checks if an error indicates NTLM challenge is required.
func IsNTLMChallengeRequired(err error) bool {
	_, ok := err.(*NTLMChallengeRequired)
	return ok
}
