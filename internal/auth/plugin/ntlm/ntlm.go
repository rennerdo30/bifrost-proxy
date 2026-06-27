// Package ntlm provides NTLM/Negotiate authentication for Bifrost.
// It supports Windows NTLM authentication as a fallback when Kerberos is not available.
package ntlm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// ErrVerificationUnsupported is returned when an NTLM Type 3 message is
// syntactically valid but cannot be cryptographically verified. This plugin
// has no credential source (no NT-hash store and no domain-controller
// pass-through), so it cannot recompute and compare the client's NTLMv2
// response. Authenticating on the basis of the client-supplied username alone
// would be an authentication bypass, so the plugin fails closed instead.
var ErrVerificationUnsupported = errors.New(
	"NTLM response verification is not supported: no credential source " +
		"(NT-hash store or domain-controller pass-through) is configured to " +
		"verify the client response; refusing to authenticate")

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

	// Transform username (for logging only — see security note below).
	transformedUsername := a.transformUsername(username, domain)

	// SECURITY: do NOT authenticate on the basis of the parsed username alone.
	// The NTLMv2 response in this message is never verified (no credential
	// source exists), so returning a UserInfo here would let any client
	// authenticate as any user. Fail closed.
	slog.Warn("NTLM authentication refused: response verification unsupported",
		"username", transformedUsername,
		"domain", domain,
	)

	return nil, auth.NewAuthError("ntlm", "validate", ErrVerificationUnsupported)
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

// encodeUTF16LE encodes a string to UTF-16 little-endian bytes.
func encodeUTF16LE(s string) []byte {
	u16s := utf16.Encode([]rune(s))
	b := make([]byte, len(u16s)*2)
	for i, u := range u16s {
		binary.LittleEndian.PutUint16(b[i*2:], u)
	}
	return b
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
	if len(negotiateMsg) < 12 || string(negotiateMsg[:7]) != "NTLMSSP" {
		return nil, fmt.Errorf("invalid NTLM negotiate message")
	}

	domain := a.config.Domain
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generate NTLM challenge bytes: %w", err)
	}

	// Store challenge state for validation
	a.mu.Lock()
	a.challenges[sessionID] = &challengeState{
		domain:    domain,
		timestamp: time.Now().Unix(),
	}
	a.mu.Unlock()

	// Clean up old challenges periodically
	go a.cleanupChallenges()

	return buildType2Message(domain, challenge), nil
}

// AV pair (target-info) IDs from MS-NLMP §2.2.2.1.
const (
	avEOL             uint16 = 0x0000 // MsvAvEOL
	avNbComputerName  uint16 = 0x0001 // MsvAvNbComputerName
	avNbDomainName    uint16 = 0x0002 // MsvAvNbDomainName
	avDNSComputerName uint16 = 0x0003 // MsvAvDnsComputerName
	avDNSDomainName   uint16 = 0x0004 // MsvAvDnsDomainName
	avTimestamp       uint16 = 0x0007 // MsvAvTimestamp
)

// Negotiate flags from MS-NLMP §2.2.2.5 used in our Type 2 message.
const (
	ntlmNegotiateUnicode    uint32 = 0x00000001 // NTLMSSP_NEGOTIATE_UNICODE
	ntlmNegotiateOEM        uint32 = 0x00000002 // NTLM_NEGOTIATE_OEM
	ntlmRequestTarget       uint32 = 0x00000004 // NTLMSSP_REQUEST_TARGET
	ntlmNegotiateNTLM       uint32 = 0x00000200 // NTLMSSP_NEGOTIATE_NTLM
	ntlmNegotiateAlwaysSign uint32 = 0x00008000 // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	ntlmTargetTypeDomain    uint32 = 0x00010000 // NTLMSSP_TARGET_TYPE_DOMAIN
	ntlmNegotiateTargetInfo uint32 = 0x00800000 // NTLMSSP_NEGOTIATE_TARGET_INFO
	ntlmNegotiateExtSec     uint32 = 0x00080000 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (NTLM2)
)

// appendAVPair appends a single AV pair (2-byte ID, 2-byte length, value) to buf.
func appendAVPair(buf []byte, id uint16, value []byte) []byte {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint16(hdr[0:2], id)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(value)))
	buf = append(buf, hdr...)
	buf = append(buf, value...)
	return buf
}

// buildTargetInfo constructs the NTLM target-info (AV pair) block. It advertises
// the NetBIOS/DNS domain and computer names plus a current timestamp so that
// modern clients (which expect NTLMv2 target info) compute a well-formed
// response. The names are derived purely from the configured domain; no host
// secrets are leaked. The timestamp is FILETIME (100ns ticks since 1601-01-01).
func buildTargetInfo(domain string) []byte {
	d := strings.ToUpper(strings.TrimSpace(domain))

	// NetBIOS computer name is conventionally the domain's leading label
	// uppercased and truncated to 15 chars; DNS computer name uses the full
	// domain. These are advertised hints only — they are never used to make an
	// authentication decision (the plugin is fail-closed).
	nbDomain := d
	dnsDomain := strings.ToLower(d)

	nbComputer := d
	if idx := strings.IndexByte(d, '.'); idx >= 0 {
		nbComputer = d[:idx]
	}
	if len(nbComputer) > 15 {
		nbComputer = nbComputer[:15]
	}
	dnsComputer := strings.ToLower(d)

	var info []byte
	if nbDomain != "" {
		info = appendAVPair(info, avNbDomainName, encodeUTF16LE(nbDomain))
	}
	if nbComputer != "" {
		info = appendAVPair(info, avNbComputerName, encodeUTF16LE(nbComputer))
	}
	if dnsDomain != "" {
		info = appendAVPair(info, avDNSDomainName, encodeUTF16LE(dnsDomain))
	}
	if dnsComputer != "" {
		info = appendAVPair(info, avDNSComputerName, encodeUTF16LE(dnsComputer))
	}
	info = appendAVPair(info, avTimestamp, filetimeNow())

	// Terminating MsvAvEOL pair (zero length).
	info = appendAVPair(info, avEOL, nil)
	return info
}

// filetimeNow returns the current time as a little-endian Windows FILETIME
// (number of 100-nanosecond intervals since 1601-01-01 00:00:00 UTC), 8 bytes.
func filetimeNow() []byte {
	// 11644473600 seconds between 1601-01-01 and 1970-01-01.
	const epochDeltaSeconds = 11644473600
	now := time.Now().UTC()
	ticks := (uint64(now.Unix()) + epochDeltaSeconds) * 10000000
	ticks += uint64(now.Nanosecond()) / 100
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ticks)
	return b
}

// buildType2Message builds an NTLM Type 2 (Challenge) message that carries the
// server challenge and a target-info block (NetBIOS/DNS domain and computer
// names plus a timestamp) for client compatibility.
//
// SECURITY: this message is purely advisory. The plugin remains fail-closed: it
// has no credential source and never verifies the resulting Type 3 response, so
// the contents here cannot enable an authentication bypass.
func buildType2Message(domain string, challenge []byte) []byte {
	targetName := encodeUTF16LE(strings.ToUpper(strings.TrimSpace(domain)))
	targetInfo := buildTargetInfo(domain)

	const headerLen = 56 // fixed header incl. 8-byte target-info security buffer + 8-byte context
	targetNameOffset := uint32(headerLen)
	targetInfoOffset := targetNameOffset + uint32(len(targetName))

	msg := make([]byte, int(targetInfoOffset)+len(targetInfo))

	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2) // Type 2

	// Target name security buffer (offset 12).
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], targetNameOffset)

	// Negotiate flags (offset 20). Advertise Unicode, target info, and that the
	// target type is a domain so clients build NTLMv2 responses.
	flags := ntlmNegotiateUnicode | ntlmNegotiateOEM | ntlmRequestTarget |
		ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign | ntlmNegotiateExtSec |
		ntlmTargetTypeDomain | ntlmNegotiateTargetInfo
	binary.LittleEndian.PutUint32(msg[20:24], flags)

	// Server challenge (offset 24, 8 bytes).
	copy(msg[24:32], challenge)

	// Reserved/context (offset 32, 8 bytes) — left as zero.

	// Target info security buffer (offset 40).
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], targetInfoOffset)

	// Version (offset 48, 8 bytes) — left as zero; harmless and optional.

	copy(msg[targetNameOffset:], targetName)
	copy(msg[targetInfoOffset:], targetInfo)
	return msg
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

	_ = state // The stored challenge cannot be used to verify the response: no credential source exists.

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

	// Transform username (for logging only — see security note below).
	transformedUsername := a.transformUsername(username, domain)

	// SECURITY: the NTLMv2 response is never cryptographically verified here,
	// so we must not return a successful UserInfo. Fail closed. The session
	// challenge has already been consumed above.
	slog.Warn("NTLM authentication refused: response verification unsupported",
		"username", transformedUsername,
		"domain", domain,
	)

	return nil, auth.NewAuthError("ntlm", "validate", ErrVerificationUnsupported)
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
