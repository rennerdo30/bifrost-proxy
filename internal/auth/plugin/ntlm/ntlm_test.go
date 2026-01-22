package ntlm_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodeUTF16LE encodes a string as UTF-16 LE bytes
func encodeUTF16LE(s string) []byte {
	u16s := utf16.Encode([]rune(s))
	b := make([]byte, len(u16s)*2)
	for i, u := range u16s {
		binary.LittleEndian.PutUint16(b[i*2:], u)
	}
	return b
}

// createNTLMType1 creates a minimal NTLM Type 1 (Negotiate) message
func createNTLMType1() []byte {
	msg := make([]byte, 32)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1) // Type 1
	return msg
}

// createNTLMType3 creates a minimal NTLM Type 3 (Authenticate) message
func createNTLMType3(domain, username string) []byte {
	domainBytes := encodeUTF16LE(domain)
	usernameBytes := encodeUTF16LE(username)

	// Calculate offsets
	headerSize := uint32(64)
	domainOffset := headerSize
	usernameOffset := domainOffset + uint32(len(domainBytes))

	msg := make([]byte, usernameOffset+uint32(len(usernameBytes)))

	// NTLMSSP signature
	copy(msg[:8], "NTLMSSP\x00")
	// Type 3
	binary.LittleEndian.PutUint32(msg[8:12], 3)

	// LM response (empty)
	binary.LittleEndian.PutUint16(msg[12:14], 0) // Length
	binary.LittleEndian.PutUint16(msg[14:16], 0) // Max Length
	binary.LittleEndian.PutUint32(msg[16:20], 0) // Offset

	// NTLM response (empty)
	binary.LittleEndian.PutUint16(msg[20:22], 0) // Length
	binary.LittleEndian.PutUint16(msg[22:24], 0) // Max Length
	binary.LittleEndian.PutUint32(msg[24:28], 0) // Offset

	// Domain name
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[32:36], domainOffset)

	// User name
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(usernameBytes)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(usernameBytes)))
	binary.LittleEndian.PutUint32(msg[40:44], usernameOffset)

	// Workstation (empty)
	binary.LittleEndian.PutUint16(msg[44:46], 0)
	binary.LittleEndian.PutUint16(msg[46:48], 0)
	binary.LittleEndian.PutUint32(msg[48:52], 0)

	// Copy domain and username
	copy(msg[domainOffset:], domainBytes)
	copy(msg[usernameOffset:], usernameBytes)

	return msg
}

func createNTLMAuthenticator(t *testing.T, cfg map[string]any) auth.Authenticator {
	t.Helper()
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config:  cfg,
	})
	require.NoError(t, err)
	return authenticator
}

func TestNTLMPlugin_Registration(t *testing.T) {
	plugin, ok := auth.GetPlugin("ntlm")
	require.True(t, ok, "ntlm plugin not registered")
	assert.Equal(t, "ntlm", plugin.Type())
	assert.NotEmpty(t, plugin.Description())
}

func TestNTLMPlugin_ValidateConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("ntlm")
	require.True(t, ok)

	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "empty config is valid",
			config:  map[string]any{},
			wantErr: false,
		},
		{
			name: "config with domain",
			config: map[string]any{
				"domain": "CORP",
			},
			wantErr: false,
		},
		{
			name: "config with allowed_domains",
			config: map[string]any{
				"allowed_domains": []any{"CORP", "SALES"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNTLMPlugin_DefaultConfig(t *testing.T) {
	plugin, ok := auth.GetPlugin("ntlm")
	require.True(t, ok)

	defaults := plugin.DefaultConfig()
	assert.NotNil(t, defaults)
	assert.Equal(t, "EXAMPLE", defaults["domain"])
	assert.Equal(t, true, defaults["strip_domain"])
	assert.Equal(t, true, defaults["username_to_lowercase"])
}

func TestNTLMPlugin_ConfigSchema(t *testing.T) {
	plugin, ok := auth.GetPlugin("ntlm")
	require.True(t, ok)

	schema := plugin.ConfigSchema()
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, "domain")
	assert.Contains(t, schema, "allowed_domains")
	assert.Contains(t, schema, "strip_domain")
	assert.Contains(t, schema, "username_to_lowercase")
}

func TestNTLMAuthenticator_Type3Message(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create Type 3 message with domain and username
	type3Msg := createNTLMType3("CORP", "testuser")

	// Pass via context
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "ntlm", user.Metadata["auth_type"])
	assert.Equal(t, "CORP", user.Metadata["domain"])
}

func TestNTLMAuthenticator_Type3Message_WithDomain(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain":                "CORP",
		"strip_domain":          false,
		"username_to_lowercase": false,
	})

	type3Msg := createNTLMType3("CORP", "testuser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "CORP\\testuser", user.Username)
}

func TestNTLMAuthenticator_Type3Message_Lowercase(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"username_to_lowercase": true,
	})

	type3Msg := createNTLMType3("CORP", "TestUser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestNTLMAuthenticator_Type1Message_ChallengeRequired(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create Type 1 message
	type1Msg := createNTLMType1()
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type1Msg)

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)

	// Should return NTLMChallengeRequired error
	assert.True(t, ntlm.IsNTLMChallengeRequired(err))
}

func TestNTLMAuthenticator_AllowedDomains(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"allowed_domains": []any{"CORP", "SALES"},
	})

	// Test allowed domain
	type3Msg := createNTLMType3("CORP", "testuser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	// Test disallowed domain
	type3Msg2 := createNTLMType3("OTHER", "testuser")
	ctx2 := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg2)

	_, err = authenticator.Authenticate(ctx2, "", "")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_NoToken(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// No token in context
	_, err := authenticator.Authenticate(context.Background(), "", "")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_InvalidToken(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Invalid token (not NTLMSSP)
	invalidToken := []byte("not an ntlm token")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, invalidToken)

	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_ShortToken(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Token too short
	shortToken := []byte("NTLM")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, shortToken)

	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_NameAndType(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	assert.Equal(t, "ntlm", authenticator.Name())
	assert.Equal(t, "ntlm", authenticator.Type())
}

func TestNTLMAuthenticator_GetDomain(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "TESTDOMAIN",
	})

	// Test GetDomain if the authenticator exposes it
	if da, ok := authenticator.(interface{ GetDomain() string }); ok {
		assert.Equal(t, "TESTDOMAIN", da.GetDomain())
	}
}

func TestNTLMChallengeRequired_Error(t *testing.T) {
	err := &ntlm.NTLMChallengeRequired{
		Token: []byte("test token"),
	}
	assert.Equal(t, "NTLM challenge required", err.Error())
}

func TestIsNTLMChallengeRequired_False(t *testing.T) {
	// Test with a non-NTLMChallengeRequired error
	err := assert.AnError
	assert.False(t, ntlm.IsNTLMChallengeRequired(err))

	// Test with nil
	assert.False(t, ntlm.IsNTLMChallengeRequired(nil))
}

func TestNTLMAuthenticator_Base64EncodedToken(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create Type 3 message and base64 encode it as password
	type3Msg := createNTLMType3("CORP", "testuser")
	encodedToken := base64.StdEncoding.EncodeToString(type3Msg)

	// Authenticate using base64-encoded token as password
	user, err := authenticator.Authenticate(context.Background(), "", encodedToken)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "ntlm", user.Metadata["auth_type"])
}

func TestNTLMAuthenticator_Base64EncodedType1Token(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create Type 1 message and base64 encode it as password
	type1Msg := createNTLMType1()
	encodedToken := base64.StdEncoding.EncodeToString(type1Msg)

	// Authenticate using base64-encoded Type 1 token - should return challenge required
	_, err := authenticator.Authenticate(context.Background(), "", encodedToken)
	require.Error(t, err)
	assert.True(t, ntlm.IsNTLMChallengeRequired(err))
}

func TestNTLMAuthenticator_InvalidBase64Password(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Not a valid base64 string, should fall through to error
	_, err := authenticator.Authenticate(context.Background(), "", "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_NonNTLMBase64Password(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Valid base64 but not an NTLM token (doesn't start with NTLMSSP)
	nonNTLMData := []byte("This is not an NTLM message but is long enough")
	encodedToken := base64.StdEncoding.EncodeToString(nonNTLMData)

	// Should fall through to error because it's not an NTLM token
	_, err := authenticator.Authenticate(context.Background(), "", encodedToken)
	assert.Error(t, err)
}

func TestNTLMAuthenticator_ShortBase64Password(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Short password (less than 10 chars), should not be treated as token
	_, err := authenticator.Authenticate(context.Background(), "", "short")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_GenerateChallenge(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain": "CORP",
		},
	})
	require.NoError(t, err)

	// Cast to Authenticator to access GenerateChallenge
	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	type1Msg := createNTLMType1()
	sessionID := "test-session-123"

	// GenerateChallenge is not fully implemented, should return error
	_, err = ntlmAuth.GenerateChallenge(type1Msg, sessionID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not fully implemented")
}

func TestNTLMAuthenticator_ValidateAuthenticate(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain": "CORP",
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// First generate a challenge to set up the session
	type1Msg := createNTLMType1()
	sessionID := "test-session-456"
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, sessionID) // Creates challenge state

	// Now validate authenticate
	type3Msg := createNTLMType3("CORP", "testuser")
	user, err := ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "ntlm", user.Metadata["auth_type"])
	assert.Equal(t, "CORP", user.Metadata["domain"])
}

func TestNTLMAuthenticator_ValidateAuthenticate_NoSession(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain": "CORP",
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// Try to validate without generating challenge first
	type3Msg := createNTLMType3("CORP", "testuser")
	_, err = ntlmAuth.ValidateAuthenticate(type3Msg, "non-existent-session")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge found")
}

func TestNTLMAuthenticator_ValidateAuthenticate_InvalidMessage(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain": "CORP",
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// Generate challenge to set up session
	sessionID := "test-session-789"
	type1Msg := createNTLMType1()
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, sessionID)

	// Try to validate with invalid message (too short)
	_, err = ntlmAuth.ValidateAuthenticate([]byte("short"), sessionID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestNTLMAuthenticator_ValidateAuthenticate_DomainNotAllowed(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"allowed_domains": []any{"CORP", "SALES"},
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// Generate challenge
	sessionID := "test-session-domain"
	type1Msg := createNTLMType1()
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, sessionID)

	// Try to validate with disallowed domain
	type3Msg := createNTLMType3("UNAUTHORIZED", "testuser")
	_, err = ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "domain not allowed")
}

func TestNTLMAuthenticator_UnexpectedMessageType(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create message with unexpected type (Type 2 is server challenge, not client message)
	msg := make([]byte, 32)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2) // Type 2

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, msg)
	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected NTLM message type")
}

func TestNTLMAuthenticator_Type3Message_EmptyUsername(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create Type 3 message with empty username
	type3Msg := createNTLMType3("CORP", "")

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)
	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract username")
}

func TestNTLMAuthenticator_Type3Message_TooShort(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create message that looks like Type 3 but is too short
	msg := make([]byte, 32)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3 but too short

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, msg)
	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// createNTLMType3WithInvalidOffsets creates a Type 3 message with offsets pointing outside the message
func createNTLMType3WithInvalidOffsets() []byte {
	msg := make([]byte, 64)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

	// Domain name field with offset pointing outside message
	binary.LittleEndian.PutUint16(msg[28:30], 10)  // Length
	binary.LittleEndian.PutUint16(msg[30:32], 10)  // Max Length
	binary.LittleEndian.PutUint32(msg[32:36], 200) // Offset outside message

	// User name field with offset pointing outside message
	binary.LittleEndian.PutUint16(msg[36:38], 10)  // Length
	binary.LittleEndian.PutUint16(msg[38:40], 10)  // Max Length
	binary.LittleEndian.PutUint32(msg[40:44], 300) // Offset outside message

	return msg
}

func TestNTLMAuthenticator_Type3Message_InvalidOffsets(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Message with offsets pointing outside message bounds
	msg := createNTLMType3WithInvalidOffsets()

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, msg)
	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_DecodeUTF16LE_OddLength(t *testing.T) {
	// This tests the odd-length byte slice case in decodeUTF16LE
	// We need to create a Type 3 message that would produce odd-length data
	// The decodeUTF16LE function returns empty string for odd-length slices

	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Create a Type 3 message with corrupted length fields
	msg := make([]byte, 100)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

	// Domain name field with odd length
	binary.LittleEndian.PutUint16(msg[28:30], 5) // Odd length
	binary.LittleEndian.PutUint16(msg[30:32], 5)
	binary.LittleEndian.PutUint32(msg[32:36], 64)

	// User name field with odd length
	binary.LittleEndian.PutUint16(msg[36:38], 5) // Odd length
	binary.LittleEndian.PutUint16(msg[38:40], 5)
	binary.LittleEndian.PutUint32(msg[40:44], 70)

	// Fill some data
	copy(msg[64:], []byte("abcde"))

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, msg)
	_, err := authenticator.Authenticate(ctx, "", "")
	// Should fail because username becomes empty after decoding
	assert.Error(t, err)
}

func TestNTLMAuthenticator_Type3Message_EmptyDomain(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain":       "CORP",
		"strip_domain": false,
	})

	// Create Type 3 message with empty domain
	type3Msg := createNTLMType3("", "testuser")

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)
	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	// With empty domain and strip_domain=false, username should just be "testuser" (no backslash prepended)
	assert.Equal(t, "testuser", user.Username)
}

func TestNTLMAuthenticator_AllowedDomains_CaseInsensitive(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"allowed_domains": []any{"CORP"},
	})

	// Test with lowercase domain (should match case-insensitively)
	type3Msg := createNTLMType3("corp", "testuser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	user, err := authenticator.Authenticate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestParseConfig_AllOptions(t *testing.T) {
	plugin, ok := auth.GetPlugin("ntlm")
	require.True(t, ok)

	// Test all configuration options
	config := map[string]any{
		"domain":                  "testdomain", // lowercase, should be uppercased
		"allowed_domains":         []any{"domain1", "DOMAIN2"},
		"strip_domain":            false,
		"username_to_lowercase":   false,
		"server_challenge_secret": "secret123",
	}

	// Validate the config
	err := plugin.ValidateConfig(config)
	require.NoError(t, err)

	// Create authenticator and verify config was applied
	authenticator, err := plugin.Create(config)
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// GetDomain should return uppercased domain
	assert.Equal(t, "TESTDOMAIN", ntlmAuth.GetDomain())
}

func TestParseConfig_InvalidAllowedDomainsItem(t *testing.T) {
	// Test that non-string items in allowed_domains are ignored
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"allowed_domains": []any{"VALID", 123, true, "ANOTHER"},
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, authenticator)
}

func TestNTLMAuthenticator_EmptyTokenInContext(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Empty token in context
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, []byte{})
	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
}

func TestNTLMAuthenticator_NotNTLMSSPSignature(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain": "CORP",
	})

	// Token with wrong signature
	msg := make([]byte, 32)
	copy(msg[:8], "WRONGSIG")
	binary.LittleEndian.PutUint32(msg[8:12], 1)

	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, msg)
	_, err := authenticator.Authenticate(ctx, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an NTLM token")
}

func TestNTLMAuthenticator_ValidateAuthenticate_AllowedDomain(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"allowed_domains": []any{"CORP"},
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// Generate challenge
	sessionID := "test-session-allowed"
	type1Msg := createNTLMType1()
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, sessionID)

	// Validate with allowed domain
	type3Msg := createNTLMType3("CORP", "testuser")
	user, err := ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestNTLMAuthenticator_ValidateAuthenticate_TransformUsername(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain":                "CORP",
			"strip_domain":          false,
			"username_to_lowercase": true,
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// Generate challenge
	sessionID := "test-session-transform"
	type1Msg := createNTLMType1()
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, sessionID)

	// Validate and check username transformation
	type3Msg := createNTLMType3("CORP", "TestUser")
	user, err := ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	require.NoError(t, err)
	// strip_domain=false should prepend domain, username_to_lowercase=true should lowercase
	assert.Equal(t, "corp\\testuser", user.Username)
}

func TestNTLMAuthenticator_CleanupChallenges(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain": "CORP",
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	// Generate multiple challenges
	type1Msg := createNTLMType1()
	for i := 0; i < 5; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		_, _ = ntlmAuth.GenerateChallenge(type1Msg, sessionID)
	}

	// Wait a bit for the cleanup goroutine to run (it's triggered by GenerateChallenge)
	time.Sleep(100 * time.Millisecond)

	// The cleanup is triggered but challenges should not be expired yet (maxAge is 5 minutes)
	// Just verify we can still use one of the sessions
	type3Msg := createNTLMType3("CORP", "testuser")
	user, err := ntlmAuth.ValidateAuthenticate(type3Msg, "session-0")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
}

func TestNTLMAuthenticator_MultipleChallenges(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config: map[string]any{
			"domain": "CORP",
		},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	type1Msg := createNTLMType1()

	// Create multiple sessions
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, "session-a")
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, "session-b")
	_, _ = ntlmAuth.GenerateChallenge(type1Msg, "session-c")

	// Validate session-b first
	type3MsgB := createNTLMType3("CORP", "userB")
	userB, err := ntlmAuth.ValidateAuthenticate(type3MsgB, "session-b")
	require.NoError(t, err)
	assert.Equal(t, "userb", userB.Username)

	// session-b should be removed, try again should fail
	_, err = ntlmAuth.ValidateAuthenticate(type3MsgB, "session-b")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge found")

	// session-a and session-c should still work
	type3MsgA := createNTLMType3("CORP", "userA")
	userA, err := ntlmAuth.ValidateAuthenticate(type3MsgA, "session-a")
	require.NoError(t, err)
	assert.Equal(t, "usera", userA.Username)
}
