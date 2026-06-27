package ntlm_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/plugin/ntlm"
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

// TestNTLMAuthenticator_NoBypass is a security regression test for the former
// authentication bypass: a syntactically valid Type 3 message used to be
// accepted and authenticated as whatever username it carried, with no
// cryptographic verification. The plugin must now fail closed for ANY
// username, via both the context-token path and the challenge-response path.
func TestNTLMAuthenticator_NoBypass(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{"domain": "CORP"})

	for _, name := range []string{"administrator", "root", "attacker", "alice"} {
		type3Msg := createNTLMType3("CORP", name)
		ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

		user, err := authenticator.Authenticate(ctx, "", "")
		require.Error(t, err, "forged Type 3 for %q must not authenticate", name)
		require.Nil(t, user, "no UserInfo may be returned for unverified %q", name)
		assert.True(t, errors.Is(err, ntlm.ErrVerificationUnsupported),
			"expected ErrVerificationUnsupported for %q, got %v", name, err)
	}

	// Same guarantee on the explicit challenge/response (ValidateAuthenticate) path.
	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)
	sessionID := "no-bypass-session"
	_, _ = ntlmAuth.GenerateChallenge(createNTLMType1(), sessionID)
	user, err := ntlmAuth.ValidateAuthenticate(createNTLMType3("CORP", "administrator"), sessionID)
	require.Error(t, err)
	require.Nil(t, user)
	assert.True(t, errors.Is(err, ntlm.ErrVerificationUnsupported))
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

	// Fail closed: a syntactically valid Type 3 message must NOT authenticate,
	// because the NTLMv2 response is never cryptographically verified.
	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
}

func TestNTLMAuthenticator_Type3Message_WithDomain(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"domain":                "CORP",
		"strip_domain":          false,
		"username_to_lowercase": false,
	})

	type3Msg := createNTLMType3("CORP", "testuser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
}

func TestNTLMAuthenticator_Type3Message_Lowercase(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"username_to_lowercase": true,
	})

	type3Msg := createNTLMType3("CORP", "TestUser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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

	// Allowed domain passes policy but still fails closed (response unverified).
	type3Msg := createNTLMType3("CORP", "testuser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")

	// Disallowed domain is rejected by policy (before the fail-closed step).
	type3Msg2 := createNTLMType3("OTHER", "testuser")
	ctx2 := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg2)

	_, err = authenticator.Authenticate(ctx2, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "domain not allowed")
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

	// Authenticate using base64-encoded token as password — still fails closed.
	_, err := authenticator.Authenticate(context.Background(), "", encodedToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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

	challenge, err := ntlmAuth.GenerateChallenge(type1Msg, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, challenge)
	assert.GreaterOrEqual(t, len(challenge), 32)
	assert.Equal(t, "NTLMSSP", string(challenge[:7]))
}

// parseType2 parses an NTLM Type 2 (Challenge) message into its constituent
// security buffers. It mirrors the on-wire layout produced by the plugin and is
// used to assert that the target-info AV pairs are emitted.
type parsedType2 struct {
	flags      uint32
	challenge  []byte
	targetName []byte
	targetInfo []byte
}

func parseType2(t *testing.T, msg []byte) parsedType2 {
	t.Helper()
	require.GreaterOrEqual(t, len(msg), 48, "type 2 message too short")
	require.Equal(t, "NTLMSSP\x00", string(msg[:8]))
	require.Equal(t, uint32(2), binary.LittleEndian.Uint32(msg[8:12]))

	readBuf := func(off int) []byte {
		l := binary.LittleEndian.Uint16(msg[off : off+2])
		o := binary.LittleEndian.Uint32(msg[off+4 : off+8])
		if l == 0 {
			return nil
		}
		require.LessOrEqual(t, int(o)+int(l), len(msg), "security buffer out of bounds")
		return msg[o : o+uint32(l)]
	}

	return parsedType2{
		flags:      binary.LittleEndian.Uint32(msg[20:24]),
		challenge:  append([]byte(nil), msg[24:32]...),
		targetName: readBuf(12),
		targetInfo: readBuf(40),
	}
}

// parseAVPairs decodes a target-info block into a map of AV-pair ID -> raw value.
func parseAVPairs(t *testing.T, info []byte) map[uint16][]byte {
	t.Helper()
	out := make(map[uint16][]byte)
	i := 0
	for i+4 <= len(info) {
		id := binary.LittleEndian.Uint16(info[i : i+2])
		l := binary.LittleEndian.Uint16(info[i+2 : i+4])
		i += 4
		if id == 0x0000 { // MsvAvEOL
			require.Equal(t, uint16(0), l, "EOL pair must have zero length")
			return out
		}
		require.LessOrEqual(t, i+int(l), len(info), "AV pair value out of bounds")
		out[id] = append([]byte(nil), info[i:i+int(l)]...)
		i += int(l)
	}
	t.Fatalf("target info missing terminating MsvAvEOL pair")
	return out
}

func decodeUTF16LETest(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

func TestNTLMAuthenticator_Type2TargetInfo(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config:  map[string]any{"domain": "corp.example.com"},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	msg, err := ntlmAuth.GenerateChallenge(createNTLMType1(), "session-ti")
	require.NoError(t, err)

	p := parseType2(t, msg)

	// Target name is the uppercased domain.
	assert.Equal(t, "CORP.EXAMPLE.COM", decodeUTF16LETest(p.targetName))

	// Server challenge is 8 bytes and not all-zero (random).
	require.Len(t, p.challenge, 8)
	assert.NotEqual(t, make([]byte, 8), p.challenge, "challenge should be random, not zero")

	// Flags advertise unicode, target info, and domain target type.
	const (
		fUnicode    = 0x00000001
		fTargetInfo = 0x00800000
		fTargetDom  = 0x00010000
		fRequestTgt = 0x00000004
	)
	assert.NotZero(t, p.flags&fUnicode, "unicode flag must be set")
	assert.NotZero(t, p.flags&fTargetInfo, "target info flag must be set")
	assert.NotZero(t, p.flags&fTargetDom, "target type domain flag must be set")
	assert.NotZero(t, p.flags&fRequestTgt, "request target flag must be set")

	// Target info must be non-empty and contain the expected AV pairs.
	require.NotEmpty(t, p.targetInfo, "target info block must be present")
	pairs := parseAVPairs(t, p.targetInfo)

	const (
		avNbComputer  = 0x0001
		avNbDomain    = 0x0002
		avDNSComputer = 0x0003
		avDNSDomain   = 0x0004
		avTimestamp   = 0x0007
	)

	require.Contains(t, pairs, uint16(avNbDomain))
	assert.Equal(t, "CORP.EXAMPLE.COM", decodeUTF16LETest(pairs[avNbDomain]))

	require.Contains(t, pairs, uint16(avNbComputer))
	// NetBIOS computer name is the leading label, truncated to 15 chars.
	assert.Equal(t, "CORP", decodeUTF16LETest(pairs[avNbComputer]))

	require.Contains(t, pairs, uint16(avDNSDomain))
	assert.Equal(t, "corp.example.com", decodeUTF16LETest(pairs[avDNSDomain]))

	require.Contains(t, pairs, uint16(avDNSComputer))
	assert.Equal(t, "corp.example.com", decodeUTF16LETest(pairs[avDNSComputer]))

	require.Contains(t, pairs, uint16(avTimestamp))
	require.Len(t, pairs[avTimestamp], 8, "timestamp must be an 8-byte FILETIME")
	ft := binary.LittleEndian.Uint64(pairs[avTimestamp])
	assert.NotZero(t, ft, "timestamp must be set")
	// Sanity: FILETIME for a recent time is well above the 1970 epoch delta.
	assert.Greater(t, ft, uint64(11644473600)*10000000)
}

func TestNTLMAuthenticator_Type2TargetInfo_LongDomainTruncation(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		// Leading label longer than 15 chars exercises NetBIOS truncation.
		Config: map[string]any{"domain": "verylongdomainname.example.com"},
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	msg, err := ntlmAuth.GenerateChallenge(createNTLMType1(), "session-long")
	require.NoError(t, err)

	pairs := parseAVPairs(t, parseType2(t, msg).targetInfo)
	const avNbComputer = 0x0001
	require.Contains(t, pairs, uint16(avNbComputer))
	nb := decodeUTF16LETest(pairs[avNbComputer])
	assert.LessOrEqual(t, len(nb), 15, "NetBIOS computer name must be truncated to 15 chars")
	assert.Equal(t, "VERYLONGDOMAINN", nb)
}

func TestNTLMAuthenticator_Type2TargetInfo_EmptyDomain(t *testing.T) {
	factory := auth.NewFactory()
	authenticator, err := factory.Create(auth.ProviderConfig{
		Name:    "ntlm-test",
		Type:    "ntlm",
		Enabled: true,
		Config:  map[string]any{}, // no domain configured
	})
	require.NoError(t, err)

	ntlmAuth, ok := authenticator.(*ntlm.Authenticator)
	require.True(t, ok)

	msg, err := ntlmAuth.GenerateChallenge(createNTLMType1(), "session-empty")
	require.NoError(t, err)

	p := parseType2(t, msg)
	// Even with no domain, the timestamp + EOL must still be present and well-formed.
	pairs := parseAVPairs(t, p.targetInfo)
	const avTimestamp = 0x0007
	require.Contains(t, pairs, uint16(avTimestamp))
	require.Len(t, pairs[avTimestamp], 8)
	// No domain/computer pairs when domain is empty.
	assert.NotContains(t, pairs, uint16(0x0002))
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

	// Now validate authenticate — fails closed: the response is never verified.
	type3Msg := createNTLMType3("CORP", "testuser")
	_, err = ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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
	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
}

func TestNTLMAuthenticator_AllowedDomains_CaseInsensitive(t *testing.T) {
	authenticator := createNTLMAuthenticator(t, map[string]any{
		"allowed_domains": []any{"CORP"},
	})

	// Test with lowercase domain (should match policy case-insensitively, then fail closed)
	type3Msg := createNTLMType3("corp", "testuser")
	ctx := context.WithValue(context.Background(), ntlm.NTLMTokenContextKey, type3Msg)

	_, err := authenticator.Authenticate(ctx, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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

	// Allowed domain passes policy, then fails closed (response unverified).
	type3Msg := createNTLMType3("CORP", "testuser")
	_, err = ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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

	// Validation reaches the fail-closed step regardless of username transform.
	type3Msg := createNTLMType3("CORP", "TestUser")
	_, err = ntlmAuth.ValidateAuthenticate(type3Msg, sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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

	// The cleanup is triggered but challenges should not be expired yet (maxAge is 5 minutes).
	// Verify session-0 is still present: we reach the fail-closed step rather than
	// "no challenge found".
	type3Msg := createNTLMType3("CORP", "testuser")
	_, err = ntlmAuth.ValidateAuthenticate(type3Msg, "session-0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
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

	// First use of session-b consumes it but fails closed (response unverified).
	type3MsgB := createNTLMType3("CORP", "userB")
	_, err = ntlmAuth.ValidateAuthenticate(type3MsgB, "session-b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")

	// session-b should now be removed, try again should report no challenge
	_, err = ntlmAuth.ValidateAuthenticate(type3MsgB, "session-b")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge found")

	// session-a and session-c are still present (reach the fail-closed step)
	type3MsgA := createNTLMType3("CORP", "userA")
	_, err = ntlmAuth.ValidateAuthenticate(type3MsgA, "session-a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification is not supported")
}
