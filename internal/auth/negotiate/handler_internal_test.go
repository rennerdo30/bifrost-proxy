package negotiate

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockInternalAuthenticator implements auth.Authenticator for internal testing
type mockInternalAuthenticator struct {
	authFunc func(ctx context.Context, username, password string) (*auth.UserInfo, error)
}

func (m *mockInternalAuthenticator) Name() string { return "mock-internal" }
func (m *mockInternalAuthenticator) Type() string { return "mock" }
func (m *mockInternalAuthenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, username, password)
	}
	return nil, auth.NewAuthError("mock", "auth", auth.ErrInvalidCredentials)
}

// ntlmMockWithChallenge implements challenge generation for testing
type ntlmMockWithChallenge struct {
	authFunc func(ctx context.Context, username, password string) (*auth.UserInfo, error)
}

func (m *ntlmMockWithChallenge) Name() string { return "ntlm-mock-internal" }
func (m *ntlmMockWithChallenge) Type() string { return "ntlm" }
func (m *ntlmMockWithChallenge) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, username, password)
	}
	return nil, auth.NewAuthError("ntlm-mock", "auth", auth.ErrInvalidCredentials)
}

func (m *ntlmMockWithChallenge) GenerateChallenge(token []byte, sessionID string) ([]byte, error) {
	// Return a minimal NTLM Type 2 (Challenge) message
	challenge := make([]byte, 56)
	copy(challenge[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(challenge[8:12], 2) // Type 2
	return challenge, nil
}

func (m *ntlmMockWithChallenge) ValidateAuthenticate(token []byte, sessionID string) (*auth.UserInfo, error) {
	return &auth.UserInfo{Username: "authenticated-user-internal"}, nil
}

// createNTLMType1Internal creates a minimal NTLM Type 1 (Negotiate) message
func createNTLMType1Internal() []byte {
	msg := make([]byte, 32)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1) // Type 1
	return msg
}

func TestCleanup_RemovesExpiredChallenges(t *testing.T) {
	config := HandlerConfig{
		PreferKerberos:   true,
		AllowNTLM:        true,
		ChallengeTimeout: 50 * time.Millisecond,
		Realm:            "Test",
	}

	h := &Handler{
		config:     config,
		challenges: make(map[string]*challengeState),
		stopCh:     make(chan struct{}),
	}

	// Add an expired challenge
	h.challenges["expired-session"] = &challengeState{
		method:    AuthMethodNTLM,
		challenge: []byte("test-challenge"),
		timestamp: time.Now().Add(-1 * time.Hour), // Long ago
	}

	// Add a non-expired challenge
	h.challenges["valid-session"] = &challengeState{
		method:    AuthMethodNTLM,
		challenge: []byte("test-challenge"),
		timestamp: time.Now(), // Just now
	}

	// Call cleanup
	h.cleanup()

	// Check expired was removed
	assert.NotContains(t, h.challenges, "expired-session")
	// Check valid is still there
	assert.Contains(t, h.challenges, "valid-session")
}

func TestCleanup_EmptyChallenges(t *testing.T) {
	config := DefaultHandlerConfig()

	h := &Handler{
		config:     config,
		challenges: make(map[string]*challengeState),
		stopCh:     make(chan struct{}),
	}

	// Call cleanup on empty map (should not panic)
	h.cleanup()

	assert.Empty(t, h.challenges)
}

func TestCleanup_AllExpired(t *testing.T) {
	config := HandlerConfig{
		PreferKerberos:   true,
		AllowNTLM:        true,
		ChallengeTimeout: 10 * time.Millisecond,
		Realm:            "Test",
	}

	h := &Handler{
		config:     config,
		challenges: make(map[string]*challengeState),
		stopCh:     make(chan struct{}),
	}

	// Add multiple expired challenges
	for i := 0; i < 5; i++ {
		h.challenges["expired-"+string(rune('a'+i))] = &challengeState{
			method:    AuthMethodNTLM,
			challenge: []byte("test-challenge"),
			timestamp: time.Now().Add(-1 * time.Hour),
		}
	}

	// Call cleanup
	h.cleanup()

	// All should be removed
	assert.Empty(t, h.challenges)
}

func TestCleanup_NoneExpired(t *testing.T) {
	config := HandlerConfig{
		PreferKerberos:   true,
		AllowNTLM:        true,
		ChallengeTimeout: 1 * time.Hour,
		Realm:            "Test",
	}

	h := &Handler{
		config:     config,
		challenges: make(map[string]*challengeState),
		stopCh:     make(chan struct{}),
	}

	// Add multiple non-expired challenges
	for i := 0; i < 5; i++ {
		h.challenges["valid-"+string(rune('a'+i))] = &challengeState{
			method:    AuthMethodNTLM,
			challenge: []byte("test-challenge"),
			timestamp: time.Now(),
		}
	}

	// Call cleanup
	h.cleanup()

	// All should still be there
	assert.Len(t, h.challenges, 5)
}

func TestCleanupLoop_StopsOnClose(t *testing.T) {
	config := DefaultHandlerConfig()

	h := &Handler{
		config:     config,
		challenges: make(map[string]*challengeState),
		stopCh:     make(chan struct{}),
	}

	// Start cleanupLoop in goroutine
	done := make(chan struct{})
	go func() {
		h.cleanupLoop()
		close(done)
	}()

	// Close should stop the loop
	close(h.stopCh)

	// Wait for goroutine to finish with timeout
	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Fatal("cleanupLoop did not stop")
	}
}

func TestDetectMethod_AllCases(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name     string
		token    []byte
		expected AuthMethod
	}{
		{
			name:     "short token",
			token:    []byte{0x01, 0x02, 0x03},
			expected: AuthMethodNone,
		},
		{
			name:     "exactly 7 bytes",
			token:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expected: AuthMethodNone,
		},
		{
			name:     "NTLM signature",
			token:    []byte("NTLMSSP\x00extra"),
			expected: AuthMethodNTLM,
		},
		{
			name:     "SPNEGO/Kerberos (0x60)",
			token:    []byte{0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2b, 0x06},
			expected: AuthMethodKerberos,
		},
		{
			name:     "Unknown (not NTLM, not 0x60)",
			token:    []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
			expected: AuthMethodNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.detectMethod(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateChallenge_AllowNTLMVariants(t *testing.T) {
	tests := []struct {
		name       string
		allowNTLM  bool
		wantNTLM   bool
	}{
		{"NTLM allowed", true, true},
		{"NTLM not allowed", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultHandlerConfig()
			config.AllowNTLM = tt.allowNTLM

			h := &Handler{
				config:     config,
				challenges: make(map[string]*challengeState),
				stopCh:     make(chan struct{}),
			}

			resp := h.createChallenge(nil)

			assert.Equal(t, 407, resp.StatusCode)
			assert.True(t, resp.Challenge)

			if tt.wantNTLM {
				assert.Contains(t, resp.Headers["Proxy-Authenticate"], "NTLM")
			} else {
				assert.NotContains(t, resp.Headers["Proxy-Authenticate"], "NTLM")
			}
			assert.Contains(t, resp.Headers["Proxy-Authenticate"], "Negotiate")
		})
	}
}

func TestChallengeState_Fields(t *testing.T) {
	// Test the challengeState struct directly
	state := &challengeState{
		method:    AuthMethodNTLM,
		challenge: []byte("test-challenge"),
		timestamp: time.Now(),
	}

	assert.Equal(t, AuthMethodNTLM, state.method)
	assert.Equal(t, []byte("test-challenge"), state.challenge)
	assert.WithinDuration(t, time.Now(), state.timestamp, time.Second)
}

func TestHandler_FullNTLMFlowInternal(t *testing.T) {
	ntlmAuth := &ntlmMockWithChallenge{}

	h := NewHandler(DefaultHandlerConfig(), nil, ntlmAuth)
	defer h.Close()

	// Type 1 message
	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1Internal())

	// Manually store a challenge for testing
	sessionID := "test-session"
	h.mu.Lock()
	h.challenges[sessionID] = &challengeState{
		method:    AuthMethodNTLM,
		challenge: []byte("test-challenge"),
		timestamp: time.Now(),
	}
	h.mu.Unlock()

	// Verify the challenge was stored
	h.mu.RLock()
	_, exists := h.challenges[sessionID]
	h.mu.RUnlock()
	require.True(t, exists)

	// Cleanup should preserve recent challenges
	h.cleanup()

	h.mu.RLock()
	_, stillExists := h.challenges[sessionID]
	h.mu.RUnlock()
	assert.True(t, stillExists)

	_ = type1Token // Suppress unused warning
}

func TestContextKeys(t *testing.T) {
	// Test that context keys are correctly typed
	assert.Equal(t, contextKey("kerberos_token"), kerberosTokenKey)
	assert.Equal(t, contextKey("ntlm_token"), ntlmTokenKey)
	assert.Equal(t, contextKey("user_info"), userInfoContextKey)
}

func TestAuthMethod_Constants(t *testing.T) {
	assert.Equal(t, AuthMethod(""), AuthMethodNone)
	assert.Equal(t, AuthMethod("kerberos"), AuthMethodKerberos)
	assert.Equal(t, AuthMethod("ntlm"), AuthMethodNTLM)
}
