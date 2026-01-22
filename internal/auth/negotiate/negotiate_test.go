package negotiate_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"unicode/utf16"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
	"github.com/rennerdo30/bifrost-proxy/internal/auth/negotiate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthenticator implements auth.Authenticator for testing
type mockAuthenticator struct {
	authFunc func(ctx context.Context, username, password string) (*auth.UserInfo, error)
}

func (m *mockAuthenticator) Name() string { return "mock" }
func (m *mockAuthenticator) Type() string { return "mock" }
func (m *mockAuthenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, username, password)
	}
	return nil, auth.NewAuthError("mock", "auth", auth.ErrInvalidCredentials)
}

// ntlmAuthenticatorWithChallenge implements NTLM challenge generation
type ntlmAuthenticatorWithChallenge struct {
	authFunc              func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	generateChallengeFunc func(token []byte, sessionID string) ([]byte, error)
	validateAuthFunc      func(token []byte, sessionID string) (*auth.UserInfo, error)
}

func (m *ntlmAuthenticatorWithChallenge) Name() string { return "ntlm-mock" }
func (m *ntlmAuthenticatorWithChallenge) Type() string { return "ntlm" }
func (m *ntlmAuthenticatorWithChallenge) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, username, password)
	}
	return nil, auth.NewAuthError("ntlm-mock", "auth", auth.ErrInvalidCredentials)
}

func (m *ntlmAuthenticatorWithChallenge) GenerateChallenge(token []byte, sessionID string) ([]byte, error) {
	if m.generateChallengeFunc != nil {
		return m.generateChallengeFunc(token, sessionID)
	}
	// Return a minimal NTLM Type 2 (Challenge) message
	challenge := make([]byte, 56)
	copy(challenge[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(challenge[8:12], 2) // Type 2
	return challenge, nil
}

func (m *ntlmAuthenticatorWithChallenge) ValidateAuthenticate(token []byte, sessionID string) (*auth.UserInfo, error) {
	if m.validateAuthFunc != nil {
		return m.validateAuthFunc(token, sessionID)
	}
	return &auth.UserInfo{Username: "authenticated-user"}, nil
}

// ntlmAuthenticatorWithoutValidate only supports GenerateChallenge
type ntlmAuthenticatorWithoutValidate struct {
	authFunc              func(ctx context.Context, username, password string) (*auth.UserInfo, error)
	generateChallengeFunc func(token []byte, sessionID string) ([]byte, error)
}

func (m *ntlmAuthenticatorWithoutValidate) Name() string { return "ntlm-basic-mock" }
func (m *ntlmAuthenticatorWithoutValidate) Type() string { return "ntlm" }
func (m *ntlmAuthenticatorWithoutValidate) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, username, password)
	}
	return nil, auth.NewAuthError("ntlm-basic-mock", "auth", auth.ErrInvalidCredentials)
}

func (m *ntlmAuthenticatorWithoutValidate) GenerateChallenge(token []byte, sessionID string) ([]byte, error) {
	if m.generateChallengeFunc != nil {
		return m.generateChallengeFunc(token, sessionID)
	}
	challenge := make([]byte, 56)
	copy(challenge[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(challenge[8:12], 2)
	return challenge, nil
}

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

// createNTLMType2 creates a minimal NTLM Type 2 (Challenge) message - unexpected in client->server flow
func createNTLMType2() []byte {
	msg := make([]byte, 32)
	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2) // Type 2
	return msg
}

// createNTLMType3 creates a minimal NTLM Type 3 (Authenticate) message
func createNTLMType3(domain, username string) []byte {
	domainBytes := encodeUTF16LE(domain)
	usernameBytes := encodeUTF16LE(username)

	headerSize := uint32(64)
	domainOffset := headerSize
	usernameOffset := domainOffset + uint32(len(domainBytes))

	msg := make([]byte, usernameOffset+uint32(len(usernameBytes)))

	copy(msg[:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3)

	// Domain name
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[32:36], domainOffset)

	// User name
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(usernameBytes)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(usernameBytes)))
	binary.LittleEndian.PutUint32(msg[40:44], usernameOffset)

	copy(msg[domainOffset:], domainBytes)
	copy(msg[usernameOffset:], usernameBytes)

	return msg
}

// createSPNEGOToken creates a mock SPNEGO token (starts with ASN.1 APPLICATION tag)
func createSPNEGOToken() []byte {
	// Simplified SPNEGO token structure - must be at least 8 bytes for detection
	// ASN.1 APPLICATION tag (0x60) followed by length and padding
	return []byte{0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2b, 0x06} // ASN.1 APPLICATION tag
}

// createUnknownToken creates a token that is neither NTLM nor Kerberos
func createUnknownToken() []byte {
	// 8+ bytes, not starting with 0x60 (Kerberos) and not NTLMSSP
	return []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}
}

func TestHandler_NoAuthHeader(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	req := httptest.NewRequest("GET", "/", nil)

	userInfo, resp, err := handler.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Nil(t, userInfo)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	assert.True(t, resp.Challenge)
	assert.Contains(t, resp.Headers["Proxy-Authenticate"], "Negotiate")
}

func TestHandler_InvalidAuthHeaderFormat(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "InvalidFormat")

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authorization header format")
}

func TestHandler_UnsupportedScheme(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth scheme")
}

func TestHandler_InvalidBase64Token(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate not-valid-base64!!!")

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode auth token")
}

func TestHandler_NTLMType1_NoAuthenticator(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "NTLM authenticator not configured")
}

func TestHandler_SPNEGO_NoAuthenticator(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Kerberos authenticator not configured")
}

func TestHandler_DetectMethod_NTLM(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	ntlmToken := createNTLMType1()
	ntlmTokenB64 := base64.StdEncoding.EncodeToString(ntlmToken)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+ntlmTokenB64)

	// Should detect NTLM and fail because no authenticator
	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "NTLM")
}

func TestHandler_DetectMethod_Kerberos(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	spnegoToken := createSPNEGOToken()
	spnegoTokenB64 := base64.StdEncoding.EncodeToString(spnegoToken)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoTokenB64)

	// Should detect Kerberos and fail because no authenticator
	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Kerberos")
}

func TestHandler_DetectMethod_Unknown(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	unknownToken := createUnknownToken()
	unknownTokenB64 := base64.StdEncoding.EncodeToString(unknownToken)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+unknownTokenB64)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown authentication method")
}

func TestHandler_AllowNTLM_False(t *testing.T) {
	config := negotiate.DefaultHandlerConfig()
	config.AllowNTLM = false

	handler := negotiate.NewHandler(config, nil, nil)
	defer handler.Close()

	req := httptest.NewRequest("GET", "/", nil)

	_, resp, err := handler.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Should not include NTLM in challenge
	assert.NotContains(t, resp.Headers["Proxy-Authenticate"], "NTLM")
	assert.Contains(t, resp.Headers["Proxy-Authenticate"], "Negotiate")
}

func TestHandler_Response_Write(t *testing.T) {
	resp := &negotiate.Response{
		StatusCode: http.StatusProxyAuthRequired,
		Headers: map[string]string{
			"Proxy-Authenticate": "Negotiate",
			"X-Custom-Header":    "value",
		},
		Challenge: true,
	}

	rec := httptest.NewRecorder()
	resp.Write(rec)

	assert.Equal(t, http.StatusProxyAuthRequired, rec.Code)
	assert.Equal(t, "Negotiate", rec.Header().Get("Proxy-Authenticate"))
	assert.Equal(t, "value", rec.Header().Get("X-Custom-Header"))
}

func TestHandler_Middleware_NoChallengeSuccess(t *testing.T) {
	// Create a mock authenticator that always succeeds
	mockAuth := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return &auth.UserInfo{Username: "testuser"}, nil
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), mockAuth, nil)
	defer handler.Close()

	// Create the actual handler that will be wrapped
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := negotiate.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	wrapped := handler.Middleware(innerHandler)

	// Test without auth header (should return challenge)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusProxyAuthRequired, rec.Code)
}

func TestHandler_Middleware_WithSuccessfulAuth(t *testing.T) {
	// Create a mock kerberos authenticator that always succeeds
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return &auth.UserInfo{Username: "kerberosuser", Groups: []string{"domain-users"}}, nil
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), mockKerberos, nil)
	defer handler.Close()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := negotiate.GetUserInfoFromContext(r.Context())
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	wrapped := handler.Middleware(innerHandler)

	// Test with SPNEGO token (Kerberos)
	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "kerberosuser", rec.Body.String())
}

func TestHandler_Middleware_AuthError(t *testing.T) {
	// Create a mock authenticator that always fails
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, errors.New("authentication failed")
		},
	}

	config := negotiate.DefaultHandlerConfig()
	config.AllowNTLM = false // Disable NTLM fallback

	handler := negotiate.NewHandler(config, mockKerberos, nil)
	defer handler.Close()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.Middleware(innerHandler)

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusProxyAuthRequired, rec.Code)
}

func TestHandler_ProxyMiddleware_NoAuth(t *testing.T) {
	config := negotiate.DefaultHandlerConfig()
	config.Realm = "Test Realm"

	handler := negotiate.NewHandler(config, nil, nil)
	defer handler.Close()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.ProxyMiddleware(innerHandler)

	// Test without auth header
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusProxyAuthRequired, rec.Code)
}

func TestHandler_ProxyMiddleware_AuthError(t *testing.T) {
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, errors.New("authentication failed")
		},
	}

	config := negotiate.DefaultHandlerConfig()
	config.Realm = "Test Realm"
	config.AllowNTLM = false

	handler := negotiate.NewHandler(config, mockKerberos, nil)
	defer handler.Close()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.ProxyMiddleware(innerHandler)

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusProxyAuthRequired, rec.Code)
	assert.Contains(t, rec.Header().Get("Proxy-Authenticate"), "Negotiate")
	assert.Contains(t, rec.Header().Get("Proxy-Authenticate"), "Test Realm")
}

func TestHandler_ProxyMiddleware_SuccessfulAuth(t *testing.T) {
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return &auth.UserInfo{Username: "proxyuser"}, nil
		},
	}

	config := negotiate.DefaultHandlerConfig()
	config.Realm = "Proxy Realm"

	handler := negotiate.NewHandler(config, mockKerberos, nil)
	defer handler.Close()

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := negotiate.GetUserInfoFromContext(r.Context())
		// Verify Proxy-Authorization was removed
		assert.Empty(t, r.Header.Get("Proxy-Authorization"))
		if userInfo != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(userInfo.Username))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	wrapped := handler.ProxyMiddleware(innerHandler)

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "proxyuser", rec.Body.String())
}

func TestHandler_Close(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)

	err := handler.Close()
	assert.NoError(t, err)
}

func TestDefaultHandlerConfig(t *testing.T) {
	config := negotiate.DefaultHandlerConfig()

	assert.True(t, config.PreferKerberos)
	assert.True(t, config.AllowNTLM)
	assert.Equal(t, "Bifrost Proxy", config.Realm)
	assert.NotZero(t, config.ChallengeTimeout)
}

func TestGetUserInfoFromContext(t *testing.T) {
	// Can't directly set the context key from outside the package,
	// but we can test that nil is returned when not present
	ctx := context.Background()
	retrieved := negotiate.GetUserInfoFromContext(ctx)
	assert.Nil(t, retrieved)
}

func TestHandler_AuthorizationHeader(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	// Test with Authorization header (instead of Proxy-Authorization)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Negotiate test")

	// Should try to decode (will fail but shows it reads the header)
	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
}

func TestHandler_ShortToken(t *testing.T) {
	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, nil)
	defer handler.Close()

	// Token too short to determine method
	shortToken := base64.StdEncoding.EncodeToString([]byte("short"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+shortToken)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown authentication method")
}

func TestHandler_NTLMType1_WithAuthenticator(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	userInfo, resp, err := handler.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Nil(t, userInfo) // Type 1 returns challenge, not user info
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	assert.True(t, resp.Challenge)
	assert.Contains(t, resp.Headers["Proxy-Authenticate"], "NTLM ")
}

func TestHandler_NTLMType1_ChallengeGenerationError(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{
		generateChallengeFunc: func(token []byte, sessionID string) ([]byte, error) {
			return nil, errors.New("challenge generation failed")
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate NTLM challenge")
}

func TestHandler_NTLMType1_AuthenticatorWithoutChallengeSupport(t *testing.T) {
	// Use a basic mock authenticator that doesn't support GenerateChallenge
	basicAuth := &mockAuthenticator{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, basicAuth)
	defer handler.Close()

	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support challenge generation")
}

func TestHandler_NTLMType3_WithAuthenticator(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// First, send Type 1 to establish session
	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	req1.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, resp, err := handler.Authenticate(context.Background(), req1)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Then, send Type 3 with same session
	type3Token := base64.StdEncoding.EncodeToString(createNTLMType3("DOMAIN", "testuser"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:12345"
	req3.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	userInfo, resp3, err := handler.Authenticate(context.Background(), req3)
	require.NoError(t, err)
	assert.Nil(t, resp3)
	assert.NotNil(t, userInfo)
	assert.Equal(t, "authenticated-user", userInfo.Username)
}

func TestHandler_NTLMType3_NoSession(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// Send Type 3 without prior Type 1
	type3Token := base64.StdEncoding.EncodeToString(createNTLMType3("DOMAIN", "testuser"))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge found for session")
}

func TestHandler_NTLMType3_ValidationError(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{
		validateAuthFunc: func(token []byte, sessionID string) (*auth.UserInfo, error) {
			return nil, errors.New("validation failed")
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// First establish session
	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:11111"
	req1.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req1)
	require.NoError(t, err)

	// Then send Type 3
	type3Token := base64.StdEncoding.EncodeToString(createNTLMType3("DOMAIN", "testuser"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:11111"
	req3.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	_, _, err = handler.Authenticate(context.Background(), req3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestHandler_NTLMType3_FallbackToBasicAuth(t *testing.T) {
	// Use authenticator that supports GenerateChallenge but not ValidateAuthenticate
	ntlmAuth := &ntlmAuthenticatorWithoutValidate{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return &auth.UserInfo{Username: "fallback-user"}, nil
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// First establish session
	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:22222"
	req1.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req1)
	require.NoError(t, err)

	// Then send Type 3
	type3Token := base64.StdEncoding.EncodeToString(createNTLMType3("DOMAIN", "testuser"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:22222"
	req3.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	userInfo, _, err := handler.Authenticate(context.Background(), req3)
	require.NoError(t, err)
	assert.NotNil(t, userInfo)
	assert.Equal(t, "fallback-user", userInfo.Username)
}

func TestHandler_NTLMType3_FallbackToBasicAuthError(t *testing.T) {
	// Use authenticator that supports GenerateChallenge but not ValidateAuthenticate
	ntlmAuth := &ntlmAuthenticatorWithoutValidate{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, errors.New("basic auth failed")
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// First establish session
	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:33333"
	req1.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req1)
	require.NoError(t, err)

	// Then send Type 3
	type3Token := base64.StdEncoding.EncodeToString(createNTLMType3("DOMAIN", "testuser"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:33333"
	req3.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	_, _, err = handler.Authenticate(context.Background(), req3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "basic auth failed")
}

func TestHandler_NTLMType2_UnexpectedMessageType(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// Type 2 is server-to-client, shouldn't come from client
	type2Token := base64.StdEncoding.EncodeToString(createNTLMType2())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "NTLM "+type2Token)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected NTLM message type")
}

func TestHandler_NTLMInvalidTokenLength(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// Create an NTLM token that's too short (less than 12 bytes)
	shortNTLMToken := []byte("NTLMSSP\x00") // 8 bytes only
	tokenB64 := base64.StdEncoding.EncodeToString(shortNTLMToken)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "NTLM "+tokenB64)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid NTLM token")
}

func TestHandler_KerberosAuthWithNTLMFallback(t *testing.T) {
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, errors.New("kerberos auth failed")
		},
	}

	// NTLM fallback needs to handle the SPNEGO token which is not a valid NTLM token
	// So the fallback path will fail with "invalid NTLM token" since SPNEGO token is too short
	// This test verifies the fallback path is attempted
	mockNTLM := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return &auth.UserInfo{Username: "ntlm-fallback-user"}, nil
		},
	}

	config := negotiate.DefaultHandlerConfig()
	config.AllowNTLM = true

	handler := negotiate.NewHandler(config, mockKerberos, mockNTLM)
	defer handler.Close()

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)

	// The fallback will try to handle the SPNEGO token as NTLM but fail because
	// the SPNEGO token is only 8 bytes and NTLM requires 12+
	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid NTLM token")
}

func TestHandler_KerberosAuthWithNTLMFallbackDisabled(t *testing.T) {
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, errors.New("kerberos auth failed")
		},
	}

	config := negotiate.DefaultHandlerConfig()
	config.AllowNTLM = false

	handler := negotiate.NewHandler(config, mockKerberos, nil)
	defer handler.Close()

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kerberos auth failed")
}

func TestHandler_KerberosAuthWithNTLMFallbackNoNTLMAuthenticator(t *testing.T) {
	mockKerberos := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, errors.New("kerberos auth failed")
		},
	}

	config := negotiate.DefaultHandlerConfig()
	config.AllowNTLM = true

	// NTLM fallback allowed but no NTLM authenticator
	handler := negotiate.NewHandler(config, mockKerberos, nil)
	defer handler.Close()

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)

	_, _, err := handler.Authenticate(context.Background(), req)
	assert.Error(t, err)
	// Should still get kerberos error since fallback fails
	assert.Contains(t, err.Error(), "kerberos auth failed")
}

func TestHandler_NTLMSchemeInHeader(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:44444"
	req.Header.Set("Proxy-Authorization", "ntlm "+type1Token) // lowercase "ntlm"

	userInfo, resp, err := handler.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Nil(t, userInfo)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
}

func TestHandler_ChallengeCleanup(t *testing.T) {
	// This test verifies that challenges are consumed on Type 3 requests
	// The cleanup goroutine runs on a minute ticker so we test the deletion behavior
	// directly through the Type 3 flow (session gets deleted after use)
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// Establish a session
	type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:66666"
	req1.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

	_, _, err := handler.Authenticate(context.Background(), req1)
	require.NoError(t, err)

	// First Type 3 should succeed
	type3Token := base64.StdEncoding.EncodeToString(createNTLMType3("DOMAIN", "testuser"))
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "127.0.0.1:66666"
	req3.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	userInfo, _, err := handler.Authenticate(context.Background(), req3)
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	// Second Type 3 with same session should fail (session was consumed/deleted)
	req3b := httptest.NewRequest("GET", "/", nil)
	req3b.RemoteAddr = "127.0.0.1:66666"
	req3b.Header.Set("Proxy-Authorization", "NTLM "+type3Token)

	_, _, err = handler.Authenticate(context.Background(), req3b)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge found for session")
}

func TestHandler_ResponseWrite_EmptyHeaders(t *testing.T) {
	resp := &negotiate.Response{
		StatusCode: http.StatusOK,
		Headers:    nil,
		Challenge:  false,
	}

	rec := httptest.NewRecorder()
	resp.Write(rec)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Middleware_NilUserInfo(t *testing.T) {
	// Create a handler with successful auth but nil user info
	mockAuth := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, nil // Success but no user info
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), mockAuth, nil)
	defer handler.Close()

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		userInfo := negotiate.GetUserInfoFromContext(r.Context())
		assert.Nil(t, userInfo)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.Middleware(innerHandler)

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_ProxyMiddleware_NilUserInfo(t *testing.T) {
	mockAuth := &mockAuthenticator{
		authFunc: func(ctx context.Context, username, password string) (*auth.UserInfo, error) {
			return nil, nil // Success but no user info
		},
	}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), mockAuth, nil)
	defer handler.Close()

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		userInfo := negotiate.GetUserInfoFromContext(r.Context())
		assert.Nil(t, userInfo)
		// Verify Proxy-Authorization was removed
		assert.Empty(t, r.Header.Get("Proxy-Authorization"))
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.ProxyMiddleware(innerHandler)

	spnegoToken := base64.StdEncoding.EncodeToString(createSPNEGOToken())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "Negotiate "+spnegoToken)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_ConcurrentRequests(t *testing.T) {
	ntlmAuth := &ntlmAuthenticatorWithChallenge{}

	handler := negotiate.NewHandler(negotiate.DefaultHandlerConfig(), nil, ntlmAuth)
	defer handler.Close()

	// Run multiple concurrent Type 1 requests from different clients
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(clientID int) {
			type1Token := base64.StdEncoding.EncodeToString(createNTLMType1())
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "127.0.0.1:" + string(rune(10000+clientID))
			req.Header.Set("Proxy-Authorization", "NTLM "+type1Token)

			_, resp, err := handler.Authenticate(context.Background(), req)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
