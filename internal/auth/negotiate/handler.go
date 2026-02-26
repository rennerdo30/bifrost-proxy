// Package negotiate provides HTTP Negotiate (SPNEGO/Kerberos/NTLM) authentication handling.
// It handles the multi-step authentication handshake required for Windows domain authentication.
package negotiate

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

// AuthMethod represents the authentication method being used.
type AuthMethod string

const (
	// AuthMethodNone indicates no authentication method has been determined.
	AuthMethodNone AuthMethod = ""
	// AuthMethodKerberos indicates Kerberos/SPNEGO authentication.
	AuthMethodKerberos AuthMethod = "kerberos"
	// AuthMethodNTLM indicates NTLM authentication.
	AuthMethodNTLM AuthMethod = "ntlm"
)

// HandlerConfig configures the Negotiate handler.
type HandlerConfig struct {
	// PreferKerberos tries Kerberos before NTLM.
	PreferKerberos bool
	// AllowNTLM enables NTLM fallback when Kerberos fails.
	AllowNTLM bool
	// ChallengeTimeout is how long to keep challenge state.
	ChallengeTimeout time.Duration
	// Realm is the realm to use in the authentication challenge.
	Realm string
}

// DefaultHandlerConfig returns sensible default configuration.
func DefaultHandlerConfig() HandlerConfig {
	return HandlerConfig{
		PreferKerberos:   true,
		AllowNTLM:        true,
		ChallengeTimeout: 5 * time.Minute,
		Realm:            "Bifrost Proxy",
	}
}

// AuthenticatorGetter is an interface for getting authenticators by type.
type AuthenticatorGetter interface {
	GetAuthenticator(authType string) auth.Authenticator
}

// Handler handles HTTP Negotiate authentication.
type Handler struct {
	config     HandlerConfig
	kerberos   auth.Authenticator
	ntlm       auth.Authenticator
	challenges map[string]*challengeState
	mu         sync.RWMutex
	stopCh     chan struct{}
}

// challengeState tracks the state of an authentication handshake.
type challengeState struct {
	method    AuthMethod
	challenge []byte
	timestamp time.Time
}

// NewHandler creates a new Negotiate handler.
func NewHandler(config HandlerConfig, kerberos, ntlm auth.Authenticator) *Handler {
	h := &Handler{
		config:     config,
		kerberos:   kerberos,
		ntlm:       ntlm,
		challenges: make(map[string]*challengeState),
		stopCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go h.cleanupLoop()

	return h
}

// Authenticate handles the Negotiate authentication flow.
// It processes the Proxy-Authorization or Authorization header and returns user info.
func (h *Handler) Authenticate(ctx context.Context, r *http.Request) (*auth.UserInfo, *Response, error) {
	// Get the authorization header (Proxy-Authorization for proxies)
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("Authorization")
	}

	if authHeader == "" {
		// No authorization header - send challenge
		return nil, h.createChallenge(r), nil
	}

	// Parse the authorization header
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid authorization header format")
	}

	scheme := strings.ToLower(parts[0])
	tokenB64 := parts[1]

	if scheme != "negotiate" && scheme != "ntlm" {
		return nil, nil, fmt.Errorf("unsupported auth scheme: %s", scheme)
	}

	// Decode the token
	token, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode auth token: %w", err)
	}

	// Determine the authentication method from the token
	method := h.detectMethod(token)

	slog.Debug("negotiate auth received",
		"method", method,
		"scheme", scheme,
		"token_len", len(token),
	)

	switch method {
	case AuthMethodKerberos:
		return h.handleKerberos(ctx, r, token)
	case AuthMethodNTLM:
		return h.handleNTLM(ctx, r, token)
	default:
		return nil, nil, fmt.Errorf("unknown authentication method")
	}
}

// createChallenge creates an authentication challenge response.
func (h *Handler) createChallenge(_ *http.Request) *Response {
	schemes := []string{"Negotiate"}
	if h.config.AllowNTLM {
		schemes = append(schemes, "NTLM")
	}

	return &Response{
		StatusCode: http.StatusProxyAuthRequired,
		Headers: map[string]string{
			"Proxy-Authenticate": strings.Join(schemes, ", "),
		},
		Challenge: true,
	}
}

// detectMethod determines the authentication method from the token.
func (h *Handler) detectMethod(token []byte) AuthMethod {
	if len(token) < 8 {
		return AuthMethodNone
	}

	// Check for NTLM signature "NTLMSSP\0"
	if string(token[:7]) == "NTLMSSP" {
		return AuthMethodNTLM
	}

	// Assume SPNEGO/Kerberos for other tokens
	// SPNEGO tokens start with ASN.1 APPLICATION tag (0x60)
	if token[0] == 0x60 {
		return AuthMethodKerberos
	}

	return AuthMethodNone
}

// handleKerberos handles Kerberos/SPNEGO authentication.
func (h *Handler) handleKerberos(ctx context.Context, r *http.Request, token []byte) (*auth.UserInfo, *Response, error) {
	if h.kerberos == nil {
		return nil, nil, fmt.Errorf("kerberos authenticator not configured")
	}

	// Create a context with the SPNEGO token
	ctx = context.WithValue(ctx, kerberosTokenKey, token)

	// Authenticate
	userInfo, err := h.kerberos.Authenticate(ctx, "", base64.StdEncoding.EncodeToString(token))
	if err != nil {
		slog.Debug("Kerberos authentication failed", "error", err)

		// If NTLM fallback is allowed and we have an NTLM authenticator, try that
		if h.config.AllowNTLM && h.ntlm != nil {
			return h.handleNTLM(ctx, r, token)
		}

		return nil, nil, err
	}

	return userInfo, nil, nil
}

// handleNTLM handles NTLM authentication.
func (h *Handler) handleNTLM(ctx context.Context, r *http.Request, token []byte) (*auth.UserInfo, *Response, error) {
	if h.ntlm == nil {
		return nil, nil, fmt.Errorf("NTLM authenticator not configured")
	}

	if len(token) < 12 {
		return nil, nil, fmt.Errorf("invalid NTLM token")
	}

	// Get message type
	msgType := uint32(token[8]) | uint32(token[9])<<8 | uint32(token[10])<<16 | uint32(token[11])<<24

	switch msgType {
	case 1:
		// Type 1: Negotiate message - generate challenge
		return h.handleNTLMType1(ctx, r, token)
	case 3:
		// Type 3: Authenticate message - validate credentials
		return h.handleNTLMType3(ctx, r, token)
	default:
		return nil, nil, fmt.Errorf("unexpected NTLM message type: %d", msgType)
	}
}

// handleNTLMType1 handles NTLM Type 1 (Negotiate) messages.
func (h *Handler) handleNTLMType1(_ context.Context, r *http.Request, token []byte) (*auth.UserInfo, *Response, error) {
	// Generate session ID for tracking the handshake
	sessionID := getClientSessionID(r)

	// Generate challenge using the NTLM authenticator
	ntlmAuth, ok := h.ntlm.(interface {
		GenerateChallenge([]byte, string) ([]byte, error)
	})
	if !ok {
		return nil, nil, fmt.Errorf("NTLM authenticator does not support challenge generation")
	}

	challenge, err := ntlmAuth.GenerateChallenge(token, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate NTLM challenge: %w", err)
	}

	// Store challenge state
	h.mu.Lock()
	h.challenges[sessionID] = &challengeState{
		method:    AuthMethodNTLM,
		challenge: challenge,
		timestamp: time.Now(),
	}
	h.mu.Unlock()

	// Return challenge response
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)

	return nil, &Response{
		StatusCode: http.StatusProxyAuthRequired,
		Headers: map[string]string{
			"Proxy-Authenticate": "NTLM " + challengeB64,
		},
		Challenge: true,
	}, nil
}

// handleNTLMType3 handles NTLM Type 3 (Authenticate) messages.
func (h *Handler) handleNTLMType3(ctx context.Context, r *http.Request, token []byte) (*auth.UserInfo, *Response, error) {
	sessionID := getClientSessionID(r)

	// Get stored challenge state
	h.mu.Lock()
	state, exists := h.challenges[sessionID]
	if exists {
		delete(h.challenges, sessionID)
	}
	h.mu.Unlock()

	if !exists {
		return nil, nil, fmt.Errorf("no challenge found for session")
	}

	// Validate using NTLM authenticator
	ntlmAuth, ok := h.ntlm.(interface {
		ValidateAuthenticate([]byte, string) (*auth.UserInfo, error)
	})
	if !ok {
		// Fall back to basic authentication
		ctx = context.WithValue(ctx, ntlmTokenKey, token)
		userInfo, err := h.ntlm.Authenticate(ctx, "", base64.StdEncoding.EncodeToString(token))
		return userInfo, nil, err
	}

	userInfo, err := ntlmAuth.ValidateAuthenticate(token, sessionID)
	if err != nil {
		return nil, nil, err
	}

	_ = state // Used for validation in full NTLM implementation

	return userInfo, nil, nil
}

// cleanupLoop periodically removes expired challenge states.
func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.cleanup()
		case <-h.stopCh:
			return
		}
	}
}

// cleanup removes expired challenge states.
func (h *Handler) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	for sessionID, state := range h.challenges {
		if now.Sub(state.timestamp) > h.config.ChallengeTimeout {
			delete(h.challenges, sessionID)
		}
	}
}

// Close stops the handler and releases resources.
func (h *Handler) Close() error {
	close(h.stopCh)
	return nil
}

// getClientSessionID generates a session ID for tracking NTLM handshakes.
func getClientSessionID(r *http.Request) string {
	// Use a combination of client IP and connection identifier
	// In production, you might want to use a more sophisticated method
	return r.RemoteAddr
}

// Response represents an authentication response.
type Response struct {
	StatusCode int
	Headers    map[string]string
	Challenge  bool
}

// Write writes the response to an HTTP response writer.
func (r *Response) Write(w http.ResponseWriter) {
	for k, v := range r.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(r.StatusCode)
}

// Middleware creates HTTP middleware for Negotiate authentication.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, resp, err := h.Authenticate(r.Context(), r)

		if err != nil {
			slog.Debug("negotiate auth failed", "error", err)
			http.Error(w, "Authentication Failed", http.StatusProxyAuthRequired)
			return
		}

		if resp != nil {
			// Need to send challenge response
			resp.Write(w)
			return
		}

		// Authentication successful - add user info to context
		ctx := r.Context()
		if userInfo != nil {
			ctx = context.WithValue(ctx, userInfoContextKey, userInfo)
		}
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// ProxyMiddleware creates HTTP middleware for proxy Negotiate authentication.
func (h *Handler) ProxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, resp, err := h.Authenticate(r.Context(), r)

		if err != nil {
			slog.Debug("negotiate proxy auth failed", "error", err)
			w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Negotiate realm="%s"`, h.config.Realm))
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}

		if resp != nil {
			// Need to send challenge response
			resp.Write(w)
			return
		}

		// Authentication successful - add user info to context
		ctx := r.Context()
		if userInfo != nil {
			ctx = context.WithValue(ctx, userInfoContextKey, userInfo)
		}
		r = r.WithContext(ctx)

		// Remove proxy auth header before forwarding
		r.Header.Del("Proxy-Authorization")

		next.ServeHTTP(w, r)
	})
}

// Context keys
type contextKey string

const (
	kerberosTokenKey   contextKey = "kerberos_token"
	ntlmTokenKey       contextKey = "ntlm_token"
	userInfoContextKey contextKey = "user_info"
)

// GetUserInfoFromContext retrieves user info from context.
func GetUserInfoFromContext(ctx context.Context) *auth.UserInfo {
	userInfo, _ := ctx.Value(userInfoContextKey).(*auth.UserInfo) //nolint:errcheck // Type assertion - nil is valid if missing
	return userInfo
}
