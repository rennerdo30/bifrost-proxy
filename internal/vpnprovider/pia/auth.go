package pia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// Token represents a PIA authentication token.
type Token struct {
	Value     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the token is expired or close to expiring.
func (t *Token) IsExpired() bool {
	if t == nil || t.Value == "" {
		return true
	}
	// Consider expired if less than 5 minutes remaining
	return time.Now().Add(5 * time.Minute).After(t.ExpiresAt)
}

// IsValid returns true if the token is valid and not expired.
func (t *Token) IsValid() bool {
	return t != nil && t.Value != "" && !t.IsExpired()
}

// TokenManager handles PIA authentication tokens with thread-safe access.
type TokenManager struct {
	mu         sync.RWMutex
	token      *Token
	username   string
	password   string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewTokenManager creates a new token manager.
func NewTokenManager(username, password string, httpClient *http.Client, logger *slog.Logger) *TokenManager {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &TokenManager{
		username:   username,
		password:   password,
		httpClient: httpClient,
		logger:     logger,
	}
}

// GetToken returns a valid token, refreshing if necessary.
func (tm *TokenManager) GetToken(ctx context.Context) (*Token, error) {
	// First check with read lock
	tm.mu.RLock()
	if tm.token != nil && tm.token.IsValid() {
		token := tm.token
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	// Need to refresh - acquire write lock
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock
	if tm.token != nil && tm.token.IsValid() {
		return tm.token, nil
	}

	// Fetch new token
	token, err := tm.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	tm.token = token
	return token, nil
}

// authenticate performs the authentication request to PIA.
func (tm *TokenManager) authenticate(ctx context.Context) (*Token, error) {
	tm.logger.Debug("authenticating with PIA")

	// Prepare form data
	formData := url.Values{}
	formData.Set("username", tm.username)
	formData.Set("password", tm.password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, vpnprovider.ErrInvalidCredentials
	}

	if resp.StatusCode != http.StatusOK {
		tm.logger.Error("authentication failed",
			"status", resp.StatusCode,
			"body", string(body),
		)
		return nil, fmt.Errorf("%w: status %d", vpnprovider.ErrAuthenticationFailed, resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse auth response: %w", err)
	}

	if tokenResp.Token == "" {
		return nil, vpnprovider.ErrAuthenticationFailed
	}

	// PIA tokens typically expire in 24 hours
	token := &Token{
		Value:     tokenResp.Token,
		ExpiresAt: time.Now().Add(TokenTTL),
	}

	tm.logger.Info("PIA authentication successful",
		"expires_at", token.ExpiresAt,
	)

	return token, nil
}

// Invalidate clears the cached token, forcing a refresh on next use.
func (tm *TokenManager) Invalidate() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.token = nil
}

// HasCredentials returns true if credentials are configured.
func (tm *TokenManager) HasCredentials() bool {
	return tm.username != "" && tm.password != ""
}

// TokenResponse represents the PIA token API response.
type TokenResponse struct {
	Token string `json:"token"`
}

// WireGuardKeyResponse represents the response from the addKey endpoint.
type WireGuardKeyResponse struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	ServerIP   string   `json:"server_ip"`
	ServerVIP  string   `json:"server_vip"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubkey string   `json:"peer_pubkey"`
	DNSServers []string `json:"dns_servers"`
}

// IsSuccess returns true if the key registration was successful.
func (r *WireGuardKeyResponse) IsSuccess() bool {
	return r.Status == "OK"
}

// PortForwardResponse represents the response from port forwarding requests.
type PortForwardResponse struct {
	Status  string `json:"status"`
	Port    int    `json:"port"`
	Expires int64  `json:"expires_at"`
}

// PayloadResponse represents the signed port forward payload.
type PayloadResponse struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
