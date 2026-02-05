package protonvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/curve25519"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// WireGuard API endpoints.
const (
	// CertificateEndpoint is the endpoint for WireGuard key registration.
	CertificateEndpoint = "/vpn/v1/certificate"
)

// WireGuard DNS servers provided by ProtonVPN.
var ProtonVPNDNS = []string{
	"10.2.0.1", // ProtonVPN internal DNS
}

// CertificateRequest is the request body for WireGuard key registration.
type CertificateRequest struct {
	ClientPublicKey     string `json:"ClientPublicKey"`
	ClientPublicKeyMode string `json:"ClientPublicKeyMode,omitempty"` // "persistent" or "ephemeral"
	DeviceName          string `json:"DeviceName,omitempty"`
	Duration            string `json:"Duration,omitempty"` // e.g., "default" or duration in seconds
}

// CertificateResponse is the response from WireGuard key registration.
type CertificateResponse struct {
	Code                int    `json:"Code"`
	ExpirationTime      int64  `json:"ExpirationTime"`
	RefreshTime         int64  `json:"RefreshTime"`
	Certificate         string `json:"Certificate,omitempty"` // PEM certificate (if any)
	ClientKeyFP         string `json:"ClientKeyFP"`           // Client key fingerprint
	ServerPublicKey     string `json:"ServerPublicKey,omitempty"`
	ServerPublicKeyMode string `json:"ServerPublicKeyMode,omitempty"`
	DeviceName          string `json:"DeviceName,omitempty"`
}

// VPNCertificateResponse wraps the certificate response.
type VPNCertificateResponse struct {
	Code  int                      `json:"Code"`
	VPN   *VPNCertificateInfo      `json:"VPN,omitempty"`
	Error *VPNCertificateErrorInfo `json:"Error,omitempty"`
}

// VPNCertificateInfo contains the VPN certificate details.
type VPNCertificateInfo struct {
	ExpirationTime int64  `json:"ExpirationTime"`
	RefreshTime    int64  `json:"RefreshTime"`
	Certificate    string `json:"Certificate,omitempty"`
	ClientKeyFP    string `json:"ClientKeyFP"`
	ClientIP       string `json:"ClientIP,omitempty"`   // Assigned client IP
	ClientIPv6     string `json:"ClientIPv6,omitempty"` // Assigned client IPv6
	DeviceName     string `json:"DeviceName,omitempty"`
	Features       int    `json:"Features"`
}

// VPNCertificateErrorInfo contains error details.
type VPNCertificateErrorInfo struct {
	Code    int    `json:"Code"`
	Message string `json:"Error"`
}

// WireGuardKeyPair holds a WireGuard private/public key pair.
type WireGuardKeyPair struct {
	PrivateKey string // Base64 encoded
	PublicKey  string // Base64 encoded
}

// GenerateWireGuardKeyPair generates a new WireGuard key pair.
func GenerateWireGuardKeyPair() (*WireGuardKeyPair, error) {
	// Generate 32 random bytes for the private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}

	// Clamp the private key per WireGuard spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key from private key using X25519
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &WireGuardKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
	}, nil
}

// RegisterWireGuardKey registers a WireGuard public key with ProtonVPN.
// This requires an authenticated session.
func (c *Client) RegisterWireGuardKey(ctx context.Context, publicKey string) (*VPNCertificateInfo, error) {
	if c.session == nil || !c.session.IsValid() {
		return nil, fmt.Errorf("%w: session required for WireGuard key registration", vpnprovider.ErrAuthenticationFailed)
	}

	url := c.baseURL + CertificateEndpoint

	reqBody := CertificateRequest{
		ClientPublicKey:     publicKey,
		ClientPublicKeyMode: "persistent",
		DeviceName:          "Bifrost-Proxy",
		Duration:            "default",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}

	var result VPNCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Code != 1000 {
		if result.Error != nil {
			return nil, fmt.Errorf("%w: %s (code %d)", vpnprovider.ErrConfigGenerationFailed, result.Error.Message, result.Error.Code)
		}
		return nil, fmt.Errorf("%w: API returned code %d", vpnprovider.ErrConfigGenerationFailed, result.Code)
	}

	if result.VPN == nil {
		return nil, fmt.Errorf("%w: empty VPN certificate response", vpnprovider.ErrConfigGenerationFailed)
	}

	c.logger.Debug("registered WireGuard key",
		"provider", c.Name(),
		"client_ip", result.VPN.ClientIP,
		"fingerprint", result.VPN.ClientKeyFP)

	return result.VPN, nil
}

// generateWireGuardConfig creates a WireGuardConfig using key registration.
func (c *Client) generateWireGuardConfig(ctx context.Context, server *vpnprovider.Server, keyPair *WireGuardKeyPair) (*vpnprovider.WireGuardConfig, error) {
	// Register the key with ProtonVPN
	certInfo, err := c.RegisterWireGuardKey(ctx, keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("register WireGuard key: %w", err)
	}

	// Build client address
	clientAddr := certInfo.ClientIP
	if clientAddr == "" {
		return nil, fmt.Errorf("%w: no client IP assigned", vpnprovider.ErrConfigGenerationFailed)
	}

	// Ensure CIDR notation
	if !containsSlash(clientAddr) {
		clientAddr += "/32"
	}

	// Build the configuration
	config := &vpnprovider.WireGuardConfig{
		PrivateKey: keyPair.PrivateKey,
		PublicKey:  keyPair.PublicKey,
		Address:    clientAddr,
		DNS:        ProtonVPNDNS,
		Peer: vpnprovider.WireGuardPeer{
			PublicKey:           server.WireGuard.PublicKey,
			Endpoint:            server.WireGuard.Endpoint,
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
		},
	}

	return config, nil
}

// containsSlash checks if a string contains a slash (for CIDR detection).
func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}
