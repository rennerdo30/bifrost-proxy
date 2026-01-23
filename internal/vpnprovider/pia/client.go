// Package pia provides a client for the Private Internet Access VPN provider API.
package pia

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// API endpoints and constants.
const (
	// ServerListEndpoint is the URL for fetching the server list.
	ServerListEndpoint = "https://serverlist.piaservers.net/vpninfo/servers/v6"

	// TokenEndpoint is the URL for obtaining authentication tokens.
	TokenEndpoint = "https://www.privateinternetaccess.com/api/client/v2/token"

	// AddKeyPath is the path for registering WireGuard keys (appended to server IP).
	AddKeyPath = "/addKey"

	// DefaultWireGuardPort is the default WireGuard port for PIA.
	DefaultWireGuardPort = "1337"

	// DefaultOpenVPNUDPPort is the default OpenVPN UDP port.
	DefaultOpenVPNUDPPort = 1198

	// DefaultOpenVPNTCPPort is the default OpenVPN TCP port.
	DefaultOpenVPNTCPPort = 502

	// TokenTTL is how long tokens remain valid.
	TokenTTL = 24 * time.Hour

	// UserAgent is the HTTP User-Agent header value.
	UserAgent = "Bifrost-Proxy/1.0"

	// ProviderName is the name of this provider.
	ProviderName = "pia"
)

// Client implements the vpnprovider.Provider interface for PIA.
type Client struct {
	httpClient   *http.Client
	tokenManager *TokenManager
	cache        *vpnprovider.ServerCache
	regions      []Region // Raw region data for API calls
	logger       *slog.Logger
}

// ClientOption is a functional option for configuring the Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithCacheTTL sets a custom cache TTL.
func WithCacheTTL(ttl time.Duration) ClientOption {
	return func(c *Client) {
		c.cache = vpnprovider.NewServerCache(ttl)
	}
}

// NewClient creates a new PIA API client.
func NewClient(username, password string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:  vpnprovider.NewServerCache(vpnprovider.DefaultCacheTTL),
		logger: slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Create token manager with configured HTTP client and logger
	c.tokenManager = NewTokenManager(username, password, c.httpClient, c.logger)

	return c
}

// Name returns the provider name.
func (c *Client) Name() string {
	return ProviderName
}

// SupportsWireGuard returns true as PIA supports WireGuard.
func (c *Client) SupportsWireGuard() bool {
	return true
}

// SupportsOpenVPN returns true as PIA supports OpenVPN.
func (c *Client) SupportsOpenVPN() bool {
	return true
}

// FetchServers retrieves the server list from PIA API.
func (c *Client) FetchServers(ctx context.Context) ([]vpnprovider.Server, error) {
	// Check cache first
	if servers, ok := c.cache.GetServers(); ok {
		c.logger.Debug("returning cached server list",
			"count", len(servers),
		)
		return servers, nil
	}

	c.logger.Debug("fetching server list from PIA API")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ServerListEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create server list request: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", vpnprovider.ErrServerListFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read server list: %w", err)
	}

	var serverList ServerListResponse
	if err := json.Unmarshal(body, &serverList); err != nil {
		return nil, fmt.Errorf("parse server list: %w", err)
	}

	// Store raw regions for later use in key registration
	c.regions = serverList.Regions

	// Convert to common format
	servers := make([]vpnprovider.Server, 0, len(serverList.Regions))
	for _, region := range serverList.Regions {
		if region.Offline {
			continue // Skip offline regions
		}
		servers = append(servers, region.ToVPNProviderServer())
	}

	// Update cache
	c.cache.SetServers(servers)

	c.logger.Info("fetched PIA server list",
		"total_regions", len(serverList.Regions),
		"online_servers", len(servers),
	)

	return servers, nil
}

// SelectServer selects the best server based on criteria.
func (c *Client) SelectServer(ctx context.Context, criteria vpnprovider.ServerCriteria) (*vpnprovider.Server, error) {
	servers, err := c.FetchServers(ctx)
	if err != nil {
		return nil, err
	}

	server := vpnprovider.SelectBestServer(servers, criteria)
	if server == nil {
		return nil, vpnprovider.ErrNoServersAvailable
	}

	return server, nil
}

// GenerateWireGuardConfig generates a WireGuard configuration for the given server.
func (c *Client) GenerateWireGuardConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.WireGuardConfig, error) {
	if server.WireGuard == nil {
		return nil, fmt.Errorf("%w: server %s does not support WireGuard", vpnprovider.ErrUnsupportedProtocol, server.ID)
	}

	// Ensure we have valid credentials
	if creds.Username == "" || creds.Password == "" {
		if !c.tokenManager.HasCredentials() {
			return nil, vpnprovider.ErrInvalidCredentials
		}
	} else {
		// Update token manager with provided credentials
		c.tokenManager = NewTokenManager(creds.Username, creds.Password, c.httpClient, c.logger)
	}

	// Get authentication token
	token, err := c.tokenManager.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get auth token: %w", err)
	}

	// Generate WireGuard key pair
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	// Find the region for this server
	region := c.findRegion(server.ID)
	if region == nil {
		return nil, fmt.Errorf("region not found for server %s", server.ID)
	}

	// Register the public key with PIA
	keyResp, err := c.registerWireGuardKey(ctx, region, publicKey, token.Value)
	if err != nil {
		return nil, fmt.Errorf("register WireGuard key: %w", err)
	}

	// Build configuration
	config := &vpnprovider.WireGuardConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    keyResp.PeerIP + "/32",
		DNS:        keyResp.DNSServers,
		Peer: vpnprovider.WireGuardPeer{
			PublicKey:           keyResp.ServerKey,
			Endpoint:            fmt.Sprintf("%s:%d", keyResp.ServerIP, keyResp.ServerPort),
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
		},
	}

	c.logger.Info("generated WireGuard config for PIA",
		"server", server.Name,
		"peer_ip", keyResp.PeerIP,
		"server_ip", keyResp.ServerIP,
	)

	return config, nil
}

// registerWireGuardKey registers a WireGuard public key with a PIA server.
func (c *Client) registerWireGuardKey(ctx context.Context, region *Region, publicKey, token string) (*WireGuardKeyResponse, error) {
	serverIP := region.GetWireGuardEndpoint()
	if serverIP == "" {
		return nil, fmt.Errorf("no WireGuard server available for region %s", region.ID)
	}

	// Build the addKey URL - PIA requires HTTPS with the server's certificate
	addKeyURL := fmt.Sprintf("https://%s:%s%s", serverIP, DefaultWireGuardPort, AddKeyPath)

	formData := url.Values{}
	formData.Set("pt", token)
	formData.Set("pubkey", publicKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addKeyURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create addKey request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)

	// Create a client that accepts the PIA server certificate
	// PIA uses self-signed certificates for the WireGuard key registration endpoint
	tlsClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // PIA uses self-signed certs for key registration
			},
		},
	}

	resp, err := tlsClient.Do(req)
	if err != nil {
		c.logger.Error("addKey request failed",
			"url", addKeyURL,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrKeyRegistrationFailed, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read addKey response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.Error("addKey request returned error",
			"status", resp.StatusCode,
			"body", string(body),
		)
		return nil, fmt.Errorf("%w: status %d", vpnprovider.ErrKeyRegistrationFailed, resp.StatusCode)
	}

	var keyResp WireGuardKeyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		return nil, fmt.Errorf("parse addKey response: %w", err)
	}

	if !keyResp.IsSuccess() {
		return nil, fmt.Errorf("%w: status %s", vpnprovider.ErrKeyRegistrationFailed, keyResp.Status)
	}

	c.logger.Debug("WireGuard key registered successfully",
		"region", region.Name,
		"server_ip", keyResp.ServerIP,
		"peer_ip", keyResp.PeerIP,
	)

	return &keyResp, nil
}

// findRegion finds the raw region data for a server ID.
func (c *Client) findRegion(serverID string) *Region {
	for i := range c.regions {
		if c.regions[i].ID == serverID {
			return &c.regions[i]
		}
	}
	return nil
}

// GenerateOpenVPNConfig generates an OpenVPN configuration for the given server.
func (c *Client) GenerateOpenVPNConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.OpenVPNConfig, error) {
	if server.OpenVPN == nil {
		return nil, fmt.Errorf("%w: server %s does not support OpenVPN", vpnprovider.ErrUnsupportedProtocol, server.ID)
	}

	// Validate credentials
	username := creds.Username
	password := creds.Password
	if username == "" && c.tokenManager.HasCredentials() {
		username = c.tokenManager.username
		password = c.tokenManager.password
	}
	if username == "" || password == "" {
		return nil, vpnprovider.ErrInvalidCredentials
	}

	// Find the region for additional server details
	region := c.findRegion(server.ID)

	// Build OpenVPN configuration
	config := c.buildOpenVPNConfig(server, region)

	return &vpnprovider.OpenVPNConfig{
		ConfigContent: config,
		Username:      username,
		Password:      password,
	}, nil
}

// buildOpenVPNConfig builds the OpenVPN configuration content.
func (c *Client) buildOpenVPNConfig(server *vpnprovider.Server, region *Region) string {
	var sb strings.Builder

	sb.WriteString("client\n")
	sb.WriteString("dev tun\n")

	// Use UDP by default if available
	if server.OpenVPN.UDPPort > 0 {
		sb.WriteString("proto udp\n")
		sb.WriteString(fmt.Sprintf("remote %s %d\n", server.OpenVPN.Hostname, server.OpenVPN.UDPPort))
	} else {
		sb.WriteString("proto tcp\n")
		sb.WriteString(fmt.Sprintf("remote %s %d\n", server.OpenVPN.Hostname, server.OpenVPN.TCPPort))
	}

	sb.WriteString("resolv-retry infinite\n")
	sb.WriteString("nobind\n")
	sb.WriteString("persist-key\n")
	sb.WriteString("persist-tun\n")
	sb.WriteString("cipher aes-256-gcm\n")
	sb.WriteString("auth sha256\n")
	sb.WriteString("compress lz4\n")
	sb.WriteString("verb 3\n")
	sb.WriteString("auth-user-pass\n")
	sb.WriteString("remote-cert-tls server\n")

	// DNS settings
	if region != nil && region.DNS != "" {
		sb.WriteString(fmt.Sprintf("dhcp-option DNS %s\n", region.DNS))
	}

	// PIA CA certificate
	sb.WriteString("<ca>\n")
	sb.WriteString(piaOpenVPNCA)
	sb.WriteString("</ca>\n")

	return sb.String()
}

// generateWireGuardKeyPair generates a new WireGuard key pair.
func generateWireGuardKeyPair() (privateKey, publicKey string, err error) {
	// Generate random private key
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", fmt.Errorf("generate random key: %w", err)
	}

	// Clamp the private key according to Curve25519 requirements
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Derive public key
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	// Encode as base64
	privateKey = base64.StdEncoding.EncodeToString(privKey[:])
	publicKey = base64.StdEncoding.EncodeToString(pubKey[:])

	return privateKey, publicKey, nil
}

// Authenticate explicitly authenticates with PIA and returns a token.
func (c *Client) Authenticate(ctx context.Context) (*Token, error) {
	return c.tokenManager.GetToken(ctx)
}

// InvalidateToken invalidates the cached token.
func (c *Client) InvalidateToken() {
	c.tokenManager.Invalidate()
}

// ClearCache clears the server cache.
func (c *Client) ClearCache() {
	c.cache.Clear()
}

// PIA OpenVPN CA certificate
const piaOpenVPNCA = `-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6gREDXiWYbAUfkD4F0B0qVWJj06T/+mhFkFCQTQ9h
QGEbwtD7ohLb/r/rFCwaTRHvtJSHYGwINV1n4/v9HxMeBPi9Q+bH+OYKkqt1cL06
8xJ9FatZ+aLPKkPAG7Us2E+z3E7TaK7E4XdEgSr7V0KvGz4xYvBQz3kCLz54G3tS
pYaKrQ2s+Bk6l2e1FfM0Aa5qSTd2V+6dTFmJstqh7R7VzbcC7bYBLdqJrGVXg7Nm
ZUgPPPQO+RKXdLnsROhM0NvCISha0EJZrxZqHiqruQOU3j4wxLEYQrkCLwAoGE2p
cvy5T7I6WXSEKz6ALrF3GAVXT5t7pJkJGhFC08ExJFiPw/WLd6pD7l8q7JL7FgHW
aWyepKCdhHNkBQBhyoA/VjVpI/voxJoR/fLPDjGzAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AHVf7EVJQ5R+UyG4FE6cBj4G+0VQBdUFnlHSqjWTqq
QgujGfqcLmfvDl4FhoJejHLtlvppl1YQxPRbVZJm7Ll6oJHgJw7lQ7r5BYJIZt6Z
f9XusGLK6jBHgRvfFfzHYtTgVF/i2y4mPcKg4W+badvLVWJbHC3duR8I3NL1axqI
rR7JKF0g0FTTVEBf0ISLvakV0AqWEOZ2lVrFJeYVwWfYMFvA4bLLPbVoC3ZLejuM
wPXKUMyYqd+RXqxmSy+SfjJEOA0B1OMpSTBqkV7NftV3qJEJk0sHl9svQINiONMp
cOWk6vjzGP7pSLSzVZFM8hlQ3RKaM3bGXclqefKQoE8mV1wJrpS6gMsCwv1B2l8E
x3jhXsnF/rTDnvJrTSI4cFBLiJYH0sNwEJm8qLthJiJo9E5jAABaS7Wjj4eqKP2W
tcD9u3sgnKNfTPfIQ+0rDrxBl7xLb0l9o/n8xqQgB8wO5K0WchF0HGP3dH04Bwvw
HYFpA+EJOYZ5cHmwPzy2s3j9nQLf6j5n9toN9Q1N2VnXHY0ZhbhlGTR4BTyU8Sg=
-----END CERTIFICATE-----`
