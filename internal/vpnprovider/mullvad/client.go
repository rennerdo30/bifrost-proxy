// Package mullvad provides a VPN provider implementation for Mullvad VPN.
package mullvad

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

const (
	// API endpoints
	relaysAPIURL    = "https://api.mullvad.net/www/relays/all/"
	wireGuardAPIURL = "https://api.mullvad.net/wg/"
	accountAPIURL   = "https://api.mullvad.net/accounts/v1/accounts/"
	providerName    = "mullvad"

	// Default WireGuard settings
	defaultWireGuardPort = 51820
	defaultDNS           = "10.64.0.1"

	// HTTP client settings
	httpTimeout = 30 * time.Second
)

// accountIDRegex validates Mullvad account numbers (16 digits).
var accountIDRegex = regexp.MustCompile(`^\d{16}$`)

// Client implements the vpnprovider.Provider interface for Mullvad VPN.
type Client struct {
	accountID  string
	httpClient *http.Client
	cache      *vpnprovider.ServerCache
	logger     *slog.Logger
}

// ClientOption is a functional option for configuring the Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithCache sets a custom server cache.
func WithCache(cache *vpnprovider.ServerCache) ClientOption {
	return func(c *Client) {
		c.cache = cache
	}
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// NewClient creates a new Mullvad API client.
func NewClient(accountID string, opts ...ClientOption) (*Client, error) {
	// Validate account ID format (16 digits)
	if !validateAccountID(accountID) {
		return nil, fmt.Errorf("%w: must be 16 digits", vpnprovider.ErrInvalidAccountID)
	}

	client := &Client{
		accountID: accountID,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		cache:  vpnprovider.NewServerCache(vpnprovider.DefaultCacheTTL),
		logger: slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// validateAccountID validates the Mullvad account ID format.
func validateAccountID(accountID string) bool {
	return accountIDRegex.MatchString(accountID)
}

// Name returns the provider name.
func (c *Client) Name() string {
	return providerName
}

// SupportsWireGuard returns true as Mullvad supports WireGuard.
func (c *Client) SupportsWireGuard() bool {
	return true
}

// SupportsOpenVPN returns true as Mullvad supports OpenVPN.
func (c *Client) SupportsOpenVPN() bool {
	return true
}

// FetchServers retrieves the server list from the Mullvad API.
func (c *Client) FetchServers(ctx context.Context) ([]vpnprovider.Server, error) {
	// Check cache first
	if servers, ok := c.cache.GetServers(); ok {
		c.logger.Debug("returning cached server list",
			"provider", providerName,
			"count", len(servers),
		)
		return servers, nil
	}

	c.logger.Info("fetching server list from API",
		"provider", providerName,
		"url", relaysAPIURL,
	)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relaysAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrServerListFetchFailed, err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "BifrostProxy/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
		c.logger.Error("failed to fetch servers",
			"provider", providerName,
			"status", resp.StatusCode,
			"body", string(body),
		)
		return nil, fmt.Errorf("%w: HTTP %d", vpnprovider.ErrServerListFetchFailed, resp.StatusCode)
	}

	// Parse response
	var relays []MullvadRelay
	if err := json.NewDecoder(resp.Body).Decode(&relays); err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrServerListFetchFailed, err)
	}

	// Convert to standard server format
	servers := convertRelaysToServers(relays)

	c.logger.Info("fetched server list",
		"provider", providerName,
		"total_relays", len(relays),
		"active_servers", len(servers),
	)

	// Update cache
	c.cache.SetServers(servers)
	c.cache.SetCountries(extractCountries(servers))

	return servers, nil
}

// SelectServer selects the best server based on criteria.
func (c *Client) SelectServer(ctx context.Context, criteria vpnprovider.ServerCriteria) (*vpnprovider.Server, error) {
	servers, err := c.FetchServers(ctx)
	if err != nil {
		return nil, err
	}

	// Use shared filtering logic
	server := vpnprovider.SelectBestServer(servers, criteria)
	if server == nil {
		return nil, vpnprovider.ErrNoServersAvailable
	}

	c.logger.Debug("selected server",
		"provider", providerName,
		"server", server.Hostname,
		"country", server.CountryCode,
		"city", server.City,
	)

	return server, nil
}

// GenerateWireGuardConfig generates WireGuard configuration for a server.
func (c *Client) GenerateWireGuardConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.WireGuardConfig, error) {
	if server.WireGuard == nil {
		return nil, fmt.Errorf("%w: server does not support WireGuard", vpnprovider.ErrUnsupportedProtocol)
	}

	// Generate key pair
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate key pair: %v", vpnprovider.ErrConfigGenerationFailed, err)
	}

	// Use account ID from creds if provided, otherwise use client's account ID
	accountID := c.accountID
	if creds.AccountID != "" {
		accountID = creds.AccountID
	}

	// Register the public key with Mullvad
	clientIP, err := c.RegisterWireGuardKey(ctx, accountID, publicKey)
	if err != nil {
		return nil, err
	}

	// Build the configuration
	config := &vpnprovider.WireGuardConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    clientIP + "/32",
		DNS:        []string{defaultDNS},
		Peer: vpnprovider.WireGuardPeer{
			PublicKey:           server.WireGuard.PublicKey,
			Endpoint:            server.WireGuard.Endpoint,
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
		},
	}

	c.logger.Info("generated WireGuard configuration",
		"provider", providerName,
		"server", server.Hostname,
		"client_ip", clientIP,
	)

	return config, nil
}

// GenerateOpenVPNConfig generates OpenVPN configuration for a server.
func (c *Client) GenerateOpenVPNConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.OpenVPNConfig, error) {
	if server.OpenVPN == nil {
		return nil, fmt.Errorf("%w: server does not support OpenVPN", vpnprovider.ErrUnsupportedProtocol)
	}

	// Use account ID from creds if provided, otherwise use client's account ID
	accountID := c.accountID
	if creds.AccountID != "" {
		accountID = creds.AccountID
	}

	// Generate OpenVPN configuration.
	// Mullvad uses account number as username and "m" as password for OpenVPN.
	// The CA certificate is required and supplied via configuration; generation
	// fails closed if it is missing or invalid.
	configContent, err := generateOpenVPNConfig(server, creds)
	if err != nil {
		return nil, err
	}

	config := &vpnprovider.OpenVPNConfig{
		ConfigContent: configContent,
		Username:      accountID,
		Password:      "m", // Mullvad uses "m" as the password
	}

	c.logger.Info("generated OpenVPN configuration",
		"provider", providerName,
		"server", server.Hostname,
	)

	return config, nil
}

// RegisterWireGuardKey registers a WireGuard public key with Mullvad.
func (c *Client) RegisterWireGuardKey(ctx context.Context, accountID, publicKey string) (string, error) {
	c.logger.Debug("registering WireGuard key",
		"provider", providerName,
	)

	// Build form data
	formData := url.Values{}
	formData.Set("account", accountID)
	formData.Set("pubkey", publicKey)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wireGuardAPIURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %v", vpnprovider.ErrKeyRegistrationFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "BifrostProxy/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read response: %v", vpnprovider.ErrKeyRegistrationFailed, err)
	}

	// Check for errors
	switch resp.StatusCode {
	case http.StatusOK:
		// Success - response is the assigned IP address
		ipAddress := strings.TrimSpace(string(body))
		c.logger.Info("registered WireGuard key",
			"provider", providerName,
			"assigned_ip", ipAddress,
		)
		return ipAddress, nil

	case http.StatusUnauthorized:
		return "", fmt.Errorf("%w: invalid account number", vpnprovider.ErrAuthenticationFailed)

	case http.StatusBadRequest:
		// Check if key already exists (Mullvad returns the IP if key is already registered)
		if strings.HasPrefix(string(body), "10.") || strings.Contains(string(body), "already") {
			ipAddress := strings.TrimSpace(string(body))
			c.logger.Info("WireGuard key already registered",
				"provider", providerName,
				"assigned_ip", ipAddress,
			)
			return ipAddress, nil
		}
		return "", fmt.Errorf("%w: %s", vpnprovider.ErrKeyRegistrationFailed, string(body))

	case http.StatusTooManyRequests:
		return "", vpnprovider.ErrRateLimited

	default:
		return "", fmt.Errorf("%w: HTTP %d: %s", vpnprovider.ErrKeyRegistrationFailed, resp.StatusCode, string(body))
	}
}

// GenerateKeyPair generates a new WireGuard key pair.
// Returns (privateKey, publicKey, error) as base64-encoded strings.
func GenerateKeyPair() (string, string, error) {
	// Generate random private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp private key per Curve25519 requirements
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Encode to base64
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKey[:])
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey[:])

	return privateKeyB64, publicKeyB64, nil
}

// generateOpenVPNConfig generates the OpenVPN configuration content.
//
// The CA certificate must be supplied by the operator via configuration
// (creds.CACert); we do NOT embed CA material in the binary. A wrong or
// placeholder CA would either fail to parse or, worse, silently disable server
// verification, so when no valid CA is supplied we fail closed rather than emit
// an unusable or insecure config. The tls-auth static key is likewise
// operator-supplied and only emitted when present.
func generateOpenVPNConfig(server *vpnprovider.Server, creds vpnprovider.Credentials) (string, error) {
	caCert := strings.TrimSpace(creds.CACert)
	if caCert == "" {
		return "", fmt.Errorf("%w: Mullvad OpenVPN requires a CA certificate to be configured (credentials.ca_cert)", vpnprovider.ErrConfigGenerationFailed)
	}
	if block, _ := pem.Decode([]byte(caCert)); block == nil {
		return "", fmt.Errorf("%w: configured Mullvad CA certificate is not valid PEM", vpnprovider.ErrConfigGenerationFailed)
	}

	var sb strings.Builder

	sb.WriteString("# Mullvad OpenVPN Configuration\n")
	sb.WriteString("# Generated by Bifrost Proxy\n\n")

	sb.WriteString("client\n")
	sb.WriteString("dev tun\n")
	sb.WriteString("proto udp\n")
	sb.WriteString(fmt.Sprintf("remote %s %d\n", server.OpenVPN.Hostname, server.OpenVPN.UDPPort))
	sb.WriteString("remote-random\n")
	sb.WriteString("resolv-retry infinite\n")
	sb.WriteString("nobind\n")
	sb.WriteString("persist-key\n")
	sb.WriteString("persist-tun\n")
	sb.WriteString("verb 3\n")
	sb.WriteString("remote-cert-tls server\n")
	sb.WriteString("ping 10\n")
	sb.WriteString("ping-restart 60\n")
	sb.WriteString("sndbuf 524288\n")
	sb.WriteString("rcvbuf 524288\n")
	sb.WriteString("cipher AES-256-GCM\n")
	sb.WriteString("tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384\n")
	sb.WriteString("auth-user-pass\n")
	sb.WriteString("auth-nocache\n")

	// CA certificate (supplied via configuration, validated above).
	sb.WriteString("\n<ca>\n")
	sb.WriteString(caCert)
	if !strings.HasSuffix(caCert, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("</ca>\n")

	// Optional tls-auth static key (only emitted when operator-supplied).
	if tlsAuth := strings.TrimSpace(creds.TLSAuthKey); tlsAuth != "" {
		sb.WriteString("key-direction 1\n")
		sb.WriteString("<tls-auth>\n")
		sb.WriteString(tlsAuth)
		if !strings.HasSuffix(tlsAuth, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("</tls-auth>\n")
	}

	return sb.String(), nil
}

// NOTE: Mullvad OpenVPN CA / tls-auth material is intentionally NOT embedded
// here. The value previously hard-coded in this file failed x509 parsing
// ("malformed algorithm identifier") and would have produced an .ovpn that
// aborts at connect time. Embedding placeholder or hand-rolled crypto material
// is unsafe. The CA certificate (and optional tls-auth key) must be supplied by
// the operator via configuration (Credentials.CACert / Credentials.TLSAuthKey)
// and is validated fail-closed at OpenVPN config-generation time. See
// generateOpenVPNConfig.

// GetAccountInfo retrieves account information from Mullvad.
func (c *Client) GetAccountInfo(ctx context.Context) (*AccountInfo, error) {
	c.logger.Debug("fetching account info",
		"provider", providerName,
	)

	// Create request
	apiURL := accountAPIURL + c.accountID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "BifrostProxy/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		return nil, vpnprovider.ErrAuthenticationFailed
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
		return nil, fmt.Errorf("API error: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var info AccountInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &info, nil
}

// ClearCache clears the server cache.
func (c *Client) ClearCache() {
	c.cache.Clear()
}

// CacheStats returns cache statistics.
func (c *Client) CacheStats() (serverCount int, lastFetch time.Time, expired bool) {
	return c.cache.ServerCount(), c.cache.LastFetch(), c.cache.IsExpired()
}
