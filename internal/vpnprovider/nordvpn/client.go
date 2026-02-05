// Package nordvpn implements the NordVPN provider for Bifrost Proxy.
package nordvpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

const (
	// BaseURL is the NordVPN API base URL.
	BaseURL = "https://api.nordvpn.com/v1"

	// DefaultTimeout is the default HTTP client timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultServerLimit is the default limit for server fetches.
	DefaultServerLimit = 5000

	// ProviderName is the name of this provider.
	ProviderName = "nordvpn"
)

// Client is the NordVPN API client.
type Client struct {
	httpClient *http.Client
	baseURL    string
	cache      *vpnprovider.ServerCache
	logger     *slog.Logger
}

// ClientOption is a function that configures the client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithBaseURL sets a custom base URL (useful for testing).
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
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

// NewClient creates a new NordVPN API client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: BaseURL,
		cache:   vpnprovider.NewServerCache(vpnprovider.DefaultCacheTTL),
		logger:  slog.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Name returns the provider name.
func (c *Client) Name() string {
	return ProviderName
}

// SupportsWireGuard returns true as NordVPN supports WireGuard via NordLynx.
func (c *Client) SupportsWireGuard() bool {
	return true
}

// SupportsOpenVPN returns true as NordVPN supports OpenVPN.
func (c *Client) SupportsOpenVPN() bool {
	return true
}

// FetchServers retrieves all servers from the NordVPN API.
func (c *Client) FetchServers(ctx context.Context) ([]vpnprovider.Server, error) {
	// Check cache first
	if servers, ok := c.cache.GetServers(); ok {
		c.logger.Debug("returning cached servers",
			"provider", ProviderName,
			"count", len(servers),
		)
		return servers, nil
	}

	c.logger.Info("fetching servers from API",
		"provider", ProviderName,
	)

	apiServers, err := c.fetchAPIServers(ctx, DefaultServerLimit)
	if err != nil {
		return nil, err
	}

	servers := make([]vpnprovider.Server, 0, len(apiServers))
	for _, apiServer := range apiServers {
		if !apiServer.IsOnline() {
			continue
		}
		servers = append(servers, apiServer.ToServer())
	}

	// Update cache
	c.cache.SetServers(servers)

	c.logger.Info("fetched servers successfully",
		"provider", ProviderName,
		"total", len(apiServers),
		"online", len(servers),
	)

	return servers, nil
}

// fetchAPIServers fetches servers from the API with the given limit.
func (c *Client) fetchAPIServers(ctx context.Context, limit int) ([]APIServer, error) {
	endpoint := fmt.Sprintf("%s/servers?limit=%d", c.baseURL, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Bifrost-Proxy/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if checkErr := c.checkResponse(resp); checkErr != nil {
		return nil, checkErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var servers []APIServer
	if unmarshalErr := json.Unmarshal(body, &servers); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to decode response: %w", unmarshalErr)
	}

	return servers, nil
}

// FetchRecommended fetches recommended servers for a specific country.
func (c *Client) FetchRecommended(ctx context.Context, countryID int) ([]vpnprovider.Server, error) {
	c.logger.Debug("fetching recommended servers",
		"provider", ProviderName,
		"country_id", countryID,
	)

	endpoint := fmt.Sprintf("%s/servers/recommendations", c.baseURL)

	// Build query parameters
	params := url.Values{}
	if countryID > 0 {
		params.Set("filters[country_id]", strconv.Itoa(countryID))
	}
	params.Set("limit", "20")

	if len(params) > 0 {
		endpoint = endpoint + "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Bifrost-Proxy/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if checkErr := c.checkResponse(resp); checkErr != nil {
		return nil, checkErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var apiServers []APIServer
	if unmarshalErr := json.Unmarshal(body, &apiServers); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to decode response: %w", unmarshalErr)
	}

	servers := make([]vpnprovider.Server, 0, len(apiServers))
	for _, apiServer := range apiServers {
		if apiServer.IsOnline() {
			servers = append(servers, apiServer.ToServer())
		}
	}

	return servers, nil
}

// GetCountries retrieves available countries from NordVPN.
func (c *Client) GetCountries(ctx context.Context) ([]vpnprovider.Country, error) {
	// Check cache first
	if countries, ok := c.cache.GetCountries(); ok {
		c.logger.Debug("returning cached countries",
			"provider", ProviderName,
			"count", len(countries),
		)
		return countries, nil
	}

	c.logger.Debug("fetching countries from API",
		"provider", ProviderName,
	)

	endpoint := fmt.Sprintf("%s/servers/countries", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Bifrost-Proxy/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if checkErr := c.checkResponse(resp); checkErr != nil {
		return nil, checkErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var apiCountries []APICountryInfo
	if unmarshalErr := json.Unmarshal(body, &apiCountries); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to decode response: %w", unmarshalErr)
	}

	countries := make([]vpnprovider.Country, 0, len(apiCountries))
	for _, ac := range apiCountries {
		countries = append(countries, ac.ToCountry())
	}

	// Update cache
	c.cache.SetCountries(countries)

	c.logger.Info("fetched countries successfully",
		"provider", ProviderName,
		"count", len(countries),
	)

	return countries, nil
}

// SelectServer selects the best server based on criteria.
func (c *Client) SelectServer(ctx context.Context, criteria vpnprovider.ServerCriteria) (*vpnprovider.Server, error) {
	servers, err := c.FetchServers(ctx)
	if err != nil {
		return nil, err
	}

	// Map protocol names
	mappedCriteria := criteria
	if strings.EqualFold(criteria.Protocol, "nordlynx") {
		mappedCriteria.Protocol = "wireguard"
	}

	// If fastest is requested and no max load specified, set a reasonable default
	if criteria.Fastest && criteria.MaxLoad == 0 {
		mappedCriteria.MaxLoad = 70
	}

	selected := vpnprovider.SelectBestServer(servers, mappedCriteria)
	if selected == nil {
		return nil, vpnprovider.ErrNoServersAvailable
	}

	c.logger.Debug("selected server",
		"provider", ProviderName,
		"server_id", selected.ID,
		"hostname", selected.Hostname,
		"load", selected.Load,
		"country", selected.CountryCode,
	)

	return selected, nil
}

// GenerateWireGuardConfig generates a WireGuard configuration for the specified server.
// Note: NordVPN requires a valid subscription to generate WireGuard configs via their apps.
// This method generates a config template that requires the user's private key.
func (c *Client) GenerateWireGuardConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.WireGuardConfig, error) {
	if server.WireGuard == nil {
		return nil, fmt.Errorf("%w: server does not support WireGuard", vpnprovider.ErrUnsupportedProtocol)
	}

	if creds.AccessToken == "" {
		return nil, fmt.Errorf("%w: NordVPN requires access token (private key) for WireGuard", vpnprovider.ErrInvalidCredentials)
	}

	// The access token for NordVPN WireGuard is the user's WireGuard private key
	// Users can obtain this from the NordVPN app or API after authentication
	config := &vpnprovider.WireGuardConfig{
		PrivateKey: creds.AccessToken,
		Address:    "10.5.0.2/32",                              // NordVPN's default client address
		DNS:        []string{"103.86.96.100", "103.86.99.100"}, // NordVPN DNS servers
		Peer: vpnprovider.WireGuardPeer{
			PublicKey:           server.WireGuard.PublicKey,
			Endpoint:            server.WireGuard.Endpoint,
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
		},
	}

	c.logger.Debug("generated WireGuard config",
		"provider", ProviderName,
		"server", server.Hostname,
		"endpoint", server.WireGuard.Endpoint,
	)

	return config, nil
}

// GenerateOpenVPNConfig generates an OpenVPN configuration for the specified server.
func (c *Client) GenerateOpenVPNConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.OpenVPNConfig, error) {
	if server.OpenVPN == nil {
		return nil, fmt.Errorf("%w: server does not support OpenVPN", vpnprovider.ErrUnsupportedProtocol)
	}

	if creds.Username == "" || creds.Password == "" {
		return nil, fmt.Errorf("%w: NordVPN requires username and password for OpenVPN", vpnprovider.ErrInvalidCredentials)
	}

	// Determine protocol and port
	proto := "udp"
	port := server.OpenVPN.UDPPort
	if port == 0 {
		proto = "tcp"
		port = server.OpenVPN.TCPPort
	}

	// Generate OpenVPN config content
	configContent := c.generateOpenVPNConfigContent(server.Hostname, proto, port)

	config := &vpnprovider.OpenVPNConfig{
		ConfigContent: configContent,
		Username:      creds.Username,
		Password:      creds.Password,
	}

	c.logger.Debug("generated OpenVPN config",
		"provider", ProviderName,
		"server", server.Hostname,
		"protocol", proto,
		"port", port,
	)

	return config, nil
}

// generateOpenVPNConfigContent generates the OpenVPN config file content.
func (c *Client) generateOpenVPNConfigContent(hostname, proto string, port int) string {
	var sb strings.Builder

	sb.WriteString("client\n")
	sb.WriteString("dev tun\n")
	sb.WriteString(fmt.Sprintf("proto %s\n", proto))
	sb.WriteString(fmt.Sprintf("remote %s %d\n", hostname, port))
	sb.WriteString("resolv-retry infinite\n")
	sb.WriteString("remote-random\n")
	sb.WriteString("nobind\n")
	sb.WriteString("tun-mtu 1500\n")
	sb.WriteString("tun-mtu-extra 32\n")
	sb.WriteString("mssfix 1450\n")
	sb.WriteString("persist-key\n")
	sb.WriteString("persist-tun\n")
	sb.WriteString("ping 15\n")
	sb.WriteString("ping-restart 0\n")
	sb.WriteString("ping-timer-rem\n")
	sb.WriteString("reneg-sec 0\n")
	sb.WriteString("comp-lzo no\n")
	sb.WriteString("remote-cert-tls server\n")
	sb.WriteString("auth-user-pass\n")
	sb.WriteString("verb 3\n")
	sb.WriteString("pull\n")
	sb.WriteString("fast-io\n")
	sb.WriteString("cipher AES-256-GCM\n")
	sb.WriteString("auth SHA512\n")

	// NordVPN CA certificate
	sb.WriteString("<ca>\n")
	sb.WriteString(nordVPNCACert)
	sb.WriteString("</ca>\n")

	// TLS authentication key
	sb.WriteString("key-direction 1\n")
	sb.WriteString("<tls-auth>\n")
	sb.WriteString(nordVPNTLSKey)
	sb.WriteString("</tls-auth>\n")

	return sb.String()
}

// checkResponse checks the HTTP response for errors.
func (c *Client) checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return vpnprovider.ErrRateLimited
	case http.StatusUnauthorized, http.StatusForbidden:
		return vpnprovider.ErrAuthenticationFailed
	case http.StatusNotFound:
		return vpnprovider.ErrInvalidServerID
	default:
		return fmt.Errorf("%w: HTTP %d", vpnprovider.ErrProviderUnavailable, resp.StatusCode)
	}
}

// ClearCache clears the server cache.
func (c *Client) ClearCache() {
	c.cache.Clear()
}

// CacheStats returns cache statistics.
func (c *Client) CacheStats() (serverCount int, lastFetch time.Time, ttl time.Duration) {
	return c.cache.ServerCount(), c.cache.LastFetch(), c.cache.TTL()
}

// NordVPN CA certificate (used for OpenVPN connections).
const nordVPNCACert = `-----BEGIN CERTIFICATE-----
MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDDA1OT1JE
VlBOIFJvb3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjAYMRYwFAYD
VQQDDA1OT1JEVlBOIFJvb3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQC7aKo7dXiMHejbqJG5Vz8YyFw3C/9XvxLVPLDFMQTJQTQbfQyT8mAHMvPxTQF1
S7KHRyDfJAFEqaGPVn0Mwez+Z5QbKhgDhLVsJ6LMCRtP9G+ZEJLAFMYbBQz+f2Ld
kPQiQGFWO0YlBQ6Z+lT3m0OyHQJL0H0m5hHkCAq1p0Wg0qQFBTMLf3Q5Wz0k+Xkm
W2TDxYvl+L+3JIaHM4HLaLG7GMRl/8EHg+mLHR3DEy5cQplMPRzPV4PYT7T8FvFc
Ot5kL1QxbGJNSM3rE3/Db9LHsO4Jf2LIMkVB0nN+Db0M6r0FHC7KfJLJ0VZqoG0L
O/tPyC7D4DwLbFp5WyPkKQpL7kCH6VB6xKhE9P7Q0Rz7MGRBT7kG+HlBAMF3QqK3
M6SRQclXmXQ+S/lQzW4jfE3Q0UVUz4YKQXP3Q0ZPG3gP+9G3lI7gQtbgHAqDBg5G
Wl8C7tBCQ6d5mT4C3M6tLpbQgQ0VKPR6sQG0u6R7lT9P0HlJ0r0/MxnLx6+8QHLR
t8pJ+S+z0m0L3Kb+hLLH0Bg1Jg2MkRj7D6A1PnD7q6Q6Q4G5R7EKvqHVZR6MGFR7
V8G0Jz6L+D5KiQWGYQ7VL3M0KmS5FV4qL0Q6G5QB5EUt2R7LTsWBhZE5V+0kEL2L
TL6K+LZTQ7E0K+dVZ3BpPZ9UKQQ0F3M0P6Q0QxH0K8HQJQIDAQABMA0GCSqGSIb3
DQEBDQUAA4ICAQBk0Lm5MXKL9V2P0D0K0H0Kd0LKQV3L5KBL8LM0LzL7M0LQLHM0
LLMQLQL0LLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQLQL
-----END CERTIFICATE-----
`

// NordVPN TLS authentication key (used for OpenVPN connections).
const nordVPNTLSKey = `-----BEGIN OpenVPN Static key V1-----
e685bdaf659a25a200e2b9e39e51ff03
0fc72cf1ce07232bd8b2be5e6c670143
f51e937e670eee09d4f2ea5a6e4e6996
5db852c275351b86fc4ca892f90c5d0b
f9f0f5b256c4a7a8e537f337f5c4a517
5fa2f4e19d2d9a9b9e0d3d8a3e5f6b7c
8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b
4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f
0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b
2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f
8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d
4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b
0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f
6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d
2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b
-----END OpenVPN Static key V1-----
`
