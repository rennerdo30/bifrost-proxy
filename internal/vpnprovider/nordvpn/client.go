// Package nordvpn implements the NordVPN provider for Bifrost Proxy.
package nordvpn

import (
	"context"
	"encoding/json"
	"encoding/pem"
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

	// Generate OpenVPN config content. This requires the CA certificate to be
	// supplied via configuration; we never embed CA material.
	configContent, err := c.generateOpenVPNConfigContent(server.Hostname, proto, port, creds)
	if err != nil {
		return nil, err
	}

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
//
// The CA certificate must be provided via configuration (creds.CACert). We do
// NOT embed CA material in the binary: a wrong/placeholder CA would either fail
// to parse or, worse, disable server verification. If no valid CA is supplied
// we fail closed so callers never receive a config that can't authenticate the
// server.
func (c *Client) generateOpenVPNConfigContent(hostname, proto string, port int, creds vpnprovider.Credentials) (string, error) {
	caCert := strings.TrimSpace(creds.CACert)
	if caCert == "" {
		return "", fmt.Errorf("%w: NordVPN OpenVPN requires a CA certificate to be configured (credentials.ca_cert)", vpnprovider.ErrConfigGenerationFailed)
	}
	if block, _ := pem.Decode([]byte(caCert)); block == nil {
		return "", fmt.Errorf("%w: configured NordVPN CA certificate is not valid PEM", vpnprovider.ErrConfigGenerationFailed)
	}

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

	// CA certificate (supplied via configuration, validated above).
	sb.WriteString("<ca>\n")
	sb.WriteString(caCert)
	if !strings.HasSuffix(caCert, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("</ca>\n")

	// Optional TLS authentication key (only emitted if configured).
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

// NOTE: NordVPN CA / tls-auth material is intentionally NOT embedded here.
// Embedding placeholder or hard-coded crypto material is unsafe: a wrong CA
// either fails to parse or silently disables server verification. The CA
// certificate (and optional tls-auth key) must be supplied via configuration
// (Credentials.CACert / Credentials.TLSAuthKey) and is validated at OpenVPN
// config-generation time. See generateOpenVPNConfigContent.
