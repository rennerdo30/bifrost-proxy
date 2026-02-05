package protonvpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

const (
	// BaseURL is the ProtonVPN API base URL.
	BaseURL = "https://api.protonvpn.ch"

	// UserAgent identifies this client to the API.
	UserAgent = "Bifrost-Proxy/1.0"

	// AppVersion is sent to the ProtonVPN API.
	// Format: <platform>-vpn@<version>
	AppVersion = "LinuxVPN_4.0.0"
)

// Client implements the vpnprovider.Provider interface for ProtonVPN.
type Client struct {
	httpClient *http.Client
	baseURL    string
	cache      *vpnprovider.ServerCache
	logger     *slog.Logger

	// Authentication
	authMode     AuthMode
	session      *Session
	sessionStore SessionStore
	manualCreds  *ManualCredentials
}

// ClientOption is a functional option for configuring the client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithBaseURL sets a custom base URL (useful for testing).
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithCacheTTL sets the server cache TTL.
func WithCacheTTL(ttl time.Duration) ClientOption {
	return func(c *Client) {
		c.cache = vpnprovider.NewServerCache(ttl)
	}
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithSessionStore sets the session storage backend.
func WithSessionStore(store SessionStore) ClientOption {
	return func(c *Client) {
		c.sessionStore = store
	}
}

// WithManualCredentials configures the client to use manual OpenVPN credentials.
// This is the recommended approach as it avoids the complexity of ProtonVPN's
// SRP authentication protocol.
func WithManualCredentials(username, password string, tier int) ClientOption {
	return func(c *Client) {
		c.authMode = AuthModeManual
		c.manualCreds = &ManualCredentials{
			OpenVPNUsername: username,
			OpenVPNPassword: password,
			Tier:            tier,
		}
	}
}

// NewClient creates a new ProtonVPN provider client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:      BaseURL,
		cache:        vpnprovider.NewServerCache(vpnprovider.DefaultCacheTTL),
		logger:       slog.Default(),
		authMode:     AuthModeManual,
		sessionStore: NewMemorySessionStore(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Name returns the provider name.
func (c *Client) Name() string {
	return "protonvpn"
}

// SupportsWireGuard returns true if ProtonVPN supports WireGuard.
// Note: WireGuard on ProtonVPN requires key registration via the API,
// which is only available in API auth mode.
func (c *Client) SupportsWireGuard() bool {
	return c.authMode == AuthModeAPI && c.session != nil && c.session.IsValid()
}

// SupportsOpenVPN returns true if ProtonVPN supports OpenVPN.
func (c *Client) SupportsOpenVPN() bool {
	return true
}

// FetchServers retrieves the server list from the ProtonVPN API.
func (c *Client) FetchServers(ctx context.Context) ([]vpnprovider.Server, error) {
	// Check cache first
	if servers, ok := c.cache.GetServers(); ok {
		c.logger.Debug("using cached server list",
			"provider", c.Name(),
			"count", len(servers))
		return servers, nil
	}

	c.logger.Debug("fetching server list from API", "provider", c.Name())

	// Fetch from API
	logicalServers, err := c.fetchLogicalServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch logical servers: %w", err)
	}

	// Convert to vpnprovider.Server format
	servers := c.convertServers(logicalServers)

	// Update cache
	c.cache.SetServers(servers)

	c.logger.Info("fetched server list",
		"provider", c.Name(),
		"count", len(servers))

	return servers, nil
}

// fetchLogicalServers fetches the raw logical server list from the API.
func (c *Client) fetchLogicalServers(ctx context.Context) ([]LogicalServer, error) {
	url := c.baseURL + "/vpn/logicals"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", vpnprovider.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}

	var result LogicalServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Code != 1000 {
		return nil, fmt.Errorf("%w: API returned code %d", vpnprovider.ErrServerListFetchFailed, result.Code)
	}

	return result.LogicalServers, nil
}

// convertServers converts ProtonVPN logical servers to vpnprovider.Server format.
func (c *Client) convertServers(logicals []LogicalServer) []vpnprovider.Server {
	var servers []vpnprovider.Server //nolint:prealloc // Size unknown due to filtering

	userTier := 2 // Default to Plus tier
	if c.manualCreds != nil {
		userTier = c.manualCreds.Tier
	}

	for _, ls := range logicals {
		// Skip offline servers
		if !ls.IsOnline() {
			continue
		}

		// Skip servers above user's tier
		if ls.Tier > userTier {
			continue
		}

		// Get the first online physical server
		physicalServer := ls.GetFirstOnlineServer()
		if physicalServer == nil {
			continue
		}

		server := vpnprovider.Server{
			ID:          ls.ID,
			Name:        ls.Name,
			Hostname:    ls.Domain,
			Country:     GetCountryName(ls.ExitCountry),
			CountryCode: ls.ExitCountry,
			City:        ls.GetCity(),
			Load:        ls.Load,
			Features:    ls.GetFeatures(),
			IPs:         []string{physicalServer.EntryIP},
		}

		// Add tier as a feature for filtering
		server.Features = append(server.Features, ls.GetTierName())

		// Add OpenVPN info
		server.OpenVPN = &vpnprovider.OpenVPNServer{
			Hostname: ls.Domain,
			TCPPort:  OpenVPNTCPPort,
			UDPPort:  OpenVPNUDPPort,
		}

		// Add WireGuard info if available
		if pubKey := ls.GetWireGuardPublicKey(); pubKey != "" {
			server.WireGuard = &vpnprovider.WireGuardServer{
				PublicKey: pubKey,
				Endpoint:  fmt.Sprintf("%s:%d", ls.Domain, WireGuardPort),
			}
		}

		servers = append(servers, server)
	}

	return servers
}

// SelectServer selects the best server based on criteria.
func (c *Client) SelectServer(ctx context.Context, criteria vpnprovider.ServerCriteria) (*vpnprovider.Server, error) {
	servers, err := c.FetchServers(ctx)
	if err != nil {
		return nil, err
	}

	// Apply default fastest selection if no specific criteria
	if criteria.ServerID == "" && criteria.Country == "" && criteria.City == "" {
		criteria.Fastest = true
	}

	server := vpnprovider.SelectBestServer(servers, criteria)
	if server == nil {
		return nil, vpnprovider.ErrNoServersAvailable
	}

	c.logger.Debug("selected server",
		"provider", c.Name(),
		"server", server.Name,
		"country", server.CountryCode,
		"load", server.Load)

	return server, nil
}

// GenerateWireGuardConfig generates WireGuard configuration for a server.
// Note: WireGuard requires API authentication to register keys.
func (c *Client) GenerateWireGuardConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.WireGuardConfig, error) {
	if !c.SupportsWireGuard() {
		return nil, fmt.Errorf("%w: WireGuard requires API authentication to register keys", vpnprovider.ErrUnsupportedProtocol)
	}

	if server.WireGuard == nil {
		return nil, fmt.Errorf("%w: server %s does not support WireGuard", vpnprovider.ErrUnsupportedProtocol, server.Name)
	}

	// Generate a new WireGuard key pair
	keyPair, err := GenerateWireGuardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate WireGuard key pair: %w", err)
	}

	c.logger.Debug("generated WireGuard key pair",
		"provider", c.Name(),
		"public_key", keyPair.PublicKey)

	// Register the key and build config
	config, err := c.generateWireGuardConfig(ctx, server, keyPair)
	if err != nil {
		return nil, err
	}

	c.logger.Info("generated WireGuard config",
		"provider", c.Name(),
		"server", server.Name,
		"client_address", config.Address)

	return config, nil
}

// GenerateOpenVPNConfig generates OpenVPN configuration for a server.
func (c *Client) GenerateOpenVPNConfig(ctx context.Context, server *vpnprovider.Server, creds vpnprovider.Credentials) (*vpnprovider.OpenVPNConfig, error) {
	if server.OpenVPN == nil {
		return nil, fmt.Errorf("%w: server %s does not support OpenVPN", vpnprovider.ErrUnsupportedProtocol, server.Name)
	}

	// Determine credentials - explicit credentials override manual credentials
	username := creds.Username
	password := creds.Password

	// Fall back to manual credentials if not explicitly provided
	if username == "" || password == "" {
		if c.manualCreds != nil && c.manualCreds.IsValid() {
			username = c.manualCreds.OpenVPNUsername
			password = c.manualCreds.OpenVPNPassword
		}
	}

	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: OpenVPN username and password required", vpnprovider.ErrInvalidCredentials)
	}

	// Generate config from template
	config, err := c.generateOpenVPNConfigContent(server, "udp")
	if err != nil {
		return nil, err
	}

	return &vpnprovider.OpenVPNConfig{
		ConfigContent: config,
		Username:      username,
		Password:      password,
	}, nil
}

// generateOpenVPNConfigContent generates the OpenVPN config file content.
func (c *Client) generateOpenVPNConfigContent(server *vpnprovider.Server, protocol string) (string, error) {
	port := server.OpenVPN.UDPPort
	if protocol == "tcp" {
		port = server.OpenVPN.TCPPort
	}

	data := struct {
		Hostname string
		Port     int
		Protocol string
		CACert   string
		TLSAuth  string
	}{
		Hostname: server.OpenVPN.Hostname,
		Port:     port,
		Protocol: protocol,
		CACert:   ProtonVPNCACert,
		TLSAuth:  ProtonVPNTLSAuth,
	}

	tmpl, err := template.New("openvpn").Parse(OpenVPNConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// setHeaders sets the required headers for ProtonVPN API requests.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-pm-appversion", AppVersion)

	// Add auth headers if we have a session
	if c.session != nil && c.session.IsValid() {
		req.Header.Set("x-pm-uid", c.session.GetUID())
		req.Header.Set("Authorization", c.session.GetAuthHeader())
	}
}

// checkResponse checks the HTTP response for errors.
func (c *Client) checkResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return vpnprovider.ErrAuthenticationFailed
	case http.StatusForbidden:
		return vpnprovider.ErrAuthenticationFailed
	case http.StatusTooManyRequests:
		return vpnprovider.ErrRateLimited
	case http.StatusServiceUnavailable:
		return vpnprovider.ErrProviderUnavailable
	default:
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // Best effort read for error message
		return fmt.Errorf("%w: status %d: %s", vpnprovider.ErrProviderUnavailable, resp.StatusCode, string(body))
	}
}

// AuthInfoResponse represents the response from /auth/info endpoint.
type AuthInfoResponse struct {
	Code            int    `json:"Code"`
	Modulus         string `json:"Modulus"`         // Base64-encoded modulus N
	ServerEphemeral string `json:"ServerEphemeral"` // Base64-encoded server public value B
	Salt            string `json:"Salt"`            // Base64-encoded salt
	SRPSession      string `json:"SRPSession"`      // Session identifier for auth request
	Version         int    `json:"Version"`         // SRP version (affects password hashing)
}

// AuthRequest represents the authentication request to /auth endpoint.
type AuthRequest struct {
	Username        string `json:"Username"`
	ClientEphemeral string `json:"ClientEphemeral"` // Base64-encoded client public value A
	ClientProof     string `json:"ClientProof"`     // Base64-encoded client proof M1
	SRPSession      string `json:"SRPSession"`      // Session identifier from auth/info
}

// AuthResponse represents the response from /auth endpoint.
type AuthResponse struct {
	Code         int    `json:"Code"`
	UID          string `json:"UID"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	Scope        string `json:"Scope"`
	ServerProof  string `json:"ServerProof"` // Base64-encoded server proof M2
}

// Login authenticates with the ProtonVPN API using SRP-6a protocol.
func (c *Client) Login(ctx context.Context, username, password string) error {
	c.logger.Debug("starting SRP authentication", "username", username)

	// Step 1: Get auth info (salt, modulus, server ephemeral)
	authInfo, err := c.getAuthInfo(ctx, username)
	if err != nil {
		return fmt.Errorf("get auth info: %w", err)
	}

	// Parse SRP parameters
	modulus, err := ParseSRPModulus(authInfo.Modulus)
	if err != nil {
		return fmt.Errorf("parse modulus: %w", err)
	}

	serverB, err := ParseServerPublicValue(authInfo.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("parse server ephemeral: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(authInfo.Salt)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}

	params := &SRPParameters{
		Modulus:   modulus,
		Generator: srpGenerator,
		Salt:      salt,
		ServerB:   serverB,
		Version:   authInfo.Version,
	}

	// Step 2: Create SRP session and compute proofs
	srpSession, err := NewSRPSession(username, password, params)
	if err != nil {
		return fmt.Errorf("create SRP session: %w", err)
	}

	// Step 3: Send authentication request
	authResp, err := c.sendAuthRequest(ctx, username, srpSession, authInfo.SRPSession)
	if err != nil {
		return fmt.Errorf("send auth request: %w", err)
	}

	// Step 4: Verify server proof
	serverProof, err := base64.StdEncoding.DecodeString(authResp.ServerProof)
	if err != nil {
		return fmt.Errorf("decode server proof: %w", err)
	}

	if !srpSession.VerifyServerProof(serverProof) {
		return fmt.Errorf("%w: server proof verification failed", vpnprovider.ErrAuthenticationFailed)
	}

	// Step 5: Store session
	c.session = &Session{
		UID:          authResp.UID,
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		TokenType:    authResp.TokenType,
	}
	c.authMode = AuthModeAPI

	if c.sessionStore != nil {
		if err := c.sessionStore.Save(c.session); err != nil {
			c.logger.Warn("failed to persist session", "error", err)
		}
	}

	c.logger.Info("SRP authentication successful", "username", username)

	return nil
}

// getAuthInfo fetches authentication info from the server.
func (c *Client) getAuthInfo(ctx context.Context, username string) (*AuthInfoResponse, error) {
	url := c.baseURL + "/auth/info"

	reqBody := map[string]string{"Username": username}
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

	var result AuthInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Code != 1000 {
		return nil, fmt.Errorf("%w: API returned code %d", vpnprovider.ErrAuthenticationFailed, result.Code)
	}

	return &result, nil
}

// sendAuthRequest sends the authentication request with SRP proof.
func (c *Client) sendAuthRequest(ctx context.Context, username string, srpSession *SRPSession, sessionID string) (*AuthResponse, error) {
	url := c.baseURL + "/auth"

	authReq := AuthRequest{
		Username:        username,
		ClientEphemeral: srpSession.GetPublicA(),
		ClientProof:     srpSession.GetClientProof(),
		SRPSession:      sessionID,
	}

	jsonBody, err := json.Marshal(authReq)
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

	var result AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Code != 1000 {
		return nil, fmt.Errorf("%w: API returned code %d", vpnprovider.ErrAuthenticationFailed, result.Code)
	}

	return &result, nil
}

// Logout clears the current session.
func (c *Client) Logout(ctx context.Context) error {
	c.session = nil
	if c.sessionStore != nil {
		return c.sessionStore.Clear()
	}
	return nil
}

// ClearCache clears the server cache.
func (c *Client) ClearCache() {
	c.cache.Clear()
}

// GetServerCount returns the number of cached servers.
func (c *Client) GetServerCount() int {
	return c.cache.ServerCount()
}

// GetAvailableCountries returns a list of available countries.
func (c *Client) GetAvailableCountries(ctx context.Context) ([]vpnprovider.Country, error) {
	servers, err := c.FetchServers(ctx)
	if err != nil {
		return nil, err
	}

	// Collect unique countries
	countryMap := make(map[string]bool)
	var countries []vpnprovider.Country

	for _, s := range servers {
		if !countryMap[s.CountryCode] {
			countryMap[s.CountryCode] = true
			countries = append(countries, vpnprovider.Country{
				Code: s.CountryCode,
				Name: s.Country,
			})
		}
	}

	return countries, nil
}

// ImportOpenVPNConfig allows importing a user-provided OpenVPN config.
// This is useful when users want to use a specific config downloaded from ProtonVPN.
func (c *Client) ImportOpenVPNConfig(configContent string, username, password string) (*vpnprovider.OpenVPNConfig, error) {
	if configContent == "" {
		return nil, fmt.Errorf("%w: config content is empty", vpnprovider.ErrConfigGenerationFailed)
	}

	// Basic validation - check for required OpenVPN directives
	if !strings.Contains(configContent, "client") {
		return nil, fmt.Errorf("%w: config does not appear to be an OpenVPN client config", vpnprovider.ErrConfigGenerationFailed)
	}

	return &vpnprovider.OpenVPNConfig{
		ConfigContent: configContent,
		Username:      username,
		Password:      password,
	}, nil
}
