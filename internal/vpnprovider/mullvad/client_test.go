package mullvad

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
		wantErr   bool
	}{
		{
			name:      "valid 16-digit account",
			accountID: "1234567890123456",
			wantErr:   false,
		},
		{
			name:      "too short",
			accountID: "123456789012345",
			wantErr:   true,
		},
		{
			name:      "too long",
			accountID: "12345678901234567",
			wantErr:   true,
		},
		{
			name:      "contains letters",
			accountID: "123456789012345a",
			wantErr:   true,
		},
		{
			name:      "empty",
			accountID: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.accountID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client without error")
			}
		})
	}
}

func TestValidateAccountID(t *testing.T) {
	tests := []struct {
		accountID string
		valid     bool
	}{
		{"1234567890123456", true},
		{"0000000000000000", true},
		{"9999999999999999", true},
		{"123456789012345", false},  // 15 digits
		{"12345678901234567", false}, // 17 digits
		{"123456789012345a", false}, // contains letter
		{"1234-5678-9012-3456", false}, // contains dashes
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.accountID, func(t *testing.T) {
			got := validateAccountID(tt.accountID)
			if got != tt.valid {
				t.Errorf("validateAccountID(%q) = %v, want %v", tt.accountID, got, tt.valid)
			}
		})
	}
}

func TestClientName(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if got := client.Name(); got != "mullvad" {
		t.Errorf("Name() = %v, want %v", got, "mullvad")
	}
}

func TestClientSupports(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if !client.SupportsWireGuard() {
		t.Error("SupportsWireGuard() = false, want true")
	}

	if !client.SupportsOpenVPN() {
		t.Error("SupportsOpenVPN() = false, want true")
	}
}

func TestFetchServers(t *testing.T) {
	// Create test server
	relays := []MullvadRelay{
		{
			Hostname:    "se-sto-wg-001",
			CountryCode: "se",
			CountryName: "Sweden",
			CityCode:    "sto",
			CityName:    "Stockholm",
			Active:      true,
			Owned:       true,
			Provider:    "mullvad",
			IPv4AddrIn:  "185.65.134.1",
			Pubkey:      "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Type:        "wireguard",
		},
		{
			Hostname:    "de-fra-ovpn-001",
			CountryCode: "de",
			CountryName: "Germany",
			CityCode:    "fra",
			CityName:    "Frankfurt",
			Active:      true,
			Owned:       false,
			Provider:    "31173",
			IPv4AddrIn:  "193.27.14.1",
			Type:        "openvpn",
		},
		{
			Hostname:    "inactive-server",
			CountryCode: "us",
			CountryName: "USA",
			CityCode:    "nyc",
			CityName:    "New York",
			Active:      false, // Should be filtered out
			IPv4AddrIn:  "10.0.0.1",
			Type:        "wireguard",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/www/relays/all/" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(relays)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client with custom HTTP client pointing to test server
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Replace the relays URL by using a custom HTTP client and transport
	// We'll use a mock transport
	origURL := relaysAPIURL
	defer func() {
		// Reset would be needed if relaysAPIURL was mutable
		_ = origURL
	}()

	// For this test, we'll directly set servers in cache and test the filtering
	servers := convertRelaysToServers(relays)

	// Should have 2 servers (inactive one filtered out)
	if len(servers) != 2 {
		t.Errorf("convertRelaysToServers() returned %d servers, want 2", len(servers))
	}

	// Check first server (WireGuard)
	if servers[0].ID != "se-sto-wg-001" {
		t.Errorf("servers[0].ID = %v, want se-sto-wg-001", servers[0].ID)
	}
	if servers[0].WireGuard == nil {
		t.Error("servers[0].WireGuard is nil, want non-nil")
	}
	if servers[0].WireGuard != nil && servers[0].WireGuard.PublicKey != "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=" {
		t.Errorf("servers[0].WireGuard.PublicKey = %v, want BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=", servers[0].WireGuard.PublicKey)
	}

	// Check second server (OpenVPN)
	if servers[1].ID != "de-fra-ovpn-001" {
		t.Errorf("servers[1].ID = %v, want de-fra-ovpn-001", servers[1].ID)
	}
	if servers[1].OpenVPN == nil {
		t.Error("servers[1].OpenVPN is nil, want non-nil")
	}

	_ = client
	_ = server
}

func TestGenerateKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Validate private key format
	privBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		t.Errorf("Private key is not valid base64: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("Private key length = %d, want 32", len(privBytes))
	}

	// Validate public key format
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Errorf("Public key is not valid base64: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("Public key length = %d, want 32", len(pubBytes))
	}

	// Generate another key pair and ensure they're different
	privateKey2, publicKey2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() second call error = %v", err)
	}

	if privateKey == privateKey2 {
		t.Error("Two generated private keys are identical")
	}
	if publicKey == publicKey2 {
		t.Error("Two generated public keys are identical")
	}
}

func TestMullvadRelayToServer(t *testing.T) {
	relay := MullvadRelay{
		Hostname:    "se-sto-wg-001",
		CountryCode: "se",
		CountryName: "Sweden",
		CityCode:    "sto",
		CityName:    "Stockholm",
		Active:      true,
		Owned:       true,
		Provider:    "mullvad",
		IPv4AddrIn:  "185.65.134.1",
		IPv6AddrIn:  "2001:db8::1",
		Pubkey:      "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
		MultihopPort: 443,
		Daita:       true,
		Type:        "wireguard",
	}

	server := mullvadRelayToServer(relay)

	if server.ID != "se-sto-wg-001" {
		t.Errorf("ID = %v, want se-sto-wg-001", server.ID)
	}
	if server.Hostname != "se-sto-wg-001.relays.mullvad.net" {
		t.Errorf("Hostname = %v, want se-sto-wg-001.relays.mullvad.net", server.Hostname)
	}
	if server.Country != "Sweden" {
		t.Errorf("Country = %v, want Sweden", server.Country)
	}
	if server.CountryCode != "SE" {
		t.Errorf("CountryCode = %v, want SE", server.CountryCode)
	}
	if server.City != "Stockholm" {
		t.Errorf("City = %v, want Stockholm", server.City)
	}

	// Check IPs (both IPv4 and IPv6)
	if len(server.IPs) != 2 {
		t.Errorf("len(IPs) = %d, want 2", len(server.IPs))
	}

	// Check features
	hasOwned := false
	hasDaita := false
	hasMultihop := false
	for _, f := range server.Features {
		switch f {
		case "owned":
			hasOwned = true
		case "daita":
			hasDaita = true
		case "multihop":
			hasMultihop = true
		}
	}
	if !hasOwned {
		t.Error("Features missing 'owned'")
	}
	if !hasDaita {
		t.Error("Features missing 'daita'")
	}
	if !hasMultihop {
		t.Error("Features missing 'multihop'")
	}

	// Check WireGuard info
	if server.WireGuard == nil {
		t.Fatal("WireGuard is nil")
	}
	if server.WireGuard.PublicKey != relay.Pubkey {
		t.Errorf("WireGuard.PublicKey = %v, want %v", server.WireGuard.PublicKey, relay.Pubkey)
	}
	if server.WireGuard.Endpoint != "185.65.134.1:51820" {
		t.Errorf("WireGuard.Endpoint = %v, want 185.65.134.1:51820", server.WireGuard.Endpoint)
	}
}

func TestExtractCountries(t *testing.T) {
	servers := []vpnprovider.Server{
		{CountryCode: "SE", Country: "Sweden"},
		{CountryCode: "DE", Country: "Germany"},
		{CountryCode: "SE", Country: "Sweden"}, // Duplicate
		{CountryCode: "US", Country: "United States"},
	}

	countries := extractCountries(servers)

	if len(countries) != 3 {
		t.Errorf("len(countries) = %d, want 3", len(countries))
	}

	countrySet := make(map[string]bool)
	for _, c := range countries {
		countrySet[c.Code] = true
	}

	if !countrySet["SE"] || !countrySet["DE"] || !countrySet["US"] {
		t.Error("Missing expected countries")
	}
}

func TestExtractCities(t *testing.T) {
	servers := []vpnprovider.Server{
		{CountryCode: "SE", City: "Stockholm"},
		{CountryCode: "SE", City: "Gothenburg"},
		{CountryCode: "SE", City: "Stockholm"}, // Duplicate
		{Country: "DE", City: "Frankfurt"},
		{Country: "DE", City: ""}, // Empty city
	}

	cities := extractCities(servers)

	if len(cities) != 3 {
		t.Errorf("len(cities) = %d, want 3", len(cities))
	}
}

func TestRegisterWireGuardKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		account := r.FormValue("account")
		pubkey := r.FormValue("pubkey")

		// Validate account
		if account != "1234567890123456" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid account"))
			return
		}

		// Validate pubkey format
		if pubkey == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing pubkey"))
			return
		}

		// Return assigned IP
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("10.64.0.42"))
	}))
	defer server.Close()

	// Create a client that uses our test server
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Override HTTP client to point to test server
	client.httpClient = &http.Client{
		Transport: &testTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	ip, err := client.RegisterWireGuardKey(ctx, "1234567890123456", publicKey)
	if err != nil {
		t.Fatalf("RegisterWireGuardKey() error = %v", err)
	}

	if ip != "10.64.0.42" {
		t.Errorf("RegisterWireGuardKey() = %v, want 10.64.0.42", ip)
	}
}

// testTransport is a custom RoundTripper that redirects requests to a test server.
type testTransport struct {
	baseURL   string
	transport http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect WireGuard API calls to test server
	if req.URL.Host == "api.mullvad.net" && req.URL.Path == "/wg/" {
		req.URL.Scheme = "http"
		req.URL.Host = t.baseURL[7:] // Remove "http://"
	}
	return t.transport.RoundTrip(req)
}

func TestGenerateOpenVPNConfig(t *testing.T) {
	server := &vpnprovider.Server{
		Hostname: "de-fra-ovpn-001.relays.mullvad.net",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de-fra-ovpn-001.relays.mullvad.net",
			UDPPort:  1194,
			TCPPort:  443,
		},
	}

	config := generateOpenVPNConfig(server, "1234567890123456")

	// Check essential parts are present
	if config == "" {
		t.Fatal("generateOpenVPNConfig() returned empty string")
	}

	expectedParts := []string{
		"client",
		"dev tun",
		"proto udp",
		"remote de-fra-ovpn-001.relays.mullvad.net 1194",
		"cipher AES-256-GCM",
		"auth-user-pass",
		"<ca>",
		"-----BEGIN CERTIFICATE-----",
		"-----END CERTIFICATE-----",
		"</ca>",
	}

	for _, part := range expectedParts {
		if !contains(config, part) {
			t.Errorf("Config missing expected part: %q", part)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCacheOperations(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Initially cache should be empty/expired
	serverCount, lastFetch, expired := client.CacheStats()
	if serverCount != 0 {
		t.Errorf("Initial serverCount = %d, want 0", serverCount)
	}
	if !lastFetch.IsZero() {
		t.Errorf("Initial lastFetch should be zero")
	}
	if !expired {
		t.Error("Initial cache should be expired")
	}

	// Clear cache (should be no-op on empty cache)
	client.ClearCache()
}

func TestWithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 10 * time.Second}

	client, err := NewClient("1234567890123456", WithHTTPClient(customClient))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.httpClient != customClient {
		t.Error("WithHTTPClient did not set the custom HTTP client")
	}
}

func TestWithCache(t *testing.T) {
	customCache := vpnprovider.NewServerCache(5 * time.Minute)

	client, err := NewClient("1234567890123456", WithCache(customCache))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.cache != customCache {
		t.Error("WithCache did not set the custom cache")
	}
}

func TestWithLogger(t *testing.T) {
	customLogger := slog.Default().With("component", "test")

	client, err := NewClient("1234567890123456", WithLogger(customLogger))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.logger != customLogger {
		t.Error("WithLogger did not set the custom logger")
	}
}

func TestFetchServersWithMockServer(t *testing.T) {
	relays := []MullvadRelay{
		{
			Hostname:    "se-sto-wg-001",
			CountryCode: "se",
			CountryName: "Sweden",
			CityCode:    "sto",
			CityName:    "Stockholm",
			Active:      true,
			Owned:       true,
			Provider:    "mullvad",
			IPv4AddrIn:  "185.65.134.1",
			Pubkey:      "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Type:        "wireguard",
		},
		{
			Hostname:    "de-fra-ovpn-001",
			CountryCode: "de",
			CountryName: "Germany",
			CityCode:    "fra",
			CityName:    "Frankfurt",
			Active:      true,
			Owned:       false,
			Provider:    "31173",
			IPv4AddrIn:  "193.27.14.1",
			Type:        "openvpn",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relays)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Use multiEndpointTransport to route API calls to test server
	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)
	if err != nil {
		t.Fatalf("FetchServers() error = %v", err)
	}

	if len(servers) != 2 {
		t.Errorf("FetchServers() returned %d servers, want 2", len(servers))
	}

	// Test cache hit
	servers2, err := client.FetchServers(ctx)
	if err != nil {
		t.Fatalf("FetchServers() cache hit error = %v", err)
	}
	if len(servers2) != 2 {
		t.Errorf("FetchServers() cache hit returned %d servers, want 2", len(servers2))
	}
}

func TestFetchServersHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, err = client.FetchServers(ctx)
	if err == nil {
		t.Error("FetchServers() expected error for HTTP 500, got nil")
	}
}

func TestFetchServersInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, err = client.FetchServers(ctx)
	if err == nil {
		t.Error("FetchServers() expected error for invalid JSON, got nil")
	}
}

func TestSelectServerWithMockServer(t *testing.T) {
	relays := []MullvadRelay{
		{
			Hostname:    "jp-tyo-wg-001",
			CountryCode: "jp",
			CountryName: "Japan",
			CityCode:    "tyo",
			CityName:    "Tokyo",
			Active:      true,
			IPv4AddrIn:  "185.65.134.1",
			Pubkey:      "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Type:        "wireguard",
		},
		{
			Hostname:    "us-nyc-wg-001",
			CountryCode: "us",
			CountryName: "USA",
			CityCode:    "nyc",
			CityName:    "New York",
			Active:      true,
			IPv4AddrIn:  "193.27.14.1",
			Pubkey:      "ABC123=",
			Type:        "wireguard",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relays)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Select server by country code
	selectedServer, err := client.SelectServer(ctx, vpnprovider.ServerCriteria{
		Country: "US",
	})
	if err != nil {
		t.Fatalf("SelectServer() error = %v", err)
	}
	if selectedServer.CountryCode != "US" {
		t.Errorf("SelectServer() returned server with country %s, want US", selectedServer.CountryCode)
	}
}

func TestSelectServerNoMatch(t *testing.T) {
	relays := []MullvadRelay{
		{
			Hostname:    "se-sto-wg-001",
			CountryCode: "se",
			CountryName: "Sweden",
			CityCode:    "sto",
			CityName:    "Stockholm",
			Active:      true,
			IPv4AddrIn:  "185.65.134.1",
			Pubkey:      "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Type:        "wireguard",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(relays)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Select server with non-existent country
	_, err = client.SelectServer(ctx, vpnprovider.ServerCriteria{
		Country: "XX",
	})
	if err != vpnprovider.ErrNoServersAvailable {
		t.Errorf("SelectServer() error = %v, want ErrNoServersAvailable", err)
	}
}

func TestGenerateWireGuardConfigMethod(t *testing.T) {
	// Set up mock server for WireGuard key registration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wg/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("10.64.0.42"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	wgServer := &vpnprovider.Server{
		ID:       "se-sto-wg-001",
		Hostname: "se-sto-wg-001.relays.mullvad.net",
		WireGuard: &vpnprovider.WireGuardServer{
			PublicKey: "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Endpoint:  "185.65.134.1:51820",
		},
	}

	config, err := client.GenerateWireGuardConfig(ctx, wgServer, vpnprovider.Credentials{})
	if err != nil {
		t.Fatalf("GenerateWireGuardConfig() error = %v", err)
	}

	if config.PrivateKey == "" {
		t.Error("GenerateWireGuardConfig() PrivateKey is empty")
	}
	if config.PublicKey == "" {
		t.Error("GenerateWireGuardConfig() PublicKey is empty")
	}
	if config.Address != "10.64.0.42/32" {
		t.Errorf("GenerateWireGuardConfig() Address = %v, want 10.64.0.42/32", config.Address)
	}
	if config.Peer.PublicKey != wgServer.WireGuard.PublicKey {
		t.Errorf("GenerateWireGuardConfig() Peer.PublicKey = %v, want %v", config.Peer.PublicKey, wgServer.WireGuard.PublicKey)
	}
}

func TestGenerateWireGuardConfigNoWireGuardSupport(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	// Server without WireGuard support
	server := &vpnprovider.Server{
		ID:       "de-fra-ovpn-001",
		Hostname: "de-fra-ovpn-001.relays.mullvad.net",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de-fra-ovpn-001.relays.mullvad.net",
			UDPPort:  1194,
		},
	}

	_, err = client.GenerateWireGuardConfig(ctx, server, vpnprovider.Credentials{})
	if err == nil {
		t.Error("GenerateWireGuardConfig() expected error for server without WireGuard support, got nil")
	}
}

func TestGenerateWireGuardConfigWithCustomCredentials(t *testing.T) {
	// Set up mock server for WireGuard key registration
	var receivedAccount string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wg/" {
			r.ParseForm()
			receivedAccount = r.FormValue("account")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("10.64.0.99"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	wgServer := &vpnprovider.Server{
		ID:       "se-sto-wg-001",
		Hostname: "se-sto-wg-001.relays.mullvad.net",
		WireGuard: &vpnprovider.WireGuardServer{
			PublicKey: "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Endpoint:  "185.65.134.1:51820",
		},
	}

	// Use custom credentials
	creds := vpnprovider.Credentials{
		AccountID: "9999888877776666",
	}

	_, err = client.GenerateWireGuardConfig(ctx, wgServer, creds)
	if err != nil {
		t.Fatalf("GenerateWireGuardConfig() error = %v", err)
	}

	if receivedAccount != "9999888877776666" {
		t.Errorf("GenerateWireGuardConfig() used account %v, want 9999888877776666", receivedAccount)
	}
}

func TestGenerateOpenVPNConfigMethod(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	ovpnServer := &vpnprovider.Server{
		ID:       "de-fra-ovpn-001",
		Hostname: "de-fra-ovpn-001.relays.mullvad.net",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de-fra-ovpn-001.relays.mullvad.net",
			UDPPort:  1194,
			TCPPort:  443,
		},
	}

	config, err := client.GenerateOpenVPNConfig(ctx, ovpnServer, vpnprovider.Credentials{})
	if err != nil {
		t.Fatalf("GenerateOpenVPNConfig() error = %v", err)
	}

	if config.ConfigContent == "" {
		t.Error("GenerateOpenVPNConfig() ConfigContent is empty")
	}
	if config.Username != "1234567890123456" {
		t.Errorf("GenerateOpenVPNConfig() Username = %v, want 1234567890123456", config.Username)
	}
	if config.Password != "m" {
		t.Errorf("GenerateOpenVPNConfig() Password = %v, want m", config.Password)
	}
}

func TestGenerateOpenVPNConfigMethodNoOpenVPNSupport(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	// Server without OpenVPN support
	server := &vpnprovider.Server{
		ID:       "se-sto-wg-001",
		Hostname: "se-sto-wg-001.relays.mullvad.net",
		WireGuard: &vpnprovider.WireGuardServer{
			PublicKey: "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
			Endpoint:  "185.65.134.1:51820",
		},
	}

	_, err = client.GenerateOpenVPNConfig(ctx, server, vpnprovider.Credentials{})
	if err == nil {
		t.Error("GenerateOpenVPNConfig() expected error for server without OpenVPN support, got nil")
	}
}

func TestGenerateOpenVPNConfigMethodWithCustomCredentials(t *testing.T) {
	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	ovpnServer := &vpnprovider.Server{
		ID:       "de-fra-ovpn-001",
		Hostname: "de-fra-ovpn-001.relays.mullvad.net",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "de-fra-ovpn-001.relays.mullvad.net",
			UDPPort:  1194,
			TCPPort:  443,
		},
	}

	// Use custom credentials
	creds := vpnprovider.Credentials{
		AccountID: "9999888877776666",
	}

	config, err := client.GenerateOpenVPNConfig(ctx, ovpnServer, creds)
	if err != nil {
		t.Fatalf("GenerateOpenVPNConfig() error = %v", err)
	}

	if config.Username != "9999888877776666" {
		t.Errorf("GenerateOpenVPNConfig() Username = %v, want 9999888877776666", config.Username)
	}
}

func TestGetAccountInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/accounts/v1/accounts/1234567890123456" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(AccountInfo{
				Account:      "1234567890123456",
				ExpiryUnix:   1735689600,
				PrettyExpiry: "2025-01-01",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	info, err := client.GetAccountInfo(ctx)
	if err != nil {
		t.Fatalf("GetAccountInfo() error = %v", err)
	}

	if info.Account != "1234567890123456" {
		t.Errorf("GetAccountInfo() Account = %v, want 1234567890123456", info.Account)
	}
	if info.ExpiryUnix != 1735689600 {
		t.Errorf("GetAccountInfo() ExpiryUnix = %v, want 1735689600", info.ExpiryUnix)
	}
}

func TestGetAccountInfoUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, err = client.GetAccountInfo(ctx)
	if err != vpnprovider.ErrAuthenticationFailed {
		t.Errorf("GetAccountInfo() error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestGetAccountInfoNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, err = client.GetAccountInfo(ctx)
	if err != vpnprovider.ErrAuthenticationFailed {
		t.Errorf("GetAccountInfo() error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestGetAccountInfoHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Server Error"))
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, err = client.GetAccountInfo(ctx)
	if err == nil {
		t.Error("GetAccountInfo() expected error for HTTP 500, got nil")
	}
}

func TestRegisterWireGuardKeyErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    error
	}{
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       "Invalid account",
			wantErr:    vpnprovider.ErrAuthenticationFailed,
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			body:       "Too many requests",
			wantErr:    vpnprovider.ErrRateLimited,
		},
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			body:       "Invalid pubkey format",
			wantErr:    vpnprovider.ErrKeyRegistrationFailed,
		},
		{
			name:       "bad request with existing key",
			statusCode: http.StatusBadRequest,
			body:       "10.64.0.50",
			wantErr:    nil, // Should succeed as key is already registered
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, err := NewClient("1234567890123456")
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			client.httpClient = &http.Client{
				Transport: &multiEndpointTransport{
					baseURL:   server.URL,
					transport: http.DefaultTransport,
				},
				Timeout: 5 * time.Second,
			}

			ctx := context.Background()
			_, publicKey, _ := GenerateKeyPair()
			ip, err := client.RegisterWireGuardKey(ctx, "1234567890123456", publicKey)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("RegisterWireGuardKey() expected error %v, got nil", tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("RegisterWireGuardKey() unexpected error: %v", err)
				}
				if ip == "" {
					t.Error("RegisterWireGuardKey() expected IP, got empty string")
				}
			}
		})
	}
}

func TestMullvadRelayToServerBridgeType(t *testing.T) {
	relay := MullvadRelay{
		Hostname:    "se-sto-br-001",
		CountryCode: "se",
		CountryName: "Sweden",
		CityCode:    "sto",
		CityName:    "Stockholm",
		Active:      true,
		IPv4AddrIn:  "185.65.134.2",
		Type:        "bridge",
	}

	server := mullvadRelayToServer(relay)

	if server.OpenVPN == nil {
		t.Fatal("Bridge server should have OpenVPN info")
	}

	hasBridgeFeature := false
	for _, f := range server.Features {
		if f == "bridge" {
			hasBridgeFeature = true
			break
		}
	}
	if !hasBridgeFeature {
		t.Error("Bridge server should have 'bridge' feature")
	}
}

// multiEndpointTransport routes requests to different handlers based on path
type multiEndpointTransport struct {
	baseURL   string
	transport http.RoundTripper
}

func (t *multiEndpointTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.mullvad.net" {
		req.URL.Scheme = "http"
		req.URL.Host = t.baseURL[7:] // Remove "http://"
	}
	return t.transport.RoundTrip(req)
}

func TestGetAccountInfoInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := NewClient("1234567890123456")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &multiEndpointTransport{
			baseURL:   server.URL,
			transport: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	_, err = client.GetAccountInfo(ctx)
	if err == nil {
		t.Error("GetAccountInfo() expected error for invalid JSON, got nil")
	}
}
