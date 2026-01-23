package protonvpn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name string
		opts []ClientOption
	}{
		{
			name: "default options",
			opts: nil,
		},
		{
			name: "with custom HTTP client",
			opts: []ClientOption{
				WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
			},
		},
		{
			name: "with manual credentials",
			opts: []ClientOption{
				WithManualCredentials("user+suffix", "password", TierPlus),
			},
		},
		{
			name: "with cache TTL",
			opts: []ClientOption{
				WithCacheTTL(1 * time.Hour),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.opts...)
			assert.NotNil(t, client)
			assert.Equal(t, "protonvpn", client.Name())
		})
	}
}

func TestClientName(t *testing.T) {
	client := NewClient()
	assert.Equal(t, "protonvpn", client.Name())
}

func TestSupportsProtocols(t *testing.T) {
	client := NewClient()

	// OpenVPN should always be supported
	assert.True(t, client.SupportsOpenVPN())

	// WireGuard requires API authentication
	assert.False(t, client.SupportsWireGuard())
}

func TestFetchServers(t *testing.T) {
	// Create a mock server
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID:          "server-1",
				Name:        "US#42",
				Domain:      "us-42.protonvpn.net",
				EntryCountry: "US",
				ExitCountry:  "US",
				Tier:        2,
				Features:    FeatureP2P | FeatureStreaming,
				Load:        25,
				Status:      1,
				Location:    Location{Lat: 40.7128, Long: -74.0060},
				Servers: []Server{
					{
						ID:      "phys-1",
						EntryIP: "192.168.1.1",
						ExitIP:  "192.168.1.2",
						Status:  1,
						X25519PublicKey: "abcd1234publickey",
					},
				},
			},
			{
				ID:          "server-2",
				Name:        "DE#10",
				Domain:      "de-10.protonvpn.net",
				EntryCountry: "DE",
				ExitCountry:  "DE",
				Tier:        0, // Free tier
				Features:    0,
				Load:        75,
				Status:      1,
				Servers: []Server{
					{
						ID:      "phys-2",
						EntryIP: "192.168.2.1",
						Status:  1,
					},
				},
			},
			{
				ID:          "server-3",
				Name:        "FR#5",
				Domain:      "fr-5.protonvpn.net",
				EntryCountry: "FR",
				ExitCountry:  "FR",
				Tier:        1,
				Status:      0, // Offline
				Servers: []Server{
					{
						ID:      "phys-3",
						EntryIP: "192.168.3.1",
						Status:  0,
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vpn/logicals" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockServers)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithManualCredentials("user", "pass", TierPlus),
	)

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Len(t, servers, 2) // Only 2 online servers (FR#5 is offline)

	// Verify first server
	usServer := servers[0]
	assert.Equal(t, "server-1", usServer.ID)
	assert.Equal(t, "US#42", usServer.Name)
	assert.Equal(t, "us-42.protonvpn.net", usServer.Hostname)
	assert.Equal(t, "US", usServer.CountryCode)
	assert.Equal(t, 25, usServer.Load)
	assert.Contains(t, usServer.Features, "p2p")
	assert.Contains(t, usServer.Features, "streaming")
	assert.NotNil(t, usServer.OpenVPN)
	assert.NotNil(t, usServer.WireGuard)
}

func TestFetchServersCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := LogicalServerResponse{
			Code: 1000,
			LogicalServers: []LogicalServer{
				{
					ID:     "test-1",
					Name:   "US#1",
					Domain: "test.protonvpn.net",
					Tier:   0,
					Status: 1,
					Servers: []Server{{ID: "s1", EntryIP: "1.2.3.4", Status: 1}},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	ctx := context.Background()

	// First call should hit the API
	_, err := client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call should use cache
	_, err = client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Clear cache and call again
	client.ClearCache()
	_, err = client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestSelectServer(t *testing.T) {
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID: "us-1", Name: "US#1", Domain: "us1.protonvpn.net",
				ExitCountry: "US", Tier: 0, Load: 50, Status: 1,
				Servers: []Server{{ID: "s1", EntryIP: "1.1.1.1", Status: 1}},
			},
			{
				ID: "us-2", Name: "US#2", Domain: "us2.protonvpn.net",
				ExitCountry: "US", Tier: 0, Load: 20, Status: 1,
				Servers: []Server{{ID: "s2", EntryIP: "2.2.2.2", Status: 1}},
			},
			{
				ID: "de-1", Name: "DE#1", Domain: "de1.protonvpn.net",
				ExitCountry: "DE", Tier: 0, Load: 30, Status: 1,
				Servers: []Server{{ID: "s3", EntryIP: "3.3.3.3", Status: 1}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	ctx := context.Background()

	// Select by country
	selected, err := client.SelectServer(ctx, vpnprovider.ServerCriteria{Country: "US"})
	require.NoError(t, err)
	assert.Equal(t, "US", selected.CountryCode)

	// Select fastest (lowest load)
	selected, err = client.SelectServer(ctx, vpnprovider.ServerCriteria{Fastest: true})
	require.NoError(t, err)
	assert.Equal(t, 20, selected.Load) // US#2 has lowest load

	// Select by specific ID
	selected, err = client.SelectServer(ctx, vpnprovider.ServerCriteria{ServerID: "de-1"})
	require.NoError(t, err)
	assert.Equal(t, "de-1", selected.ID)
}

func TestGenerateOpenVPNConfig(t *testing.T) {
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID: "test-1", Name: "US#1", Domain: "test.protonvpn.net",
				ExitCountry: "US", Tier: 0, Load: 25, Status: 1,
				Servers: []Server{{ID: "s1", EntryIP: "1.1.1.1", Status: 1}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithManualCredentials("openvpn_user+suffix", "openvpn_pass", TierFree),
	)

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, servers)

	// Generate config using client's manual credentials
	config, err := client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{})
	require.NoError(t, err)
	assert.Equal(t, "openvpn_user+suffix", config.Username)
	assert.Equal(t, "openvpn_pass", config.Password)
	assert.Contains(t, config.ConfigContent, "client")
	assert.Contains(t, config.ConfigContent, "test.protonvpn.net")
	assert.Contains(t, config.ConfigContent, "BEGIN CERTIFICATE")

	// Generate config with explicit credentials
	config, err = client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{
		Username: "explicit_user",
		Password: "explicit_pass",
	})
	require.NoError(t, err)
	assert.Equal(t, "explicit_user", config.Username)
	assert.Equal(t, "explicit_pass", config.Password)
}

func TestGenerateOpenVPNConfigNoCredentials(t *testing.T) {
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID: "test-1", Name: "US#1", Domain: "test.protonvpn.net",
				ExitCountry: "US", Tier: 0, Status: 1,
				Servers: []Server{{ID: "s1", EntryIP: "1.1.1.1", Status: 1}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	// Client without manual credentials
	client := NewClient(WithBaseURL(server.URL))

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)
	require.NoError(t, err)

	// Should fail without credentials
	_, err = client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrInvalidCredentials)
}

func TestImportOpenVPNConfig(t *testing.T) {
	client := NewClient()

	validConfig := `client
dev tun
proto udp
remote test.protonvpn.net 1194
auth-user-pass
`
	config, err := client.ImportOpenVPNConfig(validConfig, "user", "pass")
	require.NoError(t, err)
	assert.Equal(t, validConfig, config.ConfigContent)
	assert.Equal(t, "user", config.Username)
	assert.Equal(t, "pass", config.Password)

	// Empty config should fail
	_, err = client.ImportOpenVPNConfig("", "user", "pass")
	assert.Error(t, err)

	// Invalid config (no client directive) should fail
	_, err = client.ImportOpenVPNConfig("some random content", "user", "pass")
	assert.Error(t, err)
}

func TestAPIErrors(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectedError  error
	}{
		{
			name:          "unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectedError: vpnprovider.ErrAuthenticationFailed,
		},
		{
			name:          "forbidden",
			statusCode:    http.StatusForbidden,
			expectedError: vpnprovider.ErrAuthenticationFailed,
		},
		{
			name:          "rate limited",
			statusCode:    http.StatusTooManyRequests,
			expectedError: vpnprovider.ErrRateLimited,
		},
		{
			name:          "service unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectedError: vpnprovider.ErrProviderUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := NewClient(WithBaseURL(server.URL))
			client.ClearCache() // Ensure we hit the API

			_, err := client.FetchServers(context.Background())
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.expectedError)
		})
	}
}

func TestTierFiltering(t *testing.T) {
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID: "free-1", Name: "US-FREE#1", Domain: "free.protonvpn.net",
				ExitCountry: "US", Tier: TierFree, Status: 1,
				Servers: []Server{{ID: "s1", EntryIP: "1.1.1.1", Status: 1}},
			},
			{
				ID: "basic-1", Name: "US-BASIC#1", Domain: "basic.protonvpn.net",
				ExitCountry: "US", Tier: TierBasic, Status: 1,
				Servers: []Server{{ID: "s2", EntryIP: "2.2.2.2", Status: 1}},
			},
			{
				ID: "plus-1", Name: "US-PLUS#1", Domain: "plus.protonvpn.net",
				ExitCountry: "US", Tier: TierPlus, Status: 1,
				Servers: []Server{{ID: "s3", EntryIP: "3.3.3.3", Status: 1}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	// Free tier user - should only see free servers
	freeClient := NewClient(
		WithBaseURL(server.URL),
		WithManualCredentials("user", "pass", TierFree),
	)

	ctx := context.Background()
	servers, err := freeClient.FetchServers(ctx)
	require.NoError(t, err)
	assert.Len(t, servers, 1)
	assert.Equal(t, "free-1", servers[0].ID)

	// Plus tier user - should see all servers
	plusClient := NewClient(
		WithBaseURL(server.URL),
		WithManualCredentials("user", "pass", TierPlus),
	)
	plusClient.ClearCache()

	servers, err = plusClient.FetchServers(ctx)
	require.NoError(t, err)
	assert.Len(t, servers, 3)
}
