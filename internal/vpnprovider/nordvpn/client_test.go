package nordvpn

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	assert.NotNil(t, client)
	assert.Equal(t, ProviderName, client.Name())
	assert.Equal(t, BaseURL, client.baseURL)
}

func TestNewClientWithOptions(t *testing.T) {
	customHTTPClient := &http.Client{Timeout: 60 * time.Second}
	customBaseURL := "https://custom.api.example.com"

	client := NewClient(
		WithHTTPClient(customHTTPClient),
		WithBaseURL(customBaseURL),
		WithCacheTTL(1*time.Hour),
	)

	assert.NotNil(t, client)
	assert.Equal(t, customHTTPClient, client.httpClient)
	assert.Equal(t, customBaseURL, client.baseURL)
	assert.Equal(t, 1*time.Hour, client.cache.TTL())
}

func TestClientName(t *testing.T) {
	client := NewClient()
	assert.Equal(t, "nordvpn", client.Name())
}

func TestClientSupports(t *testing.T) {
	client := NewClient()
	assert.True(t, client.SupportsWireGuard())
	assert.True(t, client.SupportsOpenVPN())
}

func TestFetchServers(t *testing.T) {
	// Create mock server
	mockServers := []APIServer{
		{
			ID:       1,
			Name:     "us1234",
			Station:  "1.2.3.4",
			Hostname: "us1234.nordvpn.com",
			Load:     25,
			Status:   "online",
			Locations: []APILocation{
				{
					Country: APICountry{
						ID:   228,
						Name: "United States",
						Code: "US",
						City: APICity{Name: "New York", DNSName: "new-york"},
					},
				},
			},
			Technologies: []APITechnology{
				{
					Identifier: TechNordLynx,
					Pivot:      APITechPivot{Status: "online"},
					Metadata:   []APITechMetadata{{Name: "public_key", Value: "testkey123"}},
				},
				{
					Identifier: TechOpenVPNUDP,
					Pivot:      APITechPivot{Status: "online"},
				},
				{
					Identifier: TechOpenVPNTCP,
					Pivot:      APITechPivot{Status: "online"},
				},
			},
			Groups: []APIGroup{
				{Identifier: GroupP2P, Title: "P2P"},
			},
			IPs: []APIIP{
				{IP: APIIPAddr{IP: "1.2.3.4", Version: 4}},
			},
		},
		{
			ID:       2,
			Name:     "de5678",
			Station:  "5.6.7.8",
			Hostname: "de5678.nordvpn.com",
			Load:     50,
			Status:   "online",
			Locations: []APILocation{
				{
					Country: APICountry{
						ID:   81,
						Name: "Germany",
						Code: "DE",
						City: APICity{Name: "Berlin", DNSName: "berlin"},
					},
				},
			},
			Technologies: []APITechnology{
				{
					Identifier: TechOpenVPNUDP,
					Pivot:      APITechPivot{Status: "online"},
				},
			},
			IPs: []APIIP{
				{IP: APIIPAddr{IP: "5.6.7.8", Version: 4}},
			},
		},
		{
			ID:       3,
			Name:     "offline1",
			Hostname: "offline.nordvpn.com",
			Load:     0,
			Status:   "offline", // Should be filtered out
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/servers" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockServers)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)

	require.NoError(t, err)
	require.Len(t, servers, 2) // Offline server should be filtered

	// Check first server
	assert.Equal(t, "1", servers[0].ID)
	assert.Equal(t, "us1234", servers[0].Name)
	assert.Equal(t, "us1234.nordvpn.com", servers[0].Hostname)
	assert.Equal(t, 25, servers[0].Load)
	assert.Equal(t, "United States", servers[0].Country)
	assert.Equal(t, "US", servers[0].CountryCode)
	assert.Equal(t, "New York", servers[0].City)
	assert.Contains(t, servers[0].Features, "p2p")
	assert.NotNil(t, servers[0].WireGuard)
	assert.Equal(t, "testkey123", servers[0].WireGuard.PublicKey)
	assert.NotNil(t, servers[0].OpenVPN)

	// Check second server
	assert.Equal(t, "2", servers[1].ID)
	assert.Equal(t, "Germany", servers[1].Country)
	assert.Nil(t, servers[1].WireGuard) // No WireGuard support
	assert.NotNil(t, servers[1].OpenVPN)
}

func TestFetchServersWithCache(t *testing.T) {
	callCount := 0
	mockServers := []APIServer{
		{
			ID:       1,
			Name:     "test1",
			Hostname: "test1.nordvpn.com",
			Status:   "online",
			Load:     10,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithCacheTTL(1*time.Hour),
	)

	ctx := context.Background()

	// First call should hit the API
	_, err := client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call should use cache
	_, err = client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount) // Still 1, cache was used

	// Clear cache and call again
	client.ClearCache()
	_, err = client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, callCount) // Now 2, cache was cleared
}

func TestGetCountries(t *testing.T) {
	mockCountries := []APICountryInfo{
		{
			ID:          228,
			Name:        "United States",
			Code:        "US",
			ServerCount: 2000,
			Cities: []APICityInfo{
				{ID: 1, Name: "New York", ServerCount: 500},
				{ID: 2, Name: "Los Angeles", ServerCount: 300},
			},
		},
		{
			ID:          81,
			Name:        "Germany",
			Code:        "DE",
			ServerCount: 500,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/servers/countries" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockCountries)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	ctx := context.Background()
	countries, err := client.GetCountries(ctx)

	require.NoError(t, err)
	require.Len(t, countries, 2)

	assert.Equal(t, 228, countries[0].ID)
	assert.Equal(t, "US", countries[0].Code)
	assert.Equal(t, "United States", countries[0].Name)
}

func TestFetchRecommended(t *testing.T) {
	mockServers := []APIServer{
		{
			ID:       100,
			Name:     "recommended1",
			Hostname: "recommended1.nordvpn.com",
			Status:   "online",
			Load:     5,
			Locations: []APILocation{
				{
					Country: APICountry{
						ID:   228,
						Name: "United States",
						Code: "US",
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/servers/recommendations" {
			// Check query parameters
			assert.Contains(t, r.URL.RawQuery, "country_id")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockServers)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	ctx := context.Background()
	servers, err := client.FetchRecommended(ctx, 228)

	require.NoError(t, err)
	require.Len(t, servers, 1)
	assert.Equal(t, "100", servers[0].ID)
	assert.Equal(t, 5, servers[0].Load)
}

func TestSelectServer(t *testing.T) {
	mockServers := []APIServer{
		{
			ID:       1,
			Name:     "us-high-load",
			Hostname: "us1.nordvpn.com",
			Status:   "online",
			Load:     90,
			Locations: []APILocation{
				{Country: APICountry{Name: "United States", Code: "US"}},
			},
			Technologies: []APITechnology{
				{Identifier: TechNordLynx, Pivot: APITechPivot{Status: "online"}, Metadata: []APITechMetadata{{Name: "public_key", Value: "key1"}}},
			},
		},
		{
			ID:       2,
			Name:     "us-low-load",
			Hostname: "us2.nordvpn.com",
			Status:   "online",
			Load:     10,
			Locations: []APILocation{
				{Country: APICountry{Name: "United States", Code: "US"}},
			},
			Technologies: []APITechnology{
				{Identifier: TechNordLynx, Pivot: APITechPivot{Status: "online"}, Metadata: []APITechMetadata{{Name: "public_key", Value: "key2"}}},
			},
		},
		{
			ID:       3,
			Name:     "de-server",
			Hostname: "de1.nordvpn.com",
			Status:   "online",
			Load:     5,
			Locations: []APILocation{
				{Country: APICountry{Name: "Germany", Code: "DE"}},
			},
			Technologies: []APITechnology{
				{Identifier: TechOpenVPNUDP, Pivot: APITechPivot{Status: "online"}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	ctx := context.Background()

	t.Run("select fastest US server with WireGuard", func(t *testing.T) {
		selected, err := client.SelectServer(ctx, vpnprovider.ServerCriteria{
			Country:  "US",
			Protocol: "wireguard",
			Fastest:  true,
		})

		require.NoError(t, err)
		require.NotNil(t, selected)
		assert.Equal(t, "2", selected.ID) // Low load US server
	})

	t.Run("select any German server", func(t *testing.T) {
		selected, err := client.SelectServer(ctx, vpnprovider.ServerCriteria{
			Country: "DE",
		})

		require.NoError(t, err)
		require.NotNil(t, selected)
		assert.Equal(t, "3", selected.ID)
	})

	t.Run("no servers matching criteria", func(t *testing.T) {
		selected, err := client.SelectServer(ctx, vpnprovider.ServerCriteria{
			Country: "XX", // Non-existent country
		})

		assert.ErrorIs(t, err, vpnprovider.ErrNoServersAvailable)
		assert.Nil(t, selected)
	})
}

func TestGenerateWireGuardConfig(t *testing.T) {
	client := NewClient()

	serverWithWG := &vpnprovider.Server{
		ID:       "123",
		Hostname: "us123.nordvpn.com",
		WireGuard: &vpnprovider.WireGuardServer{
			PublicKey: "server-public-key-here",
			Endpoint:  "us123.nordvpn.com:51820",
		},
	}

	serverWithoutWG := &vpnprovider.Server{
		ID:       "456",
		Hostname: "us456.nordvpn.com",
	}

	ctx := context.Background()

	t.Run("generate config with valid credentials", func(t *testing.T) {
		creds := vpnprovider.Credentials{
			AccessToken: "user-private-key-here",
		}

		config, err := client.GenerateWireGuardConfig(ctx, serverWithWG, creds)

		require.NoError(t, err)
		require.NotNil(t, config)
		assert.Equal(t, "user-private-key-here", config.PrivateKey)
		assert.Equal(t, "10.5.0.2/32", config.Address)
		assert.Contains(t, config.DNS, "103.86.96.100")
		assert.Equal(t, "server-public-key-here", config.Peer.PublicKey)
		assert.Equal(t, "us123.nordvpn.com:51820", config.Peer.Endpoint)
		assert.Contains(t, config.Peer.AllowedIPs, "0.0.0.0/0")
	})

	t.Run("error without credentials", func(t *testing.T) {
		_, err := client.GenerateWireGuardConfig(ctx, serverWithWG, vpnprovider.Credentials{})
		assert.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrInvalidCredentials)
	})

	t.Run("error for server without WireGuard", func(t *testing.T) {
		creds := vpnprovider.Credentials{AccessToken: "key"}
		_, err := client.GenerateWireGuardConfig(ctx, serverWithoutWG, creds)
		assert.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrUnsupportedProtocol)
	})
}

func TestGenerateOpenVPNConfig(t *testing.T) {
	client := NewClient()

	serverWithOVPN := &vpnprovider.Server{
		ID:       "123",
		Hostname: "us123.nordvpn.com",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "us123.nordvpn.com",
			UDPPort:  1194,
			TCPPort:  443,
		},
	}

	serverWithoutOVPN := &vpnprovider.Server{
		ID:       "456",
		Hostname: "us456.nordvpn.com",
	}

	ctx := context.Background()

	t.Run("generate config with valid credentials", func(t *testing.T) {
		creds := vpnprovider.Credentials{
			Username: "testuser",
			Password: "testpass",
		}

		config, err := client.GenerateOpenVPNConfig(ctx, serverWithOVPN, creds)

		require.NoError(t, err)
		require.NotNil(t, config)
		assert.Equal(t, "testuser", config.Username)
		assert.Equal(t, "testpass", config.Password)
		assert.Contains(t, config.ConfigContent, "client")
		assert.Contains(t, config.ConfigContent, "dev tun")
		assert.Contains(t, config.ConfigContent, "proto udp")
		assert.Contains(t, config.ConfigContent, "remote us123.nordvpn.com 1194")
		assert.Contains(t, config.ConfigContent, "<ca>")
		assert.Contains(t, config.ConfigContent, "<tls-auth>")
	})

	t.Run("error without credentials", func(t *testing.T) {
		_, err := client.GenerateOpenVPNConfig(ctx, serverWithOVPN, vpnprovider.Credentials{})
		assert.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrInvalidCredentials)
	})

	t.Run("error for server without OpenVPN", func(t *testing.T) {
		creds := vpnprovider.Credentials{Username: "user", Password: "pass"}
		_, err := client.GenerateOpenVPNConfig(ctx, serverWithoutOVPN, creds)
		assert.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrUnsupportedProtocol)
	})
}

func TestAPIServerToServer(t *testing.T) {
	apiServer := APIServer{
		ID:       12345,
		Name:     "us12345",
		Station:  "192.168.1.1",
		Hostname: "us12345.nordvpn.com",
		Load:     35,
		Status:   "online",
		Locations: []APILocation{
			{
				Country: APICountry{
					ID:   228,
					Name: "United States",
					Code: "US",
					City: APICity{Name: "Chicago", DNSName: "chicago"},
				},
			},
		},
		Technologies: []APITechnology{
			{
				Identifier: TechNordLynx,
				Pivot:      APITechPivot{Status: "online"},
				Metadata:   []APITechMetadata{{Name: "public_key", Value: "wg-pubkey-123"}},
			},
			{
				Identifier: TechOpenVPNUDP,
				Pivot:      APITechPivot{Status: "online"},
			},
			{
				Identifier: TechOpenVPNTCP,
				Pivot:      APITechPivot{Status: "online"},
			},
		},
		Groups: []APIGroup{
			{Identifier: GroupP2P, Title: "P2P"},
			{Identifier: GroupStandardVPN, Title: "Standard VPN servers"},
		},
		IPs: []APIIP{
			{IP: APIIPAddr{IP: "203.0.113.1", Version: 4}},
			{IP: APIIPAddr{IP: "2001:db8::1", Version: 6}},
		},
	}

	server := apiServer.ToServer()

	assert.Equal(t, "12345", server.ID)
	assert.Equal(t, "us12345", server.Name)
	assert.Equal(t, "us12345.nordvpn.com", server.Hostname)
	assert.Equal(t, 35, server.Load)
	assert.Equal(t, "United States", server.Country)
	assert.Equal(t, "US", server.CountryCode)
	assert.Equal(t, "Chicago", server.City)
	assert.Contains(t, server.Features, "p2p")
	assert.Contains(t, server.IPs, "203.0.113.1")
	assert.NotContains(t, server.IPs, "2001:db8::1") // IPv6 not included

	require.NotNil(t, server.WireGuard)
	assert.Equal(t, "wg-pubkey-123", server.WireGuard.PublicKey)
	assert.Equal(t, "us12345.nordvpn.com:51820", server.WireGuard.Endpoint)

	require.NotNil(t, server.OpenVPN)
	assert.Equal(t, "us12345.nordvpn.com", server.OpenVPN.Hostname)
	assert.Equal(t, DefaultOpenVPNUDPPort, server.OpenVPN.UDPPort)
	assert.Equal(t, DefaultOpenVPNTCPPort, server.OpenVPN.TCPPort)
}

func TestAPIServerHelpers(t *testing.T) {
	apiServer := APIServer{
		Status: "online",
		Technologies: []APITechnology{
			{
				Identifier: TechNordLynx,
				Pivot:      APITechPivot{Status: "online"},
				Metadata:   []APITechMetadata{{Name: "public_key", Value: "key123"}},
			},
			{
				Identifier: TechOpenVPNUDP,
				Pivot:      APITechPivot{Status: "offline"},
			},
		},
		Groups: []APIGroup{
			{Identifier: GroupP2P},
			{Identifier: GroupStandardVPN},
		},
	}

	t.Run("IsOnline", func(t *testing.T) {
		assert.True(t, apiServer.IsOnline())

		offline := APIServer{Status: "offline"}
		assert.False(t, offline.IsOnline())

		caseInsensitive := APIServer{Status: "ONLINE"}
		assert.True(t, caseInsensitive.IsOnline())
	})

	t.Run("HasTechnology", func(t *testing.T) {
		assert.True(t, apiServer.HasTechnology(TechNordLynx))
		assert.False(t, apiServer.HasTechnology(TechOpenVPNUDP)) // offline
		assert.False(t, apiServer.HasTechnology(TechOpenVPNTCP))
	})

	t.Run("HasGroup", func(t *testing.T) {
		assert.True(t, apiServer.HasGroup(GroupP2P))
		assert.True(t, apiServer.HasGroup(GroupStandardVPN))
		assert.False(t, apiServer.HasGroup(GroupDoubleVPN))
	})

	t.Run("GetTechnologyMetadata", func(t *testing.T) {
		val, ok := apiServer.GetTechnologyMetadata(TechNordLynx, "public_key")
		assert.True(t, ok)
		assert.Equal(t, "key123", val)

		_, ok = apiServer.GetTechnologyMetadata(TechNordLynx, "nonexistent")
		assert.False(t, ok)

		_, ok = apiServer.GetTechnologyMetadata("nonexistent", "public_key")
		assert.False(t, ok)
	})
}

func TestCheckResponse(t *testing.T) {
	client := NewClient()

	tests := []struct {
		statusCode int
		expectErr  error
	}{
		{200, nil},
		{201, nil},
		{204, nil},
		{429, vpnprovider.ErrRateLimited},
		{401, vpnprovider.ErrAuthenticationFailed},
		{403, vpnprovider.ErrAuthenticationFailed},
		{404, vpnprovider.ErrInvalidServerID},
		{500, vpnprovider.ErrProviderUnavailable},
		{503, vpnprovider.ErrProviderUnavailable},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.statusCode}
			err := client.checkResponse(resp)

			if tt.expectErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectErr)
			}
		})
	}
}

func TestCacheStats(t *testing.T) {
	client := NewClient(WithCacheTTL(2 * time.Hour))

	serverCount, lastFetch, ttl := client.CacheStats()
	assert.Equal(t, 0, serverCount)
	assert.True(t, lastFetch.IsZero())
	assert.Equal(t, 2*time.Hour, ttl)
}

func TestWithLogger(t *testing.T) {
	customLogger := slog.Default().With("component", "nordvpn-test")

	client := NewClient(WithLogger(customLogger))

	assert.NotNil(t, client)
	assert.Equal(t, customLogger, client.logger)
}
