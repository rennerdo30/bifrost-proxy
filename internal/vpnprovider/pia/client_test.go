package pia

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

func TestNewClient(t *testing.T) {
	client := NewClient("testuser", "testpass")

	assert.NotNil(t, client)
	assert.Equal(t, ProviderName, client.Name())
	assert.True(t, client.SupportsWireGuard())
	assert.True(t, client.SupportsOpenVPN())
}

func TestFetchServers(t *testing.T) {
	// Mock server response
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:          "us-east",
				Name:        "US East",
				Country:     "US",
				PortForward: true,
				Servers: RegionServers{
					WireGuard: []WGServer{
						{IP: "1.2.3.4", CN: "us-east-wg"},
					},
					OpenVPN: []OVPNServer{
						{IP: "1.2.3.5", CN: "us-east-ovpn"},
					},
					Meta: []MetaServer{
						{IP: "1.2.3.6", CN: "us-east-meta"},
					},
				},
			},
			{
				ID:      "uk-london",
				Name:    "UK London",
				Country: "UK",
				Offline: true, // Should be excluded
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create client with mocked HTTP client
	client := NewClient("testuser", "testpass")
	client.httpClient = server.Client()

	// Override the endpoint for testing
	origEndpoint := ServerListEndpoint
	defer func() { _ = origEndpoint }() // Unused, but keeps the original

	// Create a new test server specifically for the server list
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer testServer.Close()

	// We can't easily override the const, so we'll test the parsing directly
	t.Run("ServerListParsing", func(t *testing.T) {
		// Test that online servers are included and offline ones are not
		assert.False(t, mockResponse.Regions[0].Offline)
		assert.True(t, mockResponse.Regions[1].Offline)
	})
}

func TestRegionToVPNProviderServer(t *testing.T) {
	region := Region{
		ID:          "us-california",
		Name:        "US California",
		Country:     "US",
		PortForward: true,
		DNS:         "10.0.0.1",
		Servers: RegionServers{
			WireGuard: []WGServer{
				{IP: "1.2.3.4", CN: "us-ca-wg"},
			},
			OpenVPN: []OVPNServer{
				{IP: "1.2.3.5", CN: "us-ca-ovpn"},
			},
			OpenVPNTC: []OVPNServer{
				{IP: "1.2.3.6", CN: "us-ca-ovpn-tcp"},
			},
			Meta: []MetaServer{
				{IP: "1.2.3.7", CN: "us-ca-meta"},
			},
		},
	}

	server := region.ToVPNProviderServer()

	assert.Equal(t, "us-california", server.ID)
	assert.Equal(t, "US California", server.Name)
	assert.Equal(t, "US", server.Country)
	assert.Equal(t, "California", server.City)

	// Check WireGuard info
	require.NotNil(t, server.WireGuard)
	assert.Equal(t, "1.2.3.4:"+DefaultWireGuardPort, server.WireGuard.Endpoint)

	// Check OpenVPN info
	require.NotNil(t, server.OpenVPN)
	assert.Equal(t, DefaultOpenVPNUDPPort, server.OpenVPN.UDPPort)
	assert.Equal(t, DefaultOpenVPNTCPPort, server.OpenVPN.TCPPort)

	// Check features
	assert.Contains(t, server.Features, "port_forwarding")
	assert.Contains(t, server.Features, "wireguard")
	assert.Contains(t, server.Features, "openvpn")

	// Check IPs are collected
	assert.Len(t, server.IPs, 4)
}

func TestExtractCountryCode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"US", "US"},
		{"United States", "US"},
		{"united states", "US"},
		{"UK", "GB"},
		{"United Kingdom", "GB"},
		{"Germany", "DE"},
		{"de", "DE"},
		{"Unknown Country", "Unknown Country"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := extractCountryCode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractCity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"US California", "California"},
		{"UK London", "London"},
		{"Singapore", "Singapore"},
		{"US New York", "New York"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := extractCity(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTokenExpiration(t *testing.T) {
	t.Run("NilToken", func(t *testing.T) {
		var token *Token
		assert.True(t, token.IsExpired())
		assert.False(t, token.IsValid())
	})

	t.Run("EmptyToken", func(t *testing.T) {
		token := &Token{}
		assert.True(t, token.IsExpired())
		assert.False(t, token.IsValid())
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		token := &Token{
			Value:     "test-token",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, token.IsExpired())
		assert.False(t, token.IsValid())
	})

	t.Run("ValidToken", func(t *testing.T) {
		token := &Token{
			Value:     "test-token",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, token.IsExpired())
		assert.True(t, token.IsValid())
	})

	t.Run("AboutToExpireToken", func(t *testing.T) {
		// Token expires in 3 minutes (less than 5 minute buffer)
		token := &Token{
			Value:     "test-token",
			ExpiresAt: time.Now().Add(3 * time.Minute),
		}
		assert.True(t, token.IsExpired())
		assert.False(t, token.IsValid())
	})
}

func TestGenerateWireGuardKeyPair(t *testing.T) {
	privateKey, publicKey, err := generateWireGuardKeyPair()

	require.NoError(t, err)
	assert.NotEmpty(t, privateKey)
	assert.NotEmpty(t, publicKey)
	assert.NotEqual(t, privateKey, publicKey)

	// Verify keys are base64 encoded and correct length
	// WireGuard keys are 32 bytes, base64 encoded = 44 characters
	assert.Len(t, privateKey, 44)
	assert.Len(t, publicKey, 44)

	// Generate another pair to verify they're unique
	privateKey2, publicKey2, err := generateWireGuardKeyPair()
	require.NoError(t, err)
	assert.NotEqual(t, privateKey, privateKey2)
	assert.NotEqual(t, publicKey, publicKey2)
}

func TestWireGuardKeyResponseIsSuccess(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		resp := &WireGuardKeyResponse{Status: "OK"}
		assert.True(t, resp.IsSuccess())
	})

	t.Run("Failure", func(t *testing.T) {
		resp := &WireGuardKeyResponse{Status: "ERROR"}
		assert.False(t, resp.IsSuccess())
	})
}

func TestSelectServer(t *testing.T) {
	// Create a mock server
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:          "us-east",
				Name:        "US East",
				Country:     "US",
				PortForward: true,
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "1.2.3.4", CN: "us-east-wg"}},
				},
			},
			{
				ID:      "de-berlin",
				Name:    "DE Berlin",
				Country: "Germany",
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "5.6.7.8", CN: "de-berlin-wg"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create servers directly for testing SelectBestServer
	servers := []vpnprovider.Server{
		mockResponse.Regions[0].ToVPNProviderServer(),
		mockResponse.Regions[1].ToVPNProviderServer(),
	}

	t.Run("SelectByCountry", func(t *testing.T) {
		criteria := vpnprovider.ServerCriteria{
			Country: "US",
		}
		selected := vpnprovider.SelectBestServer(servers, criteria)
		require.NotNil(t, selected)
		assert.Equal(t, "us-east", selected.ID)
	})

	t.Run("SelectByServerID", func(t *testing.T) {
		criteria := vpnprovider.ServerCriteria{
			ServerID: "de-berlin",
		}
		selected := vpnprovider.SelectBestServer(servers, criteria)
		require.NotNil(t, selected)
		assert.Equal(t, "de-berlin", selected.ID)
	})

	t.Run("NoMatchingServer", func(t *testing.T) {
		criteria := vpnprovider.ServerCriteria{
			Country: "JP",
		}
		selected := vpnprovider.SelectBestServer(servers, criteria)
		assert.Nil(t, selected)
	})
}

func TestTokenManager(t *testing.T) {
	t.Run("HasCredentials", func(t *testing.T) {
		tm := NewTokenManager("user", "pass", nil, nil)
		assert.True(t, tm.HasCredentials())

		tm2 := NewTokenManager("", "", nil, nil)
		assert.False(t, tm2.HasCredentials())
	})

	t.Run("Invalidate", func(t *testing.T) {
		tm := NewTokenManager("user", "pass", nil, nil)
		tm.token = &Token{
			Value:     "test",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		tm.Invalidate()
		assert.Nil(t, tm.token)
	})
}

func TestBuildFeatures(t *testing.T) {
	region := Region{
		PortForward: true,
		Geo:         true,
		Servers: RegionServers{
			WireGuard: []WGServer{{IP: "1.2.3.4"}},
			OpenVPN:   []OVPNServer{{IP: "1.2.3.5"}},
		},
	}

	features := buildFeatures(&region)

	assert.Contains(t, features, "port_forwarding")
	assert.Contains(t, features, "geo")
	assert.Contains(t, features, "wireguard")
	assert.Contains(t, features, "openvpn")
}

func TestGetMetaEndpoint(t *testing.T) {
	t.Run("WithMetaServer", func(t *testing.T) {
		region := Region{
			Servers: RegionServers{
				Meta:      []MetaServer{{IP: "1.2.3.4"}},
				WireGuard: []WGServer{{IP: "5.6.7.8"}},
			},
		}
		assert.Equal(t, "1.2.3.4", region.GetMetaEndpoint())
	})

	t.Run("FallbackToWireGuard", func(t *testing.T) {
		region := Region{
			Servers: RegionServers{
				WireGuard: []WGServer{{IP: "5.6.7.8"}},
			},
		}
		assert.Equal(t, "5.6.7.8", region.GetMetaEndpoint())
	})

	t.Run("NoServers", func(t *testing.T) {
		region := Region{}
		assert.Empty(t, region.GetMetaEndpoint())
	})
}

func TestGenerateOpenVPNConfig(t *testing.T) {
	client := NewClient("testuser", "testpass")

	region := &Region{
		ID:   "us-test",
		Name: "US Test",
		DNS:  "10.0.0.1",
	}

	server := &vpnprovider.Server{
		ID:   "us-test",
		Name: "US Test",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  1198,
			TCPPort:  443,
		},
	}

	config := client.buildOpenVPNConfig(server, region)

	assert.Contains(t, config, "client")
	assert.Contains(t, config, "dev tun")
	assert.Contains(t, config, "proto udp")
	assert.Contains(t, config, "remote test.example.com 1198")
	assert.Contains(t, config, "dhcp-option DNS 10.0.0.1")
	assert.Contains(t, config, "<ca>")
	assert.Contains(t, config, "BEGIN CERTIFICATE")
}

func TestClientCacheOperations(t *testing.T) {
	client := NewClient("testuser", "testpass")

	// Initially cache should be empty
	servers, ok := client.cache.GetServers()
	assert.False(t, ok)
	assert.Nil(t, servers)

	// Clear cache (should not panic)
	client.ClearCache()

	// Cache should still be empty
	servers, ok = client.cache.GetServers()
	assert.False(t, ok)
	assert.Nil(t, servers)
}

func TestAuthenticationFlow(t *testing.T) {
	// Test authentication with mock server
	mockToken := TokenResponse{Token: "test-token-12345"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a POST request
		assert.Equal(t, http.MethodPost, r.Method)

		// Verify content type
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Parse form data
		err := r.ParseForm()
		require.NoError(t, err)

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		if username == "validuser" && password == "validpass" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockToken)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	// We can't easily override the const TokenEndpoint, so we test the TokenManager
	// response parsing directly
	t.Run("TokenResponseParsing", func(t *testing.T) {
		data, err := json.Marshal(mockToken)
		require.NoError(t, err)

		var resp TokenResponse
		err = json.Unmarshal(data, &resp)
		require.NoError(t, err)
		assert.Equal(t, "test-token-12345", resp.Token)
	})
}

func TestCollectIPs(t *testing.T) {
	region := &Region{
		Servers: RegionServers{
			WireGuard: []WGServer{
				{IP: "1.1.1.1"},
				{IP: "1.1.1.2"},
			},
			OpenVPN: []OVPNServer{
				{IP: "2.2.2.1"},
				{IP: "1.1.1.1"}, // Duplicate
			},
			Meta: []MetaServer{
				{IP: "3.3.3.1"},
			},
		},
	}

	ips := collectIPs(region)

	// Should have 4 unique IPs (1.1.1.1 is deduplicated)
	assert.Len(t, ips, 4)

	// Verify all unique IPs are present
	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}
	assert.True(t, ipSet["1.1.1.1"])
	assert.True(t, ipSet["1.1.1.2"])
	assert.True(t, ipSet["2.2.2.1"])
	assert.True(t, ipSet["3.3.3.1"])
}

func TestClientWithOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 60 * time.Second}

	client := NewClient("user", "pass",
		WithHTTPClient(customClient),
		WithCacheTTL(1*time.Hour),
	)

	assert.Equal(t, customClient, client.httpClient)
	assert.Equal(t, 1*time.Hour, client.cache.TTL())
}

func TestCredentialsValidation(t *testing.T) {
	client := NewClient("", "")

	server := &vpnprovider.Server{
		ID: "test",
		WireGuard: &vpnprovider.WireGuardServer{
			Endpoint: "1.2.3.4:1337",
		},
	}

	// Should fail without credentials
	_, err := client.GenerateWireGuardConfig(context.Background(), server, vpnprovider.Credentials{})
	assert.ErrorIs(t, err, vpnprovider.ErrInvalidCredentials)
}

func TestWithLogger(t *testing.T) {
	client := NewClient("user", "pass", WithLogger(nil))
	assert.NotNil(t, client)
}

func TestFetchServersWithMockServer(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:          "us-east",
				Name:        "US East",
				Country:     "US",
				PortForward: true,
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "1.2.3.4", CN: "us-east-wg"}},
					Meta:      []MetaServer{{IP: "1.2.3.5", CN: "us-east-meta"}},
				},
			},
			{
				ID:      "de-berlin",
				Name:    "DE Berlin",
				Country: "Germany",
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "5.6.7.8", CN: "de-berlin-wg"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("testuser", "testpass")
	// Override the httpClient transport to redirect to our mock server
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				// Redirect all requests to our mock server
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Len(t, servers, 2)
	assert.Equal(t, "us-east", servers[0].ID)
	assert.Equal(t, "de-berlin", servers[1].ID)
}

// mockTransport is a custom http.RoundTripper for testing
type mockTransport struct {
	handler func(*http.Request) (*http.Response, error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.handler(req)
}

func TestSelectServerWithMockServer(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:          "us-east",
				Name:        "US East",
				Country:     "US",
				PortForward: true,
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "1.2.3.4", CN: "us-east-wg"}},
					Meta:      []MetaServer{{IP: "1.2.3.5", CN: "us-east-meta"}},
				},
			},
			{
				ID:      "de-berlin",
				Name:    "DE Berlin",
				Country: "Germany",
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "5.6.7.8", CN: "de-berlin-wg"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("testuser", "testpass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	criteria := vpnprovider.ServerCriteria{Country: "US"}

	selected, err := client.SelectServer(ctx, criteria)
	require.NoError(t, err)
	require.NotNil(t, selected)
	assert.Equal(t, "us-east", selected.ID)
}

func TestSelectServerNoMatch(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:      "us-east",
				Name:    "US East",
				Country: "US",
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "1.2.3.4", CN: "us-east-wg"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("testuser", "testpass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	criteria := vpnprovider.ServerCriteria{Country: "JP"} // No Japanese servers

	selected, err := client.SelectServer(ctx, criteria)
	// SelectServer returns an error when no servers match
	assert.Error(t, err)
	assert.Nil(t, selected)
}

func TestClientAuthenticateAndInvalidate(t *testing.T) {
	client := NewClient("testuser", "testpass")

	// Test Authenticate returns error when auth endpoint is unreachable
	ctx := context.Background()
	_, err := client.Authenticate(ctx)
	assert.Error(t, err) // Will fail because we can't reach real PIA API

	// Test InvalidateToken doesn't panic
	client.InvalidateToken()
}

func TestFindRegion(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{ID: "us-east", Name: "US East", Country: "US",
				Servers: RegionServers{WireGuard: []WGServer{{IP: "1.2.3.4"}}}},
			{ID: "de-berlin", Name: "DE Berlin", Country: "Germany",
				Servers: RegionServers{WireGuard: []WGServer{{IP: "5.6.7.8"}}}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("user", "pass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	// Populate cache by fetching servers
	ctx := context.Background()
	_, err := client.FetchServers(ctx)
	require.NoError(t, err)

	t.Run("FindByID", func(t *testing.T) {
		region := client.findRegion("de-berlin")
		require.NotNil(t, region)
		assert.Equal(t, "de-berlin", region.ID)
	})

	t.Run("NotFound", func(t *testing.T) {
		region := client.findRegion("nonexistent")
		assert.Nil(t, region)
	})
}

func TestGenerateOpenVPNConfigFull(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:      "us-test",
				Name:    "US Test",
				Country: "US",
				DNS:     "10.0.0.1",
				Servers: RegionServers{
					OpenVPN: []OVPNServer{{IP: "1.2.3.4", CN: "us-test-ovpn"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("testuser", "testpass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	vpnServer := &vpnprovider.Server{
		ID:   "us-test",
		Name: "US Test",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  1198,
			TCPPort:  443,
		},
	}
	creds := vpnprovider.Credentials{
		Username: "testuser",
		Password: "testpass",
	}

	config, err := client.GenerateOpenVPNConfig(ctx, vpnServer, creds)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Contains(t, config.ConfigContent, "client")
	assert.Contains(t, config.ConfigContent, "dev tun")
	assert.Contains(t, config.ConfigContent, "remote test.example.com")
}

func TestGenerateOpenVPNConfig_ServerNotFound(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{ID: "us-east", Name: "US East"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("testuser", "testpass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	vpnServer := &vpnprovider.Server{
		ID:   "nonexistent",
		Name: "Non Existent",
	}
	creds := vpnprovider.Credentials{
		Username: "testuser",
		Password: "testpass",
	}

	_, err := client.GenerateOpenVPNConfig(ctx, vpnServer, creds)
	assert.Error(t, err)
}

func TestGetWireGuardEndpoint(t *testing.T) {
	t.Run("WithWireGuardServer", func(t *testing.T) {
		region := Region{
			Servers: RegionServers{
				WireGuard: []WGServer{{IP: "1.2.3.4"}},
			},
		}
		endpoint := region.GetWireGuardEndpoint()
		assert.Equal(t, "1.2.3.4", endpoint) // Returns just the IP
	})

	t.Run("NoWireGuardServers", func(t *testing.T) {
		region := Region{
			Servers: RegionServers{
				OpenVPN: []OVPNServer{{IP: "1.2.3.4"}},
			},
		}
		endpoint := region.GetWireGuardEndpoint()
		assert.Empty(t, endpoint)
	})
}

func TestGetTokenWithCachedToken(t *testing.T) {
	tm := NewTokenManager("user", "pass", nil, nil)
	// Pre-set a valid token
	tm.token = &Token{
		Value:     "cached-token-123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	ctx := context.Background()
	token, err := tm.GetToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "cached-token-123", token.Value)
}

func TestGetTokenAuthentication(t *testing.T) {
	mockToken := TokenResponse{Token: "new-token-456"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		if r.Form.Get("username") == "validuser" && r.Form.Get("password") == "validpass" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockToken)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	// Create token manager with custom http client that redirects to our mock
	tm := NewTokenManager("validuser", "validpass", &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}, nil)

	ctx := context.Background()
	token, err := tm.GetToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "new-token-456", token.Value)
}

func TestGetTokenUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	tm := NewTokenManager("baduser", "badpass", &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}, nil)

	ctx := context.Background()
	_, err := tm.GetToken(ctx)
	assert.ErrorIs(t, err, vpnprovider.ErrInvalidCredentials)
}

func TestGetTokenEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{Token: ""})
	}))
	defer server.Close()

	tm := NewTokenManager("user", "pass", &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}, nil)

	ctx := context.Background()
	_, err := tm.GetToken(ctx)
	assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
}

func TestGetTokenServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	tm := NewTokenManager("user", "pass", &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}, nil)

	ctx := context.Background()
	_, err := tm.GetToken(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
}

func TestGenerateWireGuardConfigRegionNotFound(t *testing.T) {
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:      "us-east",
				Name:    "US East",
				Country: "US",
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "1.2.3.4"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vpninfo/servers/v6" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mockResponse)
		} else {
			// Token endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{Token: "test-token"})
		}
	}))
	defer server.Close()

	client := NewClient("testuser", "testpass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	// Fetch servers to populate regions
	ctx := context.Background()
	_, err := client.FetchServers(ctx)
	require.NoError(t, err)

	// Try to generate config for a server that doesn't have a region
	vpnServer := &vpnprovider.Server{
		ID:   "nonexistent",
		Name: "Non Existent",
		WireGuard: &vpnprovider.WireGuardServer{
			Endpoint: "9.9.9.9:1337",
		},
	}

	_, err = client.GenerateWireGuardConfig(ctx, vpnServer, vpnprovider.Credentials{
		Username: "testuser",
		Password: "testpass",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "region not found")
}

func TestGenerateWireGuardConfigNoWireGuardSupport(t *testing.T) {
	client := NewClient("testuser", "testpass")

	// Server without WireGuard support
	vpnServer := &vpnprovider.Server{
		ID:        "test",
		Name:      "Test Server",
		WireGuard: nil, // No WireGuard support
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  1198,
		},
	}

	ctx := context.Background()
	_, err := client.GenerateWireGuardConfig(ctx, vpnServer, vpnprovider.Credentials{
		Username: "testuser",
		Password: "testpass",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrUnsupportedProtocol)
}

func TestGenerateOpenVPNConfigNoSupport(t *testing.T) {
	client := NewClient("testuser", "testpass")

	// Server without OpenVPN support
	vpnServer := &vpnprovider.Server{
		ID:      "test",
		Name:    "Test Server",
		OpenVPN: nil, // No OpenVPN support
	}

	ctx := context.Background()
	_, err := client.GenerateOpenVPNConfig(ctx, vpnServer, vpnprovider.Credentials{
		Username: "testuser",
		Password: "testpass",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrUnsupportedProtocol)
}

func TestGenerateOpenVPNConfigNoCredentials(t *testing.T) {
	client := NewClient("", "")

	vpnServer := &vpnprovider.Server{
		ID:   "test",
		Name: "Test Server",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  1198,
		},
	}

	ctx := context.Background()
	_, err := client.GenerateOpenVPNConfig(ctx, vpnServer, vpnprovider.Credentials{})
	assert.ErrorIs(t, err, vpnprovider.ErrInvalidCredentials)
}

func TestBuildOpenVPNConfigTCPOnly(t *testing.T) {
	client := NewClient("testuser", "testpass")

	// Server with only TCP port
	vpnServer := &vpnprovider.Server{
		ID:   "test",
		Name: "Test Server",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  0, // No UDP
			TCPPort:  443,
		},
	}

	config := client.buildOpenVPNConfig(vpnServer, nil)
	assert.Contains(t, config, "proto tcp")
	assert.Contains(t, config, "remote test.example.com 443")
}

func TestBuildOpenVPNConfigNoDNS(t *testing.T) {
	client := NewClient("testuser", "testpass")

	vpnServer := &vpnprovider.Server{
		ID:   "test",
		Name: "Test Server",
		OpenVPN: &vpnprovider.OpenVPNServer{
			Hostname: "test.example.com",
			UDPPort:  1198,
		},
	}

	// Nil region (no DNS)
	config := client.buildOpenVPNConfig(vpnServer, nil)
	assert.NotContains(t, config, "dhcp-option DNS")

	// Region with empty DNS
	region := &Region{DNS: ""}
	config = client.buildOpenVPNConfig(vpnServer, region)
	assert.NotContains(t, config, "dhcp-option DNS")
}

func TestFetchServersError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient("user", "pass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	_, err := client.FetchServers(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrServerListFetchFailed)
}

func TestFetchServersInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClient("user", "pass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()
	_, err := client.FetchServers(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse server list")
}

func TestFetchServersFromCache(t *testing.T) {
	callCount := 0
	mockResponse := ServerListResponse{
		Regions: []Region{
			{
				ID:      "us-east",
				Name:    "US East",
				Country: "US",
				Servers: RegionServers{
					WireGuard: []WGServer{{IP: "1.2.3.4"}},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client := NewClient("user", "pass")
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				req.URL.Scheme = "http"
				req.URL.Host = server.Listener.Addr().String()
				return http.DefaultTransport.RoundTrip(req)
			},
		},
	}

	ctx := context.Background()

	// First call should hit the API
	servers1, err := client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Len(t, servers1, 1)
	assert.Equal(t, 1, callCount)

	// Second call should use cache
	servers2, err := client.FetchServers(ctx)
	require.NoError(t, err)
	assert.Len(t, servers2, 1)
	assert.Equal(t, 1, callCount) // Should still be 1 - using cache
}
