package protonvpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
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

func TestLogin_SRP(t *testing.T) {
	// Create a test modulus (2048-bit)
	modulusHex := "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
	modulus := new(big.Int)
	modulus.SetString(modulusHex, 16)

	// Generate server's ephemeral key
	bPrivate := make([]byte, 32)
	rand.Read(bPrivate)
	b := new(big.Int).SetBytes(bPrivate)
	serverB := new(big.Int).Exp(srpGenerator, b, modulus)

	// Generate salt
	salt := make([]byte, 16)
	rand.Read(salt)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/info":
			// Return SRP parameters
			resp := AuthInfoResponse{
				Code:            1000,
				Modulus:         base64.StdEncoding.EncodeToString(modulus.Bytes()),
				ServerEphemeral: base64.StdEncoding.EncodeToString(serverB.Bytes()),
				Salt:            base64.StdEncoding.EncodeToString(salt),
				SRPSession:      "test-session-123",
				Version:         0,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case "/auth":
			// Verify auth request and return session
			var authReq AuthRequest
			if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Verify required fields
			if authReq.Username == "" || authReq.ClientEphemeral == "" || authReq.ClientProof == "" {
				http.Error(w, "missing fields", http.StatusBadRequest)
				return
			}

			// Return success (in real SRP, we'd verify the proof)
			resp := AuthResponse{
				Code:         1000,
				UID:          "user-123",
				AccessToken:  "access-token-xyz",
				RefreshToken: "refresh-token-abc",
				TokenType:    "Bearer",
				Scope:        "full",
				// In a real implementation, we'd compute the actual server proof
				ServerProof: base64.StdEncoding.EncodeToString(make([]byte, 64)),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	// Note: This test verifies the flow works, but since we don't compute
	// the real server proof, the verification will fail
	err := client.Login(context.Background(), "testuser", "testpassword")

	// We expect an error because the mock server doesn't compute the real proof
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server proof verification failed")
}

func TestLogin_AuthInfoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/info" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	err := client.Login(context.Background(), "user", "pass")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get auth info")
}

func TestLogin_InvalidModulus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/info" {
			resp := AuthInfoResponse{
				Code:            1000,
				Modulus:         "not-valid-base64!!!",
				ServerEphemeral: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
				Salt:            base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
				SRPSession:      "test",
				Version:         0,
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	err := client.Login(context.Background(), "user", "pass")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse modulus")
}

func TestWithLogger(t *testing.T) {
	customLogger := slog.Default().With("component", "test")

	client := NewClient(WithLogger(customLogger))
	assert.NotNil(t, client)
	assert.Equal(t, customLogger, client.logger)
}

func TestWithSessionStore(t *testing.T) {
	customStore := NewMemorySessionStore()

	client := NewClient(WithSessionStore(customStore))
	assert.NotNil(t, client)
	assert.Equal(t, customStore, client.sessionStore)
}

func TestLogout(t *testing.T) {
	store := NewMemorySessionStore()
	client := NewClient(WithSessionStore(store))

	// Set a session
	client.session = NewSession(&SessionResponse{
		UID:          "uid",
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
	})
	store.Save(client.session)

	// Verify session exists
	loaded, err := store.Load()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Logout
	err = client.Logout(context.Background())
	require.NoError(t, err)

	// Verify session is cleared
	assert.Nil(t, client.session)
	loaded, err = store.Load()
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLogout_NoSessionStore(t *testing.T) {
	client := &Client{
		session: NewSession(&SessionResponse{
			UID:          "uid",
			AccessToken:  "access",
			RefreshToken: "refresh",
			TokenType:    "Bearer",
		}),
		sessionStore: nil,
	}

	err := client.Logout(context.Background())
	require.NoError(t, err)
	assert.Nil(t, client.session)
}

func TestGetServerCount(t *testing.T) {
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID: "s1", Name: "US#1", Domain: "us1.protonvpn.net",
				ExitCountry: "US", Tier: 0, Status: 1,
				Servers: []Server{{ID: "ps1", EntryIP: "1.1.1.1", Status: 1}},
			},
			{
				ID: "s2", Name: "US#2", Domain: "us2.protonvpn.net",
				ExitCountry: "US", Tier: 0, Status: 1,
				Servers: []Server{{ID: "ps2", EntryIP: "2.2.2.2", Status: 1}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	// Before fetching, count should be 0
	assert.Equal(t, 0, client.GetServerCount())

	// Fetch servers
	_, err := client.FetchServers(context.Background())
	require.NoError(t, err)

	// After fetching, count should be 2
	assert.Equal(t, 2, client.GetServerCount())
}

func TestGetAvailableCountries(t *testing.T) {
	mockServers := LogicalServerResponse{
		Code: 1000,
		LogicalServers: []LogicalServer{
			{
				ID: "us1", Name: "US#1", Domain: "us1.protonvpn.net",
				EntryCountry: "US", ExitCountry: "US", Tier: 0, Status: 1,
				Servers: []Server{{ID: "s1", EntryIP: "1.1.1.1", Status: 1}},
			},
			{
				ID: "us2", Name: "US#2", Domain: "us2.protonvpn.net",
				EntryCountry: "US", ExitCountry: "US", Tier: 0, Status: 1,
				Servers: []Server{{ID: "s2", EntryIP: "2.2.2.2", Status: 1}},
			},
			{
				ID: "de1", Name: "DE#1", Domain: "de1.protonvpn.net",
				EntryCountry: "DE", ExitCountry: "DE", Tier: 0, Status: 1,
				Servers: []Server{{ID: "s3", EntryIP: "3.3.3.3", Status: 1}},
			},
			{
				ID: "jp1", Name: "JP#1", Domain: "jp1.protonvpn.net",
				EntryCountry: "JP", ExitCountry: "JP", Tier: 0, Status: 1,
				Servers: []Server{{ID: "s4", EntryIP: "4.4.4.4", Status: 1}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockServers)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	countries, err := client.GetAvailableCountries(context.Background())
	require.NoError(t, err)
	assert.Len(t, countries, 3) // US, DE, JP (US deduplicated)

	// Verify countries are unique
	codes := make(map[string]bool)
	for _, c := range countries {
		codes[c.Code] = true
	}
	assert.True(t, codes["US"])
	assert.True(t, codes["DE"])
	assert.True(t, codes["JP"])
}

func TestGetAvailableCountries_FetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	_, err := client.GetAvailableCountries(context.Background())
	assert.Error(t, err)
}

func TestGenerateWireGuardConfig_NotSupported(t *testing.T) {
	// Client without API authentication
	client := NewClient()

	testServer := &vpnprovider.Server{
		ID:   "test",
		Name: "Test Server",
		WireGuard: &vpnprovider.WireGuardServer{
			PublicKey: "testkey",
			Endpoint:  "1.2.3.4:51820",
		},
	}

	// Should fail because SupportsWireGuard returns false without API auth
	_, err := client.GenerateWireGuardConfig(context.Background(), testServer, vpnprovider.Credentials{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrUnsupportedProtocol)
}

func TestSRPSession_GetSessionKey(t *testing.T) {
	// Create a mock SRP session with a known session key
	session := &SRPSession{
		sessionKey: []byte("test-session-key-12345"),
	}

	key := session.GetSessionKey()
	assert.Equal(t, []byte("test-session-key-12345"), key)
}

func TestSRPSession_GetSessionKey_Empty(t *testing.T) {
	// Empty session key
	session := &SRPSession{}

	key := session.GetSessionKey()
	assert.Nil(t, key)
}
