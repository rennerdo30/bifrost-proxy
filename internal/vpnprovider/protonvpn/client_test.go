package protonvpn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	srp "github.com/ProtonMail/go-srp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

const (
	// srpSaltSize is the salt size Proton uses for auth version 3/4 accounts.
	srpSaltSize = 10

	// testSRPSessionID is an opaque session identifier, as returned by
	// /auth/info and echoed back in the /auth request.
	testSRPSessionID = "6f1c9a24b8e34f5f9d2c7e0a1b3d5f78"
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
				ID:           "server-1",
				Name:         "US#42",
				Domain:       "us-42.protonvpn.net",
				EntryCountry: "US",
				ExitCountry:  "US",
				Tier:         2,
				Features:     FeatureP2P | FeatureStreaming,
				Load:         25,
				Status:       1,
				Location:     Location{Lat: 40.7128, Long: -74.0060},
				Servers: []Server{
					{
						ID:              "phys-1",
						EntryIP:         "192.168.1.1",
						ExitIP:          "192.168.1.2",
						Status:          1,
						X25519PublicKey: "abcd1234publickey",
					},
				},
			},
			{
				ID:           "server-2",
				Name:         "DE#10",
				Domain:       "de-10.protonvpn.net",
				EntryCountry: "DE",
				ExitCountry:  "DE",
				Tier:         0, // Free tier
				Features:     0,
				Load:         75,
				Status:       1,
				Servers: []Server{
					{
						ID:      "phys-2",
						EntryIP: "192.168.2.1",
						Status:  1,
					},
				},
			},
			{
				ID:           "server-3",
				Name:         "FR#5",
				Domain:       "fr-5.protonvpn.net",
				EntryCountry: "FR",
				ExitCountry:  "FR",
				Tier:         1,
				Status:       0, // Offline
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
					ID:      "test-1",
					Name:    "US#1",
					Domain:  "test.protonvpn.net",
					Tier:    0,
					Status:  1,
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

// testCACertPEM is a real (self-signed) CA certificate used purely for tests so
// that emitted OpenVPN config can be PEM-decoded and x509-parsed. It is not used
// to connect to any real server.
const testCACertPEM = `-----BEGIN CERTIFICATE-----
MIIBUzCB+6ADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMTB1Rlc3QgQ0Ew
HhcNMjYwNjI3MTIzNTI0WhcNMzYwNjI0MTIzNTI0WjASMRAwDgYDVQQDEwdUZXN0
IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUzndd0wJKtQO8Q/l4p+0Z/5K
mS+AtgAehJjRYxWTlgpPogetBPYUlIHG9rmhJFkzVWPZ/i8bTDTtCY6dFx/PtaNC
MEAwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKYF
7ig5A/ISFTZATfLnyWTTcfUUMAoGCCqGSM49BAMCA0cAMEQCIExEnID/hMLz2uhy
S3vk1kV7KCOQGo8kaZuf/FMb5i01AiBM7NIPGiss4EsEm98gobuEpZGmhAwwWKS4
PuVu76HIBw==
-----END CERTIFICATE-----`

// testTLSAuthKey is a randomly generated, well-formed 2048-bit OpenVPN static
// key used purely for tests. It is not any provider's key and is not used to
// connect anywhere.
const testTLSAuthKey = `-----BEGIN OpenVPN Static key V1-----
b471dc400a1e110cbf55a761d7a8927f
a3ea0ae7e958d84ef04e0ca554fa7a14
31cf280937e61b5e4e7ec53df634f622
8a5e421fc63606e79ff03b2d138ed3a9
be609e6e7ba610fb970faac041c49aff
dd6abd72d1c74e4573970a81898d1380
48825ded9a3c6c2b8d094b5778fde088
b296d22eb4ab8bd1e014f07f1d5950f9
195a6668313671b57addc3d5adbac360
3e9b078adf53a6556b756c6ebfe6d99b
dcfa55397bc13ee066a4e3b2bb5b292f
817eba92be7defe63f74a9ae0c6550ac
9bc3fe7f7d9c49c58f6a3ec67f0a3a7a
adbac2964e22b8e671399ecd244c1862
eb53499ee020d56274df454ea88a6754
3e337ffc0264f94fde0f9485f2d0a757
-----END OpenVPN Static key V1-----`

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

	// Generate config using client's manual credentials. The operator supplies
	// the CA certificate (and optional tls-auth key) via configuration.
	config, err := client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{
		CACert:     testCACertPEM,
		TLSAuthKey: testTLSAuthKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "openvpn_user+suffix", config.Username)
	assert.Equal(t, "openvpn_pass", config.Password)
	assert.Contains(t, config.ConfigContent, "client")
	assert.Contains(t, config.ConfigContent, "test.protonvpn.net")
	assert.Contains(t, config.ConfigContent, "BEGIN CERTIFICATE")
	assert.Contains(t, config.ConfigContent, "BEGIN OpenVPN Static key V1")
	// The generated config must NOT run host resolv-conf scripts.
	assert.NotContains(t, config.ConfigContent, "script-security")
	assert.NotContains(t, config.ConfigContent, "update-resolv-conf")

	// The embedded CA must be genuinely parseable: extract it and x509-parse it.
	start := strings.Index(config.ConfigContent, "-----BEGIN CERTIFICATE-----")
	end := strings.Index(config.ConfigContent, "-----END CERTIFICATE-----")
	require.GreaterOrEqual(t, start, 0)
	require.Greater(t, end, start)
	certPEM := config.ConfigContent[start : end+len("-----END CERTIFICATE-----")]
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "emitted CA must be valid PEM")
	_, parseErr := x509.ParseCertificate(block.Bytes)
	require.NoError(t, parseErr, "emitted CA must be a valid x509 certificate")

	// Generate config with explicit credentials.
	config, err = client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{
		Username: "explicit_user",
		Password: "explicit_pass",
		CACert:   testCACertPEM,
	})
	require.NoError(t, err)
	assert.Equal(t, "explicit_user", config.Username)
	assert.Equal(t, "explicit_pass", config.Password)
}

func TestGenerateOpenVPNConfigFailsClosedWithoutCA(t *testing.T) {
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

	client := NewClient(
		WithBaseURL(server.URL),
		WithManualCredentials("openvpn_user", "openvpn_pass", TierFree),
	)

	ctx := context.Background()
	servers, err := client.FetchServers(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, servers)

	// No CA supplied: must fail closed rather than emit a broken/insecure config.
	_, err = client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{})
	require.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrConfigGenerationFailed)

	// Malformed CA supplied: must also fail closed.
	_, err = client.GenerateOpenVPNConfig(ctx, &servers[0], vpnprovider.Credentials{
		CACert: "not a valid pem",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrConfigGenerationFailed)
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
		name          string
		statusCode    int
		expectedError error
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

// srpTestServer runs the server side of a Proton-style SRP exchange for a known
// password, using the same library the client uses. This makes the mock behave
// like the real API: it hands out a clear-signed modulus, a genuine challenge
// derived from a verifier, and verifies the client's proof before answering with
// a server proof the client can check.
type srpTestServer struct {
	t          *testing.T
	srpServer  *srp.Server
	salt       []byte
	authFailed bool // set when the client proof did not verify
}

// newSRPTestServer builds a server-side SRP state for password, mirroring what
// Proton stores for an account (a verifier plus salt, never the password).
func newSRPTestServer(t *testing.T, password string) *srpTestServer {
	t.Helper()

	salt := make([]byte, srpSaltSize)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	verifierAuth, err := srp.NewAuthForVerifier([]byte(password), testSignedModulus, salt)
	require.NoError(t, err)

	verifier, err := verifierAuth.GenerateVerifier(SRPBitLength)
	require.NoError(t, err)

	srpServer, err := srp.NewServerFromSigned(testSignedModulus, verifier, SRPBitLength)
	require.NoError(t, err)

	return &srpTestServer{t: t, srpServer: srpServer, salt: salt}
}

// handler returns an http.Handler implementing /auth/info and /auth.
func (s *srpTestServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/info":
			challenge, err := s.srpServer.GenerateChallenge()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(AuthInfoResponse{ //nolint:errcheck // test handler
				Code:            apiCodeSuccess,
				Modulus:         testSignedModulus,
				ServerEphemeral: base64.StdEncoding.EncodeToString(challenge),
				Salt:            base64.StdEncoding.EncodeToString(s.salt),
				SRPSession:      testSRPSessionID,
				Version:         testAuthVersion,
			})

		case "/auth":
			var authReq AuthRequest
			if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if authReq.SRPSession != testSRPSessionID {
				http.Error(w, "unknown SRP session", http.StatusBadRequest)
				return
			}

			clientEphemeral, err := base64.StdEncoding.DecodeString(authReq.ClientEphemeral)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			clientProof, err := base64.StdEncoding.DecodeString(authReq.ClientProof)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			serverProof, err := s.srpServer.VerifyProofs(clientEphemeral, clientProof)
			if err != nil {
				// This is what the real API does for a wrong password.
				s.authFailed = true
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(AuthResponse{ //nolint:errcheck // test handler
				Code:         apiCodeSuccess,
				UID:          "uid-abc123",
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				TokenType:    "Bearer",
				Scope:        "full self vpn",
				ServerProof:  base64.StdEncoding.EncodeToString(serverProof),
			})

		default:
			http.NotFound(w, r)
		}
	})
}

// TestLogin_SRPRoundTrip drives the full SRP exchange against a mock that
// performs the real server-side computation, so a correct client proof (and only
// a correct one) completes login.
func TestLogin_SRPRoundTrip(t *testing.T) {
	const password = "correct-horse-battery-staple"

	srpBackend := newSRPTestServer(t, password)
	server := httptest.NewServer(srpBackend.handler())
	defer server.Close()

	store := NewMemorySessionStore()
	client := NewClient(WithBaseURL(server.URL), WithSessionStore(store))

	require.NoError(t, client.Login(context.Background(), "proton-user", password))

	require.NotNil(t, client.session)
	assert.Equal(t, "uid-abc123", client.session.GetUID())
	assert.Equal(t, AuthModeAPI, client.authMode)
	assert.True(t, client.SupportsWireGuard(), "API auth mode unlocks WireGuard key registration")

	saved, err := store.Load()
	require.NoError(t, err)
	require.NotNil(t, saved)
	assert.Equal(t, "uid-abc123", saved.GetUID())
}

// TestLogin_SRPWrongPassword asserts a wrong password is rejected by the server
// side of the exchange rather than producing a session.
func TestLogin_SRPWrongPassword(t *testing.T) {
	srpBackend := newSRPTestServer(t, "the-real-password")
	server := httptest.NewServer(srpBackend.handler())
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	err := client.Login(context.Background(), "proton-user", "not-the-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
	assert.True(t, srpBackend.authFailed, "server must have rejected the client proof")
	assert.Nil(t, client.session)
}

// TestLogin_SRPForgedServerProof asserts the client verifies the server proof:
// an API that answers with a well-formed but wrong proof must not yield a
// session, since it does not know the password verifier.
func TestLogin_SRPForgedServerProof(t *testing.T) {
	const password = "correct-horse-battery-staple"

	srpBackend := newSRPTestServer(t, password)
	inner := srpBackend.handler()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth" {
			inner.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthResponse{ //nolint:errcheck // test handler
			Code:         apiCodeSuccess,
			UID:          "uid-forged",
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			TokenType:    "Bearer",
			ServerProof:  base64.StdEncoding.EncodeToString(make([]byte, SRPProofSize)),
		})
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	err := client.Login(context.Background(), "proton-user", password)
	require.Error(t, err)
	assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
	assert.Contains(t, err.Error(), "server proof verification failed")
	assert.Nil(t, client.session)
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

// TestLogin_UnsignedModulus is the regression test for the modulus-signature
// gap: the real API returns a PGP clear-signed modulus, and an API (or
// man-in-the-middle) that supplies a bare base64 group must be refused instead
// of downgrading the exchange to an attacker-chosen group.
func TestLogin_UnsignedModulus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/info" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthInfoResponse{ //nolint:errcheck // test handler
			Code:            apiCodeSuccess,
			Modulus:         testPlainModulus,
			ServerEphemeral: testServerEphemeral,
			Salt:            testSalt,
			SRPSession:      testSRPSessionID,
			Version:         testAuthVersion,
		})
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	err := client.Login(context.Background(), "user", "pass")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSRPModulusUntrusted)
	assert.Nil(t, client.session)
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

// The SRP shared session key is never exposed by SRPSession: nothing in the
// ProtonVPN flow needs it, and handing out key material invites misuse. The
// exchange is covered end-to-end by TestLogin_SRPRoundTrip and by the
// known-answer vectors in srp_test.go.
