package protonvpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateWireGuardKeyPair(t *testing.T) {
	keyPair, err := GenerateWireGuardKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPair)

	// Verify keys are base64 encoded
	privateKeyBytes, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)
	require.NoError(t, err)
	assert.Len(t, privateKeyBytes, 32, "private key should be 32 bytes")

	publicKeyBytes, err := base64.StdEncoding.DecodeString(keyPair.PublicKey)
	require.NoError(t, err)
	assert.Len(t, publicKeyBytes, 32, "public key should be 32 bytes")

	// Verify keys are different
	assert.NotEqual(t, keyPair.PrivateKey, keyPair.PublicKey)

	// Verify private key clamping (WireGuard spec)
	assert.Equal(t, byte(0), privateKeyBytes[0]&7, "first 3 bits should be 0")
	assert.Equal(t, byte(0), privateKeyBytes[31]&128, "MSB of last byte should be 0")
	assert.Equal(t, byte(64), privateKeyBytes[31]&64, "second-highest bit of last byte should be 1")
}

func TestGenerateWireGuardKeyPair_Uniqueness(t *testing.T) {
	// Generate multiple key pairs and verify they're unique
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		keyPair, err := GenerateWireGuardKeyPair()
		require.NoError(t, err)

		assert.False(t, seen[keyPair.PrivateKey], "duplicate private key generated")
		assert.False(t, seen[keyPair.PublicKey], "duplicate public key generated")

		seen[keyPair.PrivateKey] = true
		seen[keyPair.PublicKey] = true
	}
}

func TestRegisterWireGuardKey_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, CertificateEndpoint, r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req CertificateRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.NotEmpty(t, req.ClientPublicKey)
		assert.Equal(t, "persistent", req.ClientPublicKeyMode)

		response := VPNCertificateResponse{
			Code: 1000,
			VPN: &VPNCertificateInfo{
				ExpirationTime: 1800000000,
				RefreshTime:    1700000000,
				ClientIP:       "10.2.0.100",
				ClientKeyFP:    "abc123",
				DeviceName:     "Bifrost-Proxy",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
	)
	// Set a valid session
	client.session = &Session{
		UID:         "test-uid",
		AccessToken: "test-token",
		TokenType:   "Bearer",
	}
	client.authMode = AuthModeAPI

	keyPair, err := GenerateWireGuardKeyPair()
	require.NoError(t, err)

	certInfo, err := client.RegisterWireGuardKey(context.Background(), keyPair.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, certInfo)

	assert.Equal(t, "10.2.0.100", certInfo.ClientIP)
	assert.Equal(t, "abc123", certInfo.ClientKeyFP)
}

func TestRegisterWireGuardKey_NoSession(t *testing.T) {
	client := NewClient()

	keyPair, err := GenerateWireGuardKeyPair()
	require.NoError(t, err)

	_, err = client.RegisterWireGuardKey(context.Background(), keyPair.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session required")
}

func TestRegisterWireGuardKey_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := VPNCertificateResponse{
			Code: 2000,
			Error: &VPNCertificateErrorInfo{
				Code:    2000,
				Message: "Key already registered",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
	)
	client.session = &Session{
		UID:         "test-uid",
		AccessToken: "test-token",
		TokenType:   "Bearer",
	}
	client.authMode = AuthModeAPI

	keyPair, err := GenerateWireGuardKeyPair()
	require.NoError(t, err)

	_, err = client.RegisterWireGuardKey(context.Background(), keyPair.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Key already registered")
}

func TestContainsSlash(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"10.2.0.100/32", true},
		{"10.2.0.100", false},
		{"", false},
		{"/", true},
		{"192.168.1.0/24", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, containsSlash(tt.input))
		})
	}
}
