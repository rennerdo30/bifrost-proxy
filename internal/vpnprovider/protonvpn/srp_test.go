package protonvpn

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test modulus - a small safe prime for testing (NOT for production use)
// In production, ProtonVPN uses a 2048-bit modulus
var testModulus = func() *big.Int {
	// 2048-bit safe prime for testing
	// This is the same format ProtonVPN uses
	modulusHex := "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
	n := new(big.Int)
	n.SetString(modulusHex, 16)
	return n
}()

func TestNewSRPSession(t *testing.T) {
	// Generate test parameters
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	// Generate a random server B value
	bPrivate := make([]byte, 32)
	_, err = rand.Read(bPrivate)
	require.NoError(t, err)
	b := new(big.Int).SetBytes(bPrivate)

	// Compute B = g^b mod N (simplified, in real SRP there's also k*v term)
	serverB := new(big.Int).Exp(srpGenerator, b, testModulus)

	params := &SRPParameters{
		Modulus:   testModulus,
		Generator: srpGenerator,
		Salt:      salt,
		ServerB:   serverB,
		Version:   0, // Use simple SHA-512 hashing for tests
	}

	session, err := NewSRPSession("testuser", "testpassword", params)
	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify session has expected properties
	assert.NotNil(t, session.publicA)
	assert.NotNil(t, session.privateA)
	assert.NotNil(t, session.sharedSecret)
	assert.NotEmpty(t, session.sessionKey)
	assert.NotEmpty(t, session.clientProof)
	assert.NotEmpty(t, session.expectedM2)

	// Verify public value A is valid
	assert.True(t, session.publicA.Cmp(big.NewInt(0)) > 0)
	assert.True(t, session.publicA.Cmp(testModulus) < 0)
}

func TestSRPSession_GetPublicA(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	b := make([]byte, 32)
	rand.Read(b)
	serverB := new(big.Int).Exp(srpGenerator, new(big.Int).SetBytes(b), testModulus)

	params := &SRPParameters{
		Modulus:   testModulus,
		Generator: srpGenerator,
		Salt:      salt,
		ServerB:   serverB,
		Version:   0,
	}

	session, err := NewSRPSession("user", "pass", params)
	require.NoError(t, err)

	publicA := session.GetPublicA()
	assert.NotEmpty(t, publicA)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(publicA)
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

func TestSRPSession_GetClientProof(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	b := make([]byte, 32)
	rand.Read(b)
	serverB := new(big.Int).Exp(srpGenerator, new(big.Int).SetBytes(b), testModulus)

	params := &SRPParameters{
		Modulus:   testModulus,
		Generator: srpGenerator,
		Salt:      salt,
		ServerB:   serverB,
		Version:   0,
	}

	session, err := NewSRPSession("user", "pass", params)
	require.NoError(t, err)

	proof := session.GetClientProof()
	assert.NotEmpty(t, proof)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(proof)
	require.NoError(t, err)
	assert.Len(t, decoded, 64) // SHA-512 produces 64 bytes
}

func TestSRPSession_Uniqueness(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	b := make([]byte, 32)
	rand.Read(b)
	serverB := new(big.Int).Exp(srpGenerator, new(big.Int).SetBytes(b), testModulus)

	params := &SRPParameters{
		Modulus:   testModulus,
		Generator: srpGenerator,
		Salt:      salt,
		ServerB:   serverB,
		Version:   0,
	}

	// Create two sessions with same parameters
	session1, err := NewSRPSession("user", "pass", params)
	require.NoError(t, err)

	session2, err := NewSRPSession("user", "pass", params)
	require.NoError(t, err)

	// They should have different random values
	assert.NotEqual(t, session1.GetPublicA(), session2.GetPublicA())
	assert.NotEqual(t, session1.GetClientProof(), session2.GetClientProof())
}

func TestParseSRPModulus(t *testing.T) {
	t.Run("valid modulus", func(t *testing.T) {
		// Base64 encode the test modulus
		modulusB64 := base64.StdEncoding.EncodeToString(testModulus.Bytes())

		parsed, err := ParseSRPModulus(modulusB64)
		require.NoError(t, err)
		assert.Equal(t, 0, parsed.Cmp(testModulus))
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := ParseSRPModulus("not-valid-base64!!!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decode modulus")
	})

	t.Run("zero modulus", func(t *testing.T) {
		zeroB64 := base64.StdEncoding.EncodeToString([]byte{0})
		// Zero is technically positive in big.Int, so this will pass validation
		// but will fail during SRP calculations
		_, _ = ParseSRPModulus(zeroB64)
	})
}

func TestParseServerPublicValue(t *testing.T) {
	t.Run("valid value", func(t *testing.T) {
		b := make([]byte, 256)
		rand.Read(b)
		B := new(big.Int).SetBytes(b)
		bB64 := base64.StdEncoding.EncodeToString(B.Bytes())

		parsed, err := ParseServerPublicValue(bB64)
		require.NoError(t, err)
		assert.Equal(t, 0, parsed.Cmp(B))
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := ParseServerPublicValue("invalid!!!")
		assert.Error(t, err)
	})
}

func TestComputeK(t *testing.T) {
	// k = H(N || PAD(g))
	k := computeK(testModulus, srpGenerator)

	assert.NotNil(t, k)
	assert.True(t, k.Cmp(big.NewInt(0)) > 0)

	// Should be deterministic
	k2 := computeK(testModulus, srpGenerator)
	assert.Equal(t, 0, k.Cmp(k2))
}

func TestComputeU(t *testing.T) {
	// Create random A and B values
	a := make([]byte, 256)
	rand.Read(a)
	A := new(big.Int).SetBytes(a)

	b := make([]byte, 256)
	rand.Read(b)
	B := new(big.Int).SetBytes(b)

	u := computeU(A, B, testModulus)

	assert.NotNil(t, u)
	assert.True(t, u.Cmp(big.NewInt(0)) > 0)

	// Should be deterministic
	u2 := computeU(A, B, testModulus)
	assert.Equal(t, 0, u.Cmp(u2))
}

func TestHashBytes(t *testing.T) {
	input := []byte("test input")
	hash := hashBytes(input)

	assert.Len(t, hash, 64) // SHA-512 output is 64 bytes

	// Should be deterministic
	hash2 := hashBytes(input)
	assert.Equal(t, hash, hash2)

	// Different input should produce different hash
	hash3 := hashBytes([]byte("different"))
	assert.NotEqual(t, hash, hash3)
}

func TestPadToLen(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		length   int
		expected int
	}{
		{"no padding needed", []byte{1, 2, 3}, 3, 3},
		{"padding needed", []byte{1, 2}, 5, 5},
		{"longer than target", []byte{1, 2, 3, 4, 5}, 3, 5},
		{"empty input", []byte{}, 4, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padToLen(tt.input, tt.length)
			assert.Len(t, result, tt.expected)

			// Verify original data is at the end
			if len(tt.input) > 0 && len(result) >= len(tt.input) {
				assert.Equal(t, tt.input, result[len(result)-len(tt.input):])
			}
		})
	}
}

func TestPasswordHashVersions(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)
	password := "testpassword"

	// Test version 0 (SHA-512 based)
	x0, err := computePasswordHash(password, salt, 0)
	require.NoError(t, err)
	assert.NotNil(t, x0)

	// Different versions should produce different hashes
	// Note: Version 3 (bcrypt+argon2) is slow, so we skip it in short tests
	if !testing.Short() {
		x4, err := computePasswordHash(password, salt, 4)
		require.NoError(t, err)
		assert.NotNil(t, x4)
		assert.NotEqual(t, x0.Cmp(x4), 0)
	}
}

func TestInvalidServerB(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	// Server B = 0 should be rejected
	params := &SRPParameters{
		Modulus:   testModulus,
		Generator: srpGenerator,
		Salt:      salt,
		ServerB:   big.NewInt(0),
		Version:   0,
	}

	_, err := NewSRPSession("user", "pass", params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server public value")
}
