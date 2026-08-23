package protonvpn

import (
	"encoding/base64"
	mathrand "math/rand"
	"strings"
	"testing"

	srp "github.com/ProtonMail/go-srp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// Realistic SRP fixtures.
//
// testSignedModulus is a genuine PGP clear-signed SRP modulus as served by
// Proton's /auth/info endpoint, taken from Proton's own go-srp test vectors. Its
// signature verifies against the modulus-signing key embedded in go-srp, so it
// exercises the real verification path rather than a stand-in. The matching
// server ephemeral, salt, username and password below come from the same vector
// set, and testKATClientProof / testKATServerProof are the proofs Proton's
// implementation produces for them (with the deterministic random source set
// up in withDeterministicSRPRandom).
const (
	testSignedModulus = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----`

	// testPlainModulus is the same modulus without the PGP wrapper: what the
	// previous implementation (and the previous tests) incorrectly expected the
	// API to return. It must be rejected.
	testPlainModulus = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="

	testServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA=="
	testSalt            = "yKlc5/CvObfoiw=="
	testUsername        = "jakubqa"
	testPassword        = "abc123" //nolint:gosec // G101: test vector from Proton's published SRP test data, not a real credential
	testAuthVersion     = 4

	testKATClientProof = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ=="
	testKATServerProof = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g=="
)

// testAuthInfo returns an /auth/info response shaped like the real API's.
func testAuthInfo() *AuthInfoResponse {
	return &AuthInfoResponse{
		Code:            apiCodeSuccess,
		Modulus:         testSignedModulus,
		ServerEphemeral: testServerEphemeral,
		Salt:            testSalt,
		SRPSession:      "b7f1d0a9c3e24f6b8a0d5e1f2c3b4a59",
		Version:         testAuthVersion,
	}
}

func TestNewSRPSession(t *testing.T) {
	session, err := NewSRPSession(testUsername, testPassword, testAuthInfo())
	require.NoError(t, err)
	require.NotNil(t, session)

	ephemeral, err := base64.StdEncoding.DecodeString(session.GetClientEphemeral())
	require.NoError(t, err)
	assert.Len(t, ephemeral, SRPBitLength/8, "client ephemeral must be a full-width group element")

	proof, err := base64.StdEncoding.DecodeString(session.GetClientProof())
	require.NoError(t, err)
	assert.Len(t, proof, SRPProofSize, "Proton proofs are 2048-bit expanded hashes, not raw SHA-512")
}

// TestSRPKnownAnswerVectors pins the whole derivation chain — clear-signed
// modulus parsing, little-endian encoding, bcrypt password hashing and the
// expanded-hash proofs — against Proton's published test vectors. Any drift in
// the hash scheme changes these values.
func TestSRPKnownAnswerVectors(t *testing.T) {
	restore := withDeterministicSRPRandom(t)
	defer restore()

	session, err := NewSRPSession(testUsername, testPassword, testAuthInfo())
	require.NoError(t, err)

	assert.Equal(t, testKATClientProof, session.GetClientProof())

	expectedServerProof, err := base64.StdEncoding.DecodeString(testKATServerProof)
	require.NoError(t, err)
	assert.True(t, session.VerifyServerProof(expectedServerProof),
		"expected server proof must match Proton's published vector")
}

// TestNewSRPSessionRejectsUntrustedModulus covers the SRP-downgrade gap: a
// modulus that is not clear-signed by Proton's modulus key must be refused,
// including the plain-base64 form the previous implementation accepted.
func TestNewSRPSessionRejectsUntrustedModulus(t *testing.T) {
	tamperedSignature := strings.Replace(testSignedModulus,
		"wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa",
		"wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIb", 1)
	require.NotEqual(t, testSignedModulus, tamperedSignature)

	tamperedPayload := strings.Replace(testSignedModulus, "W2z5HBi8RvsfYzZTS7qBaUxx", "W2z5HBi8RvsfYzZTS7qBaUxy", 1)
	require.NotEqual(t, testSignedModulus, tamperedPayload)

	tests := []struct {
		name    string
		modulus string
	}{
		{name: "plain base64 modulus", modulus: testPlainModulus},
		{name: "tampered signature", modulus: tamperedSignature},
		{name: "tampered payload", modulus: tamperedPayload},
		{name: "trailing data after modulus", modulus: testSignedModulus + "\nextra"},
		{name: "empty", modulus: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := testAuthInfo()
			info.Modulus = tt.modulus

			session, err := NewSRPSession(testUsername, testPassword, info)
			require.Error(t, err)
			assert.Nil(t, session)
			assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
			assert.ErrorIs(t, err, ErrSRPModulusUntrusted)
		})
	}
}

func TestNewSRPSessionInvalidParameters(t *testing.T) {
	t.Run("nil auth info", func(t *testing.T) {
		_, err := NewSRPSession(testUsername, testPassword, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
	})

	t.Run("unsupported auth version", func(t *testing.T) {
		info := testAuthInfo()
		info.Version = 99

		_, err := NewSRPSession(testUsername, testPassword, info)
		require.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
		assert.NotErrorIs(t, err, ErrSRPModulusUntrusted)
	})

	t.Run("malformed salt", func(t *testing.T) {
		info := testAuthInfo()
		info.Salt = "not base64!!!"

		_, err := NewSRPSession(testUsername, testPassword, info)
		require.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
	})

	t.Run("malformed server ephemeral", func(t *testing.T) {
		info := testAuthInfo()
		info.ServerEphemeral = "not base64!!!"

		_, err := NewSRPSession(testUsername, testPassword, info)
		require.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
	})

	t.Run("server ephemeral out of bounds", func(t *testing.T) {
		info := testAuthInfo()
		info.ServerEphemeral = base64.StdEncoding.EncodeToString(make([]byte, SRPBitLength/8))

		_, err := NewSRPSession(testUsername, testPassword, info)
		require.Error(t, err)
		assert.ErrorIs(t, err, vpnprovider.ErrAuthenticationFailed)
	})
}

func TestSRPSessionUniqueness(t *testing.T) {
	first, err := NewSRPSession(testUsername, testPassword, testAuthInfo())
	require.NoError(t, err)

	second, err := NewSRPSession(testUsername, testPassword, testAuthInfo())
	require.NoError(t, err)

	assert.NotEqual(t, first.GetClientEphemeral(), second.GetClientEphemeral(),
		"each exchange must use a fresh client secret")
	assert.NotEqual(t, first.GetClientProof(), second.GetClientProof())
}

func TestVerifyServerProof(t *testing.T) {
	session, err := NewSRPSession(testUsername, testPassword, testAuthInfo())
	require.NoError(t, err)

	valid := session.expectedServerProof

	assert.True(t, session.VerifyServerProof(valid))
	assert.False(t, session.VerifyServerProof(nil), "empty proof must never verify")
	assert.False(t, session.VerifyServerProof(make([]byte, SRPProofSize)), "zero proof must never verify")
	assert.False(t, session.VerifyServerProof(valid[:len(valid)-1]), "truncated proof must never verify")

	flipped := append([]byte(nil), valid...)
	flipped[0] ^= 0xFF
	assert.False(t, session.VerifyServerProof(flipped))
}

// srpKATSeed is the seed Proton's published SRP test vectors were generated
// with; reproducing their proofs requires the same deterministic stream.
const srpKATSeed = 42

// withDeterministicSRPRandom replaces the SRP library's random source with a
// deterministic one so proofs can be compared against known-answer vectors, and
// returns a function restoring the crypto/rand default.
func withDeterministicSRPRandom(t *testing.T) func() {
	t.Helper()

	previous := srp.RandReader
	//nolint:gosec // G404: deterministic stream is the point; test-only, never used for real key material
	srp.RandReader = mathrand.New(mathrand.NewSource(srpKATSeed))

	return func() { srp.RandReader = previous }
}
