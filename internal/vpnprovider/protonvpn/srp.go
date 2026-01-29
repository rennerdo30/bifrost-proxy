package protonvpn

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// SRP-6a implementation for ProtonVPN authentication.
// ProtonVPN uses a modified SRP protocol with specific parameters.

// SRPParameters holds the SRP parameters from the server.
type SRPParameters struct {
	Modulus   *big.Int // N - safe prime
	Generator *big.Int // g - generator
	Salt      []byte   // User's salt
	ServerB   *big.Int // Server's public value B
	Version   int      // SRP version (affects password hashing)
}

// SRPSession holds the SRP session state.
type SRPSession struct {
	params       *SRPParameters
	username     string
	privateA     *big.Int // Client's private value a
	publicA      *big.Int // Client's public value A
	sharedSecret *big.Int // Session key material S
	sessionKey   []byte   // Derived session key K
	clientProof  []byte   // Client proof M1
	expectedM2   []byte   // Expected server proof M2
}

// ProtonVPN SRP constants.
var (
	// SRP generator - ProtonVPN uses g=2
	srpGenerator = big.NewInt(2)

	// SRP multiplier k = H(N, g) - computed lazily per modulus
)

// NewSRPSession creates a new SRP session from server parameters.
func NewSRPSession(username, password string, params *SRPParameters) (*SRPSession, error) {
	session := &SRPSession{
		params:   params,
		username: username,
	}

	// Generate random private value a (256 bits)
	aBytes := make([]byte, 32)
	if _, err := rand.Read(aBytes); err != nil {
		return nil, fmt.Errorf("generate random: %w", err)
	}
	session.privateA = new(big.Int).SetBytes(aBytes)

	// Compute A = g^a mod N
	session.publicA = new(big.Int).Exp(params.Generator, session.privateA, params.Modulus)

	// Verify A != 0 (mod N)
	if new(big.Int).Mod(session.publicA, params.Modulus).Sign() == 0 {
		return nil, fmt.Errorf("invalid client public value")
	}

	// Derive password verifier x
	x, err := computePasswordHash(password, params.Salt, params.Version)
	if err != nil {
		return nil, fmt.Errorf("compute password hash: %w", err)
	}

	// Compute shared secret S
	if err := session.computeSharedSecret(x, params); err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	// Derive session key K
	session.sessionKey = hashBytes(session.sharedSecret.Bytes())

	// Compute client proof M1
	session.clientProof = session.computeClientProof()

	// Compute expected server proof M2
	session.expectedM2 = session.computeExpectedM2()

	return session, nil
}

// computePasswordHash derives x from password using the appropriate hash function.
func computePasswordHash(password string, salt []byte, version int) (*big.Int, error) {
	var hashedPassword []byte

	switch version {
	case 3:
		// Version 3: bcrypt + argon2
		// First bcrypt the password
		bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
		if err != nil {
			return nil, fmt.Errorf("bcrypt: %w", err)
		}
		// Then argon2
		hashedPassword = argon2.IDKey(bcryptHash, salt, 3, 64*1024, 4, 32)

	case 4:
		// Version 4: argon2 only
		hashedPassword = argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	default:
		// Default: SHA-512 based hashing (versions 0-2)
		h := sha512.New()
		h.Write(salt)
		h.Write([]byte(password))
		hashedPassword = h.Sum(nil)
	}

	// x = H(salt || hashedPassword)
	h := sha512.New()
	h.Write(salt)
	h.Write(hashedPassword)
	xBytes := h.Sum(nil)

	return new(big.Int).SetBytes(xBytes), nil
}

// computeSharedSecret computes the shared secret S.
func (s *SRPSession) computeSharedSecret(x *big.Int, params *SRPParameters) error {
	N := params.Modulus
	g := params.Generator
	B := params.ServerB
	a := s.privateA
	A := s.publicA

	// Verify B != 0 (mod N)
	if new(big.Int).Mod(B, N).Sign() == 0 {
		return fmt.Errorf("invalid server public value")
	}

	// Compute k = H(N || PAD(g))
	k := computeK(N, g)

	// Compute u = H(PAD(A) || PAD(B))
	u := computeU(A, B, N)

	// Verify u != 0
	if u.Sign() == 0 {
		return fmt.Errorf("invalid scrambling parameter")
	}

	// Compute S = (B - k * g^x)^(a + u * x) mod N
	// First: g^x mod N
	gx := new(big.Int).Exp(g, x, N)

	// k * g^x mod N
	kgx := new(big.Int).Mul(k, gx)
	kgx.Mod(kgx, N)

	// B - k * g^x mod N
	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, N)

	// Make sure base is positive
	if base.Sign() < 0 {
		base.Add(base, N)
	}

	// a + u * x
	ux := new(big.Int).Mul(u, x)
	exp := new(big.Int).Add(a, ux)

	// S = base^exp mod N
	s.sharedSecret = new(big.Int).Exp(base, exp, N)

	return nil
}

// computeK computes k = H(N || PAD(g)).
func computeK(N, g *big.Int) *big.Int {
	nBytes := N.Bytes()
	gBytes := padToLen(g.Bytes(), len(nBytes))

	h := sha512.New()
	h.Write(nBytes)
	h.Write(gBytes)

	return new(big.Int).SetBytes(h.Sum(nil))
}

// computeU computes u = H(PAD(A) || PAD(B)).
func computeU(A, B, N *big.Int) *big.Int {
	nLen := len(N.Bytes())
	aBytes := padToLen(A.Bytes(), nLen)
	bBytes := padToLen(B.Bytes(), nLen)

	h := sha512.New()
	h.Write(aBytes)
	h.Write(bBytes)

	return new(big.Int).SetBytes(h.Sum(nil))
}

// computeClientProof computes M1 = H(H(N) XOR H(g) || H(username) || salt || A || B || K).
func (s *SRPSession) computeClientProof() []byte {
	N := s.params.Modulus
	g := s.params.Generator

	// H(N)
	hN := hashBytes(N.Bytes())

	// H(g)
	hG := hashBytes(g.Bytes())

	// H(N) XOR H(g)
	hNxorG := make([]byte, len(hN))
	for i := range hN {
		hNxorG[i] = hN[i] ^ hG[i]
	}

	// H(username)
	hUsername := hashBytes([]byte(s.username))

	// Compute M1
	h := sha512.New()
	h.Write(hNxorG)
	h.Write(hUsername)
	h.Write(s.params.Salt)
	h.Write(s.publicA.Bytes())
	h.Write(s.params.ServerB.Bytes())
	h.Write(s.sessionKey)

	return h.Sum(nil)
}

// computeExpectedM2 computes the expected server proof M2 = H(A || M1 || K).
func (s *SRPSession) computeExpectedM2() []byte {
	h := sha512.New()
	h.Write(s.publicA.Bytes())
	h.Write(s.clientProof)
	h.Write(s.sessionKey)
	return h.Sum(nil)
}

// GetPublicA returns the client's public value A as base64.
func (s *SRPSession) GetPublicA() string {
	return base64.StdEncoding.EncodeToString(s.publicA.Bytes())
}

// GetClientProof returns the client proof M1 as base64.
func (s *SRPSession) GetClientProof() string {
	return base64.StdEncoding.EncodeToString(s.clientProof)
}

// VerifyServerProof verifies the server's proof M2.
func (s *SRPSession) VerifyServerProof(serverProof []byte) bool {
	return subtle.ConstantTimeCompare(s.expectedM2, serverProof) == 1
}

// GetSessionKey returns the derived session key.
func (s *SRPSession) GetSessionKey() []byte {
	return s.sessionKey
}

// hashBytes computes SHA-512 hash of input.
func hashBytes(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// padToLen pads bytes to specified length with leading zeros.
func padToLen(data []byte, length int) []byte {
	if len(data) >= length {
		return data
	}
	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}

// ParseSRPModulus parses a base64-encoded modulus and validates it.
func ParseSRPModulus(modulusB64 string) (*big.Int, error) {
	modulusBytes, err := base64.StdEncoding.DecodeString(modulusB64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}

	modulus := new(big.Int).SetBytes(modulusBytes)

	// Basic validation: modulus should be > 0 and odd (safe prime)
	if modulus.Sign() <= 0 {
		return nil, fmt.Errorf("invalid modulus: must be positive")
	}
	if modulus.Bit(0) == 0 {
		return nil, fmt.Errorf("invalid modulus: must be odd")
	}

	return modulus, nil
}

// ParseServerPublicValue parses a base64-encoded server public value B.
func ParseServerPublicValue(serverEphemeralB64 string) (*big.Int, error) {
	bBytes, err := base64.StdEncoding.DecodeString(serverEphemeralB64)
	if err != nil {
		return nil, fmt.Errorf("decode server ephemeral: %w", err)
	}

	return new(big.Int).SetBytes(bBytes), nil
}
