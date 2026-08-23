package protonvpn

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	srp "github.com/ProtonMail/go-srp"

	"github.com/rennerdo30/bifrost-proxy/internal/vpnprovider"
)

// SRP-6a authentication against the Proton API.
//
// Proton does not use textbook SRP-6a: the modulus is transported as a PGP
// clear-signed message (so plain base64 decoding of the /auth/info Modulus field
// fails), all group elements are little-endian, the hash is a 2048-bit
// "expanded" SHA-512 construction, and the password verifier is derived with
// bcrypt using a Proton-specific salt encoding. Getting any of that wrong yields
// proofs the API rejects, which is what the previous hand-rolled implementation
// here did.
//
// Rather than re-deriving those details, this wraps Proton's own MIT-licensed
// implementation (github.com/ProtonMail/go-srp), which is also the only place
// the modulus-signing public key is published. That library verifies the
// clear-signed modulus against that key before use, closing the SRP-downgrade
// gap: a tampered or unsigned modulus is rejected instead of being trusted.
//
// NOTE: this code path has not been exercised against the live Proton API from
// this repository (that needs real account credentials). It is covered by tests
// using Proton's own published SRP test vectors and a mock API that runs the
// server side of the exchange with the same library.

const (
	// SRPBitLength is the size in bits of the SRP modulus used by the Proton
	// API. Proofs and ephemerals are serialized at this width.
	SRPBitLength = 2048

	// SRPProofSize is the size in bytes of a Proton SRP proof (the expanded
	// hash output: 4 x SHA-512).
	SRPProofSize = 256

	// pgpSignedMessageHeader and pgpSignatureFooter delimit the clear-signed
	// message the API wraps the modulus in.
	pgpSignedMessageHeader = "-----BEGIN PGP SIGNED MESSAGE-----"
	pgpSignatureFooter     = "-----END PGP SIGNATURE-----"
)

// ErrSRPModulusUntrusted indicates the modulus returned by /auth/info was not a
// PGP clear-signed message carrying a valid signature from Proton's
// modulus-signing key. Continuing would allow an attacker-supplied group.
var ErrSRPModulusUntrusted = errors.New("SRP modulus is not signed by ProtonVPN's modulus key")

// SRPSession holds the client-side state of one SRP exchange: the values sent
// to the API and the server proof expected back.
type SRPSession struct {
	clientEphemeral     []byte
	clientProof         []byte
	expectedServerProof []byte
}

// NewSRPSession verifies the clear-signed modulus from /auth/info, derives the
// password verifier for the account's auth version and computes the SRP proofs.
//
// The password is only passed to the key-derivation routine; neither it nor any
// derived secret is logged or returned.
func NewSRPSession(username, password string, info *AuthInfoResponse) (*SRPSession, error) {
	if info == nil {
		return nil, fmt.Errorf("%w: missing SRP parameters", vpnprovider.ErrAuthenticationFailed)
	}

	// Reject anything that is not a clear-signed message before handing it to
	// the SRP library: it dereferences a nil block for input without one.
	if !strings.Contains(info.Modulus, pgpSignedMessageHeader) ||
		!strings.Contains(info.Modulus, pgpSignatureFooter) {
		return nil, fmt.Errorf("%w: %w: /auth/info modulus is not a PGP clear-signed message",
			vpnprovider.ErrAuthenticationFailed, ErrSRPModulusUntrusted)
	}

	auth, err := srp.NewAuth(info.Version, username, []byte(password), info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		if errors.Is(err, srp.ErrInvalidSignature) || errors.Is(err, srp.ErrDataAfterModulus) {
			return nil, fmt.Errorf("%w: %w: %w", vpnprovider.ErrAuthenticationFailed, ErrSRPModulusUntrusted, err)
		}
		return nil, fmt.Errorf("%w: prepare SRP authentication: %w", vpnprovider.ErrAuthenticationFailed, err)
	}

	proofs, err := auth.GenerateProofs(SRPBitLength)
	if err != nil {
		return nil, fmt.Errorf("%w: compute SRP proofs: %w", vpnprovider.ErrAuthenticationFailed, err)
	}

	return &SRPSession{
		clientEphemeral:     proofs.ClientEphemeral,
		clientProof:         proofs.ClientProof,
		expectedServerProof: proofs.ExpectedServerProof,
	}, nil
}

// GetClientEphemeral returns the client public value A, base64-encoded for the
// ClientEphemeral field of the /auth request.
func (s *SRPSession) GetClientEphemeral() string {
	return base64.StdEncoding.EncodeToString(s.clientEphemeral)
}

// GetClientProof returns the client proof M1, base64-encoded for the
// ClientProof field of the /auth request.
func (s *SRPSession) GetClientProof() string {
	return base64.StdEncoding.EncodeToString(s.clientProof)
}

// VerifyServerProof reports whether the server proof M2 returned by /auth
// matches the expected value, using a constant-time comparison. A false result
// means the server does not know the password verifier and the session must be
// discarded.
func (s *SRPSession) VerifyServerProof(serverProof []byte) bool {
	if len(serverProof) == 0 || len(serverProof) != len(s.expectedServerProof) {
		return false
	}
	return subtle.ConstantTimeCompare(s.expectedServerProof, serverProof) == 1
}
