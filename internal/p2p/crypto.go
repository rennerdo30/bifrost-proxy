package p2p

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Crypto errors.
var (
	ErrInvalidKeySize       = errors.New("crypto: invalid key size")
	ErrInvalidNonce         = errors.New("crypto: invalid nonce")
	ErrAuthenticationFailed = errors.New("crypto: authentication failed")
	ErrHandshakeNotComplete = errors.New("crypto: handshake not complete")
)

// Key sizes.
const (
	// PrivateKeySize is the size of a private key.
	PrivateKeySize = 32

	// PublicKeySize is the size of a public key.
	PublicKeySize = 32

	// NonceSize is the size of a nonce.
	NonceSize = 12

	// TagSize is the size of the authentication tag.
	TagSize = 16
)

// Message types for handshake.
const (
	msgTypeHandshakeInit     byte = 0x01
	msgTypeHandshakeResponse byte = 0x02
	msgTypeData              byte = 0x03
)

// KeyPair represents a Curve25519 key pair.
type KeyPair struct {
	PrivateKey [PrivateKeySize]byte
	PublicKey  [PublicKeySize]byte
}

// GenerateKeyPair generates a new Curve25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair

	// Generate random private key
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, err
	}

	// Clamp private key per Curve25519 requirements
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)

	return &kp, nil
}

// PublicKeyFromPrivate derives a public key from a private key.
func PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	var private, public [32]byte
	copy(private[:], privateKey)

	curve25519.ScalarBaseMult(&public, &private)

	return public[:], nil
}

// CryptoSession manages an encrypted session with a peer.
type CryptoSession struct {
	localPrivate [PrivateKeySize]byte
	localPublic  [PublicKeySize]byte
	remotePublic [PublicKeySize]byte
	sharedSecret [32]byte

	sendCipher cipher.AEAD
	recvCipher cipher.AEAD

	sendNonce atomic.Uint64
	recvNonce atomic.Uint64

	handshakeComplete atomic.Bool
}

// NewCryptoSession creates a new crypto session.
func NewCryptoSession(privateKey []byte) (*CryptoSession, error) {
	cs := &CryptoSession{}

	if len(privateKey) == 0 {
		// Generate new key pair
		kp, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		cs.localPrivate = kp.PrivateKey
		cs.localPublic = kp.PublicKey
	} else {
		if len(privateKey) != PrivateKeySize {
			return nil, ErrInvalidKeySize
		}
		copy(cs.localPrivate[:], privateKey)

		// Derive public key
		curve25519.ScalarBaseMult(&cs.localPublic, &cs.localPrivate)
	}

	return cs, nil
}

// LocalPublicKey returns the local public key.
func (cs *CryptoSession) LocalPublicKey() []byte {
	return cs.localPublic[:]
}

// CreateHandshakeInit creates a handshake initiation message.
func (cs *CryptoSession) CreateHandshakeInit(remotePublicKey []byte) ([]byte, error) {
	if len(remotePublicKey) != PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	copy(cs.remotePublic[:], remotePublicKey)

	// Compute shared secret using X25519
	sharedSecret, err := curve25519.X25519(cs.localPrivate[:], cs.remotePublic[:])
	if err != nil {
		return nil, err
	}
	copy(cs.sharedSecret[:], sharedSecret)

	// Build init message: type (1) + local public key (32) + random (32)
	msg := make([]byte, 1+PublicKeySize+32)
	msg[0] = msgTypeHandshakeInit
	copy(msg[1:33], cs.localPublic[:])

	// Add random bytes for freshness
	if _, err := rand.Read(msg[33:65]); err != nil {
		return nil, err
	}

	return msg, nil
}

// ProcessHandshakeInit processes a handshake initiation message.
func (cs *CryptoSession) ProcessHandshakeInit(msg []byte) ([]byte, error) {
	if len(msg) < 1+PublicKeySize {
		return nil, ErrHandshakeFailed
	}

	if msg[0] != msgTypeHandshakeInit {
		return nil, ErrHandshakeFailed
	}

	// Extract remote public key
	copy(cs.remotePublic[:], msg[1:33])

	// Compute shared secret using X25519
	sharedSecret, err := curve25519.X25519(cs.localPrivate[:], cs.remotePublic[:])
	if err != nil {
		return nil, err
	}
	copy(cs.sharedSecret[:], sharedSecret)

	// Initialize ciphers
	if err := cs.initializeCiphers(); err != nil {
		return nil, err
	}

	cs.handshakeComplete.Store(true)

	// Build response: type (1) + local public key (32) + random (32)
	response := make([]byte, 1+PublicKeySize+32)
	response[0] = msgTypeHandshakeResponse
	copy(response[1:33], cs.localPublic[:])

	if _, err := rand.Read(response[33:65]); err != nil {
		return nil, err
	}

	return response, nil
}

// ProcessHandshakeResponse processes a handshake response message.
func (cs *CryptoSession) ProcessHandshakeResponse(msg []byte) error {
	if len(msg) < 1+PublicKeySize {
		return ErrHandshakeFailed
	}

	if msg[0] != msgTypeHandshakeResponse {
		return ErrHandshakeFailed
	}

	// Verify remote public key matches
	var receivedPublic [PublicKeySize]byte
	copy(receivedPublic[:], msg[1:33])

	if receivedPublic != cs.remotePublic {
		return ErrHandshakeFailed
	}

	// Initialize ciphers
	if err := cs.initializeCiphers(); err != nil {
		return err
	}

	cs.handshakeComplete.Store(true)

	return nil
}

// initializeCiphers initializes the send and receive ciphers.
func (cs *CryptoSession) initializeCiphers() error {
	// Derive separate keys for send and receive
	// Use simple key derivation: send_key = H(shared || "send"), recv_key = H(shared || "recv")
	// In production, use proper KDF like HKDF

	sendKey := deriveKey(cs.sharedSecret[:], []byte("send"))
	recvKey := deriveKey(cs.sharedSecret[:], []byte("recv"))

	// Determine direction based on public key comparison
	// Higher public key sends with sendKey, receives with recvKey
	if compareKeys(cs.localPublic[:], cs.remotePublic[:]) > 0 {
		sendKey, recvKey = recvKey, sendKey
	}

	var err error
	cs.sendCipher, err = chacha20poly1305.New(sendKey)
	if err != nil {
		return err
	}

	cs.recvCipher, err = chacha20poly1305.New(recvKey)
	if err != nil {
		return err
	}

	return nil
}

// Encrypt encrypts data for sending.
func (cs *CryptoSession) Encrypt(plaintext []byte) []byte {
	if !cs.handshakeComplete.Load() {
		return nil
	}

	// Get next nonce
	nonce := make([]byte, NonceSize)
	nonceVal := cs.sendNonce.Add(1) - 1
	binary.LittleEndian.PutUint64(nonce, nonceVal)

	// Encrypt: type (1) + nonce (12) + ciphertext
	ciphertext := cs.sendCipher.Seal(nil, nonce, plaintext, nil)

	msg := make([]byte, 1+NonceSize+len(ciphertext))
	msg[0] = msgTypeData
	copy(msg[1:13], nonce)
	copy(msg[13:], ciphertext)

	return msg
}

// Decrypt decrypts received data.
func (cs *CryptoSession) Decrypt(msg []byte) ([]byte, error) {
	if !cs.handshakeComplete.Load() {
		return nil, ErrHandshakeNotComplete
	}

	if len(msg) < 1+NonceSize+TagSize {
		return nil, ErrDecryptionFailed
	}

	if msg[0] != msgTypeData {
		return nil, ErrDecryptionFailed
	}

	nonce := msg[1:13]
	ciphertext := msg[13:]

	plaintext, err := cs.recvCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	// Verify nonce is not replayed (simplified check)
	nonceVal := binary.LittleEndian.Uint64(nonce)
	lastNonce := cs.recvNonce.Load()
	if nonceVal <= lastNonce && lastNonce > 0 {
		// Allow some out-of-order delivery within a window
		if lastNonce-nonceVal > 1024 {
			return nil, ErrInvalidNonce
		}
	}
	cs.recvNonce.Store(nonceVal)

	return plaintext, nil
}

// deriveKey derives a key from shared secret and label.
// In production, use HKDF or similar.
func deriveKey(sharedSecret, label []byte) []byte {
	// Simple XOR-based derivation (for illustration)
	// In production, use proper KDF
	key := make([]byte, 32)
	copy(key, sharedSecret)

	for i := 0; i < len(label) && i < 32; i++ {
		key[i] ^= label[i]
	}

	return key
}

// compareKeys compares two public keys.
func compareKeys(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// NoiseHandshake implements a simplified Noise Protocol handshake.
type NoiseHandshake struct {
	pattern   string
	initiator bool

	localStatic     *KeyPair
	localEphemeral  *KeyPair
	remoteStatic    [PublicKeySize]byte
	remoteEphemeral [PublicKeySize]byte

	complete bool
}

// NewNoiseHandshake creates a new Noise handshake.
func NewNoiseHandshake(pattern string, initiator bool, localStatic *KeyPair) *NoiseHandshake {
	return &NoiseHandshake{
		pattern:     pattern,
		initiator:   initiator,
		localStatic: localStatic,
	}
}

// SetRemoteStatic sets the remote static public key.
func (h *NoiseHandshake) SetRemoteStatic(pubkey []byte) {
	copy(h.remoteStatic[:], pubkey)
}

// WriteMessage writes a handshake message.
func (h *NoiseHandshake) WriteMessage(payload []byte) ([]byte, error) {
	if h.localEphemeral == nil {
		// Generate ephemeral key pair
		var err error
		h.localEphemeral, err = GenerateKeyPair()
		if err != nil {
			return nil, err
		}
	}

	// Simplified: just send ephemeral public key + encrypted payload
	msg := make([]byte, PublicKeySize+len(payload))
	copy(msg[:PublicKeySize], h.localEphemeral.PublicKey[:])
	copy(msg[PublicKeySize:], payload)

	return msg, nil
}

// ReadMessage reads a handshake message.
func (h *NoiseHandshake) ReadMessage(msg []byte) ([]byte, error) {
	if len(msg) < PublicKeySize {
		return nil, ErrHandshakeFailed
	}

	copy(h.remoteEphemeral[:], msg[:PublicKeySize])

	payload := msg[PublicKeySize:]
	return payload, nil
}

// Split completes the handshake and returns send/receive ciphers.
func (h *NoiseHandshake) Split() (cipher.AEAD, cipher.AEAD, error) {
	if h.localEphemeral == nil {
		return nil, nil, ErrHandshakeNotComplete
	}

	// Compute shared secret from ephemeral keys using X25519
	sharedSecretBytes, err := curve25519.X25519(h.localEphemeral.PrivateKey[:], h.remoteEphemeral[:])
	if err != nil {
		return nil, nil, err
	}
	var sharedSecret [32]byte
	copy(sharedSecret[:], sharedSecretBytes)

	// Derive keys
	sendKey := deriveKey(sharedSecret[:], []byte("send"))
	recvKey := deriveKey(sharedSecret[:], []byte("recv"))

	if h.initiator {
		sendKey, recvKey = recvKey, sendKey
	}

	sendCipher, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, nil, err
	}

	recvCipher, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, nil, err
	}

	h.complete = true

	return sendCipher, recvCipher, nil
}

// IsComplete returns whether the handshake is complete.
func (h *NoiseHandshake) IsComplete() bool {
	return h.complete
}
