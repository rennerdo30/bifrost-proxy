package p2p

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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

// ephemeralPubSize is the size of the ephemeral X25519 public key each side
// contributes in its handshake message (in the slot previously used for a raw
// random value). The ephemeral-ephemeral X25519 result is mixed into the KDF
// salt so that:
//   - session keys are unique per handshake (per reconnect), which prevents
//     ChaCha20-Poly1305 nonce reuse even though the counter restarts at 0 and
//     the static X25519 shared secret is deterministic; and
//   - the session gains forward secrecy: the ephemeral private keys are
//     discarded after the handshake, so a later compromise of a static private
//     key does not reveal past session keys.
//
// Authentication is still provided by the static-static X25519 shared secret,
// which is used as the HKDF input keying material.
const ephemeralPubSize = PublicKeySize

// CryptoSession manages an encrypted session with a peer.
type CryptoSession struct {
	localPrivate [PrivateKeySize]byte
	localPublic  [PublicKeySize]byte
	remotePublic [PublicKeySize]byte
	sharedSecret [32]byte

	// localEphemeral is this side's per-session ephemeral key pair; its private
	// half is discarded (dropped with the session) after the handshake.
	localEphemeral *KeyPair
	// ephemeralShared is the ephemeral-ephemeral X25519 result, identical on
	// both peers and used as the KDF salt to make each session's keys unique.
	ephemeralShared [32]byte

	sendCipher cipher.AEAD
	recvCipher cipher.AEAD

	sendNonce atomic.Uint64
	replay    replayFilter

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

	// Compute the static-static shared secret using X25519. This authenticates
	// the peer (only a holder of the peer's static private key can derive it)
	// and is used as the HKDF input keying material.
	sharedSecret, err := curve25519.X25519(cs.localPrivate[:], cs.remotePublic[:])
	if err != nil {
		return nil, err
	}
	copy(cs.sharedSecret[:], sharedSecret)

	// Generate a per-session ephemeral key pair. Its public half is sent in the
	// handshake; the ephemeral-ephemeral X25519 result becomes the KDF salt,
	// giving per-session keys and forward secrecy.
	eph, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	cs.localEphemeral = eph

	// Build init message: type (1) + local public key (32) + ephemeral pub (32)
	msg := make([]byte, 1+PublicKeySize+ephemeralPubSize)
	msg[0] = msgTypeHandshakeInit
	copy(msg[1:33], cs.localPublic[:])
	copy(msg[33:65], eph.PublicKey[:])

	return msg, nil
}

// ProcessHandshakeInit processes a handshake initiation message.
func (cs *CryptoSession) ProcessHandshakeInit(msg []byte) ([]byte, error) {
	if len(msg) < 1+PublicKeySize+ephemeralPubSize {
		return nil, ErrHandshakeFailed
	}

	if msg[0] != msgTypeHandshakeInit {
		return nil, ErrHandshakeFailed
	}

	// Extract remote static public key and the initiator's ephemeral public key.
	copy(cs.remotePublic[:], msg[1:33])
	var remoteEphemeral [ephemeralPubSize]byte
	copy(remoteEphemeral[:], msg[33:65])

	// Compute the static-static shared secret (authentication + HKDF IKM).
	sharedSecret, err := curve25519.X25519(cs.localPrivate[:], cs.remotePublic[:])
	if err != nil {
		return nil, err
	}
	copy(cs.sharedSecret[:], sharedSecret)

	// Generate this side's ephemeral key pair and compute the ephemeral-ephemeral
	// shared secret used as the KDF salt.
	eph, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	cs.localEphemeral = eph
	if err := cs.computeEphemeralShared(remoteEphemeral[:]); err != nil {
		return nil, err
	}

	// Initialize ciphers
	if err := cs.initializeCiphers(); err != nil {
		return nil, err
	}

	cs.handshakeComplete.Store(true)

	// Build response: type (1) + local public key (32) + ephemeral pub (32)
	response := make([]byte, 1+PublicKeySize+ephemeralPubSize)
	response[0] = msgTypeHandshakeResponse
	copy(response[1:33], cs.localPublic[:])
	copy(response[33:65], eph.PublicKey[:])

	return response, nil
}

// ProcessHandshakeResponse processes a handshake response message.
func (cs *CryptoSession) ProcessHandshakeResponse(msg []byte) error {
	if len(msg) < 1+PublicKeySize+ephemeralPubSize {
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

	if cs.localEphemeral == nil {
		return ErrHandshakeFailed
	}

	// Compute the ephemeral-ephemeral shared secret (KDF salt) from the
	// responder's ephemeral public key.
	if err := cs.computeEphemeralShared(msg[33:65]); err != nil {
		return err
	}

	// Initialize ciphers
	if err := cs.initializeCiphers(); err != nil {
		return err
	}

	cs.handshakeComplete.Store(true)

	return nil
}

// computeEphemeralShared derives the ephemeral-ephemeral X25519 shared secret
// from the local ephemeral private key and the peer's ephemeral public key and
// stores it as the KDF salt. Both peers compute the identical value (DH is
// commutative). X25519 rejects low-order points by returning an error, in which
// case the handshake fails closed.
func (cs *CryptoSession) computeEphemeralShared(remoteEphemeralPub []byte) error {
	if cs.localEphemeral == nil {
		return ErrHandshakeNotComplete
	}
	shared, err := curve25519.X25519(cs.localEphemeral.PrivateKey[:], remoteEphemeralPub)
	if err != nil {
		return err
	}
	copy(cs.ephemeralShared[:], shared)
	return nil
}

// initializeCiphers initializes the send and receive ciphers.
func (cs *CryptoSession) initializeCiphers() error {
	// Derive separate keys for send and receive using HKDF. The input keying
	// material is the deterministic static-static X25519 secret (which
	// authenticates the peer); the salt is the per-session ephemeral-ephemeral
	// X25519 secret. Because the salt changes every handshake, the derived keys
	// are unique per session, so the nonce counter (which restarts at 0 each
	// session) never reuses a (key, nonce) pair — essential for
	// ChaCha20-Poly1305. Because the ephemeral private keys are discarded after
	// the handshake, the session also has forward secrecy.
	salt := cs.ephemeralShared[:]

	sendKey := deriveKey(cs.sharedSecret[:], salt, []byte("send"))
	recvKey := deriveKey(cs.sharedSecret[:], salt, []byte("recv"))

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

	// Reject replays. The frame is only checked after successful AEAD
	// authentication, so the nonce is guaranteed authentic at this point. The
	// sliding-window filter accepts each authentic nonce at most once and
	// rejects anything older than the window, defeating replay of previously
	// captured frames.
	nonceVal := binary.LittleEndian.Uint64(nonce)
	if !cs.replay.accept(nonceVal) {
		return nil, ErrInvalidNonce
	}

	return plaintext, nil
}

// deriveKey derives a key from shared secret, salt and label using HKDF. The
// salt binds the derived key to per-session handshake randomness so that keys
// are unique per session even when sharedSecret is deterministic.
func deriveKey(sharedSecret, salt, label []byte) []byte {
	kdf := hkdf.New(sha256.New, sharedSecret, salt, label)
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		// HKDF with valid params should never fail; fall back to SHA-256
		h := sha256.New()
		h.Write(sharedSecret)
		h.Write(salt)
		h.Write(label)
		return h.Sum(nil)
	}
	return key
}

// Replay-window sizing. The window is a bitmap of recently accepted nonces; any
// authenticated nonce older than replayWindowBits behind the highest accepted
// nonce is rejected, as is any nonce already recorded in the window.
const (
	replayBlockBits  = 64
	replayBlocks     = 32
	replayWindowBits = replayBlockBits * replayBlocks // 2048
)

// replayFilter is a sliding-window anti-replay filter over strictly increasing
// per-session nonces. A single monotonic counter with a 1024-slot tolerance is
// insufficient (it accepts exact replays and drags backwards); this bitmap
// records each accepted nonce so a given nonce is accepted at most once.
type replayFilter struct {
	mu      sync.Mutex
	last    uint64
	seenAny bool
	bitmap  [replayBlocks]uint64
}

// accept reports whether nonce is fresh (not previously seen and within the
// window) and records it. It returns false for replays and out-of-window
// nonces, in which case the frame must be dropped.
func (r *replayFilter) accept(nonce uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.seenAny {
		r.seenAny = true
		r.last = nonce
		r.setBit(nonce)
		return true
	}

	if nonce > r.last {
		// Advance the window, clearing bits for the blocks we skip past.
		curBlock := r.last / replayBlockBits
		newBlock := nonce / replayBlockBits
		diff := newBlock - curBlock
		if diff >= replayBlocks {
			for i := range r.bitmap {
				r.bitmap[i] = 0
			}
		} else {
			for i := uint64(1); i <= diff; i++ {
				r.bitmap[(curBlock+i)%replayBlocks] = 0
			}
		}
		r.last = nonce
		r.setBit(nonce)
		return true
	}

	// nonce <= last: reject if too old or already seen.
	if r.last-nonce >= replayWindowBits {
		return false
	}
	if r.testBit(nonce) {
		return false
	}
	r.setBit(nonce)
	return true
}

func (r *replayFilter) setBit(nonce uint64) {
	block := (nonce / replayBlockBits) % replayBlocks
	r.bitmap[block] |= 1 << (nonce % replayBlockBits)
}

func (r *replayFilter) testBit(nonce uint64) bool {
	block := (nonce / replayBlockBits) % replayBlocks
	return r.bitmap[block]&(1<<(nonce%replayBlockBits)) != 0
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

	// Derive keys. The ephemeral X25519 exchange already yields a fresh shared
	// secret per handshake, so no additional salt is required here.
	sendKey := deriveKey(sharedSecret[:], nil, []byte("send"))
	recvKey := deriveKey(sharedSecret[:], nil, []byte("recv"))

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
