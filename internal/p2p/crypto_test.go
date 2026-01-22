package p2p

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	kp1, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, kp1)

	assert.Len(t, kp1.PrivateKey, PrivateKeySize)
	assert.Len(t, kp1.PublicKey, PublicKeySize)

	// Keys should not be zero
	assert.NotEqual(t, [PrivateKeySize]byte{}, kp1.PrivateKey)
	assert.NotEqual(t, [PublicKeySize]byte{}, kp1.PublicKey)

	// Generating again should produce different keys
	kp2, err := GenerateKeyPair()
	require.NoError(t, err)

	assert.NotEqual(t, kp1.PrivateKey, kp2.PrivateKey)
	assert.NotEqual(t, kp1.PublicKey, kp2.PublicKey)
}

func TestPublicKeyFromPrivate(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	derived, err := PublicKeyFromPrivate(kp.PrivateKey[:])
	require.NoError(t, err)

	assert.Equal(t, kp.PublicKey[:], derived)
}

func TestPublicKeyFromPrivateInvalidSize(t *testing.T) {
	_, err := PublicKeyFromPrivate([]byte{1, 2, 3})
	assert.Equal(t, ErrInvalidKeySize, err)
}

func TestNewCryptoSession(t *testing.T) {
	t.Run("with private key", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		require.NoError(t, err)

		cs, err := NewCryptoSession(kp.PrivateKey[:])
		require.NoError(t, err)
		require.NotNil(t, cs)

		assert.Equal(t, kp.PublicKey[:], cs.LocalPublicKey())
	})

	t.Run("generate key", func(t *testing.T) {
		cs, err := NewCryptoSession(nil)
		require.NoError(t, err)
		require.NotNil(t, cs)

		assert.Len(t, cs.LocalPublicKey(), PublicKeySize)
	})

	t.Run("invalid key size", func(t *testing.T) {
		_, err := NewCryptoSession([]byte{1, 2, 3})
		assert.Equal(t, ErrInvalidKeySize, err)
	})
}

func TestCryptoSessionHandshake(t *testing.T) {
	// Create two crypto sessions
	initiator, err := NewCryptoSession(nil)
	require.NoError(t, err)

	responder, err := NewCryptoSession(nil)
	require.NoError(t, err)

	// Initiator creates handshake init
	initMsg, err := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	require.NoError(t, err)
	assert.Equal(t, msgTypeHandshakeInit, initMsg[0])
	assert.Len(t, initMsg, 1+PublicKeySize+32)

	// Responder processes init and creates response
	response, err := responder.ProcessHandshakeInit(initMsg)
	require.NoError(t, err)
	assert.Equal(t, msgTypeHandshakeResponse, response[0])
	assert.True(t, responder.handshakeComplete.Load())

	// Initiator processes response
	err = initiator.ProcessHandshakeResponse(response)
	require.NoError(t, err)
	assert.True(t, initiator.handshakeComplete.Load())
}

func TestCryptoSessionEncryptDecrypt(t *testing.T) {
	// Setup handshake
	initiator, err := NewCryptoSession(nil)
	require.NoError(t, err)

	responder, err := NewCryptoSession(nil)
	require.NoError(t, err)

	initMsg, err := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	require.NoError(t, err)

	response, err := responder.ProcessHandshakeInit(initMsg)
	require.NoError(t, err)

	err = initiator.ProcessHandshakeResponse(response)
	require.NoError(t, err)

	// Test encryption/decryption
	plaintext := []byte("Hello, World!")

	// Initiator encrypts, responder decrypts
	ciphertext := initiator.Encrypt(plaintext)
	assert.NotNil(t, ciphertext)
	assert.Equal(t, msgTypeData, ciphertext[0])

	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Responder encrypts, initiator decrypts
	ciphertext2 := responder.Encrypt(plaintext)
	assert.NotNil(t, ciphertext2)

	decrypted2, err := initiator.Decrypt(ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}

func TestCryptoSessionEncryptBeforeHandshake(t *testing.T) {
	cs, err := NewCryptoSession(nil)
	require.NoError(t, err)

	ciphertext := cs.Encrypt([]byte("test"))
	assert.Nil(t, ciphertext)
}

func TestCryptoSessionDecryptBeforeHandshake(t *testing.T) {
	cs, err := NewCryptoSession(nil)
	require.NoError(t, err)

	_, err = cs.Decrypt([]byte{msgTypeData, 1, 2, 3})
	assert.Equal(t, ErrHandshakeNotComplete, err)
}

func TestCryptoSessionDecryptInvalidMessage(t *testing.T) {
	// Setup complete handshake
	initiator, _ := NewCryptoSession(nil)
	responder, _ := NewCryptoSession(nil)

	initMsg, _ := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	response, _ := responder.ProcessHandshakeInit(initMsg)
	initiator.ProcessHandshakeResponse(response)

	t.Run("too short", func(t *testing.T) {
		_, err := responder.Decrypt([]byte{msgTypeData})
		assert.Equal(t, ErrDecryptionFailed, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		msg := make([]byte, 1+NonceSize+TagSize+10)
		msg[0] = msgTypeHandshakeInit
		_, err := responder.Decrypt(msg)
		assert.Equal(t, ErrDecryptionFailed, err)
	})
}

func TestProcessHandshakeInitInvalid(t *testing.T) {
	cs, err := NewCryptoSession(nil)
	require.NoError(t, err)

	t.Run("too short", func(t *testing.T) {
		_, err := cs.ProcessHandshakeInit([]byte{msgTypeHandshakeInit})
		assert.Equal(t, ErrHandshakeFailed, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		msg := make([]byte, 1+PublicKeySize+32)
		msg[0] = msgTypeData
		_, err := cs.ProcessHandshakeInit(msg)
		assert.Equal(t, ErrHandshakeFailed, err)
	})
}

func TestProcessHandshakeResponseInvalid(t *testing.T) {
	cs, err := NewCryptoSession(nil)
	require.NoError(t, err)

	t.Run("too short", func(t *testing.T) {
		err := cs.ProcessHandshakeResponse([]byte{msgTypeHandshakeResponse})
		assert.Equal(t, ErrHandshakeFailed, err)
	})

	t.Run("wrong type", func(t *testing.T) {
		msg := make([]byte, 1+PublicKeySize+32)
		msg[0] = msgTypeData
		err := cs.ProcessHandshakeResponse(msg)
		assert.Equal(t, ErrHandshakeFailed, err)
	})
}

func TestCompareKeys(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 6}
	c := []byte{1, 2, 3, 4, 5}

	assert.Equal(t, -1, compareKeys(a, b))
	assert.Equal(t, 1, compareKeys(b, a))
	assert.Equal(t, 0, compareKeys(a, c))
}

func TestDeriveKey(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	key1 := deriveKey(secret, []byte("send"))
	key2 := deriveKey(secret, []byte("recv"))

	assert.Len(t, key1, 32)
	assert.Len(t, key2, 32)
	assert.NotEqual(t, key1, key2)

	// Same inputs should produce same output
	key3 := deriveKey(secret, []byte("send"))
	assert.Equal(t, key1, key3)
}

func TestNoiseHandshake(t *testing.T) {
	initiator, err := GenerateKeyPair()
	require.NoError(t, err)

	responder, err := GenerateKeyPair()
	require.NoError(t, err)

	// Create handshakes
	initHandshake := NewNoiseHandshake("XX", true, initiator)
	initHandshake.SetRemoteStatic(responder.PublicKey[:])

	respHandshake := NewNoiseHandshake("XX", false, responder)
	respHandshake.SetRemoteStatic(initiator.PublicKey[:])

	// Write message from initiator
	msg1, err := initHandshake.WriteMessage(nil)
	require.NoError(t, err)
	assert.Len(t, msg1, PublicKeySize)

	// Read message at responder
	payload, err := respHandshake.ReadMessage(msg1)
	require.NoError(t, err)
	assert.Empty(t, payload)

	// Write response
	msg2, err := respHandshake.WriteMessage(nil)
	require.NoError(t, err)

	// Read response at initiator
	payload2, err := initHandshake.ReadMessage(msg2)
	require.NoError(t, err)
	assert.Empty(t, payload2)

	// Split for ciphers
	sendCipher, recvCipher, err := initHandshake.Split()
	require.NoError(t, err)
	assert.NotNil(t, sendCipher)
	assert.NotNil(t, recvCipher)
	assert.True(t, initHandshake.IsComplete())
}

func TestNoiseHandshakeReadMessageTooShort(t *testing.T) {
	kp, _ := GenerateKeyPair()
	handshake := NewNoiseHandshake("XX", true, kp)

	_, err := handshake.ReadMessage([]byte{1, 2, 3})
	assert.Equal(t, ErrHandshakeFailed, err)
}

func TestNoiseHandshakeSplitWithoutEphemeral(t *testing.T) {
	kp, _ := GenerateKeyPair()
	handshake := NewNoiseHandshake("XX", true, kp)

	_, _, err := handshake.Split()
	assert.Equal(t, ErrHandshakeNotComplete, err)
}

func TestCryptoMultipleMessages(t *testing.T) {
	// Setup handshake
	initiator, _ := NewCryptoSession(nil)
	responder, _ := NewCryptoSession(nil)

	initMsg, _ := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	response, _ := responder.ProcessHandshakeInit(initMsg)
	initiator.ProcessHandshakeResponse(response)

	// Send multiple messages
	messages := []string{
		"Hello",
		"World",
		"This is a longer message with more content",
		"",
		"Final message",
	}

	for _, msg := range messages {
		plaintext := []byte(msg)
		ciphertext := initiator.Encrypt(plaintext)
		decrypted, err := responder.Decrypt(ciphertext)
		require.NoError(t, err)
		// Use string comparison to handle nil vs empty slice
		assert.Equal(t, string(plaintext), string(decrypted))
	}
}

func TestCryptoLargeMessage(t *testing.T) {
	// Setup handshake
	initiator, _ := NewCryptoSession(nil)
	responder, _ := NewCryptoSession(nil)

	initMsg, _ := initiator.CreateHandshakeInit(responder.LocalPublicKey())
	response, _ := responder.ProcessHandshakeInit(initMsg)
	initiator.ProcessHandshakeResponse(response)

	// Large message
	plaintext := bytes.Repeat([]byte("X"), 64*1024) // 64KB

	ciphertext := initiator.Encrypt(plaintext)
	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
