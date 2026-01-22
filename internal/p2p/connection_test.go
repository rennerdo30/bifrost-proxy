package p2p

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConnectionTypeString(t *testing.T) {
	tests := []struct {
		connType ConnectionType
		expected string
	}{
		{ConnectionTypeDirect, "direct"},
		{ConnectionTypeRelayed, "relayed"},
		{ConnectionTypeMultiHop, "multi_hop"},
		{ConnectionType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.connType.String())
		})
	}
}

func TestConnectionStateString(t *testing.T) {
	tests := []struct {
		state    ConnectionState
		expected string
	}{
		{ConnectionStateNew, "new"},
		{ConnectionStateConnecting, "connecting"},
		{ConnectionStateConnected, "connected"},
		{ConnectionStateDisconnected, "disconnected"},
		{ConnectionStateFailed, "failed"},
		{ConnectionState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestDefaultConnectionConfig(t *testing.T) {
	config := DefaultConnectionConfig()

	assert.Equal(t, 10*time.Second, config.ConnectTimeout)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 10*time.Second, config.WriteTimeout)
	assert.Equal(t, 25*time.Second, config.KeepAliveInterval)
	assert.Equal(t, 3, config.MaxRetries)
}

func TestConnectionErrors(t *testing.T) {
	assert.Equal(t, "p2p: connection closed", ErrConnectionClosed.Error())
	assert.Equal(t, "p2p: connection failed", ErrConnectionFailed.Error())
	assert.Equal(t, "p2p: connection timeout", ErrConnectionTimeout.Error())
	assert.Equal(t, "p2p: not connected", ErrNotConnected.Error())
	assert.Equal(t, "p2p: handshake failed", ErrHandshakeFailed.Error())
	assert.Equal(t, "p2p: encryption failed", ErrEncryptionFailed.Error())
	assert.Equal(t, "p2p: decryption failed", ErrDecryptionFailed.Error())
}
