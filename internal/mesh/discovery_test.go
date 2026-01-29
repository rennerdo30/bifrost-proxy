package mesh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiscoveryClient(t *testing.T) {
	config := DiscoveryConfig{
		Server: "discovery.example.com",
	}
	localPeer := NewPeer("test-peer", "test-public-key")
	registry := NewPeerRegistry()

	client := NewDiscoveryClient(config, "test-network", localPeer, registry)

	require.NotNil(t, client)
	assert.Equal(t, config, client.config)
	assert.Equal(t, "test-network", client.networkID)
	assert.Equal(t, localPeer, client.localPeer)
	assert.Equal(t, registry, client.registry)
	assert.NotNil(t, client.eventChan)
	assert.NotNil(t, client.httpClient)
}

func TestDiscoveryClient_BuildURL(t *testing.T) {
	config := DiscoveryConfig{
		Server: "discovery.example.com",
	}
	client := NewDiscoveryClient(config, "test-network", nil, nil)

	tests := []struct {
		name     string
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "simple path",
			format:   "/api/register",
			args:     nil,
			expected: "https://discovery.example.com/api/register",
		},
		{
			name:     "path with format args",
			format:   "/api/networks/%s/peers",
			args:     []interface{}{"my-network"},
			expected: "https://discovery.example.com/api/networks/my-network/peers",
		},
		{
			name:     "path with multiple args",
			format:   "/api/networks/%s/peers/%s",
			args:     []interface{}{"net1", "peer1"},
			expected: "https://discovery.example.com/api/networks/net1/peers/peer1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.buildURL(tt.format, tt.args...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDiscoveryClient_BuildWSURL(t *testing.T) {
	config := DiscoveryConfig{
		Server: "discovery.example.com",
	}
	client := NewDiscoveryClient(config, "test-network", nil, nil)

	tests := []struct {
		name     string
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "simple ws path",
			format:   "/ws/events",
			args:     nil,
			expected: "wss://discovery.example.com/ws/events",
		},
		{
			name:     "ws path with format args",
			format:   "/ws/networks/%s/events",
			args:     []interface{}{"my-network"},
			expected: "wss://discovery.example.com/ws/networks/my-network/events",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.buildWSURL(tt.format, tt.args...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDiscoveryClient_IsConnected(t *testing.T) {
	config := DiscoveryConfig{
		Server: "discovery.example.com",
	}
	client := NewDiscoveryClient(config, "test-network", nil, nil)

	// Initially not connected
	assert.False(t, client.IsConnected())

	// Simulate connection
	client.mu.Lock()
	client.connected = true
	client.mu.Unlock()

	assert.True(t, client.IsConnected())

	// Simulate disconnection
	client.mu.Lock()
	client.connected = false
	client.mu.Unlock()

	assert.False(t, client.IsConnected())
}

func TestDiscoveryClient_Events(t *testing.T) {
	config := DiscoveryConfig{
		Server: "discovery.example.com",
	}
	client := NewDiscoveryClient(config, "test-network", nil, nil)

	eventChan := client.Events()
	assert.NotNil(t, eventChan)
	// Events returns a read-only channel
}
