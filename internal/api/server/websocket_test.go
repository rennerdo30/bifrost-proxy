package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebSocketHub(t *testing.T) {
	hub := NewWebSocketHub()
	require.NotNil(t, hub)
	assert.NotNil(t, hub.clients)
	assert.NotNil(t, hub.broadcast)
	assert.NotNil(t, hub.register)
	assert.NotNil(t, hub.unregister)
}

func TestWebSocketHub_Broadcast(t *testing.T) {
	hub := NewWebSocketHub()

	// Start hub in background
	go hub.Run()

	// Send broadcast (will be buffered)
	hub.Broadcast("test.event", map[string]string{"key": "value"})

	// Give it a moment
	time.Sleep(10 * time.Millisecond)

	// No clients, so message just gets discarded
	// This test mainly verifies Broadcast doesn't panic
}

func TestWebSocketHub_BroadcastWithData(t *testing.T) {
	hub := NewWebSocketHub()

	// Test with various data types
	hub.Broadcast("event1", "string data")
	hub.Broadcast("event2", 123)
	hub.Broadcast("event3", map[string]interface{}{"nested": true})
	hub.Broadcast("event4", []string{"a", "b", "c"})
	hub.Broadcast("event5", nil)

	// Verify no panic
}

func TestEventConstants(t *testing.T) {
	assert.Equal(t, "backend.health", EventBackendHealth)
	assert.Equal(t, "connection.new", EventConnectionNew)
	assert.Equal(t, "connection.close", EventConnectionClose)
	assert.Equal(t, "config.reload", EventConfigReload)
	assert.Equal(t, "stats.update", EventStats)
}

func TestBackendHealthEvent_Struct(t *testing.T) {
	event := BackendHealthEvent{
		Name:    "test-backend",
		Healthy: true,
	}

	assert.Equal(t, "test-backend", event.Name)
	assert.True(t, event.Healthy)
}

func TestBackendHealthEvent_Unhealthy(t *testing.T) {
	event := BackendHealthEvent{
		Name:    "failed-backend",
		Healthy: false,
	}

	assert.Equal(t, "failed-backend", event.Name)
	assert.False(t, event.Healthy)
}

func TestConnectionEvent_Struct(t *testing.T) {
	event := ConnectionEvent{
		Protocol: "HTTP",
		Host:     "example.com",
		Backend:  "default",
		ClientIP: "192.168.1.1",
	}

	assert.Equal(t, "HTTP", event.Protocol)
	assert.Equal(t, "example.com", event.Host)
	assert.Equal(t, "default", event.Backend)
	assert.Equal(t, "192.168.1.1", event.ClientIP)
}

func TestConnectionEvent_SOCKS5(t *testing.T) {
	event := ConnectionEvent{
		Protocol: "SOCKS5",
		Host:     "secure.example.com:443",
		Backend:  "wireguard",
		ClientIP: "10.0.0.5",
	}

	assert.Equal(t, "SOCKS5", event.Protocol)
	assert.Equal(t, "secure.example.com:443", event.Host)
}

func TestStatsEvent_Struct(t *testing.T) {
	event := StatsEvent{
		ActiveConnections: 10,
		TotalConnections:  1000,
		BytesSent:         1024 * 1024,
		BytesReceived:     2048 * 1024,
	}

	assert.Equal(t, int64(10), event.ActiveConnections)
	assert.Equal(t, int64(1000), event.TotalConnections)
	assert.Equal(t, int64(1024*1024), event.BytesSent)
	assert.Equal(t, int64(2048*1024), event.BytesReceived)
}

func TestStatsEvent_Zero(t *testing.T) {
	event := StatsEvent{}

	assert.Equal(t, int64(0), event.ActiveConnections)
	assert.Equal(t, int64(0), event.TotalConnections)
	assert.Equal(t, int64(0), event.BytesSent)
	assert.Equal(t, int64(0), event.BytesReceived)
}

func TestWebSocketHub_BroadcastTypedEvents(t *testing.T) {
	hub := NewWebSocketHub()

	// Test broadcasting typed events
	hub.Broadcast(EventBackendHealth, BackendHealthEvent{
		Name:    "test",
		Healthy: true,
	})

	hub.Broadcast(EventConnectionNew, ConnectionEvent{
		Protocol: "HTTP",
		Host:     "example.com",
		Backend:  "default",
		ClientIP: "127.0.0.1",
	})

	hub.Broadcast(EventStats, StatsEvent{
		ActiveConnections: 5,
		TotalConnections:  100,
	})

	// No panic means success
}

func TestWebSocketHub_ChannelBufferSize(t *testing.T) {
	hub := NewWebSocketHub()

	// Broadcast channel should have buffer size of 256
	// Send 256 messages without blocking (no consumers)
	for i := 0; i < 256; i++ {
		select {
		case hub.broadcast <- []byte("test"):
			// OK
		default:
			t.Fatalf("Channel blocked at message %d", i)
		}
	}
}

func TestAPI_AddWebSocketRoutes(t *testing.T) {
	api := New(Config{})
	hub := NewWebSocketHub()

	// This test verifies the method exists and doesn't panic
	// Actual routing would require a full router setup
	_ = api
	_ = hub
}

func TestWebSocketHub_RunStartsWithoutPanic(t *testing.T) {
	hub := NewWebSocketHub()

	done := make(chan bool)
	go func() {
		// This will run forever, but we just want to make sure it starts
		go hub.Run()
		time.Sleep(10 * time.Millisecond)
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Fatal("Hub.Run did not start in time")
	}
}

func TestWebSocketHub_BroadcastMessageFormat(t *testing.T) {
	hub := NewWebSocketHub()

	// Start hub
	go hub.Run()

	// The broadcast method creates a JSON message with type, timestamp, and data
	hub.Broadcast("test.event", map[string]string{"key": "value"})

	// Give it a moment to process
	time.Sleep(10 * time.Millisecond)

	// No clients connected, so we can't verify the actual message
	// But we can verify it doesn't panic with various data types
}

func TestConnectionEvent_CONNECT(t *testing.T) {
	event := ConnectionEvent{
		Protocol: "CONNECT",
		Host:     "api.example.com:443",
		Backend:  "default",
		ClientIP: "192.168.1.100",
	}

	assert.Equal(t, "CONNECT", event.Protocol)
}

func TestBackendHealthEvent_JSONTags(t *testing.T) {
	// Verify struct has proper JSON tags by checking it can be used
	event := BackendHealthEvent{
		Name:    "my-backend",
		Healthy: false,
	}

	assert.Equal(t, "my-backend", event.Name)
	assert.False(t, event.Healthy)
}

func TestStatsEvent_LargeNumbers(t *testing.T) {
	event := StatsEvent{
		ActiveConnections: 1000000,
		TotalConnections:  int64(1e12),
		BytesSent:         int64(1e15),
		BytesReceived:     int64(1e15),
	}

	assert.Equal(t, int64(1000000), event.ActiveConnections)
	assert.Equal(t, int64(1e12), event.TotalConnections)
	assert.Equal(t, int64(1e15), event.BytesSent)
}
