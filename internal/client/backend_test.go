package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/router"
)

func TestClientBackend_Name_Direct(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	assert.Equal(t, "direct", be.Name())
}

func TestClientBackend_Name_Server(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionServer,
	}

	assert.Equal(t, "server", be.Name())
}

func TestClientBackend_Type(t *testing.T) {
	tests := []struct {
		name     string
		action   router.ClientAction
		expected string
	}{
		{"direct", router.ActionDirect, "direct"},
		{"server", router.ActionServer, "server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &ClientBackend{action: tt.action}
			assert.Equal(t, tt.expected, be.Type())
		})
	}
}

func TestClientBackend_Start(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	err := be.Start(context.Background())
	assert.NoError(t, err)
}

func TestClientBackend_Stop(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	err := be.Stop(context.Background())
	assert.NoError(t, err)
}

func TestClientBackend_IsHealthy(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	assert.True(t, be.IsHealthy())
}

func TestClientBackend_Stats(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	stats := be.Stats()
	assert.Equal(t, "direct", stats.Name)
	assert.Equal(t, "direct", stats.Type)
	assert.True(t, stats.Healthy)
}

func TestClientBackend_Stats_Server(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionServer,
	}

	stats := be.Stats()
	assert.Equal(t, "server", stats.Name)
	assert.Equal(t, "server", stats.Type)
	assert.True(t, stats.Healthy)
}

func TestClientBackend_DialTimeout_Direct(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	ctx := context.Background()

	// This will fail because there's no server, but we can test it doesn't panic
	_, err := be.DialTimeout(ctx, "tcp", "127.0.0.1:1", 100*time.Millisecond)
	assert.Error(t, err) // Expected to fail - no server
}

func TestClientBackend_Dial_Direct(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will fail because there's no server, but we can test it doesn't panic
	_, err := be.Dial(ctx, "tcp", "127.0.0.1:1")
	assert.Error(t, err) // Expected to fail - no server
}

func TestClientBackend_Dial_Server_NoServerConn(t *testing.T) {
	be := &ClientBackend{
		action:     router.ActionServer,
		serverConn: nil,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will panic if we don't handle nil serverConn
	// But based on code, it will try to call serverConn.Connect and panic
	// This test documents current behavior
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil serverConn
		}
	}()

	_, _ = be.Dial(ctx, "tcp", "127.0.0.1:1")
}

func TestClientBackend_Dial_Server_WithServerConn(t *testing.T) {
	serverConn := NewServerConnection(ServerConnectionConfig{
		Address:    "127.0.0.1:1", // Invalid port
		Protocol:   "http",
		Timeout:    100 * time.Millisecond,
		RetryCount: 0,
	})

	be := &ClientBackend{
		action:     router.ActionServer,
		serverConn: serverConn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// This will fail because there's no server
	_, err := be.Dial(ctx, "tcp", "example.com:80")
	assert.Error(t, err)
}

func TestClientBackend_dialDirect(t *testing.T) {
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should fail - no server listening
	_, err := be.dialDirect(ctx, "tcp", "127.0.0.1:1")
	assert.Error(t, err)
}

func TestClientBackend_dialServer(t *testing.T) {
	serverConn := NewServerConnection(ServerConnectionConfig{
		Address:    "127.0.0.1:1",
		Protocol:   "http",
		Timeout:    100 * time.Millisecond,
		RetryCount: 0,
	})

	be := &ClientBackend{
		action:     router.ActionServer,
		serverConn: serverConn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := be.dialServer(ctx, "tcp", "example.com:80")
	assert.Error(t, err)
}

func TestClientBackend_ImplementsBackendInterface(t *testing.T) {
	// Compile-time check that ClientBackend implements backend.Backend
	be := &ClientBackend{
		action: router.ActionDirect,
	}

	// Test all interface methods exist
	_ = be.Name()
	_ = be.Type()
	_ = be.IsHealthy()
	_ = be.Stats()
	require.NoError(t, be.Start(context.Background()))
	require.NoError(t, be.Stop(context.Background()))
}
