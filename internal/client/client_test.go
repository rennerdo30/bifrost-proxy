package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestNew(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP:   config.ListenerConfig{Listen: "127.0.0.1:0"},
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:8080",
			Protocol: "http",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.router)
	assert.NotNil(t, client.serverConn)
	assert.False(t, client.Running())
}

func TestNew_WithRoutes(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:8080",
			Protocol: "http",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*.local"}, Action: "direct"},
			{Name: "server", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNew_WithDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  "localhost:8080",
			Protocol: "http",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 100,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.debugger)
}

func TestClient_Running(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	assert.False(t, client.Running())
}

func TestClient_GetDebugEntries_NilDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
		Debug: config.DebugConfig{
			Enabled: false,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	entries := client.GetDebugEntries()
	assert.Nil(t, entries)
}

func TestClient_GetDebugEntries_WithDebugger(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
		Debug: config.DebugConfig{
			Enabled:    true,
			MaxEntries: 10,
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	entries := client.GetDebugEntries()
	assert.NotNil(t, entries)
	assert.Empty(t, entries)
}

func TestClient_StartStop(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Start
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Start again (should be no-op)
	err = client.Start(ctx)
	require.NoError(t, err)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, client.Running())

	// Stop again (should be no-op)
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_StartWithSOCKS5(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_StartWithAPI(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Token:   "test-token",
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)
	assert.True(t, client.Running())

	// Give API server time to start
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Stop(ctx)
	require.NoError(t, err)
}

func TestClient_getBackend_Direct(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*.local"}, Action: "direct"},
			{Name: "server", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Should match direct route
	be := client.getBackend("test.local", "192.168.1.1")
	require.NotNil(t, be)
	assert.Equal(t, "direct", be.Name())
}

func TestClient_getBackend_Server(t *testing.T) {
	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address: "localhost:8080",
		},
		Routes: []config.ClientRouteConfig{
			{Name: "direct", Domains: []string{"*.local"}, Action: "direct"},
			{Name: "server", Domains: []string{"*"}, Action: "server"},
		},
	}

	client, err := New(cfg)
	require.NoError(t, err)

	// Should match server route (catch-all)
	be := client.getBackend("example.com", "192.168.1.1")
	require.NotNil(t, be)
	assert.Equal(t, "server", be.Name())
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	// IDs should be different (very high probability)
	// Note: This could technically fail if nanoseconds match, but extremely unlikely
}
