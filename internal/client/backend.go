package client

import (
	"context"
	"net"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/router"
)

// ClientBackend wraps the client's routing logic as a backend.
type ClientBackend struct {
	action     router.ClientAction
	serverConn *ServerConnection
}

// Name returns the backend name.
func (b *ClientBackend) Name() string {
	if b.action == router.ActionDirect {
		return "direct"
	}
	return "server"
}

// Type returns the backend type.
func (b *ClientBackend) Type() string {
	return string(b.action)
}

// Dial creates a connection based on the routing action.
func (b *ClientBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if b.action == router.ActionDirect {
		return b.dialDirect(ctx, network, address)
	}
	return b.dialServer(ctx, network, address)
}

// DialTimeout creates a connection with a timeout.
func (b *ClientBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// dialDirect connects directly to the target.
func (b *ClientBackend) dialDirect(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, address)
}

// dialServer connects through the Bifrost server.
func (b *ClientBackend) dialServer(ctx context.Context, _, address string) (net.Conn, error) {
	return b.serverConn.Connect(ctx, address)
}

// Start is a no-op for client backend.
func (b *ClientBackend) Start(ctx context.Context) error {
	return nil
}

// Stop is a no-op for client backend.
func (b *ClientBackend) Stop(ctx context.Context) error {
	return nil
}

// IsHealthy always returns true for client backend.
func (b *ClientBackend) IsHealthy() bool {
	return true
}

// Stats returns backend statistics.
func (b *ClientBackend) Stats() backend.Stats {
	return backend.Stats{
		Name:    b.Name(),
		Type:    b.Type(),
		Healthy: true,
	}
}
