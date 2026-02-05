package backend

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WireGuardBackend provides connections through a WireGuard tunnel.
type WireGuardBackend struct {
	name      string
	config    WireGuardConfig
	device    *device.Device
	tnet      *netstack.Net
	startTime time.Time
	healthy   atomic.Bool
	stats     wireguardStats
	mu        sync.RWMutex
	running   bool
}

type wireguardStats struct {
	activeConns   atomic.Int64
	totalConns    atomic.Int64
	bytesSent     atomic.Int64
	bytesRecv     atomic.Int64
	errors        atomic.Int64
	lastError     string
	lastErrorMu   sync.RWMutex
	lastErrorTime time.Time
}

// WireGuardConfig holds configuration for a WireGuard backend.
type WireGuardConfig struct {
	Name       string        `yaml:"name"`
	PrivateKey string        `yaml:"private_key"`
	Address    string        `yaml:"address"` // Local IP address (e.g., "10.0.0.2/24")
	DNS        []string      `yaml:"dns"`     // DNS servers
	MTU        int           `yaml:"mtu"`
	Peer       WireGuardPeer `yaml:"peer"`
}

// WireGuardPeer represents a WireGuard peer configuration.
type WireGuardPeer struct {
	PublicKey           string   `yaml:"public_key"`
	Endpoint            string   `yaml:"endpoint"`
	AllowedIPs          []string `yaml:"allowed_ips"`
	PersistentKeepalive int      `yaml:"persistent_keepalive"`
	PresharedKey        string   `yaml:"preshared_key,omitempty"`
}

// NewWireGuardBackend creates a new WireGuard backend.
func NewWireGuardBackend(cfg WireGuardConfig) *WireGuardBackend {
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	return &WireGuardBackend{
		name:   cfg.Name,
		config: cfg,
	}
}

// Name returns the backend name.
func (b *WireGuardBackend) Name() string {
	return b.name
}

// Type returns the backend type.
func (b *WireGuardBackend) Type() string {
	return "wireguard"
}

// Dial creates a connection through the WireGuard tunnel.
func (b *WireGuardBackend) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.RLock()
	if !b.running || b.tnet == nil {
		b.mu.RUnlock()
		return nil, NewBackendError(b.name, "dial", ErrBackendNotStarted)
	}
	tnet := b.tnet
	b.mu.RUnlock()

	var conn net.Conn
	var err error

	switch network {
	case "tcp", "tcp4", "tcp6":
		// Resolve the target address first
		tcpAddr, resolveErr := net.ResolveTCPAddr(network, address)
		if resolveErr != nil {
			b.recordError(resolveErr)
			return nil, NewBackendError(b.name, "resolve", resolveErr)
		}
		// Connect to the target through the WireGuard tunnel
		conn, err = tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(
			netip.MustParseAddr(tcpAddr.IP.String()),
			uint16(tcpAddr.Port), //nolint:gosec // G115: TCP port is always 0-65535
		))
	case "udp", "udp4", "udp6":
		udpAddr, resolveErr := net.ResolveUDPAddr(network, address)
		if resolveErr != nil {
			b.recordError(resolveErr)
			return nil, NewBackendError(b.name, "resolve", resolveErr)
		}
		conn, err = tnet.DialUDPAddrPort(
			netip.AddrPort{},
			netip.AddrPortFrom(
				netip.MustParseAddr(udpAddr.IP.String()),
				uint16(udpAddr.Port), //nolint:gosec // G115: UDP port is always 0-65535
			),
		)
	default:
		return nil, NewBackendError(b.name, "dial", fmt.Errorf("unsupported network: %s", network))
	}

	if err != nil {
		b.recordError(err)
		return nil, NewBackendError(b.name, "dial", err)
	}

	b.stats.activeConns.Add(1)
	b.stats.totalConns.Add(1)

	// Wrap connection to track stats
	tracked := &TrackedConn{
		Conn: conn,
		OnClose: func(bytesRead, bytesWritten int64) {
			b.stats.activeConns.Add(-1)
			b.stats.bytesRecv.Add(bytesRead)
			b.stats.bytesSent.Add(bytesWritten)
		},
	}

	return tracked, nil
}

// DialTimeout creates a connection with a specific timeout.
func (b *WireGuardBackend) DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.Dial(ctx, network, address)
}

// Start initializes the WireGuard tunnel.
func (b *WireGuardBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	// Parse local address
	localAddr, err := netip.ParsePrefix(b.config.Address)
	if err != nil {
		return NewBackendError(b.name, "parse address", err)
	}

	// Parse DNS servers
	dnsAddrs := make([]netip.Addr, 0, len(b.config.DNS))
	for _, dns := range b.config.DNS {
		addr, parseErr := netip.ParseAddr(dns)
		if parseErr != nil {
			return NewBackendError(b.name, "parse dns", parseErr)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	// Create netstack TUN
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr.Addr()},
		dnsAddrs,
		b.config.MTU,
	)
	if err != nil {
		return NewBackendError(b.name, "create tun", err)
	}

	// Create device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	// Configure device
	configStr := b.buildConfig()
	if err := dev.IpcSet(configStr); err != nil {
		dev.Close()
		return NewBackendError(b.name, "configure device", err)
	}

	// Bring up device
	if err := dev.Up(); err != nil {
		dev.Close()
		return NewBackendError(b.name, "bring up device", err)
	}

	b.device = dev
	b.tnet = tnet
	b.running = true
	b.startTime = time.Now()
	b.healthy.Store(true)

	return nil
}

func (b *WireGuardBackend) buildConfig() string {
	config := fmt.Sprintf("private_key=%s\n", b.config.PrivateKey)

	config += fmt.Sprintf("public_key=%s\n", b.config.Peer.PublicKey)

	if b.config.Peer.PresharedKey != "" {
		config += fmt.Sprintf("preshared_key=%s\n", b.config.Peer.PresharedKey)
	}

	if b.config.Peer.Endpoint != "" {
		config += fmt.Sprintf("endpoint=%s\n", b.config.Peer.Endpoint)
	}

	for _, allowedIP := range b.config.Peer.AllowedIPs {
		config += fmt.Sprintf("allowed_ip=%s\n", allowedIP)
	}

	if b.config.Peer.PersistentKeepalive > 0 {
		config += fmt.Sprintf("persistent_keepalive_interval=%d\n", b.config.Peer.PersistentKeepalive)
	}

	return config
}

// Stop shuts down the WireGuard tunnel.
func (b *WireGuardBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return nil
	}

	if b.device != nil {
		b.device.Close()
		b.device = nil
	}

	b.tnet = nil
	b.running = false
	b.healthy.Store(false)

	return nil
}

// IsHealthy returns the health status.
func (b *WireGuardBackend) IsHealthy() bool {
	return b.healthy.Load()
}

// Stats returns backend statistics.
func (b *WireGuardBackend) Stats() Stats {
	b.stats.lastErrorMu.RLock()
	lastErr := b.stats.lastError
	lastErrTime := b.stats.lastErrorTime
	b.stats.lastErrorMu.RUnlock()

	return Stats{
		Name:              b.name,
		Type:              "wireguard",
		Healthy:           b.healthy.Load(),
		ActiveConnections: b.stats.activeConns.Load(),
		TotalConnections:  b.stats.totalConns.Load(),
		BytesSent:         b.stats.bytesSent.Load(),
		BytesReceived:     b.stats.bytesRecv.Load(),
		Errors:            b.stats.errors.Load(),
		LastError:         lastErr,
		LastErrorTime:     lastErrTime,
		Uptime:            time.Since(b.startTime),
	}
}

func (b *WireGuardBackend) recordError(err error) {
	b.stats.errors.Add(1)
	b.stats.lastErrorMu.Lock()
	b.stats.lastError = err.Error()
	b.stats.lastErrorTime = time.Now()
	b.stats.lastErrorMu.Unlock()
}
