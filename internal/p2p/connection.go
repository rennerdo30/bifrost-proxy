package p2p

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionType represents the type of P2P connection.
type ConnectionType int

const (
	// ConnectionTypeDirect is a direct P2P connection.
	ConnectionTypeDirect ConnectionType = iota

	// ConnectionTypeRelayed is a connection through a TURN relay.
	ConnectionTypeRelayed

	// ConnectionTypeMultiHop is a connection through multiple peers.
	ConnectionTypeMultiHop
)

// String returns a human-readable string for the connection type.
func (t ConnectionType) String() string {
	switch t {
	case ConnectionTypeDirect:
		return "direct"
	case ConnectionTypeRelayed:
		return "relayed"
	case ConnectionTypeMultiHop:
		return "multi_hop"
	default:
		return "unknown"
	}
}

// ConnectionState represents the state of a P2P connection.
type ConnectionState int

const (
	// ConnectionStateNew is a newly created connection.
	ConnectionStateNew ConnectionState = iota

	// ConnectionStateConnecting is attempting to connect.
	ConnectionStateConnecting

	// ConnectionStateConnected is successfully connected.
	ConnectionStateConnected

	// ConnectionStateDisconnected is disconnected.
	ConnectionStateDisconnected

	// ConnectionStateFailed has failed to connect.
	ConnectionStateFailed
)

// String returns a human-readable string for the connection state.
func (s ConnectionState) String() string {
	switch s {
	case ConnectionStateNew:
		return "new"
	case ConnectionStateConnecting:
		return "connecting"
	case ConnectionStateConnected:
		return "connected"
	case ConnectionStateDisconnected:
		return "disconnected"
	case ConnectionStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Connection errors.
var (
	ErrConnectionClosed   = errors.New("p2p: connection closed")
	ErrConnectionFailed   = errors.New("p2p: connection failed")
	ErrConnectionTimeout  = errors.New("p2p: connection timeout")
	ErrNotConnected       = errors.New("p2p: not connected")
	ErrHandshakeFailed    = errors.New("p2p: handshake failed")
	ErrEncryptionFailed   = errors.New("p2p: encryption failed")
	ErrDecryptionFailed   = errors.New("p2p: decryption failed")
)

// P2PConnection represents a peer-to-peer connection.
type P2PConnection interface {
	// PeerID returns the remote peer's ID.
	PeerID() string

	// Send sends data to the peer.
	Send(data []byte) error

	// Receive receives data from the peer.
	Receive() ([]byte, error)

	// Latency returns the current latency to the peer.
	Latency() time.Duration

	// Type returns the connection type.
	Type() ConnectionType

	// State returns the current connection state.
	State() ConnectionState

	// LocalAddr returns the local address.
	LocalAddr() netip.AddrPort

	// RemoteAddr returns the remote address.
	RemoteAddr() netip.AddrPort

	// Close closes the connection.
	Close() error
}

// ConnectionConfig contains connection configuration.
type ConnectionConfig struct {
	// PeerID is the remote peer's ID.
	PeerID string

	// LocalPrivateKey is the local private key for encryption.
	LocalPrivateKey []byte

	// RemotePublicKey is the remote peer's public key.
	RemotePublicKey []byte

	// ConnectTimeout is the connection timeout.
	ConnectTimeout time.Duration

	// ReadTimeout is the read timeout.
	ReadTimeout time.Duration

	// WriteTimeout is the write timeout.
	WriteTimeout time.Duration

	// KeepAliveInterval is the keep-alive interval.
	KeepAliveInterval time.Duration

	// MaxRetries is the maximum number of connection retries.
	MaxRetries int
}

// DefaultConnectionConfig returns a default connection configuration.
func DefaultConnectionConfig() ConnectionConfig {
	return ConnectionConfig{
		ConnectTimeout:    10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Second,
		KeepAliveInterval: 25 * time.Second,
		MaxRetries:        3,
	}
}

// DirectConnection implements P2PConnection for direct connections.
type DirectConnection struct {
	config     ConnectionConfig
	conn       net.PacketConn
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort

	crypto     *CryptoSession
	state      atomic.Int32
	latency    atomic.Int64 // nanoseconds

	sendQueue chan []byte
	recvQueue chan []byte

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// NewDirectConnection creates a new direct P2P connection.
func NewDirectConnection(config ConnectionConfig, conn net.PacketConn, remoteAddr netip.AddrPort) (*DirectConnection, error) {
	ctx, cancel := context.WithCancel(context.Background())

	localUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	localAddr := netip.AddrPortFrom(
		netip.MustParseAddr(localUDPAddr.IP.String()),
		uint16(localUDPAddr.Port),
	)

	dc := &DirectConnection{
		config:     config,
		conn:       conn,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		ctx:        ctx,
		cancel:     cancel,
	}

	dc.state.Store(int32(ConnectionStateNew))

	return dc, nil
}

// Connect establishes the connection with the peer.
func (c *DirectConnection) Connect(ctx context.Context) error {
	c.state.Store(int32(ConnectionStateConnecting))

	// Initialize crypto session
	crypto, err := NewCryptoSession(c.config.LocalPrivateKey)
	if err != nil {
		c.state.Store(int32(ConnectionStateFailed))
		return err
	}
	c.crypto = crypto

	// Perform handshake
	if err := c.performHandshake(ctx); err != nil {
		c.state.Store(int32(ConnectionStateFailed))
		return err
	}

	c.state.Store(int32(ConnectionStateConnected))

	// Start workers
	c.wg.Add(3)
	go c.sendWorker()
	go c.recvWorker()
	go c.keepAliveWorker()

	return nil
}

// performHandshake performs the Noise Protocol handshake.
func (c *DirectConnection) performHandshake(ctx context.Context) error {
	deadline := time.Now().Add(c.config.ConnectTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetDeadline(deadline)
	defer c.conn.SetDeadline(time.Time{})

	// Send handshake initiation
	initMsg, err := c.crypto.CreateHandshakeInit(c.config.RemotePublicKey)
	if err != nil {
		return err
	}

	remoteUDPAddr := net.UDPAddrFromAddrPort(c.remoteAddr)
	if _, err := c.conn.WriteTo(initMsg, remoteUDPAddr); err != nil {
		return err
	}

	// Wait for handshake response
	buf := make([]byte, 4096)
	n, from, err := c.conn.ReadFrom(buf)
	if err != nil {
		return err
	}

	// Verify it's from the expected peer
	fromUDP := from.(*net.UDPAddr)
	if !fromUDP.IP.Equal(c.remoteAddr.Addr().AsSlice()) {
		return ErrHandshakeFailed
	}

	// Process handshake response
	if err := c.crypto.ProcessHandshakeResponse(buf[:n]); err != nil {
		return err
	}

	// Measure initial latency
	start := time.Now()
	pingMsg := c.crypto.Encrypt([]byte("PING"))
	if _, err := c.conn.WriteTo(pingMsg, remoteUDPAddr); err != nil {
		return err
	}

	n, _, err = c.conn.ReadFrom(buf)
	if err != nil {
		return err
	}

	if _, err := c.crypto.Decrypt(buf[:n]); err != nil {
		return err
	}

	c.latency.Store(time.Since(start).Nanoseconds())

	return nil
}

// sendWorker handles outgoing messages.
func (c *DirectConnection) sendWorker() {
	defer c.wg.Done()

	remoteAddr := net.UDPAddrFromAddrPort(c.remoteAddr)

	for {
		select {
		case <-c.ctx.Done():
			return
		case data := <-c.sendQueue:
			if c.State() != ConnectionStateConnected {
				continue
			}

			// Encrypt and send
			encrypted := c.crypto.Encrypt(data)
			c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
			c.conn.WriteTo(encrypted, remoteAddr)
		}
	}
}

// recvWorker handles incoming messages.
func (c *DirectConnection) recvWorker() {
	defer c.wg.Done()

	buf := make([]byte, 65536)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if c.State() != ConnectionStateConnected {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		c.conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		// Verify source
		fromUDP := from.(*net.UDPAddr)
		if !fromUDP.IP.Equal(c.remoteAddr.Addr().AsSlice()) {
			continue
		}

		// Decrypt
		decrypted, err := c.crypto.Decrypt(buf[:n])
		if err != nil {
			continue
		}

		// Handle keep-alive
		if len(decrypted) == 4 && string(decrypted) == "PING" {
			pong := c.crypto.Encrypt([]byte("PONG"))
			c.conn.WriteTo(pong, from)
			continue
		}

		if len(decrypted) == 4 && string(decrypted) == "PONG" {
			continue
		}

		// Queue for receive
		select {
		case c.recvQueue <- decrypted:
		default:
			// Queue full, drop packet
		}
	}
}

// keepAliveWorker sends periodic keep-alive messages.
func (c *DirectConnection) keepAliveWorker() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.KeepAliveInterval)
	defer ticker.Stop()

	remoteAddr := net.UDPAddrFromAddrPort(c.remoteAddr)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if c.State() != ConnectionStateConnected {
				continue
			}

			start := time.Now()
			pingMsg := c.crypto.Encrypt([]byte("PING"))
			c.conn.WriteTo(pingMsg, remoteAddr)

			// Wait for PONG (handled in recvWorker)
			// Update latency after response
			go func() {
				time.Sleep(c.config.ReadTimeout)
				// If no response, increase latency estimate
				currentLatency := time.Duration(c.latency.Load())
				if time.Since(start) > currentLatency*2 {
					c.latency.Store(time.Since(start).Nanoseconds())
				}
			}()
		}
	}
}

// PeerID returns the remote peer's ID.
func (c *DirectConnection) PeerID() string {
	return c.config.PeerID
}

// Send sends data to the peer.
func (c *DirectConnection) Send(data []byte) error {
	if c.State() != ConnectionStateConnected {
		return ErrNotConnected
	}

	select {
	case c.sendQueue <- data:
		return nil
	case <-c.ctx.Done():
		return ErrConnectionClosed
	default:
		return errors.New("send queue full")
	}
}

// Receive receives data from the peer.
func (c *DirectConnection) Receive() ([]byte, error) {
	if c.State() != ConnectionStateConnected {
		return nil, ErrNotConnected
	}

	select {
	case data := <-c.recvQueue:
		return data, nil
	case <-c.ctx.Done():
		return nil, ErrConnectionClosed
	}
}

// Latency returns the current latency.
func (c *DirectConnection) Latency() time.Duration {
	return time.Duration(c.latency.Load())
}

// Type returns the connection type.
func (c *DirectConnection) Type() ConnectionType {
	return ConnectionTypeDirect
}

// State returns the connection state.
func (c *DirectConnection) State() ConnectionState {
	return ConnectionState(c.state.Load())
}

// LocalAddr returns the local address.
func (c *DirectConnection) LocalAddr() netip.AddrPort {
	return c.localAddr
}

// RemoteAddr returns the remote address.
func (c *DirectConnection) RemoteAddr() netip.AddrPort {
	return c.remoteAddr
}

// Close closes the connection.
func (c *DirectConnection) Close() error {
	c.state.Store(int32(ConnectionStateDisconnected))
	c.cancel()
	c.wg.Wait()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// RelayedConnection implements P2PConnection for TURN-relayed connections.
type RelayedConnection struct {
	config     ConnectionConfig
	turnClient *TURNClient
	crypto     *CryptoSession
	state      atomic.Int32
	latency    atomic.Int64

	sendQueue chan []byte
	recvQueue chan []byte

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRelayedConnection creates a new relayed P2P connection.
func NewRelayedConnection(config ConnectionConfig, turnClient *TURNClient) (*RelayedConnection, error) {
	ctx, cancel := context.WithCancel(context.Background())

	rc := &RelayedConnection{
		config:     config,
		turnClient: turnClient,
		sendQueue:  make(chan []byte, 256),
		recvQueue:  make(chan []byte, 256),
		ctx:        ctx,
		cancel:     cancel,
	}

	rc.state.Store(int32(ConnectionStateNew))

	return rc, nil
}

// Connect establishes the relayed connection.
func (c *RelayedConnection) Connect(ctx context.Context, peerAddr netip.AddrPort) error {
	c.state.Store(int32(ConnectionStateConnecting))

	// Initialize crypto session
	crypto, err := NewCryptoSession(c.config.LocalPrivateKey)
	if err != nil {
		c.state.Store(int32(ConnectionStateFailed))
		return err
	}
	c.crypto = crypto

	// Create permission for peer IP
	if err := c.turnClient.CreatePermission(ctx, peerAddr.Addr()); err != nil {
		c.state.Store(int32(ConnectionStateFailed))
		return err
	}

	// Bind channel for efficient data transfer
	if _, err := c.turnClient.BindChannel(ctx, peerAddr); err != nil {
		// Channel binding is optional, continue without it
	}

	c.state.Store(int32(ConnectionStateConnected))

	// Start workers
	c.wg.Add(2)
	go c.sendWorker(peerAddr)
	go c.recvWorker()

	return nil
}

// sendWorker handles outgoing messages through the relay.
func (c *RelayedConnection) sendWorker(peerAddr netip.AddrPort) {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case data := <-c.sendQueue:
			if c.State() != ConnectionStateConnected {
				continue
			}

			encrypted := c.crypto.Encrypt(data)
			c.turnClient.Send(peerAddr, encrypted)
		}
	}
}

// recvWorker handles incoming messages from the relay.
func (c *RelayedConnection) recvWorker() {
	defer c.wg.Done()

	buf := make([]byte, 65536)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if c.State() != ConnectionStateConnected {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, _, err := c.turnClient.Receive(buf)
		if err != nil {
			continue
		}

		decrypted, err := c.crypto.Decrypt(buf[:n])
		if err != nil {
			continue
		}

		select {
		case c.recvQueue <- decrypted:
		default:
		}
	}
}

// PeerID returns the remote peer's ID.
func (c *RelayedConnection) PeerID() string {
	return c.config.PeerID
}

// Send sends data to the peer.
func (c *RelayedConnection) Send(data []byte) error {
	if c.State() != ConnectionStateConnected {
		return ErrNotConnected
	}

	select {
	case c.sendQueue <- data:
		return nil
	case <-c.ctx.Done():
		return ErrConnectionClosed
	default:
		return errors.New("send queue full")
	}
}

// Receive receives data from the peer.
func (c *RelayedConnection) Receive() ([]byte, error) {
	if c.State() != ConnectionStateConnected {
		return nil, ErrNotConnected
	}

	select {
	case data := <-c.recvQueue:
		return data, nil
	case <-c.ctx.Done():
		return nil, ErrConnectionClosed
	}
}

// Latency returns the current latency.
func (c *RelayedConnection) Latency() time.Duration {
	return time.Duration(c.latency.Load())
}

// Type returns the connection type.
func (c *RelayedConnection) Type() ConnectionType {
	return ConnectionTypeRelayed
}

// State returns the connection state.
func (c *RelayedConnection) State() ConnectionState {
	return ConnectionState(c.state.Load())
}

// LocalAddr returns the local address.
func (c *RelayedConnection) LocalAddr() netip.AddrPort {
	addr, _ := c.turnClient.RelayAddress()
	return addr
}

// RemoteAddr returns the remote address.
func (c *RelayedConnection) RemoteAddr() netip.AddrPort {
	return netip.AddrPort{}
}

// Close closes the connection.
func (c *RelayedConnection) Close() error {
	c.state.Store(int32(ConnectionStateDisconnected))
	c.cancel()
	c.wg.Wait()
	return nil
}
