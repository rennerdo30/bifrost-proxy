package p2p

import (
	"context"
	"errors"
	"log/slog"
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
	ErrConnectionClosed  = errors.New("p2p: connection closed")
	ErrConnectionFailed  = errors.New("p2p: connection failed")
	ErrConnectionTimeout = errors.New("p2p: connection timeout")
	ErrNotConnected      = errors.New("p2p: not connected")
	ErrHandshakeFailed   = errors.New("p2p: handshake failed")
	ErrEncryptionFailed  = errors.New("p2p: encryption failed")
	ErrDecryptionFailed  = errors.New("p2p: decryption failed")
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
//
// The manager owns the shared UDP socket and is the sole reader of it. Inbound
// datagrams destined for this connection are pushed by the manager into the
// inbound channel (raw ciphertext); recvWorker decrypts them, filters
// keep-alive traffic, and delivers plaintext via the onData callback (and the
// recvQueue for callers that prefer the Receive() API). The connection never
// reads from the socket directly, eliminating the dual-reader race.
type DirectConnection struct {
	config     ConnectionConfig
	conn       net.PacketConn
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort

	crypto  *CryptoSession
	state   atomic.Int32
	latency atomic.Int64 // nanoseconds

	sendQueue chan []byte
	recvQueue chan []byte

	// inbound carries raw ciphertext datagrams routed by the manager's
	// receiveWorker once the connection is established.
	inbound chan []byte

	// handshakeInbound carries raw datagrams during the handshake phase, fed by
	// the manager so the connection does not read from the shared socket.
	handshakeInbound chan []byte

	// onData, when set, receives decrypted plaintext payloads. Keep-alive
	// (PING/PONG) traffic is filtered out before this is invoked.
	onData func(peerID string, plaintext []byte)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDirectConnection creates a new direct P2P connection.
func NewDirectConnection(config ConnectionConfig, conn net.PacketConn, remoteAddr netip.AddrPort) (*DirectConnection, error) {
	ctx, cancel := context.WithCancel(context.Background())

	localUDPAddr := conn.LocalAddr().(*net.UDPAddr) //nolint:errcheck // Type is always *net.UDPAddr for UDP connections
	localAddr := netip.AddrPortFrom(
		netip.MustParseAddr(localUDPAddr.IP.String()),
		uint16(localUDPAddr.Port), //nolint:gosec // G115: UDP port is always 0-65535
	)

	dc := &DirectConnection{
		config:           config,
		conn:             conn,
		remoteAddr:       remoteAddr,
		localAddr:        localAddr,
		sendQueue:        make(chan []byte, 256),
		recvQueue:        make(chan []byte, 256),
		inbound:          make(chan []byte, 256),
		handshakeInbound: make(chan []byte, 8),
		ctx:              ctx,
		cancel:           cancel,
	}

	dc.state.Store(int32(ConnectionStateNew))

	return dc, nil
}

// SetOnData sets the callback invoked with decrypted plaintext payloads.
// It must be set before the connection is started.
func (c *DirectConnection) SetOnData(fn func(peerID string, plaintext []byte)) {
	c.onData = fn
}

// deliverDatagram routes a raw inbound datagram (read by the manager from the
// shared socket) to this connection for decryption. Returns false if the
// connection is shutting down.
func (c *DirectConnection) deliverDatagram(data []byte) bool {
	// Copy: the manager reuses its read buffer for the next datagram.
	buf := make([]byte, len(data))
	copy(buf, data)

	if c.State() != ConnectionStateConnected {
		// Still handshaking: route to the handshake channel.
		select {
		case c.handshakeInbound <- buf:
			return true
		case <-c.ctx.Done():
			return false
		default:
			return true
		}
	}

	select {
	case c.inbound <- buf:
		return true
	case <-c.ctx.Done():
		return false
	default:
		// Inbound queue full, drop datagram.
		return true
	}
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
//
// The manager is the sole reader of the shared socket, so handshake response
// datagrams arrive via handshakeInbound rather than a direct ReadFrom. Outbound
// writes still go through the shared socket.
func (c *DirectConnection) performHandshake(ctx context.Context) error {
	deadline := time.Now().Add(c.config.ConnectTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// Send handshake initiation
	initMsg, err := c.crypto.CreateHandshakeInit(c.config.RemotePublicKey)
	if err != nil {
		return err
	}

	remoteUDPAddr := net.UDPAddrFromAddrPort(c.remoteAddr)
	if _, writeErr := c.conn.WriteTo(initMsg, remoteUDPAddr); writeErr != nil {
		return writeErr
	}

	// Wait for handshake response (routed by the manager).
	respData, err := c.waitHandshakeDatagram(ctx, deadline)
	if err != nil {
		return err
	}

	// Process handshake response
	if processErr := c.crypto.ProcessHandshakeResponse(respData); processErr != nil {
		return processErr
	}

	// Measure initial latency
	start := time.Now()
	pingMsg := c.crypto.Encrypt([]byte("PING"))
	if _, pingWriteErr := c.conn.WriteTo(pingMsg, remoteUDPAddr); pingWriteErr != nil {
		return pingWriteErr
	}

	pongData, err := c.waitHandshakeDatagram(ctx, deadline)
	if err != nil {
		return err
	}

	if _, decryptErr := c.crypto.Decrypt(pongData); decryptErr != nil {
		return decryptErr
	}

	c.latency.Store(time.Since(start).Nanoseconds())

	return nil
}

// waitHandshakeDatagram waits for the next datagram routed to this connection
// during the handshake phase, honoring the context and deadline.
func (c *DirectConnection) waitHandshakeDatagram(ctx context.Context, deadline time.Time) ([]byte, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case data := <-c.handshakeInbound:
		return data, nil
	case <-timer.C:
		return nil, ErrConnectionTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, ErrConnectionClosed
	}
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

			// Encrypt and send.
			//
			// The socket is shared and owned by the manager; do not set write
			// deadlines here. A per-connection write deadline races with the
			// manager's read deadline on the same socket, and a zero WriteTimeout
			// would make every UDP write time out immediately.
			encrypted := c.crypto.Encrypt(data)
			if _, err := c.conn.WriteTo(encrypted, remoteAddr); err != nil {
				slog.Debug("failed to write to connection", "error", err)
			}
		}
	}
}

// recvWorker decrypts inbound datagrams routed by the manager.
//
// It does not read from the shared socket directly. Datagrams arrive via the
// inbound channel (raw ciphertext), are decrypted, and keep-alive (PING/PONG)
// traffic is filtered out. Decrypted application payloads are delivered through
// the onData callback (if set) and queued for the Receive() API.
func (c *DirectConnection) recvWorker() {
	defer c.wg.Done()

	remoteAddr := net.UDPAddrFromAddrPort(c.remoteAddr)

	for {
		select {
		case <-c.ctx.Done():
			return
		case data := <-c.inbound:
			// Decrypt
			decrypted, err := c.crypto.Decrypt(data)
			if err != nil {
				continue
			}

			// Handle keep-alive: respond to PING, swallow PONG. Never surface
			// these to the application layer.
			if len(decrypted) == 4 && string(decrypted) == "PING" {
				pong := c.crypto.Encrypt([]byte("PONG"))
				if _, writeErr := c.conn.WriteTo(pong, remoteAddr); writeErr != nil {
					slog.Debug("failed to send pong", "error", writeErr)
				}
				continue
			}

			if len(decrypted) == 4 && string(decrypted) == "PONG" {
				continue
			}

			// Deliver decrypted application payload.
			if c.onData != nil {
				c.onData(c.config.PeerID, decrypted)
			}

			// Also queue for callers using the Receive() API.
			select {
			case c.recvQueue <- decrypted:
			default:
				// Queue full, drop packet.
			}
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
			if _, err := c.conn.WriteTo(pingMsg, remoteAddr); err != nil {
				slog.Debug("failed to send ping", "error", err)
			}

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

	// onData, when set, receives decrypted plaintext payloads so relayed
	// traffic surfaces through the same mechanism as direct connections.
	onData func(peerID string, plaintext []byte)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// SetOnData sets the callback invoked with decrypted plaintext payloads.
// It must be set before the connection is started.
func (c *RelayedConnection) SetOnData(fn func(peerID string, plaintext []byte)) {
	c.onData = fn
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

	// Bind channel for efficient data transfer (optional, continue if it fails)
	_, _ = c.turnClient.BindChannel(ctx, peerAddr) //nolint:errcheck // Optional optimization

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
			_ = c.turnClient.Send(peerAddr, encrypted) //nolint:errcheck // Best effort send through TURN relay
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

		// Filter keep-alive traffic so it does not reach the application layer.
		if len(decrypted) == 4 && (string(decrypted) == "PING" || string(decrypted) == "PONG") {
			continue
		}

		// Deliver decrypted application payload through the unified callback so
		// relayed connections surface inbound data the same way direct ones do.
		if c.onData != nil {
			c.onData(c.config.PeerID, decrypted)
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
	addr, _ := c.turnClient.RelayAddress() //nolint:errcheck // Return zero value if relay not allocated
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
