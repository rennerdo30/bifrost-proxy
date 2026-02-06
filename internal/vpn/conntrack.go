package vpn

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Connection tracking limits
const (
	// MaxTrackedConnections is the maximum number of tracked connections
	MaxTrackedConnections = 50000
	// MaxNATEntries is the maximum number of NAT table entries
	MaxNATEntries = 50000
)

// ConnKey uniquely identifies a connection.
type ConnKey struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// TrackedConnection represents a connection being tracked through the VPN.
type TrackedConnection struct {
	Key           ConnKey
	ProxyConn     net.Conn // Connection through the proxy
	Created       time.Time
	LastActivity  time.Time
	BytesSent     atomic.Int64
	BytesReceived atomic.Int64
	State         ConnState
	TCP           *TCPState
}

// TCPState tracks minimal TCP sequencing state for a connection.
type TCPState struct {
	mu          sync.Mutex
	ClientISN   uint32
	ServerISN   uint32
	ClientNext  uint32
	ServerNext  uint32
	Established bool
}

// ConnState represents the state of a tracked connection.
type ConnState int

const (
	ConnStateNew ConnState = iota
	ConnStateEstablished
	ConnStateClosing
	ConnStateClosed
)

// ConnTracker manages tracked VPN connections.
type ConnTracker struct {
	connections map[ConnKey]*TrackedConnection
	mu          sync.RWMutex
	closed      bool

	// Cleanup settings
	idleTimeout time.Duration
	cleanupTick time.Duration
	done        chan struct{}
}

// ConnTrackerConfig holds configuration for the connection tracker.
type ConnTrackerConfig struct {
	// IdleTimeout is the maximum time a connection can be idle before being cleaned up.
	// Default: 5 minutes.
	IdleTimeout time.Duration
	// CleanupInterval is the interval between cleanup runs.
	// Default: 30 seconds.
	CleanupInterval time.Duration
}

// DefaultConnTrackerConfig returns the default configuration.
func DefaultConnTrackerConfig() ConnTrackerConfig {
	return ConnTrackerConfig{
		IdleTimeout:     5 * time.Minute,
		CleanupInterval: 30 * time.Second,
	}
}

// NewConnTracker creates a new connection tracker with default configuration.
func NewConnTracker() *ConnTracker {
	return NewConnTrackerWithConfig(DefaultConnTrackerConfig())
}

// NewConnTrackerWithConfig creates a new connection tracker with the given configuration.
func NewConnTrackerWithConfig(cfg ConnTrackerConfig) *ConnTracker {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 30 * time.Second
	}

	ct := &ConnTracker{
		connections: make(map[ConnKey]*TrackedConnection),
		idleTimeout: cfg.IdleTimeout,
		cleanupTick: cfg.CleanupInterval,
		done:        make(chan struct{}),
	}

	go ct.cleanupLoop()

	return ct
}

// Add adds a new tracked connection.
func (ct *ConnTracker) Add(conn *TrackedConnection) {
	var evictedConn net.Conn

	ct.mu.Lock()
	if ct.closed {
		ct.mu.Unlock()
		return
	}

	// Enforce connection limit - evict oldest if at capacity
	if len(ct.connections) >= MaxTrackedConnections {
		evictedConn = ct.evictOldestLocked()
	}

	conn.Created = time.Now()
	conn.LastActivity = time.Now()
	conn.State = ConnStateNew

	ct.connections[conn.Key] = conn
	ct.mu.Unlock()

	// Close evicted connection outside the lock to avoid blocking
	if evictedConn != nil {
		evictedConn.Close()
	}
}

// evictOldestLocked removes the oldest connection from the map. Must be called with mu held.
// Returns the evicted connection's ProxyConn (if any) so the caller can close it outside the lock.
func (ct *ConnTracker) evictOldestLocked() net.Conn {
	var oldestKey ConnKey
	var oldestTime time.Time

	for key, conn := range ct.connections {
		if oldestTime.IsZero() || conn.LastActivity.Before(oldestTime) {
			oldestKey = key
			oldestTime = conn.LastActivity
		}
	}

	if !oldestTime.IsZero() {
		if conn, ok := ct.connections[oldestKey]; ok {
			proxyConn := conn.ProxyConn
			delete(ct.connections, oldestKey)
			return proxyConn
		}
	}
	return nil
}

// Get retrieves a tracked connection by its key.
func (ct *ConnTracker) Get(key ConnKey) *TrackedConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	return ct.connections[key]
}

// GetByRemote retrieves a tracked connection by remote address and protocol.
func (ct *ConnTracker) GetByRemote(remoteIP netip.Addr, remotePort uint16, protocol uint8) *TrackedConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	for _, conn := range ct.connections {
		if conn.Key.DstIP == remoteIP && conn.Key.DstPort == remotePort && conn.Key.Protocol == protocol {
			return conn
		}
	}
	return nil
}

// Remove removes a tracked connection.
func (ct *ConnTracker) Remove(key ConnKey) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	delete(ct.connections, key)
}

// UpdateActivity updates the last activity time for a connection.
func (ct *ConnTracker) UpdateActivity(key ConnKey) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if conn, ok := ct.connections[key]; ok {
		conn.LastActivity = time.Now()
	}
}

// SetState sets the state of a tracked connection.
func (ct *ConnTracker) SetState(key ConnKey, state ConnState) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if conn, ok := ct.connections[key]; ok {
		conn.State = state
	}
}

// All returns a copy of all tracked connections.
func (ct *ConnTracker) All() []*TrackedConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make([]*TrackedConnection, 0, len(ct.connections))
	for _, conn := range ct.connections {
		result = append(result, conn)
	}
	return result
}

// Count returns the number of tracked connections.
func (ct *ConnTracker) Count() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	return len(ct.connections)
}

// Close closes the connection tracker and all tracked connections.
func (ct *ConnTracker) Close() {
	ct.mu.Lock()
	if ct.closed {
		ct.mu.Unlock()
		return
	}

	ct.closed = true
	close(ct.done)

	// Collect connections to close
	var toClose []net.Conn
	for key, conn := range ct.connections {
		if conn.ProxyConn != nil {
			toClose = append(toClose, conn.ProxyConn)
		}
		delete(ct.connections, key)
	}
	ct.mu.Unlock()

	// Close connections outside the lock
	for _, c := range toClose {
		c.Close()
	}
}

// cleanupLoop periodically removes idle connections.
func (ct *ConnTracker) cleanupLoop() {
	ticker := time.NewTicker(ct.cleanupTick)
	defer ticker.Stop()

	for {
		select {
		case <-ct.done:
			return
		case <-ticker.C:
			ct.cleanupIdleConnections()
		}
	}
}

// cleanupIdleConnections removes connections that have been idle too long.
func (ct *ConnTracker) cleanupIdleConnections() {
	// Collect idle connections under lock
	ct.mu.Lock()
	now := time.Now()
	var toClose []net.Conn

	for key, conn := range ct.connections {
		if now.Sub(conn.LastActivity) > ct.idleTimeout {
			if conn.ProxyConn != nil {
				toClose = append(toClose, conn.ProxyConn)
			}
			delete(ct.connections, key)
		}
	}
	ct.mu.Unlock()

	// Close connections outside the lock to avoid blocking other operations
	for _, c := range toClose {
		c.Close()
	}
}

// Stats returns connection tracking statistics.
func (ct *ConnTracker) Stats() ConnTrackerStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	stats := ConnTrackerStats{
		TotalConnections: len(ct.connections),
	}

	for _, conn := range ct.connections {
		switch conn.State {
		case ConnStateNew:
			stats.NewConnections++
		case ConnStateEstablished:
			stats.EstablishedConnections++
		case ConnStateClosing:
			stats.ClosingConnections++
		}

		switch conn.Key.Protocol {
		case ProtocolTCP:
			stats.TCPConnections++
		case ProtocolUDP:
			stats.UDPConnections++
		}

		stats.TotalBytesSent += conn.BytesSent.Load()
		stats.TotalBytesReceived += conn.BytesReceived.Load()
	}

	return stats
}

// ConnTrackerStats contains connection tracking statistics.
type ConnTrackerStats struct {
	TotalConnections       int   `json:"total_connections"`
	NewConnections         int   `json:"new_connections"`
	EstablishedConnections int   `json:"established_connections"`
	ClosingConnections     int   `json:"closing_connections"`
	TCPConnections         int   `json:"tcp_connections"`
	UDPConnections         int   `json:"udp_connections"`
	TotalBytesSent         int64 `json:"total_bytes_sent"`
	TotalBytesReceived     int64 `json:"total_bytes_received"`
}

// NATEntry represents a NAT mapping for the VPN.
type NATEntry struct {
	OriginalSrc  netip.AddrPort
	MappedSrc    netip.AddrPort
	Destination  netip.AddrPort
	Protocol     uint8
	Created      time.Time
	LastActivity time.Time
}

// NATTable manages NAT mappings for the VPN.
type NATTable struct {
	// Forward mapping: original -> mapped
	forward map[string]*NATEntry
	// Reverse mapping: mapped -> original
	reverse map[string]*NATEntry

	nextPort  uint16
	basePort  uint16
	maxPort   uint16
	localAddr netip.Addr

	mu sync.RWMutex
}

// NewNATTable creates a new NAT table.
func NewNATTable(localAddr netip.Addr, basePort, maxPort uint16) *NATTable {
	return &NATTable{
		forward:   make(map[string]*NATEntry),
		reverse:   make(map[string]*NATEntry),
		nextPort:  basePort,
		basePort:  basePort,
		maxPort:   maxPort,
		localAddr: localAddr,
	}
}

// Lookup looks up a NAT entry by original source and destination.
func (nt *NATTable) Lookup(src, dst netip.AddrPort, protocol uint8) *NATEntry {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	key := nt.forwardKey(src, dst, protocol)
	return nt.forward[key]
}

// LookupReverse looks up a NAT entry by mapped source.
func (nt *NATTable) LookupReverse(mapped netip.AddrPort, protocol uint8) *NATEntry {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	key := nt.reverseKey(mapped, protocol)
	return nt.reverse[key]
}

// Allocate allocates a new NAT mapping.
func (nt *NATTable) Allocate(src, dst netip.AddrPort, protocol uint8) (*NATEntry, error) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	// Check if mapping already exists
	fwdKey := nt.forwardKey(src, dst, protocol)
	if entry, ok := nt.forward[fwdKey]; ok {
		entry.LastActivity = time.Now()
		return entry, nil
	}

	// Enforce entry limit - evict oldest if at capacity
	if len(nt.forward) >= MaxNATEntries {
		nt.evictOldestLocked()
	}

	// Find an available port
	port := nt.nextPort
	startPort := port

	for {
		mapped := netip.AddrPortFrom(nt.localAddr, port)
		revKey := nt.reverseKey(mapped, protocol)

		if _, exists := nt.reverse[revKey]; !exists {
			// Port is available
			entry := &NATEntry{
				OriginalSrc:  src,
				MappedSrc:    mapped,
				Destination:  dst,
				Protocol:     protocol,
				Created:      time.Now(),
				LastActivity: time.Now(),
			}

			nt.forward[fwdKey] = entry
			nt.reverse[revKey] = entry

			nt.nextPort = port + 1
			if nt.nextPort > nt.maxPort {
				nt.nextPort = nt.basePort
			}

			return entry, nil
		}

		port++
		if port > nt.maxPort {
			port = nt.basePort
		}

		if port == startPort {
			return nil, ErrNATTableFull
		}
	}
}

// evictOldestLocked removes the oldest NAT entry. Must be called with mu held.
func (nt *NATTable) evictOldestLocked() {
	var oldestKey string
	var oldestEntry *NATEntry

	for fwdKey, entry := range nt.forward {
		if oldestEntry == nil || entry.LastActivity.Before(oldestEntry.LastActivity) {
			oldestKey = fwdKey
			oldestEntry = entry
		}
	}

	if oldestEntry != nil {
		revKey := nt.reverseKey(oldestEntry.MappedSrc, oldestEntry.Protocol)
		delete(nt.forward, oldestKey)
		delete(nt.reverse, revKey)
	}
}

// Release releases a NAT mapping.
func (nt *NATTable) Release(src, dst netip.AddrPort, protocol uint8) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	fwdKey := nt.forwardKey(src, dst, protocol)
	if entry, ok := nt.forward[fwdKey]; ok {
		revKey := nt.reverseKey(entry.MappedSrc, protocol)
		delete(nt.forward, fwdKey)
		delete(nt.reverse, revKey)
	}
}

// forwardKey generates a key for the forward mapping.
func (nt *NATTable) forwardKey(src, dst netip.AddrPort, protocol uint8) string {
	return src.String() + "->" + dst.String() + ":" + string(rune(protocol))
}

// reverseKey generates a key for the reverse mapping.
func (nt *NATTable) reverseKey(mapped netip.AddrPort, protocol uint8) string {
	return mapped.String() + ":" + string(rune(protocol))
}

// Cleanup removes expired NAT entries.
func (nt *NATTable) Cleanup(maxAge time.Duration) int {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	now := time.Now()
	count := 0

	for fwdKey, entry := range nt.forward {
		if now.Sub(entry.LastActivity) > maxAge {
			revKey := nt.reverseKey(entry.MappedSrc, entry.Protocol)
			delete(nt.forward, fwdKey)
			delete(nt.reverse, revKey)
			count++
		}
	}

	return count
}

// Error types for NAT table.
var (
	ErrNATTableFull = &NATError{Message: "NAT table is full, no ports available"}
)

// NATError represents a NAT-related error.
type NATError struct {
	Message string
}

func (e *NATError) Error() string {
	return e.Message
}
