package server

import (
	"sync"
	"sync/atomic"
	"time"
)

// Connection represents an active proxy connection.
type Connection struct {
	ID         string    `json:"id"`
	ClientIP   string    `json:"client_ip"`
	ClientPort string    `json:"client_port"`
	Host       string    `json:"host"`
	Backend    string    `json:"backend"`
	Protocol   string    `json:"protocol"` // HTTP, SOCKS5, CONNECT
	StartTime  time.Time `json:"start_time"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
}

// ConnectionTracker tracks active proxy connections.
type ConnectionTracker struct {
	mu          sync.RWMutex
	connections map[string]*trackedConnection
	nextID      atomic.Int64
}

// trackedConnection wraps Connection with atomic byte counters.
type trackedConnection struct {
	conn      Connection
	bytesSent atomic.Int64
	bytesRecv atomic.Int64
}

// NewConnectionTracker creates a new connection tracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*trackedConnection),
	}
}

// Add adds a new connection and returns its ID.
func (t *ConnectionTracker) Add(clientIP, clientPort, host, backend, protocol string) string {
	id := t.nextID.Add(1)
	connID := generateConnID(id)

	conn := &trackedConnection{
		conn: Connection{
			ID:         connID,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			Host:       host,
			Backend:    backend,
			Protocol:   protocol,
			StartTime:  time.Now(),
		},
	}

	t.mu.Lock()
	t.connections[connID] = conn
	t.mu.Unlock()

	return connID
}

// Remove removes a connection by ID.
func (t *ConnectionTracker) Remove(id string) {
	t.mu.Lock()
	delete(t.connections, id)
	t.mu.Unlock()
}

// Get returns a snapshot of the tracked connection and true when it exists.
func (t *ConnectionTracker) Get(id string) (Connection, bool) {
	t.mu.RLock()
	tc, ok := t.connections[id]
	t.mu.RUnlock()
	if !ok {
		return Connection{}, false
	}
	conn := tc.conn
	conn.BytesSent = tc.bytesSent.Load()
	conn.BytesRecv = tc.bytesRecv.Load()
	return conn, true
}

// SetDestination sets the destination host and backend for a tracked
// connection once they are known (after CONNECT / backend selection). It
// returns a snapshot of the updated connection and true when the connection is
// still tracked, or a zero Connection and false otherwise.
func (t *ConnectionTracker) SetDestination(id, host, backend string) (Connection, bool) {
	t.mu.Lock()
	tc, ok := t.connections[id]
	if !ok {
		t.mu.Unlock()
		return Connection{}, false
	}
	tc.conn.Host = host
	tc.conn.Backend = backend
	snapshot := tc.conn
	t.mu.Unlock()

	snapshot.BytesSent = tc.bytesSent.Load()
	snapshot.BytesRecv = tc.bytesRecv.Load()
	return snapshot, true
}

// UpdateBytes updates the byte counters for a connection.
func (t *ConnectionTracker) UpdateBytes(id string, sent, recv int64) {
	t.mu.RLock()
	conn, ok := t.connections[id]
	t.mu.RUnlock()

	if ok {
		conn.bytesSent.Add(sent)
		conn.bytesRecv.Add(recv)
	}
}

// GetAll returns all active connections.
func (t *ConnectionTracker) GetAll() []Connection {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]Connection, 0, len(t.connections))
	for _, tc := range t.connections {
		conn := tc.conn
		conn.BytesSent = tc.bytesSent.Load()
		conn.BytesRecv = tc.bytesRecv.Load()
		result = append(result, conn)
	}
	return result
}

// Count returns the number of active connections.
func (t *ConnectionTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.connections)
}

// GetByClient returns connections for a specific client IP.
func (t *ConnectionTracker) GetByClient(clientIP string) []Connection {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []Connection
	for _, tc := range t.connections {
		if tc.conn.ClientIP == clientIP {
			conn := tc.conn
			conn.BytesSent = tc.bytesSent.Load()
			conn.BytesRecv = tc.bytesRecv.Load()
			result = append(result, conn)
		}
	}
	return result
}

// GetUniqueClients returns a list of unique client IPs with connection counts.
func (t *ConnectionTracker) GetUniqueClients() []ClientSummary {
	t.mu.RLock()
	defer t.mu.RUnlock()

	clients := make(map[string]*ClientSummary)
	for _, tc := range t.connections {
		ip := tc.conn.ClientIP
		if c, ok := clients[ip]; ok {
			c.Connections++
			c.BytesSent += tc.bytesSent.Load()
			c.BytesRecv += tc.bytesRecv.Load()
			if tc.conn.StartTime.Before(c.FirstSeen) {
				c.FirstSeen = tc.conn.StartTime
			}
		} else {
			clients[ip] = &ClientSummary{
				ClientIP:    ip,
				Connections: 1,
				BytesSent:   tc.bytesSent.Load(),
				BytesRecv:   tc.bytesRecv.Load(),
				FirstSeen:   tc.conn.StartTime,
			}
		}
	}

	result := make([]ClientSummary, 0, len(clients))
	for _, c := range clients {
		result = append(result, *c)
	}
	return result
}

// ClientSummary summarizes connections from a single client.
type ClientSummary struct {
	ClientIP    string    `json:"client_ip"`
	Connections int       `json:"connections"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`
	FirstSeen   time.Time `json:"first_seen"`
}

func generateConnID(id int64) string {
	return time.Now().Format("20060102150405") + "-" + itoa(id)
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := 19
	for i > 0 {
		b[pos] = byte('0' + i%10)
		i /= 10
		pos--
	}
	return string(b[pos+1:])
}
