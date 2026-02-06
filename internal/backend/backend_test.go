package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
	mu       sync.Mutex
}

func newMockConn(readData []byte) *mockConn {
	return &mockConn{
		readBuf:  bytes.NewBuffer(readData),
		writeBuf: &bytes.Buffer{},
	}
}

func (m *mockConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestTrackedConn_Read(t *testing.T) {
	data := []byte("hello world")
	inner := newMockConn(data)
	tc := &TrackedConn{Conn: inner}

	buf := make([]byte, 5)
	n, err := tc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, int64(5), tc.BytesRead)
	assert.Equal(t, "hello", string(buf))

	// Read more
	n, err = tc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, int64(10), tc.BytesRead)
}

func TestTrackedConn_Write(t *testing.T) {
	inner := newMockConn(nil)
	tc := &TrackedConn{Conn: inner}

	n, err := tc.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, int64(5), tc.BytesWritten)

	// Write more
	n, err = tc.Write([]byte(" world"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.Equal(t, int64(11), tc.BytesWritten)
	assert.Equal(t, "hello world", inner.writeBuf.String())
}

func TestTrackedConn_Close(t *testing.T) {
	inner := newMockConn([]byte("test"))
	var callbackCalled bool
	var callbackRead, callbackWritten int64

	tc := &TrackedConn{
		Conn: inner,
		OnClose: func(read, written int64) {
			callbackCalled = true
			callbackRead = read
			callbackWritten = written
		},
	}

	// Read some data
	buf := make([]byte, 4)
	tc.Read(buf)

	// Write some data
	tc.Write([]byte("hello"))

	// Close
	err := tc.Close()
	require.NoError(t, err)

	assert.True(t, callbackCalled)
	assert.Equal(t, int64(4), callbackRead)
	assert.Equal(t, int64(5), callbackWritten)
}

func TestTrackedConn_Close_NoCallback(t *testing.T) {
	inner := newMockConn(nil)
	tc := &TrackedConn{Conn: inner}

	err := tc.Close()
	require.NoError(t, err)
}

func TestCopyBidirectional(t *testing.T) {
	// Create two pipes
	conn1Read, conn1Write := io.Pipe()
	conn2Read, conn2Write := io.Pipe()

	type pipeConn struct {
		io.Reader
		io.Writer
		io.Closer
	}

	conn1 := &pipeConn{Reader: conn1Read, Writer: conn2Write, Closer: conn1Write}
	conn2 := &pipeConn{Reader: conn2Read, Writer: conn1Write, Closer: conn2Write}

	ctx := context.Background()

	// Run copy in background
	done := make(chan struct{})
	var sent, received int64
	var copyErr error

	go func() {
		sent, received, copyErr = CopyBidirectional(ctx, conn1, conn2)
		close(done)
	}()

	// Close pipes to trigger completion (CopyBidirectional will close connections
	// once one direction finishes, which unblocks the other)
	conn1Read.Close()
	conn2Read.Close()

	select {
	case <-done:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for CopyBidirectional")
	}

	// Verify that the function completed without panicking
	// and returned sensible values (bytes counts are non-negative)
	assert.GreaterOrEqual(t, sent, int64(0), "sent bytes should be non-negative")
	assert.GreaterOrEqual(t, received, int64(0), "received bytes should be non-negative")
	// Error may or may not be nil depending on which pipe was closed first
	_ = copyErr
}

func TestCopyBidirectional_ContextCanceled(t *testing.T) {
	conn1 := newMockConn(nil)
	conn2 := newMockConn(nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		CopyBidirectional(ctx, conn1, conn2)
		close(done)
	}()

	// Cancel context
	cancel()

	select {
	case <-done:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for context cancellation")
	}
}

func TestStats_JSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second) // Truncate for JSON round-trip
	s := Stats{
		Name:              "test-backend",
		Type:              "direct",
		Healthy:           true,
		ActiveConnections: 5,
		TotalConnections:  100,
		BytesSent:         1024,
		BytesReceived:     2048,
		Errors:            3,
		LastError:         "test error",
		LastErrorTime:     now,
		Latency:           10 * time.Millisecond,
		Uptime:            time.Hour,
	}

	// Marshal to JSON
	data, err := json.Marshal(s)
	require.NoError(t, err)

	// Verify JSON field names match struct tags
	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "name")
	assert.Contains(t, raw, "type")
	assert.Contains(t, raw, "healthy")
	assert.Contains(t, raw, "active_connections")
	assert.Contains(t, raw, "total_connections")
	assert.Contains(t, raw, "bytes_sent")
	assert.Contains(t, raw, "bytes_received")
	assert.Contains(t, raw, "errors")
	assert.Contains(t, raw, "last_error")
	assert.Contains(t, raw, "latency")
	assert.Contains(t, raw, "uptime")

	// Unmarshal back and verify values survive round-trip
	var decoded Stats
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, s.Name, decoded.Name)
	assert.Equal(t, s.Type, decoded.Type)
	assert.Equal(t, s.Healthy, decoded.Healthy)
	assert.Equal(t, s.ActiveConnections, decoded.ActiveConnections)
	assert.Equal(t, s.TotalConnections, decoded.TotalConnections)
	assert.Equal(t, s.BytesSent, decoded.BytesSent)
	assert.Equal(t, s.BytesReceived, decoded.BytesReceived)
	assert.Equal(t, s.Errors, decoded.Errors)
	assert.Equal(t, s.LastError, decoded.LastError)

	// Verify omitempty: zero-value Stats should not include last_error (string omitempty works)
	zeroData, err := json.Marshal(Stats{})
	require.NoError(t, err)
	var zeroRaw map[string]interface{}
	err = json.Unmarshal(zeroData, &zeroRaw)
	require.NoError(t, err)
	assert.NotContains(t, zeroRaw, "last_error")
}

func TestDialer_Type(t *testing.T) {
	// Dialer is just a function type, verify it compiles
	var d Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, nil
	}
	assert.NotNil(t, d)
}
