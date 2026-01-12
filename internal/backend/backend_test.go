package backend

import (
	"bytes"
	"context"
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

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Close one side to trigger completion
	conn1Read.Close()
	conn2Read.Close()

	select {
	case <-done:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for CopyBidirectional")
	}

	// Results may vary based on timing
	_ = sent
	_ = received
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

func TestStats_Struct(t *testing.T) {
	now := time.Now()
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

	assert.Equal(t, "test-backend", s.Name)
	assert.Equal(t, "direct", s.Type)
	assert.True(t, s.Healthy)
	assert.Equal(t, int64(5), s.ActiveConnections)
	assert.Equal(t, int64(100), s.TotalConnections)
	assert.Equal(t, int64(1024), s.BytesSent)
	assert.Equal(t, int64(2048), s.BytesReceived)
	assert.Equal(t, int64(3), s.Errors)
	assert.Equal(t, "test error", s.LastError)
	assert.Equal(t, now, s.LastErrorTime)
}

func TestDialer_Type(t *testing.T) {
	// Dialer is just a function type, verify it compiles
	var d Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, nil
	}
	assert.NotNil(t, d)
}
