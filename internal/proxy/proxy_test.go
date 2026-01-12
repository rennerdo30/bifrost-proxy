package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

func TestHTTPHandler_ServeConn(t *testing.T) {
	// Create a test HTTP server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from target"))
	}))
	defer targetServer.Close()

	// Create a direct backend
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-direct"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	// Create handler
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 5 * time.Second,
	})

	// Create a pipe to simulate client connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Send request in background
	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Send HTTP request
	req, err := http.NewRequest("GET", targetServer.URL, nil)
	require.NoError(t, err)
	req.Host = targetServer.Listener.Addr().String()

	err = req.Write(clientConn)
	require.NoError(t, err)

	// This is a simplified test - full integration would need proper request handling
	clientConn.Close()
}

func TestCopyBidirectional(t *testing.T) {
	// Create two pipes
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()

	defer client1.Close()
	defer client2.Close()

	// Start bidirectional copy
	done := make(chan struct{})
	go func() {
		CopyBidirectional(context.Background(), server1, server2)
		close(done)
	}()

	// Write from client1, read from client2
	testData := []byte("Hello, World!")
	go func() {
		client1.Write(testData)
		client1.Close()
	}()

	received := make([]byte, len(testData))
	n, err := io.ReadFull(client2, received)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		// Connection may close during read, which is expected
		t.Logf("Read returned: %v (read %d bytes)", err, n)
	}

	client2.Close()
	<-done
}

func TestHTTPHandler_CONNECT(t *testing.T) {
	// Create a direct backend
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-direct"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	var connectCalled bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 5 * time.Second,
		OnConnect: func(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
			connectCalled = true
		},
	})

	assert.NotNil(t, handler)
	assert.False(t, connectCalled, "OnConnect should not be called without a CONNECT request")
	// Full CONNECT test would require more setup
}

func TestCopyStats_TotalBytes(t *testing.T) {
	stats := CopyStats{
		BytesSent:     1024,
		BytesReceived: 2048,
		Duration:      time.Second,
	}

	assert.Equal(t, int64(3072), stats.TotalBytes())
}

func TestCopyStats_Throughput(t *testing.T) {
	stats := CopyStats{
		BytesSent:     1000,
		BytesReceived: 2000,
		Duration:      time.Second,
	}

	// 3000 bytes / 1 second = 3000 bytes/second
	assert.Equal(t, float64(3000), stats.Throughput())
}

func TestCopyStats_Throughput_ZeroDuration(t *testing.T) {
	stats := CopyStats{
		BytesSent:     1000,
		BytesReceived: 2000,
		Duration:      0,
	}

	assert.Equal(t, float64(0), stats.Throughput())
}

func TestCopyBidirectionalWithStats(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()

	defer client1.Close()
	defer client2.Close()

	done := make(chan CopyStats)
	go func() {
		stats := CopyBidirectionalWithStats(context.Background(), server1, server2)
		done <- stats
	}()

	// Write data and close
	testData := []byte("test data")
	go func() {
		client1.Write(testData)
		time.Sleep(10 * time.Millisecond)
		client1.Close()
	}()

	// Read data
	go func() {
		buf := make([]byte, 100)
		client2.Read(buf)
		time.Sleep(10 * time.Millisecond)
		client2.Close()
	}()

	select {
	case stats := <-done:
		assert.NotNil(t, stats)
		assert.True(t, stats.Duration > 0)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for copy")
	}
}

func TestHTTPHandlerConfig_Struct(t *testing.T) {
	var connectCalled bool
	var errorCalled bool

	cfg := HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		DialTimeout: 10 * time.Second,
		OnConnect: func(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
			connectCalled = true
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled = true
		},
	}

	assert.NotNil(t, cfg.GetBackend)
	assert.Equal(t, 10*time.Second, cfg.DialTimeout)
	assert.NotNil(t, cfg.OnConnect)
	assert.NotNil(t, cfg.OnError)

	// Test callbacks
	cfg.OnConnect(context.Background(), nil, "test", nil)
	cfg.OnError(context.Background(), nil, "test", nil)
	assert.True(t, connectCalled)
	assert.True(t, errorCalled)
}

func TestNewHTTPHandler(t *testing.T) {
	cfg := HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	}

	handler := NewHTTPHandler(cfg)
	assert.NotNil(t, handler)
}

func TestCopyBidirectional_ContextCanceled(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()

	defer client1.Close()
	defer client2.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		CopyBidirectional(ctx, server1, server2)
		close(done)
	}()

	// Cancel context after brief delay
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Close connections to unblock
	server1.Close()
	server2.Close()

	select {
	case <-done:
		// Expected
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for cancellation")
	}
}
