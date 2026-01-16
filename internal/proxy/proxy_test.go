package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestHTTPHandler_handleConnect(t *testing.T) {
	// Create a test server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	targetAddr := targetServer.Addr().(*net.TCPAddr)
	targetHost := targetAddr.String()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	var connectCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 5 * time.Second,
		OnConnect: func(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
			connectCalled.Store(true)
		},
	})

	// Create CONNECT request
	req, err := http.NewRequest("CONNECT", "http://"+targetHost, nil)
	require.NoError(t, err)
	req.Host = targetHost

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Write request
	err = req.Write(clientConn)
	require.NoError(t, err)

	// Read response
	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(50 * time.Millisecond)
	assert.True(t, connectCalled.Load())
}

func TestHTTPHandler_handleConnect_NoBackend(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	req, err := http.NewRequest("CONNECT", "http://example.com:443", nil)
	require.NoError(t, err)

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	err = req.Write(clientConn)
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	time.Sleep(50 * time.Millisecond)
	assert.True(t, errorCalled.Load())
}

func TestHTTPHandler_handleConnect_HostWithoutPort(t *testing.T) {
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
	})

	req, err := http.NewRequest("CONNECT", "http://example.com", nil)
	require.NoError(t, err)
	req.Host = "example.com" // No port

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	err = req.Write(clientConn)
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	// Should default to 443
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHTTPHandler_sendResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	// Test sendResponse in goroutine to avoid blocking
	done := make(chan struct{})
	go func() {
		defer serverConn.Close()
		handler.sendResponse(serverConn, http.StatusOK, "Connection Established")
		close(done)
	}()

	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, line, "200")
	assert.Contains(t, line, "Connection Established")

	clientConn.Close()
	<-done
}

func TestHTTPHandler_sendHTTPError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	done := make(chan struct{})
	go func() {
		defer serverConn.Close()
		handler.sendHTTPError(serverConn, http.StatusBadGateway, "No backend available")
		close(done)
	}()

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

	clientConn.Close()
	<-done
}

func TestHTTPHandler_handleHTTP_HTTPS(t *testing.T) {
	// Create a test HTTP server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer targetServer.Close()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	var connectCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 5 * time.Second,
		OnConnect: func(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
			connectCalled.Store(true)
		},
	})

	// Create HTTP request with https scheme
	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	require.NoError(t, err)
	req.Host = targetServer.Listener.Addr().String()

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	err = req.Write(clientConn)
	require.NoError(t, err)

	// Read response
	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(50 * time.Millisecond)
	assert.True(t, connectCalled.Load())
}

func TestHTTPHandler_handleHTTP_NoBackend(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	req, err := http.NewRequest("GET", "http://example.com/path", nil)
	require.NoError(t, err)

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	err = req.Write(clientConn)
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	time.Sleep(50 * time.Millisecond)
	assert.True(t, errorCalled.Load())
}
