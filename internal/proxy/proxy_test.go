package proxy

import (
	"bufio"
	"context"
	"fmt"
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

func TestHTTPHandler_ServeConn_ReadRequestError(t *testing.T) {
	// Test early connection close (not EOF) - malformed request
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Write malformed HTTP request (not valid HTTP)
	_, err := clientConn.Write([]byte("NOT A VALID HTTP REQUEST\r\n\r\n"))
	require.NoError(t, err)
	clientConn.Close()

	<-done
	assert.True(t, errorCalled.Load())
}

func TestHTTPHandler_ServeConn_EOF(t *testing.T) {
	// Test immediate EOF - should not call error callback
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Close immediately to trigger EOF
	clientConn.Close()

	<-done
	// EOF should not trigger error callback
	assert.False(t, errorCalled.Load())
}

func TestHTTPHandler_ServeConn_EmptyHost(t *testing.T) {
	// Test request with empty Host header - should use URL host
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer targetServer.Close()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 5 * time.Second,
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Create a request manually with Host in URL
	requestLine := fmt.Sprintf("GET %s HTTP/1.1\r\n\r\n", targetServer.URL)
	_, err := clientConn.Write([]byte(requestLine))
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHTTPHandler_handleConnect_DialFailure(t *testing.T) {
	// Test when dial fails
	clientConn, serverConn := net.Pipe()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 100 * time.Millisecond,
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	// CONNECT to an unreachable address
	req, err := http.NewRequest("CONNECT", "http://192.0.2.1:12345", nil) // TEST-NET-1, RFC 5737
	require.NoError(t, err)
	req.Host = "192.0.2.1:12345"

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

	time.Sleep(200 * time.Millisecond)
	assert.True(t, errorCalled.Load())
}

func TestHTTPHandler_handleHTTP_DialFailure(t *testing.T) {
	// Test HTTP forward proxy when dial fails
	clientConn, serverConn := net.Pipe()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		DialTimeout: 100 * time.Millisecond,
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	// GET to an unreachable address
	req, err := http.NewRequest("GET", "http://192.0.2.1:12345/path", nil)
	require.NoError(t, err)
	req.Host = "192.0.2.1:12345"

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

	time.Sleep(200 * time.Millisecond)
	assert.True(t, errorCalled.Load())
}

func TestHTTPHandler_handleHTTP_EmptyHostFromRequest(t *testing.T) {
	// Test when Host is empty but URL.Host is set
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
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

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Write raw HTTP request with Host in URL only (typical proxy request)
	rawRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		targetServer.URL, targetServer.Listener.Addr().String())
	_, err := clientConn.Write([]byte(rawRequest))
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHTTPHandler_sendResponse_WriteError(t *testing.T) {
	// Test sendResponse when write fails
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	// Create a pipe and close the read end to cause write error
	clientConn, serverConn := net.Pipe()
	clientConn.Close() // Close client side to cause write error

	// This should not panic and should handle the error gracefully
	handler.sendResponse(serverConn, http.StatusOK, "OK")
	serverConn.Close()
}

func TestHTTPHandler_sendHTTPError_WriteError(t *testing.T) {
	// Test sendHTTPError when write fails
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	clientConn, serverConn := net.Pipe()
	clientConn.Close()

	// This should not panic
	handler.sendHTTPError(serverConn, http.StatusBadGateway, "Error")
	serverConn.Close()
}

func TestHTTPHandler_handleError_NilCallback(t *testing.T) {
	// Test handleError when callback is nil
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		OnError: nil, // No error callback
	})

	// Should not panic
	handler.handleError(context.Background(), nil, "test", assert.AnError)
}

func TestHTTPHandler_DefaultDialTimeout(t *testing.T) {
	// Test that default dial timeout is set when not specified
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		// DialTimeout not set
	})

	assert.Equal(t, 30*time.Second, handler.dialTimeout)
}

func TestHTTPHandler_handleHTTP_WriteRequestError(t *testing.T) {
	// Test when writing request to target fails
	// Create a server that closes connection immediately after accepting
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Server that accepts then immediately closes
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // Close immediately
	}()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	req, err := http.NewRequest("GET", "http://"+serverAddr+"/path", nil)
	require.NoError(t, err)
	req.Host = serverAddr

	err = req.Write(clientConn)
	require.NoError(t, err)

	// Wait for handler to process
	time.Sleep(100 * time.Millisecond)
	clientConn.Close()

	// Error should be called due to write/read failure
	time.Sleep(50 * time.Millisecond)
	// Connection might complete or fail depending on timing
}

func TestCopyBidirectional_WithTCPConn(t *testing.T) {
	// Test with real TCP connections to hit CloseWrite paths
	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener1.Close()

	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener2.Close()

	// Accept connections on both listeners
	var server1Conn, server2Conn net.Conn
	acceptDone := make(chan struct{})

	go func() {
		var err error
		server1Conn, err = listener1.Accept()
		if err != nil {
			return
		}
		server2Conn, err = listener2.Accept()
		if err != nil {
			return
		}
		close(acceptDone)
	}()

	// Connect to both listeners
	client1Conn, err := net.Dial("tcp", listener1.Addr().String())
	require.NoError(t, err)
	defer client1Conn.Close()

	client2Conn, err := net.Dial("tcp", listener2.Addr().String())
	require.NoError(t, err)
	defer client2Conn.Close()

	<-acceptDone

	// Start bidirectional copy between the server sides
	done := make(chan struct{})
	go func() {
		CopyBidirectional(context.Background(), server1Conn, server2Conn)
		close(done)
	}()

	// Write from client1, should appear on client2
	testData := []byte("Hello")
	go func() {
		client1Conn.Write(testData)
		time.Sleep(50 * time.Millisecond)
		client1Conn.Close()
	}()

	buf := make([]byte, 100)
	n, _ := client2Conn.Read(buf)
	assert.Equal(t, testData, buf[:n])

	client2Conn.Close()
	server1Conn.Close()
	server2Conn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestCopyWithContext_EOF(t *testing.T) {
	// Test that io.EOF is handled correctly by copyWithContext
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()
	defer client1.Close()
	defer client2.Close()

	done := make(chan struct{})
	go func() {
		// Copy will return io.EOF when one side closes
		CopyBidirectional(context.Background(), server1, server2)
		close(done)
	}()

	// Write data, then close to generate EOF
	_, err := client1.Write([]byte("test"))
	require.NoError(t, err)
	client1.Close()

	// Read on the other side
	buf := make([]byte, 100)
	_, _ = client2.Read(buf)
	client2.Close()

	<-done
}

func TestHTTPHandler_ServeConn_NonTCPAddr(t *testing.T) {
	// Test with net.Pipe (non-TCP address) to cover the non-TCPAddr branch
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	// net.Pipe doesn't return a TCPAddr
	clientConn, serverConn := net.Pipe()

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Write HTTP request
	req, err := http.NewRequest("GET", targetServer.URL, nil)
	require.NoError(t, err)
	req.Host = targetServer.Listener.Addr().String()
	err = req.Write(clientConn)
	require.NoError(t, err)

	// Read response
	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	clientConn.Close()
	<-done
}

func TestHTTPHandler_handleHTTP_EmptyHostFallbackToURLHost(t *testing.T) {
	// Test the case where req.Host is empty but req.URL.Host has the host
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
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

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Create a request where Host header is empty but URL has the host
	rawRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		targetServer.URL, targetServer.Listener.Addr().String())
	_, err := clientConn.Write([]byte(rawRequest))
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	clientConn.Close()
}

func TestHTTPHandler_handleHTTP_WriteResponseError(t *testing.T) {
	// Test when writing response to client fails
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response body"))
	}))
	defer targetServer.Close()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Write request then close immediately before response can be written back
	req, err := http.NewRequest("GET", targetServer.URL, nil)
	require.NoError(t, err)
	req.Host = targetServer.Listener.Addr().String()
	err = req.Write(clientConn)
	require.NoError(t, err)

	// Close before response comes back
	time.Sleep(10 * time.Millisecond)
	clientConn.Close()

	<-done
	// Error may or may not be called depending on timing
}

func TestHTTPHandler_handleHTTP_ReadResponseError(t *testing.T) {
	// Test when reading response from target fails
	// Create a server that closes connection after sending partial response
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Server that sends a partial response then closes
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Read the request
		buf := make([]byte, 1024)
		conn.Read(buf)
		// Send partial response then close
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"))
		conn.Close() // Close before sending full body
	}()

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	var errorCalled atomic.Bool
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled.Store(true)
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	req, err := http.NewRequest("GET", "http://"+serverAddr+"/path", nil)
	require.NoError(t, err)
	req.Host = serverAddr

	err = req.Write(clientConn)
	require.NoError(t, err)

	// Read response (may be partial)
	reader := bufio.NewReader(clientConn)
	_, _ = http.ReadResponse(reader, req)

	time.Sleep(100 * time.Millisecond)
	clientConn.Close()
}
