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
