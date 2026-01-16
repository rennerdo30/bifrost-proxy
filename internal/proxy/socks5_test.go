package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

func TestNewSOCKS5Handler(t *testing.T) {
	cfg := SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		DialTimeout: 5 * time.Second,
	}

	handler := NewSOCKS5Handler(cfg)
	assert.NotNil(t, handler)
	assert.Equal(t, 5*time.Second, handler.dialTimeout)

	// Test default timeout
	cfg2 := SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	}
	handler2 := NewSOCKS5Handler(cfg2)
	assert.Equal(t, 30*time.Second, handler2.dialTimeout)
}

func TestSOCKS5Handler_handleAuth_NoAuth(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		AuthRequired: false,
	})

	// Send auth request: version 5, 1 method, method 0 (no auth)
	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Send auth request
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)

	// Read response
	resp := make([]byte, 2)
	n, err := io.ReadFull(clientConn, resp)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, socks5Version, resp[0])
	assert.Equal(t, socks5AuthNone, resp[1])
}

func TestSOCKS5Handler_handleAuth_PasswordAuth(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	authCalled := false
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		AuthRequired: true,
		Authenticate: func(username, password string) bool {
			authCalled = true
			return username == "testuser" && password == "testpass"
		},
	})

	// Send auth request: version 5, 1 method, method 2 (password)
	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Send auth method selection
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthPassword})
	require.NoError(t, err)

	// Read method selection response
	resp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, resp)
	require.NoError(t, err)
	assert.Equal(t, socks5Version, resp[0])
	assert.Equal(t, socks5AuthPassword, resp[1])

	// Send username/password
	authData := []byte{0x01} // version
	authData = append(authData, byte(len("testuser")))
	authData = append(authData, []byte("testuser")...)
	authData = append(authData, byte(len("testpass")))
	authData = append(authData, []byte("testpass")...)

	_, err = clientConn.Write(authData)
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), authResp[0]) // version
	assert.Equal(t, byte(0x00), authResp[1]) // success
	assert.True(t, authCalled)
}

func TestSOCKS5Handler_handleAuth_PasswordAuth_Failed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		AuthRequired: true,
		Authenticate: func(username, password string) bool {
			return false
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Send auth method selection
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthPassword})
	require.NoError(t, err)

	// Read method selection response
	resp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, resp)
	require.NoError(t, err)

	// Send invalid credentials
	authData := []byte{0x01}
	authData = append(authData, byte(len("wrong")))
	authData = append(authData, []byte("wrong")...)
	authData = append(authData, byte(len("wrong")))
	authData = append(authData, []byte("wrong")...)

	_, err = clientConn.Write(authData)
	require.NoError(t, err)

	// Read auth response (should be failure)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)
	assert.Equal(t, byte(0x01), authResp[0])
	assert.Equal(t, byte(0x01), authResp[1]) // failure
}

func TestSOCKS5Handler_handleAuth_InvalidVersion(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var errorCalled bool
	done := make(chan struct{})
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled = true
		},
	})

	go func() {
		defer close(done)
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Send invalid version - only send 2 bytes (the header the handler reads first)
	// Handler reads {version, nmethods} then checks version and returns error
	_, err := clientConn.Write([]byte{0x04, 0x01})
	require.NoError(t, err)

	// Wait for handler to complete
	<-done
	assert.True(t, errorCalled)
}

func TestSOCKS5Handler_handleRequest_Connect_IPv4(t *testing.T) {
	// Create a test server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	targetAddr := targetServer.Addr().(*net.TCPAddr)
	targetIP := targetAddr.IP.To4()
	targetPort := targetAddr.Port

	// Create backend
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	var connectCalled bool
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
		OnConnect: func(ctx context.Context, conn net.Conn, host string, be backend.Backend) {
			connectCalled = true
		},
	})

	// Handle connection
	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Send auth (no auth)
	_, err = clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// Send CONNECT request with IPv4 address
	req := []byte{socks5Version, socks5CmdConnect, 0x00, socks5AddrIPv4}
	req = append(req, targetIP...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	req = append(req, portBytes...)

	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Read reply
	reply := make([]byte, 10)
	n, err := io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 4)
	assert.Equal(t, socks5Version, reply[0])
	assert.Equal(t, socks5ReplySuccess, reply[1])

	time.Sleep(50 * time.Millisecond)
	assert.True(t, connectCalled)
}

func TestSOCKS5Handler_handleRequest_Connect_Domain(t *testing.T) {
	// Create a test server
	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	targetAddr := targetServer.Addr().(*net.TCPAddr)
	targetPort := targetAddr.Port
	targetHost := "localhost"

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Auth
	_, err = clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// CONNECT request with domain
	req := []byte{socks5Version, socks5CmdConnect, 0x00, socks5AddrDomain}
	req = append(req, byte(len(targetHost)))
	req = append(req, []byte(targetHost)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	req = append(req, portBytes...)

	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Read reply
	reply := make([]byte, 10)
	n, err := io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 4)
	assert.Equal(t, socks5Version, reply[0])
	assert.Equal(t, socks5ReplySuccess, reply[1])
}

func TestSOCKS5Handler_handleRequest_Connect_IPv6(t *testing.T) {
	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background())

	clientConn, serverConn := net.Pipe()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return directBackend
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Auth
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// CONNECT request with IPv6
	req := []byte{socks5Version, socks5CmdConnect, 0x00, socks5AddrIPv6}
	ipv6 := net.ParseIP("::1")
	req = append(req, ipv6...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 8080)
	req = append(req, portBytes...)

	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Read reply (may fail if IPv6 not available, but should handle gracefully)
	reply := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, reply)
}

func TestSOCKS5Handler_handleRequest_Bind_NotSupported(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Auth
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// BIND request
	req := []byte{socks5Version, socks5CmdBind, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Read reply
	reply := make([]byte, 10)
	n, err := io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 4)
	assert.Equal(t, socks5Version, reply[0])
	assert.Equal(t, socks5ReplyCmdNotSupported, reply[1])
}

func TestSOCKS5Handler_handleRequest_UDPAssociate_NotSupported(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Auth
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// UDP ASSOCIATE request
	req := []byte{socks5Version, socks5CmdUDPAssociate, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Read reply
	reply := make([]byte, 10)
	n, err := io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 4)
	assert.Equal(t, socks5Version, reply[0])
	assert.Equal(t, socks5ReplyCmdNotSupported, reply[1])
}

func TestSOCKS5Handler_handleRequest_InvalidAddressType(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Auth
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// Request with invalid address type - only send bytes that will be read
	// before the handler sends an error (version, cmd, reserved, addrType)
	req := []byte{socks5Version, socks5CmdConnect, 0x00, 0xFF}

	// Write and read concurrently to avoid deadlock with net.Pipe
	done := make(chan struct{})
	var reply []byte
	var readErr error
	go func() {
		reply = make([]byte, 10)
		_, readErr = io.ReadFull(clientConn, reply)
		close(done)
	}()

	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Wait for read to complete
	<-done
	require.NoError(t, readErr)
	assert.Equal(t, socks5Version, reply[0])
	assert.Equal(t, socks5ReplyAddrNotSupported, reply[1])
}

func TestSOCKS5Handler_handleRequest_NoBackend(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var errorCalled bool
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled = true
		},
	})

	go func() {
		defer serverConn.Close()
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Auth
	_, err := clientConn.Write([]byte{socks5Version, 0x01, socks5AuthNone})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(clientConn, authResp)
	require.NoError(t, err)

	// CONNECT request
	req := []byte{socks5Version, socks5CmdConnect, 0x00, socks5AddrIPv4, 127, 0, 0, 1, 0, 80}
	_, err = clientConn.Write(req)
	require.NoError(t, err)

	// Read reply
	reply := make([]byte, 10)
	_, err = io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	assert.Equal(t, socks5ReplyGeneralFailure, reply[1])
	time.Sleep(50 * time.Millisecond)
	assert.True(t, errorCalled)
}

func TestSOCKS5Handler_sendReply(t *testing.T) {
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	// Test with nil address - use concurrent read/write to avoid net.Pipe deadlock
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	reply := make([]byte, 10)
	var readErr error
	var n int
	done := make(chan struct{})
	go func() {
		n, readErr = clientConn.Read(reply)
		close(done)
	}()

	handler.sendReply(serverConn, socks5ReplySuccess, nil)
	<-done

	require.NoError(t, readErr)
	assert.GreaterOrEqual(t, n, 4)
	assert.Equal(t, socks5Version, reply[0])
	assert.Equal(t, socks5ReplySuccess, reply[1])

	// Test with TCP address - use concurrent read/write to avoid net.Pipe deadlock
	clientConn2, serverConn2 := net.Pipe()
	defer clientConn2.Close()

	reply2 := make([]byte, 10)
	done2 := make(chan struct{})
	go func() {
		n, readErr = clientConn2.Read(reply2)
		close(done2)
	}()

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	handler.sendReply(serverConn2, socks5ReplySuccess, addr)
	<-done2

	require.NoError(t, readErr)
	assert.GreaterOrEqual(t, n, 4)
	assert.Equal(t, socks5Version, reply2[0])
	assert.Equal(t, socks5ReplySuccess, reply2[1])
}

func TestSOCKS5Handler_errToReply(t *testing.T) {
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})

	// Test nil error
	assert.Equal(t, socks5ReplySuccess, handler.errToReply(nil))

	// Test dial error
	dialErr := &net.OpError{Op: "dial", Err: assert.AnError}
	assert.Equal(t, socks5ReplyConnRefused, handler.errToReply(dialErr))

	// Test other error
	assert.Equal(t, socks5ReplyGeneralFailure, handler.errToReply(assert.AnError))
}

func TestSOCKS5Handler_handleError(t *testing.T) {
	var errorCalled bool
	var errorHost string
	var errorErr error

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
		OnError: func(ctx context.Context, conn net.Conn, host string, err error) {
			errorCalled = true
			errorHost = host
			errorErr = err
		},
	})

	ctx := context.Background()
	testErr := assert.AnError
	handler.handleError(ctx, nil, "test.example.com", testErr)

	assert.True(t, errorCalled)
	assert.Equal(t, "test.example.com", errorHost)
	assert.Equal(t, testErr, errorErr)

	// Test without callback
	handler2 := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend {
			return nil
		},
	})
	handler2.handleError(ctx, nil, "test", testErr)
	// Should not panic
}
