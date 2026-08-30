package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// originCapture is a TCP origin that records the raw request bytes it received
// and answers a fixed HTTP/1.1 response.
func originCapture(t *testing.T, response string) (addr string, received *strings.Builder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	received = &strings.Builder{}
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, rerr := reader.ReadString('\n')
			if rerr != nil {
				return
			}
			received.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte(response))
	}()
	return ln.Addr().String(), received
}

func newHygieneHandler(t *testing.T) *HTTPHandler {
	t.Helper()
	be := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, be.Start(context.Background()))
	t.Cleanup(func() { _ = be.Stop(context.Background()) })
	return NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:  func(domain, clientIP string) backend.Backend { return be },
		DialTimeout: 5 * time.Second,
	})
}

func roundTripRaw(t *testing.T, h *HTTPHandler, rawRequest string) string {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeConn(context.Background(), serverConn)
	}()
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := clientConn.Write([]byte(rawRequest))
	require.NoError(t, err)
	resp, err := io.ReadAll(clientConn)
	require.NoError(t, err)
	<-done
	return string(resp)
}

// RFC 7230 §6.1: hop-by-hop headers — the standard set AND anything named in
// Connection — must not travel to the origin. The old code forwarded
// Connection: keep-alive, Keep-Alive, TE, Upgrade and Connection-named custom
// headers verbatim. §5.7.1: a proxy MUST append itself to Via.
func TestHandleHTTP_StripsHopByHopAndAppendsVia(t *testing.T) {
	originAddr, received := originCapture(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h := newHygieneHandler(t)

	raw := "GET http://" + originAddr + "/x HTTP/1.1\r\n" +
		"Host: " + originAddr + "\r\n" +
		"Connection: keep-alive, X-Custom-Hop\r\n" +
		"Keep-Alive: timeout=30\r\n" +
		"Te: trailers\r\n" +
		"X-Custom-Hop: secret\r\n" +
		"X-End-To-End: stays\r\n" +
		"\r\n"
	resp := roundTripRaw(t, h, raw)
	require.Contains(t, resp, "200 OK")

	got := received.String()
	assert.NotContains(t, got, "Keep-Alive:", "hop-by-hop header leaked to the origin")
	assert.NotContains(t, got, "Te:", "hop-by-hop header leaked to the origin")
	assert.NotContains(t, got, "X-Custom-Hop", "a Connection-named header MUST be stripped (RFC 7230 §6.1)")
	assert.Contains(t, got, "X-End-To-End: stays", "end-to-end headers must survive")
	assert.Contains(t, got, "Via: 1.1 "+viaToken, "a proxy MUST append itself to Via (RFC 7230 §5.7.1)")
}

// The handler serves one request per connection; the wire must say so instead
// of implying HTTP/1.1 persistence and then closing.
func TestHandleHTTP_AdvertisesConnectionClose(t *testing.T) {
	originAddr, _ := originCapture(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	h := newHygieneHandler(t)

	raw := "GET http://" + originAddr + "/x HTTP/1.1\r\nHost: " + originAddr + "\r\n\r\n"
	resp := roundTripRaw(t, h, raw)
	require.Contains(t, resp, "200 OK")
	assert.Contains(t, strings.ToLower(resp), "connection: close",
		"a one-request-per-connection proxy must not imply persistence")
}

// A 101 Switching Protocols must turn the pair into a tunnel: post-upgrade
// bytes cross in both directions. The old code forwarded the 101 and closed
// both connections with zero post-upgrade bytes ever crossing.
func TestHandleHTTP_UpgradeBecomesTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, rerr := reader.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		// Echo post-upgrade bytes.
		buf := make([]byte, 32)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			return
		}
		_, _ = conn.Write([]byte("echo:"))
		_, _ = conn.Write(buf[:n])
	}()
	originAddr := ln.Addr().String()

	h := newHygieneHandler(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		h.ServeConn(context.Background(), serverConn)
	}()

	require.NoError(t, clientConn.SetDeadline(time.Now().Add(5*time.Second)))
	raw := "GET http://" + originAddr + "/ws HTTP/1.1\r\n" +
		"Host: " + originAddr + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	_, err = clientConn.Write([]byte(raw))
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "101")
	for {
		line, rerr := reader.ReadString('\n')
		require.NoError(t, rerr)
		if line == "\r\n" {
			break
		}
	}

	// Post-upgrade traffic must cross both ways.
	_, err = clientConn.Write([]byte("ping"))
	require.NoError(t, err)
	got := make([]byte, 9)
	_, err = io.ReadFull(reader, got)
	require.NoError(t, err, "post-upgrade bytes must flow; the 101 used to be followed by a dead socket")
	assert.Equal(t, "echo:ping", string(got))
}

// An h2c prior-knowledge preface must be rejected as unsupported, not parsed
// as a request to host ":80" and answered with an HTTP/1.1 502 on a wire the
// client expects to carry HTTP/2 frames.
func TestServeConn_H2CPriorKnowledgeRejectedCleanly(t *testing.T) {
	h := newHygieneHandler(t)
	resp := roundTripRaw(t, h, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	assert.Contains(t, resp, "505", "HTTP Version Not Supported is the honest answer, got: %s", resp)
	assert.NotContains(t, resp, "502")
}

// A WebSocket tunnel must survive an idle period longer than read_timeout.
//
// After the 101 the connection is opaque, exactly like CONNECT, so it has to
// leave request/response deadline accounting behind. It did not: the CONNECT
// path called enterTunnel() but the Upgrade path did not, so the per-read
// read_timeout stayed armed and any socket quiet for longer than it was torn
// down. With the shipped 30s default that meant a proxied dashboard WebSocket
// died roughly every 30 seconds and the browser reconnected forever - 262
// reconnects over 18 hours in the log that surfaced this.
func TestHandleHTTP_UpgradeTunnelSurvivesIdleBeyondReadTimeout(t *testing.T) {
	const readTimeout = 150 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, rerr := reader.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		buf := make([]byte, 32)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			return
		}
		_, _ = conn.Write([]byte("late:"))
		_, _ = conn.Write(buf[:n])
	}()
	originAddr := ln.Addr().String()

	be := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, be.Start(context.Background()))
	t.Cleanup(func() { _ = be.Stop(context.Background()) })
	h := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:   func(domain, clientIP string) backend.Backend { return be },
		DialTimeout:  5 * time.Second,
		ReadTimeout:  readTimeout,
		WriteTimeout: readTimeout,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go h.ServeConn(context.Background(), serverConn)

	require.NoError(t, clientConn.SetDeadline(time.Now().Add(10*time.Second)))
	raw := "GET http://" + originAddr + "/ws HTTP/1.1\r\n" +
		"Host: " + originAddr + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	_, err = clientConn.Write([]byte(raw))
	require.NoError(t, err)

	reader := bufio.NewReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "101")
	for {
		line, rerr := reader.ReadString('\n')
		require.NoError(t, rerr)
		if line == "\r\n" {
			break
		}
	}

	// Go quiet for comfortably longer than read_timeout. A tunnel that still
	// has the per-read deadline armed is torn down during this sleep.
	time.Sleep(4 * readTimeout)

	_, err = clientConn.Write([]byte("ping"))
	require.NoError(t, err, "tunnel was torn down while idle")
	got := make([]byte, 9)
	_, err = io.ReadFull(reader, got)
	require.NoError(t, err, "an idle WebSocket tunnel must not be closed by read_timeout")
	assert.Equal(t, "late:ping", string(got))
}
