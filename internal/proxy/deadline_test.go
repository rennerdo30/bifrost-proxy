package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// Test-local timing constants. They are deliberately far apart so an assertion
// failure means a wrong deadline rather than a slow CI machine.
const (
	// tinyTimeout is short enough that an unbounded wait is obvious.
	tinyTimeout = 100 * time.Millisecond
	// generousTimeout stands in for "effectively no limit" where a test needs
	// one of the three timeouts not to be the thing that fires.
	generousTimeout = 30 * time.Second
	// settleWait bounds how long a test waits for a deadline that should
	// already have fired.
	settleWait = 5 * time.Second
	// streamTick is the gap between chunks of a slow streaming response.
	streamTick = 60 * time.Millisecond
	// streamChunks is how many chunks a slow streaming response emits.
	streamChunks = 5
)

// recordingConn is a net.Conn stub that records the deadlines set on it.
type recordingConn struct {
	net.Conn
	readDeadlines  []time.Time
	writeDeadlines []time.Time
	readData       []byte
	closeWriteHit  atomic.Bool
	closeReadHit   atomic.Bool
}

func (c *recordingConn) Read(b []byte) (int, error) {
	if len(c.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}

func (c *recordingConn) Write(b []byte) (int, error)   { return len(b), nil }
func (c *recordingConn) Close() error                  { return nil }
func (c *recordingConn) LocalAddr() net.Addr           { return &net.TCPAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr          { return &net.TCPAddr{} }
func (c *recordingConn) SetDeadline(_ time.Time) error { return nil }

func (c *recordingConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines = append(c.readDeadlines, t)
	return nil
}

func (c *recordingConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines = append(c.writeDeadlines, t)
	return nil
}

func (c *recordingConn) CloseWrite() error {
	c.closeWriteHit.Store(true)
	return nil
}

func (c *recordingConn) CloseRead() error {
	c.closeReadHit.Store(true)
	return nil
}

func TestDeadlineConn_RequestPhaseArmsIdleThenRead(t *testing.T) {
	raw := &recordingConn{readData: []byte("GET / HTTP/1.1\r\n")}
	dc := newDeadlineConn(raw, 5*time.Second, 0, 20*time.Second)

	dc.beginRequest()
	require.Equal(t, readModeRequest, readMode(dc.mode.Load()))

	buf := make([]byte, 4)
	_, err := dc.Read(buf)
	require.NoError(t, err)

	// Two deadlines: idle_timeout before the read, then read_timeout once the
	// first byte proved the connection is no longer idle.
	require.Len(t, raw.readDeadlines, 2)
	assert.InDelta(t, float64(20*time.Second), float64(time.Until(raw.readDeadlines[0])), float64(time.Second))
	assert.InDelta(t, float64(5*time.Second), float64(time.Until(raw.readDeadlines[1])), float64(time.Second))
	assert.Equal(t, readModeHeader, readMode(dc.mode.Load()))

	// The header deadline is absolute: a further read must NOT refresh it, or a
	// client trickling bytes would hold the connection open forever.
	_, err = dc.Read(buf)
	require.NoError(t, err)
	assert.Len(t, raw.readDeadlines, 2)
}

func TestDeadlineConn_BodyPhaseIsPerRead(t *testing.T) {
	raw := &recordingConn{readData: []byte("abcdefgh")}
	dc := newDeadlineConn(raw, 5*time.Second, 0, 0)

	dc.beginBody()
	// beginBody clears any pending absolute deadline.
	require.Len(t, raw.readDeadlines, 1)
	assert.True(t, raw.readDeadlines[0].IsZero())

	buf := make([]byte, 2)
	for i := 0; i < 3; i++ {
		_, err := dc.Read(buf)
		require.NoError(t, err)
	}
	// One fresh deadline per read: a slow-but-progressing upload keeps going.
	require.Len(t, raw.readDeadlines, 4)
	for _, d := range raw.readDeadlines[1:] {
		assert.False(t, d.IsZero())
	}
}

func TestDeadlineConn_WriteIsPerWriteAndDisabledInTunnel(t *testing.T) {
	raw := &recordingConn{}
	dc := newDeadlineConn(raw, 0, 5*time.Second, 0)

	dc.beginRequest()
	for i := 0; i < 3; i++ {
		_, err := dc.Write([]byte("x"))
		require.NoError(t, err)
	}
	// A fresh deadline per write, never one absolute deadline for the whole
	// response: that is what keeps a streaming response alive.
	require.Len(t, raw.writeDeadlines, 3)
	for _, d := range raw.writeDeadlines {
		assert.False(t, d.IsZero())
	}

	dc.enterTunnel()
	// enterTunnel clears both deadlines...
	require.NotEmpty(t, raw.writeDeadlines)
	assert.True(t, raw.writeDeadlines[len(raw.writeDeadlines)-1].IsZero())
	before := len(raw.writeDeadlines)
	// ...and stops arming new ones, so a hijacked connection is not killed.
	_, err := dc.Write([]byte("y"))
	require.NoError(t, err)
	assert.Len(t, raw.writeDeadlines, before)
}

func TestDeadlineConn_IdleWaitFallsBackToReadTimeout(t *testing.T) {
	raw := &recordingConn{readData: []byte("x")}
	dc := newDeadlineConn(raw, 3*time.Second, 0, 0)
	assert.Equal(t, 3*time.Second, dc.idleWait())

	dc.beginRequest()
	assert.Equal(t, readModeRequest, readMode(dc.mode.Load()))

	// With every timeout zero the wrapper must stay completely inert.
	inert := newDeadlineConn(&recordingConn{}, 0, 0, 0)
	inert.beginRequest()
	assert.Equal(t, readModeNone, readMode(inert.mode.Load()))
}

func TestDeadlineConn_ForwardsHalfClose(t *testing.T) {
	raw := &recordingConn{}
	dc := newDeadlineConn(raw, 0, 0, 0)

	// The tunnel copy loop discovers half-close support by type assertion. If
	// the wrapper hid it, a half-closed peer would never see EOF.
	require.NoError(t, dc.CloseWrite())
	require.NoError(t, dc.CloseRead())
	assert.True(t, raw.closeWriteHit.Load())
	assert.True(t, raw.closeReadHit.Load())
}

func TestConnDeadlines_UnwrapsCountingConn(t *testing.T) {
	dc := newDeadlineConn(&recordingConn{}, 0, 0, 0)
	counting := newCountingConn(dc)
	assert.Same(t, dc, connDeadlines(counting))

	// A bare connection is not deadline-managed; the nil result must be safe to
	// use, because the handlers call phase changes unconditionally.
	assert.Nil(t, connDeadlines(&recordingConn{}))
	connDeadlines(&recordingConn{}).enterTunnel()
	connDeadlines(&recordingConn{}).beginRequest()
	connDeadlines(&recordingConn{}).beginBody()
	connDeadlines(&recordingConn{}).enterKeptAlive()
}

func TestIdleCheckInterval_Bounds(t *testing.T) {
	assert.Equal(t, minIdleCheckInterval, idleCheckInterval(time.Millisecond))
	assert.Equal(t, maxIdleCheckInterval, idleCheckInterval(time.Hour))
	assert.Equal(t, 250*time.Millisecond, idleCheckInterval(time.Second))
}

// --- HTTP listener behavior ---------------------------------------------------

// TestHTTPHandler_IdleClientIsClosed proves the slowloris exposure is closed: a
// client that connects and sends nothing at all must be reaped by idle_timeout
// instead of pinning a goroutine and a file descriptor indefinitely.
func TestHTTPHandler_IdleClientIsClosed(t *testing.T) {
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:  func(domain, clientIP string) backend.Backend { return nil },
		IdleTimeout: tinyTimeout,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), serverConn)
	}()

	select {
	case <-served:
	case <-time.After(settleWait):
		t.Fatal("handler held an idle client open; idle_timeout was not applied to the pre-request wait")
	}
}

// TestHTTPHandler_TrickledHeadersAreClosed proves read_timeout is an absolute
// bound on the header block. idle_timeout is set generously so that only
// read_timeout can be what stops the trickle.
func TestHTTPHandler_TrickledHeadersAreClosed(t *testing.T) {
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:  func(domain, clientIP string) backend.Backend { return nil },
		ReadTimeout: tinyTimeout,
		IdleTimeout: generousTimeout,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Never terminate the header block.
	go func() {
		if _, err := clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n")); err != nil {
			return
		}
		for {
			if _, err := clientConn.Write([]byte("X-Pad: 1\r\n")); err != nil {
				return
			}
			time.Sleep(tinyTimeout / 2)
		}
	}()

	select {
	case <-served:
	case <-time.After(settleWait):
		t.Fatal("handler accepted trickled headers indefinitely; read_timeout was not applied")
	}
}

// TestHTTPHandler_ActiveTunnelSurvivesThenIdleReaped is the both-directions
// test the fix has to satisfy: an actively used CONNECT tunnel must live far
// longer than read_timeout, write_timeout and idle_timeout combined, and must
// then be reaped once it goes quiet.
func TestHTTPHandler_ActiveTunnelSurvivesThenIdleReaped(t *testing.T) {
	target := newEchoServer(t)

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background()) //nolint:errcheck // test cleanup

	idle := 400 * time.Millisecond
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:   func(domain, clientIP string) backend.Backend { return directBackend },
		DialTimeout:  5 * time.Second,
		ReadTimeout:  tinyTimeout,
		WriteTimeout: tinyTimeout,
		IdleTimeout:  idle,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), serverConn)
	}()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, "http://"+target, nil)
	require.NoError(t, err)
	req.Host = target
	require.NoError(t, req.Write(clientConn))

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Keep the tunnel busy for well over idle_timeout. Every round trip must
	// succeed: if read_timeout or write_timeout leaked into the tunnel, or the
	// idle watchdog ignored activity, one of these fails.
	deadline := time.Now().Add(3 * idle)
	echoes := 0
	for time.Now().Before(deadline) {
		payload := []byte(fmt.Sprintf("ping-%d\n", echoes))
		require.NoError(t, clientConn.SetDeadline(time.Now().Add(settleWait)))
		_, err = clientConn.Write(payload)
		require.NoError(t, err, "active tunnel write failed after %d echoes", echoes)
		got := make([]byte, len(payload))
		_, err = io.ReadFull(reader, got)
		require.NoError(t, err, "active tunnel read failed after %d echoes", echoes)
		require.Equal(t, payload, got)
		echoes++
		time.Sleep(idle / 4)
	}
	require.Greater(t, echoes, 2, "test did not exercise the tunnel")

	// Now go quiet. The watchdog must reap the tunnel.
	require.NoError(t, clientConn.SetDeadline(time.Time{}))
	select {
	case <-served:
	case <-time.After(settleWait):
		t.Fatal("handler held an idle CONNECT tunnel open; idle_timeout was not applied to the tunnel")
	}
}

// TestHTTPHandler_StreamingResponseIsNotTruncated guards the other half of the
// contract: a response that trickles out over far longer than write_timeout,
// read_timeout and idle_timeout must arrive in full. An absolute write deadline
// (the naive implementation) truncates it.
func TestHTTPHandler_StreamingResponseIsNotTruncated(t *testing.T) {
	target := newSlowStreamServer(t)

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background()) //nolint:errcheck // test cleanup

	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:   func(domain, clientIP string) backend.Backend { return directBackend },
		DialTimeout:  5 * time.Second,
		ReadTimeout:  streamTick / 2,
		WriteTimeout: streamTick / 2,
		IdleTimeout:  streamTick / 2,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go handler.ServeConn(context.Background(), serverConn)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+target+"/events", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(clientConn))

	reader := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "streaming response was cut off mid-flight")
	for i := 0; i < streamChunks; i++ {
		assert.Contains(t, string(body), fmt.Sprintf("event-%d", i))
	}
}

// --- SOCKS5 listener behavior ------------------------------------------------

// TestSOCKS5Handler_IdleClientIsClosed proves the SOCKS5 handshake is now
// bounded. Before the fix the SOCKS5 listener read no timeout at all.
func TestSOCKS5Handler_IdleClientIsClosed(t *testing.T) {
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend:  func(domain, clientIP string) backend.Backend { return nil },
		IdleTimeout: tinyTimeout,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), serverConn)
	}()

	select {
	case <-served:
	case <-time.After(settleWait):
		t.Fatal("SOCKS5 handler held an idle client open; idle_timeout was not applied")
	}
}

// TestSOCKS5Handler_PartialHandshakeIsClosed proves read_timeout bounds the
// handshake once it has started.
func TestSOCKS5Handler_PartialHandshakeIsClosed(t *testing.T) {
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend:  func(domain, clientIP string) backend.Backend { return nil },
		ReadTimeout: tinyTimeout,
		IdleTimeout: generousTimeout,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Announce one auth method, then never send it.
	_, err := clientConn.Write([]byte{socks5Version, 1})
	require.NoError(t, err)

	select {
	case <-served:
	case <-time.After(settleWait):
		t.Fatal("SOCKS5 handler waited forever for the rest of a handshake; read_timeout was not applied")
	}
}

// TestSOCKS5Handler_ActiveRelaySurvivesThenIdleReaped mirrors the CONNECT
// tunnel test for the SOCKS5 relay.
func TestSOCKS5Handler_ActiveRelaySurvivesThenIdleReaped(t *testing.T) {
	target := newEchoServer(t)
	host, portStr, err := net.SplitHostPort(target)
	require.NoError(t, err)
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background()) //nolint:errcheck // test cleanup

	idle := 400 * time.Millisecond
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		GetBackend:   func(domain, clientIP string) backend.Backend { return directBackend },
		DialTimeout:  5 * time.Second,
		ReadTimeout:  tinyTimeout,
		WriteTimeout: tinyTimeout,
		IdleTimeout:  idle,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), serverConn)
	}()

	// Handshake: no-auth, then CONNECT to the echo server by IPv4 literal.
	_, err = clientConn.Write([]byte{socks5Version, 1, socks5AuthNone})
	require.NoError(t, err)
	methodReply := make([]byte, 2)
	_, err = io.ReadFull(clientConn, methodReply)
	require.NoError(t, err)
	require.Equal(t, []byte{socks5Version, socks5AuthNone}, methodReply)

	ip := net.ParseIP(host).To4()
	require.NotNil(t, ip)
	request := []byte{socks5Version, socks5CmdConnect, 0x00, socks5AddrIPv4}
	request = append(request, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port)) //nolint:gosec // G115: parsed from a listener address
	request = append(request, portBytes...)
	_, err = clientConn.Write(request)
	require.NoError(t, err)

	reply := make([]byte, 10)
	_, err = io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	require.Equal(t, socks5ReplySuccess, reply[1])

	// Keep the relay busy well past idle_timeout.
	deadline := time.Now().Add(3 * idle)
	echoes := 0
	for time.Now().Before(deadline) {
		payload := []byte(fmt.Sprintf("ping-%d\n", echoes))
		require.NoError(t, clientConn.SetDeadline(time.Now().Add(settleWait)))
		_, err = clientConn.Write(payload)
		require.NoError(t, err, "active relay write failed after %d echoes", echoes)
		got := make([]byte, len(payload))
		_, err = io.ReadFull(clientConn, got)
		require.NoError(t, err, "active relay read failed after %d echoes", echoes)
		require.Equal(t, payload, got)
		echoes++
		time.Sleep(idle / 4)
	}
	require.Greater(t, echoes, 2, "test did not exercise the relay")

	require.NoError(t, clientConn.SetDeadline(time.Time{}))
	select {
	case <-served:
	case <-time.After(settleWait):
		t.Fatal("SOCKS5 handler held an idle relay open; idle_timeout was not applied to the relay")
	}
}

// --- helpers ------------------------------------------------------------------

// newEchoServer starts a TCP server that echoes everything it receives and
// returns its host:port.
func newEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // test helper
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// newSlowStreamServer starts a TCP server that answers any request with a
// chunked response emitted one chunk per streamTick, imitating an SSE stream.
func newSlowStreamServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // test helper
				br := bufio.NewReader(conn)
				if _, reqErr := http.ReadRequest(br); reqErr != nil {
					return
				}
				header := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" +
					"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
				if _, wErr := conn.Write([]byte(header)); wErr != nil {
					return
				}
				for i := 0; i < streamChunks; i++ {
					time.Sleep(streamTick)
					payload := fmt.Sprintf("data: event-%d\n\n", i)
					chunk := fmt.Sprintf("%x\r\n%s\r\n", len(payload), payload)
					if _, wErr := conn.Write([]byte(chunk)); wErr != nil {
						return
					}
				}
				_, _ = conn.Write([]byte("0\r\n\r\n"))
			}()
		}
	}()
	return ln.Addr().String()
}
