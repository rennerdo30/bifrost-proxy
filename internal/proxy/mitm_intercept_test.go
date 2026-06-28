package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
	"github.com/rennerdo30/bifrost-proxy/internal/debug"
)

// Compile-time assertion that the real *debug.Logger satisfies the proxy's
// InterceptLogger contract, so server wiring can inject it directly. This lives
// in the test package to avoid a debug->proxy import cycle in production code.
var _ InterceptLogger = (*debug.Logger)(nil)

// fakeInterceptLogger records intercepted request/response calls for assertions.
type fakeInterceptLogger struct {
	mu        sync.Mutex
	requests  []loggedReq
	responses []loggedResp
}

type loggedReq struct {
	host, method, path string
	headers            map[string]string
	body               []byte
}

type loggedResp struct {
	host       string
	statusCode int
	headers    map[string]string
	body       []byte
}

func (f *fakeInterceptLogger) LogInterceptedRequest(_ context.Context, host, method, path string, headers map[string]string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, loggedReq{host, method, path, headers, append([]byte(nil), body...)})
}

func (f *fakeInterceptLogger) LogInterceptedResponse(_ context.Context, host string, statusCode int, headers map[string]string, body []byte, _ time.Duration, _, _ int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses = append(f.responses, loggedResp{host, statusCode, headers, append([]byte(nil), body...)})
}

func (f *fakeInterceptLogger) snapshot() ([]loggedReq, []loggedResp) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]loggedReq(nil), f.requests...), append([]loggedResp(nil), f.responses...)
}

// startProxy spins up the HTTPHandler on a real TCP listener and returns its
// address plus a cleanup function.
func startProxy(t *testing.T, cfg HTTPHandlerConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	handler := NewHTTPHandler(cfg)

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// ServeConn closes conn on return; for opaque keep-alive tunnels it
			// returns once the client connection is closed by the test.
			go handler.ServeConn(context.Background(), conn)
		}
	}()

	// Cleanup only closes the listener: we do not wg.Wait() because an opaque
	// tunnel's CopyBidirectional intentionally blocks until a side closes, which
	// mirrors production. Per-connection goroutines exit when their client conn
	// is closed (the test closes rawConn before returning).
	cleanup := func() {
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

// dialProxyConnect dials the proxy and issues a CONNECT to target, returning the
// established proxy connection after a 200 response.
func dialProxyConnect(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)

	connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	_, err = conn.Write([]byte(connectReq))
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// The CONNECT response carries no body; br should have nothing buffered for
	// the subsequent TLS handshake in these tests.
	require.Equal(t, 0, br.Buffered())
	return conn
}

func TestInterceptConnect_Enabled_RoundTrips(t *testing.T) {
	// Real TLS upstream that echoes the request body and a marker header.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("echo:" + string(body)))
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	// Build a MITM CA + minter and trust the upstream's self-signed cert.
	caCertPEM, caKeyPEM := genTestCA(t, "pkcs8")
	minter, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM})
	require.NoError(t, err)

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	logger := &fakeInterceptLogger{}

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-direct"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer func() { _ = directBackend.Stop(context.Background()) }()

	proxyAddr, cleanup := startProxy(t, HTTPHandlerConfig{
		GetBackend:  func(string, string) backend.Backend { return directBackend },
		DialTimeout: 5 * time.Second,
		MITM: &MITMInterceptor{
			Minter:            minter,
			Logger:            logger,
			UpstreamTLSConfig: &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12},
		},
	})
	defer cleanup()

	// Client trusts the MITM CA so the terminated TLS verifies.
	clientRoots := x509.NewCertPool()
	require.True(t, clientRoots.AppendCertsFromPEM(caCertPEM))

	rawConn := dialProxyConnect(t, proxyAddr, upstreamAddr)
	defer rawConn.Close()

	// Use the connection IP host as the SNI/ServerName the minted leaf must match.
	host, _, err := net.SplitHostPort(upstreamAddr)
	require.NoError(t, err)

	tlsConn := tls.Client(rawConn, &tls.Config{
		RootCAs:    clientRoots,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	// Send an HTTP request over the intercepted tunnel.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+host+"/api/thing", strings.NewReader("payload-123"))
	require.NoError(t, err)
	req.Header.Set("X-Test", "abc")
	require.NoError(t, req.Write(tlsConn))

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Body round-trips correctly and upstream header is preserved.
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "echo:payload-123", string(respBody))
	assert.Equal(t, "yes", resp.Header.Get("X-Upstream"))

	// Allow the proxy goroutine to record the response log before asserting.
	reqs, resps := waitForLogs(t, logger)
	require.NotEmpty(t, reqs)
	require.NotEmpty(t, resps)

	assert.Equal(t, http.MethodPost, reqs[0].method)
	assert.Equal(t, "/api/thing", reqs[0].path)
	assert.Equal(t, host, reqs[0].host)
	assert.Equal(t, "payload-123", string(reqs[0].body))
	assert.Equal(t, "abc", reqs[0].headers["X-Test"])

	assert.Equal(t, http.StatusCreated, resps[0].statusCode)
	assert.Equal(t, "echo:payload-123", string(resps[0].body))
	assert.Equal(t, "yes", resps[0].headers["X-Upstream"])
}

func TestInterceptConnect_Bypassed_Opaque(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hi"))
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	host, _, err := net.SplitHostPort(upstreamAddr)
	require.NoError(t, err)

	caCertPEM, caKeyPEM := genTestCA(t, "pkcs8")
	minter, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM})
	require.NoError(t, err)
	logger := &fakeInterceptLogger{}

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-direct"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer func() { _ = directBackend.Stop(context.Background()) }()

	proxyAddr, cleanup := startProxy(t, HTTPHandlerConfig{
		GetBackend:  func(string, string) backend.Backend { return directBackend },
		DialTimeout: 5 * time.Second,
		MITM: &MITMInterceptor{
			Minter: minter,
			Logger: logger,
			Bypass: func(h string) bool { return h == host }, // bypass our upstream
		},
	})
	defer cleanup()

	rawConn := dialProxyConnect(t, proxyAddr, upstreamAddr)
	defer rawConn.Close()

	// Because the host is bypassed, the tunnel is opaque: the upstream's own
	// (self-signed) cert is presented, so the client must trust THAT, not the
	// MITM CA. This proves no interception occurred.
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	tlsConn := tls.Client(rawConn, &tls.Config{
		RootCAs:    upstreamRoots,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "hi", string(body))

	// Nothing should have been intercepted/logged.
	reqs, resps := logger.snapshot()
	assert.Empty(t, reqs)
	assert.Empty(t, resps)
}

func TestInterceptConnect_Disabled_TunnelUntouched(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()
	host, _, err := net.SplitHostPort(upstreamAddr)
	require.NoError(t, err)

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-direct"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer func() { _ = directBackend.Stop(context.Background()) }()

	// No MITM injected at all (default OFF).
	proxyAddr, cleanup := startProxy(t, HTTPHandlerConfig{
		GetBackend:  func(string, string) backend.Backend { return directBackend },
		DialTimeout: 5 * time.Second,
	})
	defer cleanup()

	rawConn := dialProxyConnect(t, proxyAddr, upstreamAddr)
	defer rawConn.Close()

	// Opaque tunnel: upstream presents its real cert.
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	tlsConn := tls.Client(rawConn, &tls.Config{
		RootCAs:    upstreamRoots,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "plain", string(body))
}

func TestMITMInterceptor_ShouldIntercept(t *testing.T) {
	// Nil interceptor never intercepts (disabled-path guarantee).
	var nilInt *MITMInterceptor
	assert.False(t, nilInt.shouldIntercept("example.com:443"))

	// Interceptor with nil minter never intercepts.
	assert.False(t, (&MITMInterceptor{}).shouldIntercept("example.com:443"))

	caCertPEM, caKeyPEM := genTestCA(t, "pkcs8")
	minter, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM})
	require.NoError(t, err)

	in := &MITMInterceptor{Minter: minter}
	assert.True(t, in.shouldIntercept("example.com:443"))

	in.Bypass = func(h string) bool { return h == "skip.example.com" }
	assert.False(t, in.shouldIntercept("skip.example.com:443"))
	assert.True(t, in.shouldIntercept("other.example.com:443"))
}

func TestFlattenHeaders(t *testing.T) {
	assert.Nil(t, flattenHeaders(http.Header{}))
	h := http.Header{"A": {"1"}, "B": {"x", "y"}}
	got := flattenHeaders(h)
	assert.Equal(t, "1", got["A"])
	assert.Equal(t, "x, y", got["B"])
}

func TestTruncateForLog(t *testing.T) {
	small := []byte("abc")
	assert.Equal(t, small, truncateForLog(small))
	big := make([]byte, maxLoggedBody+10)
	assert.Len(t, truncateForLog(big), maxLoggedBody)
}

// waitForLogs polls the logger until both a request and a response are present
// (the response is recorded by the proxy goroutine just after the client reads
// it), or fails after a short timeout.
func waitForLogs(t *testing.T, l *fakeInterceptLogger) ([]loggedReq, []loggedResp) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		reqs, resps := l.snapshot()
		if len(reqs) > 0 && len(resps) > 0 {
			return reqs, resps
		}
		time.Sleep(10 * time.Millisecond)
	}
	reqs, resps := l.snapshot()
	return reqs, resps
}
