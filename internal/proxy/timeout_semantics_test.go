package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/backend"
)

// write_timeout is a NO-PROGRESS bound: a receiver that steadily consumes one
// byte per tick must receive the whole response even though the total transfer
// takes many times write_timeout. The previous per-Write absolute deadline —
// which the shipped tests never caught because they drained with io.ReadAll —
// truncated exactly this traffic.
func TestDeadlineConn_SlowConsumerWriteSurvives(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const writeTimeout = 100 * time.Millisecond
	dc := newDeadlineConn(server, 0, writeTimeout, 0)
	dc.writeDeadlines.Store(true)

	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}

	writeDone := make(chan error, 1)
	go func() {
		n, err := dc.Write(payload)
		if err == nil && n != len(payload) {
			err = fmt.Errorf("short write: %d of %d", n, len(payload))
		}
		writeDone <- err
	}()

	// Consume one byte every 20ms: 40 bytes take 800ms, eight times the
	// write_timeout, with progress in every window.
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 1)
	for len(got) < len(payload) {
		// Bounded so a regression (writer giving up) fails the test promptly
		// instead of deadlocking this loop.
		require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, err := client.Read(buf)
		require.NoError(t, err, "writer gave up after %d of %d bytes", len(got), len(payload))
		got = append(got, buf[:n]...)
		time.Sleep(20 * time.Millisecond)
	}

	require.NoError(t, <-writeDone, "a slow but progressing consumer must never be cut off")
	assert.Equal(t, payload, got)
}

// The other half of the no-progress contract: a receiver that has stopped
// reading entirely is timed out within roughly one window.
func TestDeadlineConn_StalledConsumerWriteTimesOut(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const writeTimeout = 80 * time.Millisecond
	dc := newDeadlineConn(server, 0, writeTimeout, 0)
	dc.writeDeadlines.Store(true)

	start := time.Now()
	_, err := dc.Write(make([]byte, 64))
	elapsed := time.Since(start)

	require.Error(t, err, "a zero-progress write must time out")
	assert.True(t, isTimeoutErr(err), "error should be a timeout, got %v", err)
	assert.Less(t, elapsed, 10*writeTimeout, "the stall must be detected promptly")
}

// A reaping-enabled tunnel transferring to a slow receiver must not be
// reaped: the transfer makes progress in every window even though no single
// Write completes within tunnel_idle_timeout. This is the review's
// 4-of-20-bytes truncation, inverted into a guarantee.
func TestTunnel_SlowReceiverTransferSurvivesReaping(t *testing.T) {
	target := newEchoServer(t)

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background()) //nolint:errcheck // test cleanup

	const tunnelIdle = 200 * time.Millisecond
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:        func(domain, clientIP string) backend.Backend { return directBackend },
		DialTimeout:       5 * time.Second,
		TunnelIdleTimeout: tunnelIdle,
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

	// Read the CONNECT response byte-wise so nothing beyond the header is
	// buffered away from the slow-read loop below.
	respBuf := make([]byte, 1)
	var head []byte
	for {
		_, rerr := io.ReadFull(clientConn, respBuf)
		require.NoError(t, rerr)
		head = append(head, respBuf[0])
		if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
			break
		}
	}
	require.Contains(t, string(head), "200")

	// Ask the echo server for 40 bytes, then consume the echo one byte every
	// 20ms: the transfer takes ~800ms, four times tunnel_idle_timeout, with
	// progress in every window.
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte('0' + i%10)
	}
	require.NoError(t, clientConn.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err = clientConn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, 0, len(payload))
	oneByte := make([]byte, 1)
	for len(got) < len(payload) {
		require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, rerr := clientConn.Read(oneByte)
		require.NoError(t, rerr,
			"the tunnel was torn down mid-transfer after %d of %d bytes despite continuous progress",
			len(got), len(payload))
		got = append(got, oneByte[:n]...)
		time.Sleep(20 * time.Millisecond)
	}
	assert.Equal(t, payload, got)
}

// A TLS-terminated listener must bound the handshake: a client that completes
// the TCP connect and then stalls the handshake forever used to pin the
// handler goroutine indefinitely, because peerCertificateChain ran the
// handshake before any deadline was armed — the slowloris hole, one layer
// down.
func TestServeConn_TLSHandshakeStallIsBounded(t *testing.T) {
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend:  func(domain, clientIP string) backend.Backend { return nil },
		ReadTimeout: 150 * time.Millisecond,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	tlsServer := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
	})

	served := make(chan struct{})
	go func() {
		defer close(served)
		handler.ServeConn(context.Background(), tlsServer)
	}()

	// Say nothing at all: the handshake never even starts.
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("handler still blocked in the TLS handshake long after read_timeout; the slowloris hole is open on TLS listeners")
	}
}

// selfSignedCert generates an ephemeral server certificate for TLS tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// An explicit backend connect_timeout must win over the handler-supplied
// global fallback: the handler no longer injects a 30s default, and the
// backend's dialer carries the resolved precedence.
func TestDialTimeoutPrecedence_BackendConnectTimeoutWins(t *testing.T) {
	// The handler keeps an unset DialTimeout at zero (fallback semantics).
	handler := NewHTTPHandler(HTTPHandlerConfig{
		GetBackend: func(domain, clientIP string) backend.Backend { return nil },
	})
	assert.Equal(t, time.Duration(0), handler.dialTimeout)

	// A backend with an explicit 100ms connect_timeout fails a dial to a
	// blackholed address in ~100ms even when the handler supplies a much
	// larger fallback — the fallback must not override the specific value.
	be := backend.NewDirectBackend(backend.DirectConfig{
		Name:           "explicit",
		ConnectTimeout: 100 * time.Millisecond,
	})
	require.NoError(t, be.Start(context.Background()))
	defer be.Stop(context.Background()) //nolint:errcheck // test cleanup

	start := time.Now()
	// 192.0.2.0/24 (TEST-NET-1) is unroutable: the dial can only time out.
	_, err := be.DialTimeout(context.Background(), "tcp", "192.0.2.1:9", time.Hour)
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Less(t, elapsed, 5*time.Second,
		"the explicit 100ms connect_timeout must govern the dial, not the 1h fallback")
}

// A MITM-intercepted tunnel must bound each decrypted request the same way a
// plaintext one is bounded: a client that trickles header bytes forever used
// to refresh idle_timeout on every read and hold the exchange loop
// indefinitely — the slowloris hole behind the intercepted TLS.
func TestMITM_DecryptedHeaderTrickleIsBounded(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	caCertPEM, caKeyPEM := genTestCA(t, "pkcs8")
	minter, err := NewCertMinter(MITMConfig{Enabled: true, CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM})
	require.NoError(t, err)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	directBackend := backend.NewDirectBackend(backend.DirectConfig{Name: "test-direct"})
	require.NoError(t, directBackend.Start(context.Background()))
	defer directBackend.Stop(context.Background()) //nolint:errcheck // test cleanup

	const readTimeout = 300 * time.Millisecond
	proxyAddr, cleanup := startProxy(t, HTTPHandlerConfig{
		GetBackend:  func(string, string) backend.Backend { return directBackend },
		DialTimeout: 5 * time.Second,
		ReadTimeout: readTimeout,
		IdleTimeout: readTimeout,
		MITM: &MITMInterceptor{
			Minter:            minter,
			UpstreamTLSConfig: &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12},
		},
	})
	defer cleanup()

	clientRoots := x509.NewCertPool()
	require.True(t, clientRoots.AppendCertsFromPEM(caCertPEM))

	rawConn := dialProxyConnect(t, proxyAddr, upstreamAddr)
	defer rawConn.Close()

	host, _, err := net.SplitHostPort(upstreamAddr)
	require.NoError(t, err)
	tlsConn := tls.Client(rawConn, &tls.Config{
		RootCAs:    clientRoots,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	// Trickle a decrypted request header one byte every 50ms, forever. Once
	// the header's first byte has arrived, the whole block must land within
	// read_timeout, so the proxy must cut this off long before the header
	// completes.
	header := []byte("GET /slow HTTP/1.1\r\nHost: " + host + "\r\nX-Padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n")
	start := time.Now()
	var writeErr error
	for i := 0; i < len(header); i++ {
		if _, writeErr = tlsConn.Write(header[i : i+1]); writeErr != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
		if time.Since(start) > 20*readTimeout {
			break
		}
	}
	if writeErr == nil {
		// TCP buffering can hide the close from writes for a while; a read
		// settles it.
		require.NoError(t, tlsConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		oneByte := make([]byte, 1)
		_, writeErr = tlsConn.Read(oneByte)
	}
	elapsed := time.Since(start)
	require.Error(t, writeErr, "the proxy held a trickled decrypted header open indefinitely")
	assert.Less(t, elapsed, 20*readTimeout,
		"the trickled header must be cut off near read_timeout, not held for %s", elapsed)
}
