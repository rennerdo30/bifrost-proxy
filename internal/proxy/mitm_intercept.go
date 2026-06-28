package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/util"
)

// InterceptLogger receives decrypted HTTP request/response metadata observed by
// the MITM data path. It is satisfied by *debug.Logger
// (LogInterceptedRequest/LogInterceptedResponse), but is declared here as a
// minimal interface so the proxy package does not import the debug package
// (avoiding an import cycle) and so it can be faked in tests.
type InterceptLogger interface {
	LogInterceptedRequest(ctx context.Context, host, method, path string, headers map[string]string, body []byte)
	LogInterceptedResponse(ctx context.Context, host string, statusCode int, headers map[string]string, body []byte, duration time.Duration, bytesSent, bytesRecv int64)
}

// MITMInterceptor bundles everything the HTTP handler needs to perform live
// HTTPS interception. It is injected (defaulting to nil) so that when MITM is
// disabled the handler never touches the interception code path and CONNECT
// tunnels stay byte-for-byte identical to today's opaque behavior.
//
// SECURITY: a non-nil MITMInterceptor means the proxy will decrypt TLS for
// in-scope hosts. Callers must only construct one when config MITM is enabled
// and a CA has been loaded successfully.
type MITMInterceptor struct {
	// Minter mints leaf certificates per SNI/host. Required (non-nil).
	Minter *CertMinter

	// Logger receives decrypted request/response metadata. May be nil, in which
	// case interception still occurs (to decrypt and forward) but nothing is
	// logged. Typically a *debug.Logger.
	Logger InterceptLogger

	// Bypass reports whether a given target host (without port) must NOT be
	// intercepted. When it returns true the handler falls back to an opaque
	// tunnel. May be nil (intercept everything in scope).
	Bypass func(host string) bool

	// UpstreamTLSConfig is an optional base config for dialing the real
	// upstream. It is cloned per connection and its ServerName is set to the
	// target host. When nil a default (system roots, ServerName=host) is used.
	// SECURITY: leaving InsecureSkipVerify false here preserves upstream
	// certificate validation so the proxy still detects a forged upstream.
	UpstreamTLSConfig *tls.Config
}

// shouldIntercept reports whether the interceptor is active and the given host
// is in scope (not bypassed). A nil interceptor or nil minter is never active,
// guaranteeing the disabled path.
func (m *MITMInterceptor) shouldIntercept(host string) bool {
	if m == nil || m.Minter == nil {
		return false
	}
	if m.Bypass != nil && m.Bypass(normalizeHost(host)) {
		return false
	}
	return true
}

// interceptConnect performs the live MITM data path for a CONNECT request once
// the proxy has already replied 200 to the client. It terminates the client TLS
// using a minted leaf, dials the upstream over TLS through targetConn, and
// shuttles decrypted HTTP request/response pairs between them, streaming the
// decrypted metadata into the interceptor's logger.
//
// host is the full "host:port" CONNECT target. targetConn is the already-dialed
// (plaintext TCP) connection to the upstream through the selected backend.
func (h *HTTPHandler) interceptConnect(ctx context.Context, clientConn, targetConn net.Conn, host string) error {
	serverName := normalizeHost(host)

	// Terminate the client side: present a minted leaf for the SNI, falling back
	// to the CONNECT target host when the client omits SNI (e.g. IP literals,
	// which never carry an SNI extension). Without this fallback an IP-addressed
	// CONNECT would fail the client handshake with "empty server name".
	clientTLSCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = serverName
			}
			return h.mitm.Minter.GetCertificate(name)
		},
	}
	tlsClient := tls.Server(clientConn, clientTLSCfg)
	if err := tlsClient.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("mitm: client TLS handshake: %w", err)
	}
	defer tlsClient.Close()

	// Establish TLS to the real upstream over the existing backend connection.
	// Upstream certificate validation stays ON by default so the proxy still
	// detects a forged upstream rather than silently trusting it.
	var upstreamCfg *tls.Config
	if h.mitm.UpstreamTLSConfig != nil {
		upstreamCfg = h.mitm.UpstreamTLSConfig.Clone()
	} else {
		upstreamCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if upstreamCfg.ServerName == "" {
		upstreamCfg.ServerName = serverName
	}
	tlsUpstream := tls.Client(targetConn, upstreamCfg)
	if err := tlsUpstream.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("mitm: upstream TLS handshake: %w", err)
	}
	defer tlsUpstream.Close()

	clientReader := bufio.NewReader(tlsClient)
	upstreamReader := bufio.NewReader(tlsUpstream)

	// Process request/response pairs on this (potentially keep-alive) tunnel
	// until either side closes or an error occurs.
	for {
		if err := h.interceptExchange(ctx, serverName, clientReader, tlsClient, upstreamReader, tlsUpstream); err != nil {
			if errors.Is(err, io.EOF) || isClosedConnErr(err) {
				return nil
			}
			return err
		}
	}
}

// interceptExchange reads one decrypted request from the client, forwards it
// upstream, reads the response, logs both, and writes the response back to the
// client. It returns io.EOF when the client closes the tunnel.
func (h *HTTPHandler) interceptExchange(ctx context.Context, host string, clientReader *bufio.Reader, clientConn net.Conn, upstreamReader *bufio.Reader, upstreamConn net.Conn) error {
	start := time.Now()

	req, err := http.ReadRequest(clientReader)
	if err != nil {
		return err // io.EOF on clean close; surfaced to caller
	}

	// Capture and restore the request body so we can both forward it (in full)
	// and log it (possibly truncated).
	// drainBody closes the original body and swaps in a buffered NopCloser.
	defer func() { _ = req.Body.Close() }()
	reqBody, err := drainBody(&req.Body)
	if err != nil {
		return fmt.Errorf("mitm: read request body: %w", err)
	}

	if h.mitm.Logger != nil {
		h.mitm.Logger.LogInterceptedRequest(ctx, host, req.Method, req.URL.RequestURI(),
			flattenHeaders(req.Header), truncateForLog(reqBody))
	}

	// Forward the (reconstructed) request to the upstream. Use Request.Write,
	// which emits an origin-form request line suitable for an upstream server.
	if writeErr := req.Write(upstreamConn); writeErr != nil {
		return fmt.Errorf("mitm: write request upstream: %w", writeErr)
	}

	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		return fmt.Errorf("mitm: read upstream response: %w", err)
	}
	// drainBody closes the original body and swaps in a buffered NopCloser; this
	// deferred close then targets the harmless NopCloser, satisfying bodyclose
	// without double-closing the underlying connection reader.
	defer func() { _ = resp.Body.Close() }()

	respBody, err := drainBody(&resp.Body)
	if err != nil {
		return fmt.Errorf("mitm: read response body: %w", err)
	}

	if h.mitm.Logger != nil {
		h.mitm.Logger.LogInterceptedResponse(ctx, host, resp.StatusCode, flattenHeaders(resp.Header),
			truncateForLog(respBody), time.Since(start), int64(len(reqBody)), int64(len(respBody)))
	}

	// Write the response back to the client over the terminated TLS connection.
	if writeErr := resp.Write(clientConn); writeErr != nil {
		return fmt.Errorf("mitm: write response to client: %w", writeErr)
	}

	// If either side requested closing the connection, stop the loop.
	if req.Close || resp.Close {
		return io.EOF
	}
	return nil
}

// maxLoggedBody bounds how much of a decrypted body is captured for logging.
// The FULL body is always forwarded; only the copy handed to the logger is
// bounded, so correctness of the proxied stream is never affected by this limit.
const maxLoggedBody = 64 * 1024 // 64 KiB

// truncateForLog returns at most maxLoggedBody bytes of b for logging.
func truncateForLog(b []byte) []byte {
	if int64(len(b)) > maxLoggedBody {
		return b[:maxLoggedBody]
	}
	return b
}

// drainBody fully reads the body, closes it, and replaces *body with a fresh
// reader over the captured bytes so the message can be re-written verbatim to
// the peer. The complete body is preserved so forwarding is byte-accurate.
func drainBody(body *io.ReadCloser) ([]byte, error) {
	if *body == nil || *body == http.NoBody {
		return nil, nil
	}
	data, err := io.ReadAll(*body)
	closeErr := (*body).Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	*body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}

// flattenHeaders converts an http.Header to a single-valued map for logging,
// joining multi-value headers with ", ".
func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// isClosedConnErr reports whether err indicates the connection was closed,
// which is a normal end-of-tunnel condition rather than a failure.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		util.IsTimeout(err)
}
