package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// labelsFor gathers the given metric family from the server's registry and
// returns the value of the named label for every sample in it.
func labelsFor(t *testing.T, s *Server, family, label string) []string {
	t.Helper()

	families, err := s.metrics.Registry().Gather()
	require.NoError(t, err)

	var labels []string
	for _, mf := range families {
		if mf.GetName() != family {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels = append(labels, labelValue(m, label))
		}
	}
	return labels
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

// TestServer_ConnectionMetricsCarryBackendLabel is the regression test for the
// permanently-empty `backend` label: serveHTTP/serveSOCKS5 used to hand
// RecordBytes/RecordConnection an empty backend name even though routing had
// already resolved one, which made the per-backend Prometheus breakdown
// useless.
func TestServer_ConnectionMetricsCarryBackendLabel(t *testing.T) {
	const backendName = "labelled-backend"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK")) //nolint:errcheck // test upstream
	}))
	defer target.Close()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: backendName, Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: backendName},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Stop(stopCtx) //nolint:errcheck // test cleanup
	})

	// Drive one plain (non-CONNECT) request through the proxy so a backend is
	// selected and the response is fully forwarded.
	conn, err := net.DialTimeout("tcp", s.httpListener.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	targetHost := strings.TrimPrefix(target.URL, "http://")
	_, err = fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.URL, targetHost)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "OK", string(body))
	conn.Close()

	// The metrics are recorded from the connection goroutine after ServeConn
	// returns, so poll until the samples appear.
	for _, family := range []string{
		"bifrost_bytes_sent_total",
		"bifrost_bytes_received_total",
		"bifrost_connections_total",
		"bifrost_connection_duration_seconds",
	} {
		requireBackendLabel(t, s, family, backendName)
	}
}

// TestServer_SOCKS5MetricsRecorded is the regression test for SOCKS5 traffic
// being absent from the request/duration/size/byte metrics: the SOCKS5 handler
// used to be constructed without a RecordMetrics hook, so only HTTP traffic
// showed up in Prometheus.
func TestServer_SOCKS5MetricsRecorded(t *testing.T) {
	const backendName = "socks-labelled-backend"

	targetServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetServer.Close()

	go func() {
		for {
			c, acceptErr := targetServer.Accept()
			if acceptErr != nil {
				return
			}
			_, _ = c.Write([]byte("hello from target")) //nolint:errcheck // test upstream
			c.Close()
		}
	}()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			SOCKS5: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Backends: []config.BackendConfig{
			{Name: backendName, Type: "direct", Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Domains: []string{"*"}, Backend: backendName},
		},
	}

	s, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Stop(stopCtx) //nolint:errcheck // test cleanup
	})

	conn, err := net.DialTimeout("tcp", s.socks5Listener.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	// Greeting: version 5, one method, "no authentication".
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err)

	targetAddr := targetServer.Addr().(*net.TCPAddr)
	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, targetAddr.IP.To4()...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(targetAddr.Port)) //nolint:gosec // G115: test port fits uint16
	connectReq = append(connectReq, port...)
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(conn, connectResp)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), connectResp[1], "SOCKS5 CONNECT must succeed")

	// Drain the tunnel so both copy directions finish, then close.
	_, _ = io.Copy(io.Discard, conn) //nolint:errcheck // draining
	conn.Close()

	for _, family := range []string{
		"bifrost_bytes_sent_total",
		"bifrost_bytes_received_total",
		"bifrost_connections_total",
	} {
		requireBackendLabel(t, s, family, backendName)
	}

	// Request-scoped families are labelled by protocol, not backend.
	requireProtocolLabel(t, s, "bifrost_requests_total", protocolSOCKS5)
	requireProtocolLabel(t, s, "bifrost_request_duration_seconds", protocolSOCKS5)
	requireProtocolLabel(t, s, "bifrost_request_size_bytes", protocolSOCKS5)
	requireProtocolLabel(t, s, "bifrost_response_size_bytes", protocolSOCKS5)
}

func requireBackendLabel(t *testing.T, s *Server, family, want string) {
	t.Helper()
	require.Eventuallyf(t, func() bool {
		for _, label := range labelsFor(t, s, family, "backend") {
			if label == want {
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond,
		"%s never reported backend=%q; labels seen: %v", family, want, labelsFor(t, s, family, "backend"))
}

func requireProtocolLabel(t *testing.T, s *Server, family, want string) {
	t.Helper()
	require.Eventuallyf(t, func() bool {
		for _, label := range labelsFor(t, s, family, "protocol") {
			if label == want {
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond,
		"%s never reported protocol=%q; labels seen: %v", family, want, labelsFor(t, s, family, "protocol"))
}
