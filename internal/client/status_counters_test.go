package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

func TestClient_TrafficCounters_StartAtZero(t *testing.T) {
	c := newTestClient(t)
	assert.Zero(t, c.BytesSent())
	assert.Zero(t, c.BytesReceived())
	assert.Zero(t, c.ActiveConnections())
}

func TestClient_RecordProxyTraffic_IgnoresNonPositive(t *testing.T) {
	c := newTestClient(t)

	c.recordProxyTraffic(120, 34)
	c.recordProxyTraffic(-1, -1)
	c.recordProxyTraffic(0, 0)

	assert.Equal(t, int64(120), c.BytesSent())
	assert.Equal(t, int64(34), c.BytesReceived())
}

func TestClient_RecordProxyTraffic_Concurrent(t *testing.T) {
	c := newTestClient(t)

	const goroutines = 20
	const perGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				c.recordProxyTraffic(2, 3)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(goroutines*perGoroutine*2), c.BytesSent())
	assert.Equal(t, int64(goroutines*perGoroutine*3), c.BytesReceived())
}

func TestClient_ServeProxyConn_TracksActiveConnections(t *testing.T) {
	c := newTestClient(t)

	entered := make(chan int, 1)
	release := make(chan struct{})

	_, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.serveProxyConn(context.Background(), serverSide, func(_ context.Context, _ net.Conn) {
			entered <- c.ActiveConnections()
			<-release
		})
	}()

	select {
	case inFlight := <-entered:
		assert.Equal(t, 1, inFlight, "the gauge must count the in-flight connection")
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}

	close(release)
	<-done

	assert.Equal(t, 0, c.ActiveConnections(), "the gauge must be released when the handler returns")
}

func TestClient_ServeProxyConn_ReleasesGaugeOnPanic(t *testing.T) {
	c := newTestClient(t)
	_, serverSide := net.Pipe()

	assert.Panics(t, func() {
		c.serveProxyConn(context.Background(), serverSide, func(_ context.Context, _ net.Conn) {
			panic("handler exploded")
		})
	})

	assert.Equal(t, 0, c.ActiveConnections(), "a panicking handler must not leak the gauge")
}

// TestClient_StatusReportsRealTraffic is the regression test for /status always
// reporting bytes_sent=0, bytes_received=0 and active_connections=0: the API's
// counter callbacks were never supplied by the client, so the guarded branches
// were always skipped.
func TestClient_StatusReportsRealTraffic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("response-body")) //nolint:errcheck // test upstream
	}))
	defer target.Close()

	// Free ports for the proxy and the local API.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxyAddr := proxyLn.Addr().String()
	require.NoError(t, proxyLn.Close())

	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	apiAddr := apiLn.Addr().String()
	require.NoError(t, apiLn.Close())

	c, err := New(&config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: proxyAddr},
		},
		Server: config.ServerConnection{Address: "127.0.0.1:1", Protocol: "http"},
		Routes: []config.ClientRouteConfig{{Domains: []string{"*"}, Action: "direct"}},
		API:    config.APIConfig{Enabled: true, Listen: apiAddr},
	})
	require.NoError(t, err)

	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c.Stop(stopCtx) //nolint:errcheck // test cleanup
	})

	// Drive one request through the local proxy.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	targetHost := target.Listener.Addr().String()
	_, err = fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.URL, targetHost)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	conn.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "response-body", string(body))

	// Poll /status until the counters (recorded from the connection goroutine)
	// show up.
	var status map[string]interface{}
	require.Eventually(t, func() bool {
		statusResp, getErr := http.Get("http://" + apiAddr + "/api/v1/status") //nolint:noctx // short-lived test request
		if getErr != nil {
			return false
		}
		defer statusResp.Body.Close()
		if decErr := json.NewDecoder(statusResp.Body).Decode(&status); decErr != nil {
			return false
		}
		sent, ok := status["bytes_sent"].(float64)
		return ok && sent > 0
	}, 5*time.Second, 50*time.Millisecond, "status never reported non-zero bytes_sent")

	assert.Greater(t, status["bytes_sent"], float64(0))
	assert.Greater(t, status["bytes_received"], float64(0))
	assert.Contains(t, status, "active_connections")
}
