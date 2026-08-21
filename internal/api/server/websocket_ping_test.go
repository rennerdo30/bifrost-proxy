package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// wsTestPath is the endpoint every WebSocket regression test dials.
const wsTestPath = "/api/v1/ws"

// dialWS opens a WebSocket against a test server and takes care of the
// handshake response body, which callers would otherwise leak.
func dialWS(ctx context.Context, t *testing.T, srv *httptest.Server, opts *websocket.DialOptions) *websocket.Conn {
	t.Helper()

	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+wsTestPath, opts)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.NoError(t, err, "upgrade should succeed")

	return conn
}

// TestWebSocket_SurvivesProtocolPing is a regression test for the bug where
// /api/v1/ws used golang.org/x/net/websocket, which that package's own docs
// describe as having "limited support for pings, pongs and close frames".
//
// Any peer that sent a protocol-level ping — notably the Home Assistant Ingress
// proxy in front of the add-on, and browser/proxy keepalives generally —
// desynchronised the frame stream, and the client aborted the connection with
// "RSV1 set / reserved bits must be 0". The dashboard's live updates died on a
// permanent reconnect loop while every REST endpoint looked perfectly healthy.
//
// This asserts the connection survives a control-frame ping and still carries
// application traffic afterwards.
func TestWebSocket_SurvivesProtocolPing(t *testing.T) {
	hub := NewWebSocketHub()
	go hub.Run()
	defer hub.Stop()

	srv := httptest.NewServer(hub)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := dialWS(ctx, t, srv, nil)
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Give the hub a moment to register the client.
	require.Eventually(t, func() bool {
		hub.mu.RLock()
		defer hub.mu.RUnlock()
		return len(hub.clients) == 1
	}, 3*time.Second, 20*time.Millisecond, "client should be registered")

	// coder/websocket only processes control frames while a read is in flight,
	// so pump reads in the background for the duration of the test — otherwise
	// the pong can never be observed and Ping would time out spuriously.
	type frame struct {
		typ  websocket.MessageType
		data []byte
	}
	frames := make(chan frame, 4)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			frames <- frame{typ, data}
		}
	}()

	// The actual regression: a protocol-level ping must be answered, not
	// corrupt the frame stream.
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()
	require.NoError(t, conn.Ping(pingCtx), "server must answer a protocol ping")

	// ...and the connection must still carry application traffic afterwards.
	hub.Broadcast(EventStats, StatsEvent{ActiveConnections: 7})

	var got frame
	select {
	case got = <-frames:
	case err := <-readErr:
		t.Fatalf("connection broke after ping: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("broadcast did not arrive after a ping")
	}
	require.Equal(t, websocket.MessageText, got.typ)
	data := got.data

	var msg struct {
		Type string `json:"type"`
		Data struct {
			ActiveConnections int64 `json:"active_connections"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(data, &msg))
	require.Equal(t, EventStats, msg.Type)
	require.Equal(t, int64(7), msg.Data.ActiveConnections)
}

// TestWebSocket_LegacyTextPing keeps the older application-level keepalive
// working: some clients send a literal "ping" text message instead of a
// control frame, and expect "pong" back.
func TestWebSocket_LegacyTextPing(t *testing.T) {
	hub := NewWebSocketHub()
	go hub.Run()
	defer hub.Stop()

	srv := httptest.NewServer(hub)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := dialWS(ctx, t, srv, nil)
	defer conn.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, conn.Write(ctx, websocket.MessageText, []byte("ping")))

	readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readCancel()
	_, data, err := conn.Read(readCtx)
	require.NoError(t, err)
	require.Equal(t, "pong", string(data))
}

// TestWebSocket_UpgradeThroughProxiedHost covers the Home Assistant Ingress
// shape: the proxy rewrites Host, so the browser's Origin no longer matches it
// and a plain same-origin check refuses the upgrade.
//
// This used to be handled by disabling origin verification altogether, which
// also let any web page connect (see TestWebSocket_RejectsCrossOriginUpgrade).
// The supported answer is now an explicit api.allowed_origins entry, so this
// asserts both halves of the contract: refused without the entry, accepted with
// it. TestWebSocket_AcceptsAllowlistedProxyOrigin covers the allowlist in more
// detail.
func TestWebSocket_UpgradeThroughProxiedHost(t *testing.T) {
	const ingressOrigin = "http://homeassistant.local:8123"

	t.Run("refused without an allowlist entry", func(t *testing.T) {
		hub := NewWebSocketHub()
		go hub.Run()
		defer hub.Stop()

		srv := httptest.NewServer(hub)
		defer srv.Close()

		status, err := tryDialWithOrigin(t, srv, ingressOrigin)
		require.Error(t, err)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("accepted when allowlisted", func(t *testing.T) {
		hub := NewWebSocketHub()
		hub.SetAllowedOrigins([]string{ingressOrigin})
		go hub.Run()
		defer hub.Stop()

		srv := httptest.NewServer(hub)
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn := dialWS(ctx, t, srv, &websocket.DialOptions{
			HTTPHeader: http.Header{"Origin": []string{ingressOrigin}},
		})
		conn.Close(websocket.StatusNormalClosure, "")
	})
}
