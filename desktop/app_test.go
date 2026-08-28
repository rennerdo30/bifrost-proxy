package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/client"
	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

const (
	// testStopTimeout bounds client shutdown in tests.
	testStopTimeout = 5 * time.Second
	// testDialTimeout bounds test dials through the local proxy.
	testDialTimeout = 2 * time.Second
	// testDeadline bounds a single proxied request in tests.
	testDeadline = 5 * time.Second
	// testPollInterval and testPollTimeout drive the counter polling loops.
	testPollInterval = 10 * time.Millisecond
	testPollTimeout  = 5 * time.Second
)

// newTestApp builds an App around a real embedded client, bypassing
// initClient (which would read and write the user's real config directory).
func newTestApp(t *testing.T, cfg *config.ClientConfig) *App {
	t.Helper()

	c, err := client.New(cfg)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	app := NewApp()
	app.ctx = ctx
	app.cancel = cancel
	app.client = c
	app.clientCfg = cfg
	return app
}

// stopApp stops the app's embedded client with a bounded context.
func stopApp(t *testing.T, app *App) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testStopTimeout)
	defer cancel()
	if err := app.client.Stop(ctx); err != nil {
		t.Fatalf("client.Stop: %v", err)
	}
}

// freeAddr returns a loopback address that nothing is listening on. It is used
// both for "configured but unreachable" servers and to reserve a proxy port.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

// TestGetStatus_UnreachableServerIsNotConnected is the regression test for the
// fabricated connection state: GetStatus used to report
// ServerConnected = (address != ""), so any configured address lit up the
// dashboard's green "Connected" shield whether or not the server existed.
func TestGetStatus_UnreachableServerIsNotConnected(t *testing.T) {
	deadAddr := freeAddr(t)

	app := newTestApp(t, &config.ClientConfig{
		Server: config.ServerConnection{
			Address:  deadAddr,
			Protocol: "http",
			// Keep the client's own dial timeout short so the probe cannot
			// dominate the test even if the platform is slow to refuse.
			Timeout: config.Duration(500 * time.Millisecond),
		},
	})

	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer stopApp(t, app)

	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	if status.ServerAddress != deadAddr {
		t.Errorf("ServerAddress = %q, want %q", status.ServerAddress, deadAddr)
	}
	if status.ServerConnected {
		t.Error("ServerConnected = true for a configured but unreachable server; " +
			"the flag must reflect reachability, not configuration")
	}
}

// TestGetStatus_ReachableServerIsConnected is the positive half: a server that
// really accepts connections must be reported as connected.
func TestGetStatus_ReachableServerIsConnected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close() //nolint:errcheck // test stub
		}
	}()

	app := newTestApp(t, &config.ClientConfig{
		Server: config.ServerConnection{Address: ln.Addr().String(), Protocol: "http"},
	})

	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer stopApp(t, app)

	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if !status.ServerConnected {
		t.Error("ServerConnected = false for a reachable server")
	}
}

// TestGetStatus_EmptyServerAddressIsNotConnected keeps the no-address case
// honest without paying for a dial.
func TestGetStatus_EmptyServerAddressIsNotConnected(t *testing.T) {
	app := newTestApp(t, &config.ClientConfig{})

	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer stopApp(t, app)

	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.ServerConnected {
		t.Error("ServerConnected = true with no server address configured")
	}
}

// TestGetStatus_ReportsRealTraffic is the regression test for the traffic panel
// rendering permanent zeros as live telemetry: BytesSent, BytesReceived and
// ActiveConns existed on the client but GetStatus never read them.
func TestGetStatus_ReportsRealTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("desktop-telemetry")) //nolint:errcheck // test upstream
	}))
	defer upstream.Close()

	proxyAddr := freeAddr(t)

	app := newTestApp(t, &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: proxyAddr},
		},
		Server: config.ServerConnection{Address: freeAddr(t), Protocol: "http"},
		Routes: []config.ClientRouteConfig{{Domains: []string{"*"}, Action: "direct"}},
	})

	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer stopApp(t, app)

	// Drive one request through the local HTTP proxy.
	conn, err := net.DialTimeout("tcp", proxyAddr, testDialTimeout)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := fmt.Fprintf(conn,
		"GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String()); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close() //nolint:errcheck // test cleanup
	_ = conn.Close()      //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxied status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "desktop-telemetry" {
		t.Fatalf("proxied body = %q", string(body))
	}

	// The counters are recorded from the connection goroutine, so poll.
	deadline := time.Now().Add(testPollTimeout)
	var status *StatusResponse
	for time.Now().Before(deadline) {
		status, err = app.GetStatus()
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if status.BytesSent > 0 && status.BytesReceived > 0 {
			break
		}
		time.Sleep(testPollInterval)
	}

	if status.BytesSent <= 0 {
		t.Errorf("BytesSent = %d, want > 0; the traffic panel is showing fabricated zeros", status.BytesSent)
	}
	if status.BytesReceived <= 0 {
		t.Errorf("BytesReceived = %d, want > 0; the traffic panel is showing fabricated zeros", status.BytesReceived)
	}
	if status.ActiveConns < 0 {
		t.Errorf("ActiveConns = %d, want >= 0", status.ActiveConns)
	}
}

// TestGetStatus_ActiveConnectionsCountsInFlight proves the active-connection
// gauge in the dashboard is live and not a hardcoded zero.
func TestGetStatus_ActiveConnectionsCountsInFlight(t *testing.T) {
	// An upstream that blocks until released, so a proxied request stays
	// in flight while we sample the gauge.
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte("released")) //nolint:errcheck // test upstream
	}))
	defer upstream.Close()

	proxyAddr := freeAddr(t)

	app := newTestApp(t, &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: proxyAddr},
		},
		Routes: []config.ClientRouteConfig{{Domains: []string{"*"}, Action: "direct"}},
	})

	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer stopApp(t, app)

	conn, err := net.DialTimeout("tcp", proxyAddr, testDialTimeout)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := fmt.Fprintf(conn,
		"GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String()); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var peak int
	deadline := time.Now().Add(testPollTimeout)
	for time.Now().Before(deadline) {
		status, statusErr := app.GetStatus()
		if statusErr != nil {
			t.Fatalf("GetStatus: %v", statusErr)
		}
		if status.ActiveConns > peak {
			peak = status.ActiveConns
		}
		if peak > 0 {
			break
		}
		time.Sleep(testPollInterval)
	}
	close(release)

	if peak == 0 {
		t.Error("ActiveConns stayed 0 while a request was in flight")
	}
}

// TestGetStatus_NotInitialized covers the pre-client state the dashboard shows
// on a failed startup.
func TestGetStatus_NotInitialized(t *testing.T) {
	app := NewApp()

	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Status != "not_initialized" {
		t.Errorf("Status = %q, want %q", status.Status, "not_initialized")
	}
	if status.LastError == "" {
		t.Error("LastError must explain why the client is unavailable")
	}
}

// TestGetStatus_StoppedClient covers the state after Disconnect.
func TestGetStatus_StoppedClient(t *testing.T) {
	app := newTestApp(t, &config.ClientConfig{
		Server: config.ServerConnection{Address: freeAddr(t), Protocol: "http"},
	})

	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Status != "stopped" {
		t.Errorf("Status = %q, want %q", status.Status, "stopped")
	}
	if status.ServerConnected {
		t.Error("a stopped client must not report ServerConnected")
	}
}

// TestConnectDisconnectCycle is the desktop-level regression test for the
// three-click crash: Disconnect -> Connect -> Disconnect used to close the
// client's done channel twice and panic the whole process.
func TestConnectDisconnectCycle(t *testing.T) {
	app := newTestApp(t, &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{Address: freeAddr(t), Protocol: "http"},
	})

	// The real app starts the client during startup(), before the user can
	// click anything.
	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}

	// Click 1: Disconnect.
	if err := app.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if app.IsConnected() {
		t.Error("IsConnected = true after Disconnect")
	}

	// Click 2: Connect.
	if err := app.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !app.IsConnected() {
		t.Error("IsConnected = false after Connect")
	}

	// Click 3: Disconnect. This is the one that used to panic.
	if err := app.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if app.IsConnected() {
		t.Error("IsConnected = true after the second Disconnect")
	}
}

// TestSelectServer_SwitchesLiveUpstreamAndProbe is the regression for the
// contradictory desktop state: SelectServer used to mutate only the config,
// so GetStatus kept probing the OLD server (reporting Connected for a
// selection that pointed elsewhere) and GetServers labeled the selected
// server "connected" merely because the local client was running.
func TestSelectServer_SwitchesLiveUpstreamAndProbe(t *testing.T) {
	// alpha is a live listener; beta is dead.
	liveLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer liveLn.Close()
	go func() {
		for {
			conn, acceptErr := liveLn.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	aliveAddr := liveLn.Addr().String()
	deadAddr := freeAddr(t)

	cfg := &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  aliveAddr,
			Protocol: "http",
			Timeout:  config.Duration(500 * time.Millisecond),
		},
		Servers: []config.NamedServer{
			{Name: "alpha", Address: aliveAddr, Protocol: "http", IsDefault: true},
			{Name: "beta", Address: deadAddr, Protocol: "http"},
		},
	}
	app := newTestApp(t, cfg)

	if err := app.client.Start(app.ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer stopApp(t, app)

	// Sanity: the initially selected server is reachable.
	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if !status.ServerConnected {
		t.Fatal("precondition: the live alpha server should probe as connected")
	}

	// Select the unreachable server while the old one is still alive — the
	// review's exact scenario.
	if err := app.SelectServer("beta"); err != nil {
		t.Fatalf("SelectServer: %v", err)
	}

	status, err = app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.ServerAddress != deadAddr {
		t.Errorf("ServerAddress = %q, want the selected %q", status.ServerAddress, deadAddr)
	}
	if status.ServerConnected {
		t.Error("ServerConnected = true after selecting an unreachable server; " +
			"the probe must follow the selection, not the previous upstream")
	}

	servers, err := app.GetServers()
	if err != nil {
		t.Fatalf("GetServers: %v", err)
	}
	byName := map[string]string{}
	for _, s := range servers {
		byName[s.Name] = s.Status
	}
	if byName["beta"] != "disconnected" {
		t.Errorf("selected unreachable server status = %q, want %q "+
			"(a running local client must not fabricate a connected label)",
			byName["beta"], "disconnected")
	}
	if byName["alpha"] != "available" {
		t.Errorf("unselected server status = %q, want %q", byName["alpha"], "available")
	}

	// Selecting an unknown name is an error, not a silent success.
	if err := app.SelectServer("missing"); err == nil {
		t.Error("SelectServer(missing) = nil, want error")
	}
}

// TestConnectDisconnect_UnreachableUpstreamStillStops proves the lifecycle
// contract the Connect button relies on: a running client with an unreachable
// upstream is still running, and Disconnect — not Connect — is the available
// action and actually stops it.
func TestConnectDisconnect_UnreachableUpstreamStillStops(t *testing.T) {
	app := newTestApp(t, &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  freeAddr(t),
			Protocol: "http",
			Timeout:  config.Duration(500 * time.Millisecond),
		},
	})

	if err := app.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !app.client.Running() {
		t.Fatal("client should be running after Connect")
	}

	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Status != "running" {
		t.Errorf("Status = %q, want running: the UI derives the button action from it", status.Status)
	}
	if status.ServerConnected {
		t.Error("ServerConnected should be false for an unreachable upstream")
	}

	if err := app.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if app.client.Running() {
		t.Error("client should be stopped after Disconnect")
	}
}
