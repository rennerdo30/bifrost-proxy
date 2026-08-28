package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

const (
	// testStopTimeout bounds Stop in tests so a hung shutdown fails fast
	// instead of burning the package's default timeout.
	testStopTimeout = 5 * time.Second
	// testHealthInterval keeps the health monitor probing often enough for the
	// restart assertions to observe it without sleeping for long.
	testHealthInterval = 20 * time.Millisecond
	// testHealthTimeout bounds a single health probe in tests.
	testHealthTimeout = 200 * time.Millisecond
	// testEventually* configure require.Eventually polling in this file.
	testEventuallyWait = 3 * time.Second
	testEventuallyTick = 10 * time.Millisecond
)

// stopClient stops c with a bounded context, failing the test on error.
func stopClient(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testStopTimeout)
	defer cancel()
	require.NoError(t, c.Stop(ctx))
}

// countingListener is a TCP listener that accepts and immediately closes every
// connection, counting them. It stands in for a reachable Bifrost server so
// tests can observe that the health monitor is really probing.
type countingListener struct {
	ln    net.Listener
	conns atomic.Int64
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cl := &countingListener{ln: ln}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			cl.conns.Add(1)
			_ = conn.Close() //nolint:errcheck // test stub
		}
	}()
	t.Cleanup(func() { _ = ln.Close() }) //nolint:errcheck // test cleanup
	return cl
}

func (c *countingListener) addr() string { return c.ln.Addr().String() }

func (c *countingListener) count() int64 { return c.conns.Load() }

// TestClient_StopStartStop_NoPanic is the regression test for the reachable
// "close of closed channel" panic: done was allocated once in New, so the second
// Stop of a Stop -> Start -> Stop cycle closed an already-closed channel and
// killed the process. That cycle is three clicks of the desktop app's
// Connect/Disconnect button.
func TestClient_StopStartStop_NoPanic(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	require.NoError(t, c.Start(ctx))
	require.True(t, c.Running())

	stopClient(t, c)
	require.False(t, c.Running())

	require.NoError(t, c.Start(ctx))
	require.True(t, c.Running())

	// Without the per-run done channel this second Stop panics.
	stopClient(t, c)
	require.False(t, c.Running())
}

// TestClient_ManyRestartCycles_NoPanic exercises more than one restart, because
// a fix that only reallocates done on the first restart would still crash later.
func TestClient_ManyRestartCycles_NoPanic(t *testing.T) {
	const cycles = 4

	c := newTestClient(t)
	ctx := context.Background()

	for i := 0; i < cycles; i++ {
		require.NoError(t, c.Start(ctx), "cycle %d: Start", i)
		require.True(t, c.Running(), "cycle %d: Running after Start", i)
		stopClient(t, c)
		require.False(t, c.Running(), "cycle %d: Running after Stop", i)
	}
}

// TestClient_RestartRevivesBackgroundLoops covers the silent fake-success half
// of the bug: before the fix the second Start returned nil while every goroutine
// selecting on the (already closed) done channel exited immediately, so the
// health monitor never probed again even though the client reported running.
func TestClient_RestartRevivesBackgroundLoops(t *testing.T) {
	server := newCountingListener(t)

	c, err := New(&config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{
			Address:  server.addr(),
			Protocol: "http",
			HealthCheck: &config.HealthCheckConfig{
				Type:     "tcp",
				Interval: config.Duration(testHealthInterval),
				Timeout:  config.Duration(testHealthTimeout),
			},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	require.Eventually(t, func() bool { return server.count() > 0 },
		testEventuallyWait, testEventuallyTick,
		"the health monitor never probed during the first run")

	stopClient(t, c)
	afterStop := server.count()

	require.NoError(t, c.Start(ctx))
	require.Eventually(t, func() bool { return server.count() > afterStop },
		testEventuallyWait, testEventuallyTick,
		"the health monitor did not resume after the client was restarted")

	stopClient(t, c)
}

// TestClient_StopWithoutStart is a no-op and must not close the placeholder
// done channel, otherwise a later Start/Stop would panic.
func TestClient_StopWithoutStart(t *testing.T) {
	c := newTestClient(t)

	stopClient(t, c)
	require.False(t, c.Running())

	require.NoError(t, c.Start(context.Background()))
	stopClient(t, c)
}

// TestClient_DoubleStopIsNoOp verifies Stop is idempotent within a single run.
func TestClient_DoubleStopIsNoOp(t *testing.T) {
	c := newTestClient(t)
	require.NoError(t, c.Start(context.Background()))

	stopClient(t, c)
	stopClient(t, c)
}

// TestClient_FailedStartRollsBack covers the other lifecycle fake-success: a
// Start that cannot bind its listener used to leave running == true, so the
// desktop app's Connect (which only calls Start when !Running()) reported
// success forever afterwards while nothing was listening.
func TestClient_FailedStartRollsBack(t *testing.T) {
	// Occupy a port so the client's HTTP listener cannot bind.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blocker.Close() //nolint:errcheck // test cleanup

	c, err := New(&config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: blocker.Addr().String()},
		},
		Server: config.ServerConnection{Address: "127.0.0.1:1", Protocol: "http"},
	})
	require.NoError(t, err)

	err = c.Start(context.Background())
	require.Error(t, err, "Start must fail when the HTTP listener cannot bind")
	assert.Contains(t, err.Error(), "listen HTTP")
	assert.False(t, c.Running(), "a failed Start must not leave the client running")

	// The rolled-back run must not leave a closed done channel behind: a
	// subsequent successful Start/Stop has to work.
	require.NoError(t, blocker.Close())
	require.NoError(t, c.Start(context.Background()))
	stopClient(t, c)
}

// TestClient_ServerConnected_ReflectsReachability pins the honest connectivity
// check that replaced the desktop app's "an address is configured" heuristic.
func TestClient_ServerConnected_ReflectsReachability(t *testing.T) {
	server := newCountingListener(t)

	reachable, err := New(&config.ClientConfig{
		Server: config.ServerConnection{Address: server.addr(), Protocol: "http"},
	})
	require.NoError(t, err)
	assert.True(t, reachable.ServerConnected(context.Background()),
		"a reachable server must report connected")

	// Bind and release a port so the address is well-formed but nothing listens.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := deadLn.Addr().String()
	require.NoError(t, deadLn.Close())

	unreachable, err := New(&config.ClientConfig{
		Server: config.ServerConnection{Address: deadAddr, Protocol: "http"},
	})
	require.NoError(t, err)
	assert.False(t, unreachable.ServerConnected(context.Background()),
		"a configured but unreachable address must not report connected")
}
