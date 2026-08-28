package client

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
	"github.com/rennerdo30/bifrost-proxy/internal/tray"
)

func newLifecycleTestConfig() *config.ClientConfig {
	return &config.ClientConfig{
		Proxy: config.ClientProxySettings{
			HTTP: config.ListenerConfig{Listen: "127.0.0.1:0"},
		},
		Server: config.ServerConnection{Address: "127.0.0.1:39990"},
	}
}

// The audit's overlap race: Stop used to flip running=false and release the
// lock before tearing anything down, so a concurrent Start brought up a fresh
// run whose resources the tail of the old Stop then dismantled. Start must now
// block until the previous Stop's COMPLETE teardown — modeled here by an
// in-flight connection Stop drains via the WaitGroup — has finished.
func TestClient_StartBlocksUntilStopTeardownCompletes(t *testing.T) {
	client, err := New(newLifecycleTestConfig())
	require.NoError(t, err)
	require.NoError(t, client.Start(context.Background()))

	// An "in-flight connection" that Stop must drain.
	release := make(chan struct{})
	client.wg.Add(1)
	go func() {
		defer client.wg.Done()
		<-release
	}()

	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		_ = client.Stop(context.Background()) //nolint:errcheck // Exercised for blocking behavior
	}()

	// Let Stop reach its drain phase.
	time.Sleep(50 * time.Millisecond)

	var startReturned atomic.Bool
	startDone := make(chan struct{})
	go func() {
		defer close(startDone)
		_ = client.Start(context.Background()) //nolint:errcheck // Exercised for blocking behavior
		startReturned.Store(true)
	}()

	// While the old Stop is still draining, the new Start must not complete —
	// completing here is exactly the state the old Stop would dismantle.
	time.Sleep(100 * time.Millisecond)
	assert.False(t, startReturned.Load(), "Start must block until the previous Stop finishes teardown")
	select {
	case <-stopDone:
		t.Fatal("Stop finished while its in-flight connection was still open")
	default:
	}

	close(release)
	<-stopDone
	<-startDone

	// The Start that was blocked won cleanly: the client is running with its
	// own listener, untouched by the previous Stop.
	assert.True(t, client.Running())
	client.mu.RLock()
	listener := client.httpListener
	client.mu.RUnlock()
	assert.NotNil(t, listener, "the new run's listener must survive the old Stop")

	require.NoError(t, client.Stop(context.Background()))
	assert.False(t, client.Running())
}

// fakeTrayAdapter is a GUI-free SystrayAdapter so the default tray-enabled
// path can run in tests.
type fakeTrayAdapter struct {
	mu     sync.Mutex
	runs   int
	quitCh chan struct{}
}

func newFakeTrayAdapter() *fakeTrayAdapter {
	return &fakeTrayAdapter{quitCh: make(chan struct{})}
}

func (f *fakeTrayAdapter) Run(onReady func(), onExit func()) {
	f.mu.Lock()
	f.runs++
	f.mu.Unlock()
	onReady()
	<-f.quitCh
	onExit()
}

func (f *fakeTrayAdapter) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

func (f *fakeTrayAdapter) SetIcon([]byte)    {}
func (f *fakeTrayAdapter) SetTitle(string)   {}
func (f *fakeTrayAdapter) SetTooltip(string) {}
func (f *fakeTrayAdapter) AddSeparator()     {}
func (f *fakeTrayAdapter) Quit()             { close(f.quitCh) }
func (f *fakeTrayAdapter) AddMenuItem(_, _ string) tray.MenuItem {
	return fakeTrayMenuItem{}
}

type fakeTrayMenuItem struct{}

func (fakeTrayMenuItem) SetTitle(string)          {}
func (fakeTrayMenuItem) SetTooltip(string)        {}
func (fakeTrayMenuItem) Enable()                  {}
func (fakeTrayMenuItem) Disable()                 {}
func (fakeTrayMenuItem) Show()                    {}
func (fakeTrayMenuItem) Hide()                    {}
func (fakeTrayMenuItem) Clicked() <-chan struct{} { return nil }

// The default (tray-enabled) client must be restartable without growing
// goroutines: fyne.io/systray is a one-shot process-lifetime library, so the
// tray is created exactly once and survives every Stop/Start cycle. The old
// design created a tray per Start and leaked its click-loop goroutine per
// cycle (before=2 after=5 over three cycles in the review's probe).
func TestClient_TrayIsProcessLifetimeAndDoesNotLeak(t *testing.T) {
	adapter := newFakeTrayAdapter()
	var constructed atomic.Int32
	originalNewTray := newTray
	newTray = func(cfg tray.Config) *tray.Tray {
		constructed.Add(1)
		return tray.NewWithAdapter(cfg, adapter)
	}
	resetProcessTrayForTesting()
	t.Cleanup(func() {
		newTray = originalNewTray
		resetProcessTrayForTesting()
	})

	cfg := newLifecycleTestConfig()
	cfg.Tray = config.TrayConfig{Enabled: true}
	client, err := New(cfg)
	require.NoError(t, err)

	// First full cycle creates the process tray and its goroutines.
	require.NoError(t, client.Start(context.Background()))
	require.NoError(t, client.Stop(context.Background()))
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	for cycle := 0; cycle < 3; cycle++ {
		require.NoError(t, client.Start(context.Background()), "cycle %d", cycle)
		require.NoError(t, client.Stop(context.Background()), "cycle %d", cycle)
	}

	assert.Equal(t, int32(1), constructed.Load(), "the tray must be constructed exactly once per process")
	assert.Equal(t, 1, adapter.runCount(), "systray Run must be entered exactly once per process")

	// Goroutine count settles back to the post-first-cycle baseline: no
	// per-cycle click-loop leak. Poll briefly to ride out runtime noise.
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= baseline+1 || time.Now().After(deadline) {
			assert.LessOrEqual(t, n, baseline+1,
				"restart cycles must not grow goroutines (baseline %d)", baseline)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}
