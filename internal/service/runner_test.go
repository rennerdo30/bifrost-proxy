package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRunner is a test implementation of the Runner interface.
type mockRunner struct {
	mu           sync.Mutex
	started      bool
	stopped      bool
	startErr     error
	stopErr      error
	startCalled  int
	stopCalled   int
	startCtx     context.Context
	stopCtx      context.Context
	blockStartCh chan struct{} // Block Start() until closed
	blockStopCh  chan struct{} // Block Stop() until closed
}

func newMockRunner() *mockRunner {
	return &mockRunner{
		blockStartCh: make(chan struct{}),
		blockStopCh:  make(chan struct{}),
	}
}

func (m *mockRunner) Start(ctx context.Context) error {
	m.mu.Lock()
	m.startCalled++
	m.startCtx = ctx
	startErr := m.startErr
	m.mu.Unlock()

	if startErr != nil {
		return startErr
	}

	// Wait for unblock or context cancellation
	select {
	case <-m.blockStartCh:
		// Unblocked, continue
	case <-ctx.Done():
		return ctx.Err()
	}

	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	return nil
}

func (m *mockRunner) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.stopCalled++
	m.stopCtx = ctx
	stopErr := m.stopErr
	m.mu.Unlock()

	if stopErr != nil {
		return stopErr
	}

	// Wait for unblock or context cancellation
	select {
	case <-m.blockStopCh:
		// Unblocked, continue
	case <-ctx.Done():
		return ctx.Err()
	}

	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
	return nil
}

func (m *mockRunner) IsStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

func (m *mockRunner) IsStopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopped
}

func (m *mockRunner) Unblock() {
	close(m.blockStartCh)
	close(m.blockStopCh)
}

// mockReloadableRunner implements both Runner and Reloader interfaces.
type mockReloadableRunner struct {
	mockRunner
	reloadCalled int
	reloadErr    error
}

func newMockReloadableRunner() *mockReloadableRunner {
	return &mockReloadableRunner{
		mockRunner: mockRunner{
			blockStartCh: make(chan struct{}),
			blockStopCh:  make(chan struct{}),
		},
	}
}

func (m *mockReloadableRunner) ReloadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadCalled++
	return m.reloadErr
}

func (m *mockReloadableRunner) ReloadCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadCalled
}

// TestRunnerInterface verifies that the Runner interface is properly defined.
func TestRunnerInterface(t *testing.T) {
	var _ Runner = &mockRunner{}
	var _ Runner = &mockReloadableRunner{}
	var _ Reloader = &mockReloadableRunner{}
}

// TestMockRunner_StartStop tests the mock runner implementation.
func TestMockRunner_StartStop(t *testing.T) {
	runner := newMockRunner()
	runner.Unblock()

	ctx := context.Background()

	// Test Start
	err := runner.Start(ctx)
	require.NoError(t, err)
	assert.True(t, runner.IsStarted())
	assert.Equal(t, 1, runner.startCalled)

	// Test Stop
	err = runner.Stop(ctx)
	require.NoError(t, err)
	assert.True(t, runner.IsStopped())
	assert.Equal(t, 1, runner.stopCalled)
}

// TestMockRunner_StartError tests error handling in Start.
func TestMockRunner_StartError(t *testing.T) {
	runner := newMockRunner()
	runner.startErr = errors.New("start failed")
	runner.Unblock()

	err := runner.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start failed")
	assert.False(t, runner.IsStarted())
}

// TestMockRunner_StopError tests error handling in Stop.
func TestMockRunner_StopError(t *testing.T) {
	runner := newMockRunner()
	runner.stopErr = errors.New("stop failed")
	runner.Unblock()

	err := runner.Stop(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stop failed")
	assert.False(t, runner.IsStopped())
}

// TestMockRunner_ContextCancellation tests that the runner respects context.
func TestMockRunner_ContextCancellation(t *testing.T) {
	runner := newMockRunner()
	// Don't unblock - this will cause Start to wait

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := runner.Start(ctx)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
}

// TestMockReloadableRunner_Reload tests the reload functionality.
func TestMockReloadableRunner_Reload(t *testing.T) {
	runner := newMockReloadableRunner()
	runner.Unblock()

	// Test successful reload
	err := runner.ReloadConfig()
	require.NoError(t, err)
	assert.Equal(t, 1, runner.ReloadCount())

	// Test multiple reloads
	err = runner.ReloadConfig()
	require.NoError(t, err)
	assert.Equal(t, 2, runner.ReloadCount())
}

// TestMockReloadableRunner_ReloadError tests error handling in reload.
func TestMockReloadableRunner_ReloadError(t *testing.T) {
	runner := newMockReloadableRunner()
	runner.reloadErr = errors.New("reload failed")

	err := runner.ReloadConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reload failed")
}

// TestShutdownTimeout verifies the shutdown timeout constant.
func TestShutdownTimeout(t *testing.T) {
	// Verify the shutdown timeout is reasonable (30 seconds as defined)
	assert.Equal(t, 30*time.Second, ShutdownTimeout)
}

// TestReloaderInterface tests that non-Reloader runners can be detected.
func TestReloaderInterface(t *testing.T) {
	// A basic runner should not implement Reloader
	basicRunner := newMockRunner()
	_, ok := interface{}(basicRunner).(Reloader)
	assert.False(t, ok)

	// A reloadable runner should implement Reloader
	reloadableRunner := newMockReloadableRunner()
	_, ok = interface{}(reloadableRunner).(Reloader)
	assert.True(t, ok)
}

// TestRunFunction tests the exported Run function exists and is callable.
func TestRunFunction(t *testing.T) {
	// We can't fully test Run() without actually handling signals,
	// but we can verify it returns an error when Start fails.
	runner := newMockRunner()
	runner.startErr = errors.New("intentional start failure")
	runner.Unblock()

	err := Run("test-service", runner)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start service")
}
