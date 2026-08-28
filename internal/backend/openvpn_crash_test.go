package backend

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForCondition polls until cond returns true or the deadline passes.
func waitForCondition(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// An unexpected process exit must be detected and surfaced: the old monitor
// polled cmd.ProcessState, which stays nil until Wait is called — and only
// Stop called Wait — so it could never fire. The chain under test is the real
// one: a real subprocess, the real wait-owner goroutine, the real monitor.
func TestOpenVPN_UnexpectedExitIsDetected(t *testing.T) {
	b := &OpenVPNBackend{
		name:     "crash-test",
		stopChan: make(chan struct{}),
	}
	b.healthy.Store(true)

	cmd := exec.Command("sh", "-c", "exit 3")
	require.NoError(t, cmd.Start())
	waitDone := b.startWaitOwner(cmd)

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		b.monitor(b.stopChan, waitDone)
	}()

	require.True(t, waitForCondition(t, 5*time.Second, func() bool {
		select {
		case <-monitorDone:
			return true
		default:
			return false
		}
	}), "monitor must observe the process exit")

	assert.False(t, b.IsHealthy(), "an unexpectedly dead tunnel must not report healthy")
	stats := b.Stats()
	require.NotEmpty(t, stats.LastError, "the crash must be surfaced in the backend stats")
	assert.Contains(t, stats.LastError, "unexpectedly")
	assert.Contains(t, stats.LastError, "exit status 3",
		"the exit status must be part of the surfaced error")
}

// An orderly Stop must NOT be reported as a crash: Stop closes stopChan before
// the process exits, and the monitor checks it before recording anything.
func TestOpenVPN_OrderlyStopIsNotACrash(t *testing.T) {
	b := &OpenVPNBackend{
		name:     "stop-test",
		stopChan: make(chan struct{}),
	}
	b.healthy.Store(true)

	cmd := exec.Command("sh", "-c", "read _ || true") // lives until stdin closes
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	waitDone := b.startWaitOwner(cmd)

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		b.monitor(b.stopChan, waitDone)
	}()

	// Orderly shutdown: stopChan first (exactly what Stop does), then the
	// process exits.
	close(b.stopChan)
	require.NoError(t, stdin.Close())
	<-waitDone
	<-monitorDone

	assert.True(t, b.IsHealthy(), "an orderly stop must not be recorded as a crash")
	assert.Empty(t, b.Stats().LastError)
}

// The wait owner is the single Wait caller and reports the exit faithfully.
func TestOpenVPN_WaitOwnerReportsExit(t *testing.T) {
	b := &OpenVPNBackend{name: "wait-test", stopChan: make(chan struct{})}

	cmd := exec.Command("sh", "-c", "exit 7")
	require.NoError(t, cmd.Start())
	done := b.startWaitOwner(cmd)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait owner never reaped the process")
	}
	err := b.waitExitError()
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "exit status 7"), fmt.Sprintf("got %v", err))
}
