//go:build linux

package backend

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTableIDForName_StableAndInRange(t *testing.T) {
	id1 := tableIDForName("ovpn-us")
	id2 := tableIDForName("ovpn-us")
	assert.Equal(t, id1, id2)
	assert.GreaterOrEqual(t, id1, 10000)
	assert.Less(t, id1, 11000)

	// Different names usually differ; at minimum they remain in range.
	idOther := tableIDForName("ovpn-eu")
	assert.GreaterOrEqual(t, idOther, 10000)
	assert.Less(t, idOther, 11000)
}

func TestFindTunDevice_InvalidAddr(t *testing.T) {
	_, err := findTunDevice("not-an-ip")
	assert.Error(t, err)
}

func TestFindTunDevice_Loopback(t *testing.T) {
	// 127.0.0.1 should resolve to the loopback interface on Linux.
	dev, err := findTunDevice("127.0.0.1")
	require.NoError(t, err)
	assert.NotEmpty(t, dev)
}

func TestFindTunDevice_NoMatch(t *testing.T) {
	_, err := findTunDevice("203.0.113.254")
	assert.Error(t, err)
}

// withFakeIP swaps the runIP hook for the duration of the test.
func withFakeIP(t *testing.T, fn func(ctx context.Context, args ...string) (string, error)) {
	t.Helper()
	orig := runIP
	runIP = fn
	t.Cleanup(func() { runIP = orig })
}

func TestLinuxLeakProofRouter_InstallRemove(t *testing.T) {
	var calls [][]string
	withFakeIP(t, func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		return "", nil
	})

	r := &linuxLeakProofRouter{name: "test"}
	// Use loopback addr so findTunDevice succeeds.
	require.NoError(t, r.Install(context.Background(), "127.0.0.1"))
	assert.True(t, r.installed)

	// Idempotent install.
	require.NoError(t, r.Install(context.Background(), "127.0.0.1"))

	require.NoError(t, r.Remove(context.Background()))
	assert.False(t, r.installed)

	// Idempotent remove.
	require.NoError(t, r.Remove(context.Background()))

	// Verify route + rule were issued during install.
	var sawRoute, sawRule bool
	for _, c := range calls {
		if len(c) > 0 && c[0] == "route" {
			sawRoute = true
		}
		if len(c) > 0 && c[0] == "rule" {
			sawRule = true
		}
	}
	assert.True(t, sawRoute)
	assert.True(t, sawRule)
}

func TestLinuxLeakProofRouter_InstallEmptyAddr(t *testing.T) {
	r := &linuxLeakProofRouter{name: "test"}
	err := r.Install(context.Background(), "")
	assert.Error(t, err)
}

func TestLinuxLeakProofRouter_RouteFailure(t *testing.T) {
	withFakeIP(t, func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "route" && args[1] == "replace" {
			return "", errors.New("route boom")
		}
		return "", nil
	})
	r := &linuxLeakProofRouter{name: "test"}
	err := r.Install(context.Background(), "127.0.0.1")
	assert.Error(t, err)
	assert.False(t, r.installed)
}

func TestLinuxLeakProofRouter_RuleFailureRollsBack(t *testing.T) {
	var flushed bool
	withFakeIP(t, func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "rule" && args[1] == "add" {
			return "", errors.New("rule boom")
		}
		if len(args) > 1 && args[0] == "route" && args[1] == "flush" {
			flushed = true
		}
		return "", nil
	})
	r := &linuxLeakProofRouter{name: "test"}
	err := r.Install(context.Background(), "127.0.0.1")
	assert.Error(t, err)
	assert.False(t, r.installed)
	assert.True(t, flushed, "expected route table to be flushed on rollback")
}
