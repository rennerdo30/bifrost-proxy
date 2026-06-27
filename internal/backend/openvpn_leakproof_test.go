package backend

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenVPN_InstallLeakProof_Disabled(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "o", ConfigContent: "client\n"})
	// Disabled by default: no-op even without a local address.
	assert.NoError(t, b.installLeakProof(context.Background()))
	assert.Nil(t, b.leakRouter)
}

func TestOpenVPN_InstallLeakProof_FailClosedNoLocalAddr(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "o", ConfigContent: "client\n", LeakProofRouting: true})
	// Enabled but no tunnel local address known -> fail closed.
	err := b.installLeakProof(context.Background())
	assert.Error(t, err)
}

func TestOpenVPN_InstallLeakProof_UsesRouter(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "o", ConfigContent: "client\n", LeakProofRouting: true})
	fake := &fakeLeakRouter{}
	b.leakRouter = fake
	b.localAddr = "10.8.0.3"

	require.NoError(t, b.installLeakProof(context.Background()))
	assert.True(t, fake.installed)
	assert.Equal(t, "10.8.0.3", fake.gotLocalAdr)
}

func TestOpenVPN_InstallLeakProof_PropagatesError(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "o", ConfigContent: "client\n", LeakProofRouting: true})
	b.leakRouter = &fakeLeakRouter{installErr: errors.New("denied")}
	b.localAddr = "10.8.0.3"
	assert.Error(t, b.installLeakProof(context.Background()))
}

func TestOpenVPN_Stop_RemovesLeakRouting(t *testing.T) {
	b := NewOpenVPNBackend(OpenVPNConfig{Name: "o", ConfigContent: "client\n", LeakProofRouting: true})
	fake := &fakeLeakRouter{}
	b.leakRouter = fake
	// Simulate a running backend so Stop performs teardown.
	b.running = true

	require.NoError(t, b.Stop(context.Background()))
	assert.True(t, fake.removed)
}
