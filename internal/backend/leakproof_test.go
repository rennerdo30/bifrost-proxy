package backend

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnsupportedLeakProofRouter(t *testing.T) {
	r := unsupportedLeakProofRouter{}
	err := r.Install(context.Background(), "10.8.0.2")
	assert.ErrorIs(t, err, ErrLeakProofUnsupported)
	assert.NoError(t, r.Remove(context.Background()))
}

func TestNewLeakProofRouter_NotNil(t *testing.T) {
	r := newLeakProofRouter("ovpn1")
	assert.NotNil(t, r)
}

// fakeLeakRouter records calls and lets the OpenVPN backend tests exercise the
// fail-closed wiring without root.
type fakeLeakRouter struct {
	installErr  error
	installed   bool
	removed     bool
	gotLocalAdr string
}

func (f *fakeLeakRouter) Install(_ context.Context, localAddr string) error {
	f.gotLocalAdr = localAddr
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = true
	return nil
}

func (f *fakeLeakRouter) Remove(context.Context) error {
	f.removed = true
	return nil
}
