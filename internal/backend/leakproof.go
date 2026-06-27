package backend

import (
	"context"
	"errors"
)

// ErrLeakProofUnsupported is returned when leak-proof routing is requested on a
// platform that does not implement it.
var ErrLeakProofUnsupported = errors.New("leak-proof routing is only supported on Linux")

// leakProofRouter installs and removes host routing rules that force a backend's
// egress through a specific tunnel source IP so traffic cannot leak out of the
// default interface. Implementations are platform-specific.
//
// SECURITY / OPERATIONAL NOTE: this feature requires root (CAP_NET_ADMIN) and
// manipulates the host routing table. It is OFF by default and is
// runtime-unvalidated in this environment (no root/netns available here). The
// Linux implementation shells out to `ip rule` / `ip route`; failures are
// surfaced (fail-closed) so a misconfigured deployment does not silently leak.
type leakProofRouter interface {
	// Install sets up policy routing for traffic sourced from localAddr,
	// directing it into the routing table associated with the tunnel.
	Install(ctx context.Context, localAddr string) error
	// Remove tears down the rules installed by Install. It is idempotent.
	Remove(ctx context.Context) error
}

// newLeakProofRouter returns a platform-appropriate router. On non-Linux
// platforms it returns an unsupportedLeakProofRouter whose Install fails closed.
func newLeakProofRouter(name string) leakProofRouter {
	return platformLeakProofRouter(name)
}

// unsupportedLeakProofRouter is used on platforms without an implementation.
type unsupportedLeakProofRouter struct{}

func (unsupportedLeakProofRouter) Install(context.Context, string) error {
	return ErrLeakProofUnsupported
}

func (unsupportedLeakProofRouter) Remove(context.Context) error { return nil }
