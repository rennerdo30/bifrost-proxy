//go:build !linux

package backend

// platformLeakProofRouter returns a no-op/unsupported router on non-Linux
// platforms. Requesting leak-proof routing there fails closed at Install time.
func platformLeakProofRouter(name string) leakProofRouter {
	return unsupportedLeakProofRouter{}
}
