//go:build !windows && !(linux && cgo && pam)

// validateLinux: DEFAULT (fail-closed) implementation.
//
// This file is the DEFAULT (fail-closed) validateLinux implementation. It is
// compiled on every non-Windows platform EXCEPT when the real PAM backend is
// selected, i.e. it is excluded only when ALL of the following hold:
//
//	GOOS=linux  CGO_ENABLED=1  -tags pam
//
// On non-Linux Unix platforms (e.g. darwin) validateLinux is never reached at
// runtime — validatePassword routes by runtime.GOOS — but the method must still
// exist for those builds to compile, so this stub provides it everywhere.
//
// CI and the default build do not pass the 'pam' tag (and often build with cgo
// disabled), so they compile this stub and never require libpam headers.
//
// To build with real PAM authentication, see pam_linux.go.
package system

import (
	"context"
	"log/slog"
)

// validateLinux always fails closed on Linux when the real PAM backend was not
// compiled in.
//
// Background: the previous "su with password on stdin" approach did not work —
// su reads the password from the controlling TTY (/dev/tty), not stdin, so
// feeding the password to stdin authenticates nothing and could even succeed
// spuriously when run from a privileged context. Because this is an
// authentication primitive, we fail closed rather than ship unsafe behavior.
//
// To enable Linux system auth, build the cgo-based PAM backend:
//
//	CGO_ENABLED=1 go build -tags pam ./...
//
// (requires libpam development headers, e.g. libpam0g-dev / pam-devel).
func (a *Authenticator) validateLinux(_ context.Context, _, _ string) bool {
	slog.Warn("system auth: PAM password validation is not compiled in on Linux; " +
		"failing closed (the 'service' field is therefore unused). " +
		"Rebuild with CGO_ENABLED=1 -tags pam to enable PAM.")
	return false
}
