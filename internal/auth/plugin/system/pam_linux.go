//go:build linux && cgo && pam

// validateLinux: REAL libpam-backed implementation (build tag "pam").
//
// This file is the REAL Linux PAM backend. It is compiled ONLY when all of the
// following hold:
//
//	GOOS=linux  CGO_ENABLED=1  -tags pam
//
// It links against libpam, so it requires the PAM development headers at build
// time (Debian/Ubuntu: libpam0g-dev, RHEL/Fedora: pam-devel) and libpam at run
// time. Because CI and the default build do not pass the 'pam' tag, this file is
// never compiled there and CI stays green without libpam.
//
// Build example:
//
//	CGO_ENABLED=1 go build -tags pam ./...
//
// Security notes:
//   - The configured 'service' field selects the PAM service (file under
//     /etc/pam.d/). This MUST exist and be configured by the operator; if it is
//     missing PAM refuses the start and we fail closed.
//   - The process needs permission to authenticate via the chosen service. For
//     services that read /etc/shadow (e.g. a custom "bifrost" service that
//     includes common-auth) this generally requires running as root or with the
//     appropriate capabilities. If permissions are insufficient, PAM returns an
//     auth error and we fail closed.
//   - The password is passed to PAM through a conversation callback and is not
//     logged.
package system

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

// bifrost_conv is the PAM conversation callback. It answers prompt-echo-off
// (password) and prompt-echo-on (e.g. login) messages with the password we
// stashed in appdata_ptr, and ignores info/error messages.
//
// Defined in pam_conv.c so cgo can take its address.
extern int bifrost_conv(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr);

// bifrost_make_conv builds a struct pam_conv pointing at bifrost_conv with the
// given appdata. Doing this in C avoids casting the function pointer through
// cgo, whose type for the conv field is awkward to express in Go.
static struct pam_conv bifrost_make_conv(void *appdata_ptr) {
    struct pam_conv conv;
    conv.conv = bifrost_conv;
    conv.appdata_ptr = appdata_ptr;
    return conv;
}
*/
import "C"

import (
	"context"
	"log/slog"
	"unsafe"
)

// pamCompiled reports whether the real libpam-backed Linux backend was compiled
// in. In this (real PAM) build it was. See pam_stub.go for the fail-closed value.
const pamCompiled = true

// validateLinux authenticates username/password against PAM using the
// configured service. It returns true only when both pam_authenticate and
// pam_acct_mgmt succeed. Any error path fails closed.
func (a *Authenticator) validateLinux(ctx context.Context, username, password string) bool {
	// Respect a context that is already canceled before doing any work.
	if err := ctx.Err(); err != nil {
		return false
	}

	service := a.service
	if service == "" {
		service = "login"
	}

	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cUser := C.CString(username)
	defer C.free(unsafe.Pointer(cUser))

	// Stash the password in C memory that lives for the duration of the
	// handshake; the conversation callback reads it via appdata_ptr.
	cPassword := C.CString(password)
	defer func() {
		// Zero the password buffer before freeing to avoid leaving it in heap.
		C.memset(unsafe.Pointer(cPassword), 0, C.size_t(len(password)))
		C.free(unsafe.Pointer(cPassword))
	}()

	conv := C.bifrost_make_conv(unsafe.Pointer(cPassword))

	var handle *C.pam_handle_t
	ret := C.pam_start(cService, cUser, &conv, &handle)
	if ret != C.PAM_SUCCESS {
		slog.Warn("system auth: pam_start failed",
			"service", service, "code", int(ret))
		return false
	}
	// Always tidy up the PAM handle.
	defer C.pam_end(handle, ret)

	// Re-check the context: pam_start can be non-trivial.
	if err := ctx.Err(); err != nil {
		return false
	}

	ret = C.pam_authenticate(handle, 0)
	if ret != C.PAM_SUCCESS {
		// PAM_AUTH_ERR / PAM_USER_UNKNOWN etc. all map to auth failure.
		return false
	}

	// Verify the account is valid (not expired/locked).
	ret = C.pam_acct_mgmt(handle, 0)
	if ret != C.PAM_SUCCESS {
		return false
	}

	return true
}
