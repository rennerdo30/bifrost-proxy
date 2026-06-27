# System (PAM) authentication backend

This package implements the `system` auth plugin, which authenticates against the
host operating system.

## Platform behavior

| Platform | Backend | Notes |
|----------|---------|-------|
| Windows  | `LogonUser` API | `system_windows.go` |
| macOS    | `dscl . -authonly` | `system.go::validateDarwin` |
| Linux (default build) | **fail-closed stub** | `pam_stub.go`; always denies, logs a warning |
| Linux (`-tags pam`, cgo) | **real libpam** | `pam_linux.go` + `pam_conv.c` |

## Why Linux is fail-closed by default

Authenticating a local password on Linux requires PAM. PAM is exposed via
`libpam`, which means cgo + the PAM development headers at build time. The
default build and CI run **without** the PAM headers (and frequently with
`CGO_ENABLED=0`), so the real backend is hidden behind a dedicated build tag and
the default build compiles a stub that always fails closed.

The previous "`su` with the password on stdin" approach was removed: `su` reads
the password from the controlling TTY (`/dev/tty`), not stdin, so it never
actually validated the password and could even succeed spuriously in a
privileged context.

## Building with real PAM

Requirements:

- `CGO_ENABLED=1`
- A C toolchain (gcc/clang)
- PAM development headers:
  - Debian/Ubuntu: `apt-get install libpam0g-dev`
  - RHEL/Fedora: `dnf install pam-devel`
- `libpam` available at run time

Build:

```bash
CGO_ENABLED=1 go build -tags pam ./...
# or for the server binary specifically:
CGO_ENABLED=1 go build -tags pam -o bifrost-server ./cmd/server
```

If the `pam` tag (or cgo) is absent, `pam_linux.go`/`pam_conv.c` are not
compiled and the fail-closed stub is used instead.

## Configuration

```yaml
auth:
  plugins:
    - type: system
      config:
        service: bifrost          # PAM service name (file under /etc/pam.d/)
        allowed_users: []         # optional allow-list of usernames
        allowed_groups: []        # optional: user must be in one of these groups
```

The `service` field selects the PAM service. With the real backend you must
create the corresponding file under `/etc/pam.d/`, e.g. `/etc/pam.d/bifrost`:

```
auth     required pam_unix.so
account  required pam_unix.so
```

(Or `@include common-auth` / `@include common-account` on Debian.)

### Runtime privileges

PAM modules such as `pam_unix.so` read `/etc/shadow`, which usually requires the
process to run as `root` (or have the appropriate capability / be a member of
the `shadow` group, depending on distro). If the process lacks permission, PAM
returns an authentication error and the backend fails closed. Prefer a dedicated
PAM service that grants only what is needed.

## Runtime-validation status

The libpam backend (`pam_linux.go` + `pam_conv.c`) is written to link against
libpam and has been compile-checked for both Go and C syntax, but it has **not**
been exercised against a live PAM stack in this environment (no libpam headers /
no root / no configured PAM service available here). Validate it on a real Linux
host with a configured `/etc/pam.d/<service>` before relying on it in
production.
```
