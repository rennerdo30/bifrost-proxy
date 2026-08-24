# Known Issues

Deliberate limitations and open work. Fixed items are not recorded here — see
`CHANGELOG.md`. The detailed, evidence-backed backlog lives in [`audit/`](audit/),
which supersedes the retired `AUDIT.md` and `AUDIT-FINDINGS.md`.

## Unimplemented, disclosed, fails closed

These are absent rather than broken. Each refuses rather than pretending to work,
and each is documented where a user would look.

| Feature | State | Where |
|---|---|---|
| Mesh multi-hop relay (`relay_via_peers`) | Rejected by config validation | `internal/mesh/config.go` |
| NTLM response verification | No credential source exists, so every login is rejected and the provider is refused at startup. Use `kerberos` for Windows-domain SSO | `internal/auth/plugin/ntlm/` |
| ICE connectivity establishment | Present and tested, not wired into the connection path | `internal/p2p/ice.go` |
| On-device mobile VPN tunnel | The app is a remote control for a client running elsewhere. The iOS and Android native files are unbuildable skeletons and `expo prebuild` deletes them | `audit/mobile.md` |
| `system` (PAM) auth on Linux | Fails closed unless built with the `pam` tag; reported as `build_disabled` at startup rather than silently rejecting logins | `internal/auth/plugin/system/` |

## Open

**OpenWrt LuCI application.** IPK packaging exists (`make build-openwrt-ipk`, wired
into `release.yml`) along with a procd init script and UCI config, but there is no
`luci-app-bifrost`, so configuration on OpenWrt means editing YAML or using the
web UI. A native LuCI page would remove that step.

**Intermediate CA signatures are not verified.** `ValidateCACertPEM` checks a
self-issued certificate against its own key, so a corrupted *intermediate* in a
bundle passes validation. It fails closed downstream — OpenVPN rejects the
profile — so this is availability, not trust.

**PAM `build_disabled` is source-verified only.** Confirming the branch needs a
Linux run without the `pam` build tag; the checks so far ran on macOS, where
`system` uses a real `dscl` backend and reports as available.

**Mesh peers must be upgraded together.** The P2P handshake changed shape and
carries no version field, so a mixed-version mesh cannot complete a handshake. No
downgrade path was added, deliberately: negotiating down is how a security fix
becomes optional.

## Verified stale, kept for reference

Two long-standing entries here were no longer true and have been removed:
*System Proxy Support Limited to Windows* (`sysproxy_darwin.go` and
`sysproxy_linux.go` both exist with tests, and unsupported desktops return
`ErrNotSupported` rather than reporting a false success), and *Service Management
Platform Coverage*, which described a conditional enhancement for SysVinit rather
than a defect.
