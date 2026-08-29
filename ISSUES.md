# Known Issues

Deliberate limitations and open work. Fixed items are not recorded here — see
`CHANGELOG.md`.

## Unimplemented, disclosed, fails closed

These are absent rather than broken. Each refuses rather than pretending to work,
and each is documented where a user would look.

| Feature | State | Where |
|---|---|---|
| Mesh multi-hop relay (`relay_via_peers`) | Rejected by config validation | `internal/mesh/config.go` |
| NTLM response verification | No credential source exists, so every login is rejected and the provider is refused at startup. Use `kerberos` for Windows-domain SSO | `internal/auth/plugin/ntlm/` |
| ICE connectivity establishment | Present and tested, not wired into the connection path | `internal/p2p/ice.go` |
| On-device mobile VPN tunnel | The app is a remote control for a client running elsewhere. The native forwarders are raw-UDP placeholders, and `NATIVE_DATA_PATH_IS_SECURE` keeps them unreachable even in a build that links them | `mobile/README.md`, `mobile/src/native/BifrostVpn.ts` |
| `system` (PAM) auth on Linux | Fails closed unless built with the `pam` tag; reported as `build_disabled` at startup rather than silently rejecting logins | `internal/auth/plugin/system/` |
| `max_load` / `auto_select` on Mullvad and PIA | Read but inert: neither provider's API integration populates `Server.Load`, so the filter can never trip and the sort is a no-op. A startup warning names the backend rather than letting the setting look effective. `Server.Latency` is likewise never written | `internal/backend/factory.go`, `internal/vpnprovider/cache.go` |

## Open

**On-device mobile VPN.** The native path needs a real WireGuard/OpenVPN data
path (`gomobile bind` of the existing Go backend, or WireGuardKit +
wireguard-android), an iOS Network Extension target, and the `BifrostVpn` native
module. It needs a paid Apple Developer account and on-device testing, so none of
it can be built or validated in CI as it stands. Until then the path is gated off
in code, not merely in documentation.

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

**Windows and macOS code paths are never executed by CI.** Every job runs on
`ubuntu-latest`, so platform-tagged Go code is cross-compiled but never run, and
`golangci-lint`/`staticcheck` analyse only the host platform unless `GOOS` is set
explicitly. `ci.yml` now runs a cross-platform lint job to close the static half
of that gap; actually *executing* those paths still needs runners on those
platforms.
