# Bifrost Proxy — State-of-the-Project Audit

> **Status: largely remediated.** The original multi-agent audit (2026-06-27, 79
> findings) surfaced a cluster of security-critical wiring bugs. The critical and
> most high-severity items have since been **fixed** (see PRs **#130–#135**). This
> document now records what was resolved and lists only the genuinely remaining,
> intentionally-gated, or infrastructure-bound items.
>
> This file is **not** a live-vulnerability report. The previous present-tense
> vulnerability table has been removed because it described issues that are now
> fixed and could be mistaken for active exploits. For current work, prefer the
> issue tracker over this checked-in snapshot.

## 1. Overall state

Bifrost is a genuinely-built proxy system: the HTTP/CONNECT and SOCKS5 data path,
domain matching, routing with load balancers (including **weighted**), response
caching, rate limiting, bandwidth throttling, health checks, the auto-updater,
and per-OS service management are real. The commercial VPN provider clients
(NordVPN/Mullvad/PIA/ProtonVPN) speak real APIs, do SRP-6a auth, register
WireGuard keys, and PIA port-forwarding is wired end-to-end with renewal. Both
React dashboards are complete and call only endpoints that exist.

## 2. Resolved (PRs #130–#135)

### Security-critical (fixed)
- **NTLM auth bypass — fixed (now fail-closed).** The plugin no longer accepts
  unverified Type 3 messages. With no credential source to recompute and
  constant-time-compare the response, it **rejects every login**
  (`internal/auth/plugin/ntlm/ntlm.go`). NTLM is documented as non-functional.
- **Kerberos SPNEGO — fixed.** `validateSPNEGOToken` now performs real
  GSS-API `AcceptSecContext` against the keytab; forged/replayed tokens are
  rejected (`internal/auth/plugin/kerberos/kerberos.go`).
- **mTLS through the proxy — fixed.** Context key unified to
  `auth_client_cert`; the middleware reads `r.TLS.PeerCertificates` and the
  proxy path extracts the peer certificate
  (`internal/auth/middleware.go`, `internal/proxy/http.go`).
- **Mesh control + data planes — fixed.** Marker framing is prepended on send
  and stripped on receive; protocol/broadcast/data frames are dispatched
  correctly and P2P payloads are ChaCha20-Poly1305 encrypted
  (`internal/mesh/node.go`, `internal/p2p/crypto.go`).
- **Mesh virtual-IP assignment — fixed.** The server-assigned `VirtualIP` is
  applied via `SetVirtualIP`, and peer VirtualIPs are populated so routes
  install (`internal/mesh/discovery.go`).
- **Server WebSocket events — fixed.** `stats.update` and `backend.health`
  events are defined and broadcast (`internal/api/server/websocket.go`).
- **NordVPN OpenVPN CA/TLS-auth placeholders — fixed.** No CA material is
  embedded; the CA must be supplied via config and is PEM-validated
  (`internal/vpnprovider/nordvpn/client.go`).

### Functional / correctness (fixed)
- **Split-tunnel "include" routes** now install into the TUN
  (`internal/vpn/routes_*.go`).
- **WireGuard DNS leak** closed — resolution happens inside the netstack tunnel
  via configured DNS (`internal/backend/wireguard.go`).
- **macOS route netmask** uses `net.CIDRMask` (`internal/vpn/routes_darwin.go`).
- **Weighted load balancer** wired with per-backend weights
  (`internal/router/router.go`).
- **PIA port forwarding** implemented with renewal lifecycle
  (`internal/vpnprovider/pia/portforward.go`, `internal/backend/pia.go`).
- **Legacy `auth.mode` rejected**; config uses `auth.providers[]` with nested
  `config` maps (`internal/config/server.go`, `internal/server/server.go`).
- **Redis session store** implemented alongside the memory store
  (`internal/auth/session/`).
- **System proxy** extended to macOS (`networksetup`) and Linux/GNOME
  (`gsettings`); unsupported desktops return `ErrNotSupported`
  (`internal/sysproxy/`).
- **OpenWrt UCI→YAML sync** and **IPK packaging** (per-arch `Architecture:`,
  `Section`/`Priority`, `conffiles`) addressed in the `Makefile` / init script.

## 3. Remaining / gated / infrastructure-bound

These are intentionally limited, gated off by default for safety, or require
external infrastructure to validate. None is a silent fail-open.

- **NTLM is unsupported by design** — fails closed; no working configuration
  exists. Retained only so a misconfiguration does not fall through.
- **The `negotiate` auth mode is not a registered plugin.** A handler package
  exists with tests, but no plugin registers `"negotiate"`. Do not configure it.
- **OpenVPN backend egress isolation is opt-in and runtime-unvalidated.**
  `LeakProofRouting` (Linux policy-routing/netns) defaults **off** and requires
  root; with it off there is a known IP/DNS leak risk documented in
  `internal/backend/openvpn.go`. Treat as experimental until validated on real
  hardware.
- **System (PAM) auth on Linux** uses a real libpam backend only when built
  with the `pam` tag; the default build compiles a fail-closed stub. macOS uses
  `dscl -authonly`.
- **Mobile native VPN is a non-functional placeholder.** The iOS/Android native
  tunnel files are unbuildable skeletons that would forward cleartext; the path
  is gated off and the Expo app controls a remote client over REST. A real
  WireGuard implementation is future work.
- **Userspace TCP proxy in VPN mode** is in-order only (no reassembly/windowing)
  — acceptable for the current scope; flagged for future hardening.

## 4. Notes

- `SPECIFICATION.md` historically drifted from the code; the user-facing
  Starlight docs under `docs/src/content` are the authoritative reference.
- File:line references in older revisions of this document may be stale; verify
  against current code before acting.
