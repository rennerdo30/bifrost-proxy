# Bifrost Proxy — State-of-the-Project Audit

> Generated 2026-06-27 from a verified, multi-agent code audit (10 subsystems surveyed, 79 findings adversarially verified against the code). Severities reflect user/security impact. File:line references were accurate at time of writing — verify against current code.

## 1. Overall state

Bifrost is a **genuinely-built proxy system, not a skeleton**: the HTTP/CONNECT and SOCKS5 data path, domain matching, routing with three working load balancers, response caching, rate limiting, bandwidth throttling, health checks, the auto-updater, and per-OS service management are all real and production-quality. The commercial VPN provider clients (NordVPN/Mullvad/PIA/ProtonVPN) speak real APIs, do SRP-6a auth, register WireGuard keys. Both React dashboards are largely complete and call only endpoints that exist.

Maturity is uneven, and the worst problems cluster in **security-critical wiring**: the NTLM plugin is a complete auth bypass; Kerberos SPNEGO and mTLS-through-the-proxy are non-functional; the documented `negotiate` mode doesn't exist. The **mesh** subsystem is broad but its control/data planes aren't wired together, so it doesn't function end-to-end. **SPECIFICATION.md has drifted badly** from the code.

| Subsystem | Completeness | Note |
|---|---|---|
| proxy-core | Mostly | Solid; OpenVPN isolation + WireGuard DNS are the real gaps |
| auth | Partial | Good core plugins; enterprise/Windows auth + mTLS broken; **NTLM bypass** |
| vpn-tunnels | Mostly | Real clients & TUN stack; NordVPN OpenVPN certs fake, split-tunnel include broken, macOS netmask bug |
| mesh-p2p | Partial | Strong primitives, but not wired; non-functional end-to-end |
| server-client-runtime | Mostly | Solid; system proxy no-op off-Windows, client mesh unwired |
| api-layer | Mostly | REST real; WebSocket events never broadcast, client route CRUD broken |
| support-infra | Solid | Cache/ratelimit/health/updater real; cache not hot-reloadable |
| web-uis | Mostly | Complete & wired; auth config UI emits a server-rejected format |
| platforms-packaging | Mostly | Desktop/Docker/deploy excellent; OpenWrt UCI inert, mobile native VPN orphaned |
| docs-vs-spec | Docs good / Spec poor | Starlight docs accurate; SPECIFICATION.md severely stale |

## 2. Unfinished features

### Critical / High
- **NTLM Type 3 accepts any message without verifying the hash** — `internal/auth/plugin/ntlm/ntlm.go:401-447` (and `:234-271`). Verification is stubbed (`_ = state // Challenge validation would happen here`); the random challenge from `GenerateChallenge` is never stored. Returns success built solely from the attacker-supplied username. Registered & reachable (`cmd/server/main.go:33`). **Trivial auth bypass / identity spoofing.**
- **Kerberos SPNEGO validation always errors** — `internal/auth/plugin/kerberos/kerberos.go:248-265`. `validateSPNEGOToken` discards token+service and unconditionally returns an error; only `authenticateWithPassword` works. Advertised AD/GSSAPI SSO flow is dead.
- **mTLS has no working path through the proxy** — `internal/auth/middleware.go:325` vs `internal/auth/plugin/mtls/mtls.go:26,268`; `internal/proxy/http.go:368-384`. Context-key mismatch (`"mtls_client_cert"` vs `"auth_client_cert"`, different type *and* string); the middleware is never wired; the live proxy path only extracts Basic/Bearer and never reads `r.TLS.PeerCertificates` or sets `ClientCAs`. mTLS auth cannot work at all.
- **Mesh control plane can never receive messages** — `internal/mesh/node.go:1013-1029`; `protocol.go:284-288`; `broadcast.go:556-585`. `onP2PData` dispatches on marker bytes `0x01`/`0x02` that nothing prepends; `handleProtocolMessage` strips a `data[1:]` marker that isn't there. Hello/route-announce/withdraw and flood/multicast all fail the marker check and get injected to the TUN as raw packets. **Mesh routing & broadcast are dead.**
- **Server-assigned virtual IP discarded** — `internal/mesh/node.go:305-308`; `discovery.go:188-201`. `initializeDevice` self-assigns `prefix.Addr().Next()` (every node gets `.1`); the registration response's real `VirtualIP` is only logged. All nodes collide.
- **Remote peers' VirtualIP never populated → no routes installed** — `internal/mesh/discovery.go:402-410`; `node.go:831-834`. `addPeerFromInfo` never copies `info.VirtualIP`; route install is gated on `peer.VirtualIP.IsValid()` → never runs; `GetNextHopByIP` always "no route".
- **Server WebSocket never broadcasts stats/backend/connection events** — `internal/api/server/websocket.go:162-191` (only `EventConfigSaved`/`EventConfigReload`). The UI `useStats` *stops* polling once WS connects (`useStats.ts:29`) and listens for event names (`'stats'`/`'backend_status'`) that don't match backend constants. **Dashboard stats freeze once WS is up.**
- **NordVPN OpenVPN CA cert + TLS-auth key are fake placeholder data** — `internal/vpnprovider/nordvpn/client.go:477-516` (`nordVPNCACert` degenerates into `LLMQLQL0...` filler that won't parse as x509; `nordVPNTLSKey` is sequential hex). Embedded into every NordVPN `.ovpn`. NordVPN-over-OpenVPN silently fails TLS verification.
- **Split-tunnel "include" mode installs no routes** — `internal/vpn/routes_linux.go:76`, `routes_darwin.go:68`, `routes_windows.go:74`. Default-into-TUN route added only for `exclude` mode; included apps/domains/IPs never enter the tunnel (docs say it works).

### Medium
- **OpenVPN backend doesn't route through the tunnel** — `internal/backend/openvpn.go:96-140` (only binds source `LocalAddr`; no namespace/policy-routing/netstack). Silent IP leak.
- **WireGuard backend leaks DNS** — `internal/backend/wireguard.go:96-119` (resolves targets via host OS resolver before dialing through tunnel; `config.DNS` set but unused).
- **VPN auto-select refresh detects but never switches servers** — `nordvpn.go:259-287`, `pia.go:265-288`, `protonvpn.go:299-324`, `mullvad.go:251-274` (refresh loop only logs; delegate never rebuilt).
- **Bypassed TUN packets silently dropped** — `internal/vpn/vpn.go:380-393` (`handleBypassPacket` only logs; no re-injection). IP-based bypass works via routes.
- **Userspace TCP proxy lacks reassembly/windowing/retransmission** — `internal/vpn/vpn.go:513-521` (in-order only; out-of-order/lost segments corrupt streams).
- **Negotiate handler stores a challenge but never passes it to NTLM validation** — `negotiate/handler.go:267-302` (`_ = state`).
- **Linux system (PAM) auth uses `su` with stdin password** — `system/system.go:240-264` (`su` needs a TTY, not stdin; valid Linux creds commonly fail; `service` field ignored). Fails closed. macOS `dscl` works.
- **Client route add/remove unreachable & would corrupt config** — `internal/api/client/server.go:305-308` (prod `HandlerWithUI` registers only GET); `client.go:428-615` (no `_add_route`/`_remove_route` branch → `config.UpdateNode` appends literal keys). UI 405s.
- **Client `/logs` returns synthesized debug-traffic entries, not slog logs** — `server.go:1485-1552`.
- **Cache config not hot-reloadable** — `server.go:666-797` never calls `cacheManager.Reload()`; docs claim cache rules are SIGHUP-reloadable.
- **PIA port-forwarding typed but unimplemented** — `pia/auth.go:193-204`.

### Low
- Plain-proxy backends always report `IsHealthy()=true` absent health-check config (`direct.go`/`httpproxy.go`/`socks5proxy.go`).
- SOCKS5 BIND/UDP ASSOCIATE unsupported (`socks5.go:400-413`) — acceptable, document it.
- `mfa_wrapper` by-name (`primary_provider`) path is a placeholder rejecting every login (`mfa/plugin.go:40-43,397-420`).
- NTLM Type 2 omits target-info AV pairs (`ntlm.go:371-399`).
- Tray AutoConnect/StartMinimized/ShowQuickGUI persisted but inert (ShowNotifications works); VPN DNS-cache endpoint stub; config-timestamp handler returns `time.Now()`; mesh REST state in-memory only.
- AccessController `RemoveFromWhitelist/Blacklist` are no-ops; Prometheus `RequestSize`/`ResponseSize` registered but never observed.
- Client live log SSE stream never fed — `BroadcastLog` has no production callers (`server.go:1554-1638`); default 5s polling works.

## 3. Missing features
- **Documented `negotiate` auth mode does not exist** — `internal/auth/negotiate/handler.go` is dead code (`NewHandler` never called outside tests); no plugin registers `"negotiate"`; config has no `prefer_kerberos`/`allow_ntlm`/`challenge_timeout`. Following the docs (`authentication.mdx:356-1031`) causes a hard config failure.
- **Client mesh is config-only; `MeshManager` never wired** — `client.go:150-174`; `apiclient.Config` sets `VPNManager` but never `MeshManager`; `NewMeshNode` has zero non-test callers; `*MeshNode.LocalIP()` returns `netip.Addr` while the interface wants `string`. Mesh endpoints always return "Mesh not configured".
- **`weighted` load balancer never wired** — `router.go:173-184` (`NewLoadBalancer` has no `weighted` case → round-robin); `RouteConfig` carries no per-backend weights.
- **Redis session store fully documented, absent** — `SPECIFICATION.md:1361-1374` vs `internal/auth/session/store.go` (only `MemoryStore`; no redis dep; no `session:` config block).
- **Passive health checks documented, only active exists** — `SPECIFICATION.md:844-847`; no request-failure feedback loop; `healthy_threshold`/`unhealthy_threshold` config keys unimplemented.
- **Entire `network:` config block + IPv6 toggles advertised, unimplemented** — `SPECIFICATION.md:29,116-141` (IPv6 itself works transparently via Go's net stack).
- **HTTPS MITM debugging described, no implementation** — `SPECIFICATION.md:636-643` (HTTPS is CONNECT-tunneled only). Spec frames it as optional.
- **Auth UI exposes only 4 of ~10 plugin types** — `AuthSection.tsx:14-19` (native/system/ldap/oauth only).

## 4. Platform & packaging gaps
- **System proxy is a no-op on macOS & Linux** — `internal/sysproxy/sysproxy_other.go:11-18`. Worse, `client.go:202-228` logs "System proxy enabled" and sets tray "Connected" on the no-op's `nil` return — **silent false positive on 2 of 3 platforms.** Docs promise networksetup/gsettings backends.
- **macOS route netmask formatting is broken** — `internal/vpn/routes_darwin.go:205-209`. Hand-rolled `0xFF<<(8-...)` produces invalid octets (`/24`→`255.255.255.65280`); only `/32` valid. Re-rated **high**: exclude-mode `/1` defaults are the broken case → macOS VPN routing silently fails (failures only logged as warnings). Use `net.CIDRMask`.
- **OpenWrt UCI config is decorative** — `openwrt/etc/config/bifrost:1-8`; init script launches `$PROG start -c <yaml>` and never reads UCI options; no UCI→YAML sync. (The separate "missing LuCI app" claim was *refuted* — stock LuCI OPKG upload is backed by a working `build-openwrt-ipk` target.)
- **IPK control file hardcodes `Architecture: all`** — `Makefile:142-159` (line 149) for arch-specific MIPS/ARM binaries → "Exec format error". Missing `Section`/`Priority` and a `conffiles` entry for `/etc/bifrost/config.yaml` (upgrades clobber user config).
- **Mobile native VPN is orphaned & unbuildable** — `mobile/ios/.../PacketTunnelProvider.swift`, `mobile/android/.../BifrostVpnService.kt`: no Xcode project, no gradle/manifest, no `eas.json`, empty `app.json` plugins, no `BIND_VPN_SERVICE`, no JS bridge. The Expo app controls VPN via REST to `localhost:7383`. Native files can never compile.
- **Native VPN tunnels are skeleton raw-UDP forwarders** — `BifrostVpnService.kt:173-247`, `PacketTunnelProvider.swift:134-195` (raw IP packets over plain UDP to `:51820`, no WireGuard/Noise handshake — would leak cleartext).
- **Standalone `internal/wireguard` & `internal/openvpn` packages are orphaned** — zero importers; dead duplicates of `internal/backend`. Consolidate or delete.
- **Windows tray icons are PNG; systray needs ICO** — `internal/tray/icons.go:35-99` (`LoadImage(IMAGE_ICON)` fails on PNG; glyph silently doesn't render; menu works).
- **Unsupported-OS route/process management is a clean no-op** (`routes_other.go`, `process_other.go`) — acceptable; document VPN client mode is Linux/macOS/Windows only.

## 5. Doc-vs-code mismatches
The user-facing **Starlight docs (`docs/src/content`) are accurate**. **SPECIFICATION.md is the stale artifact** and is wrong on nearly every reference surface:
- **Config schema (3.1/3.2)** — `SPECIFICATION.md:103-399` documents `server.http_port`, `bind_address`, top-level `rules:`, `auth.mode`. Real schema: `server.http.listen`, `routes:`, `auth.providers`. Copying spec YAML yields an invalid config. (high)
- **Auth model** — `auth.mode` + typed `native/system/ldap/oauth` blocks documented as primary, but `internal/server/server.go:271-298` *fatally rejects* them ("legacy auth.mode is no longer supported"); even `mode: "none"` fails. (high)
- **Web auth config UI emits this same rejected format** — `AuthSection.tsx` writes legacy typed fields + `auth.mode`; `config.Validate()` doesn't catch it, so the save "succeeds" and the server fails on next restart. (high)
- **CLI reference (5.1/5.2/14.5)** — documents flat `start`/`stop`/`config show`/`user add` that don't exist; real commands are namespaced under `ctl`; no user-management subcommand. (medium)
- **REST API paths (4.3/5.x/11.5)** — omit `/api/v1` prefix; list non-existent endpoints (`/api/rules`, `/api/debug/*`, `/api/backends/:name/health`). Per-feature docs are correct. (low)
- **Docs build pipeline** — `SPECIFICATION.md:1177-1265` and `Makefile:311-321` reference MkDocs/`mkdocs.yml`, but project is Astro/Starlight; `make docs-serve`/`docs-build` are broken. (medium)
- **Rate-limit keys** — spec's `rate_limiting.bandwidth.*` nesting doesn't match the real flat `rate_limit` struct (`upload`/`download` strings); wrong top-level key → config silently dropped. (medium)
- **Other** — Grafana dashboard path wrong (`assets/grafana-dashboard.json` → actually `docker/grafana/dashboards/bifrost-overview.json`); `CLAUDE.md` claims logging "Supports file rotation" but `internal/logging/` has none (external logrotate is the real path); `protonvpn.go:193` stale "OpenVPN only" comment (WireGuard supported); tiered-cache "hot/cold" comments imply temperature promotion that doesn't exist (static size-based).

## 6. Top recommendations (prioritized)
1. **Fix or remove the NTLM authentication bypass** (`ntlm.go:401-447`) — live, trivially exploitable. Implement real NTLMv2 verification (store challenge, recompute, constant-time compare) or remove the plugin and document unsupported.
2. **Reconcile the enterprise/Windows auth + mTLS story** — wire end-to-end (register `negotiate`, pass SPNEGO to Kerberos, unify mTLS context key, configure listener `ClientCAs`, enforce `AllowedPeers`) or remove the dead plugins and the docs describing unconfigurable modes.
3. **Make the auth config UI emit the `providers[].config` map format** + server-side `config.Validate()` rejecting the legacy shape at save time.
4. **Wire the mesh control + data planes** — prepend marker bytes, apply server-assigned VirtualIP, populate peer VirtualIP; add a two-node HelloMessage integration test.
5. **Fix the macOS route netmask bug** (`routes_darwin.go:205-209`) using `net.CIDRMask`.
6. **Close silent-success traps** — macOS/Linux system-proxy no-op should return `ErrNotSupported`; replace NordVPN's placeholder OpenVPN CA/TLS-auth + a PEM-decode regression test.
7. **Implement or stop advertising VPN tunnel isolation** — OpenVPN egress not forced through tun (IP leak), WireGuard host DNS (DNS leak), split-tunnel `include` installs no routes.
8. **Rewrite SPECIFICATION.md against the code** (or replace with a banner pointing at the Starlight docs) and fix the `make docs-*` targets for Astro.
9. **Fix the dashboard live-data path** — broadcast `StatsEvent`/`BackendHealthEvent` (or stop disabling polling on WS connect) and align event-name strings; wire or remove `BroadcastLog`.
10. **Repair client route management** — register POST/DELETE in `HandlerWithUI` and implement `_add_route`/`_remove_route`.
11. **Wire cache hot-reload** (`cacheManager.Reload()` into `ReloadConfig`).
12. **Packaging cleanup** — per-arch `Architecture:` + `conffiles` in IPK; remove/integrate orphaned mobile native VPN and dead `internal/wireguard`/`internal/openvpn`; ship ICO tray icons.
