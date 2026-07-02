# Bifrost Proxy — Code & UI Issues Audit (2026-07-02)

> Documentation only. No fixes were applied. Findings below are drawn from a verified multi-area audit; refuted claims were discarded and partials are annotated "(overstated)". Severities shown are the adjudicated final severities.

---

## 1. Executive Summary

Bifrost Proxy is, on the whole, a **mature and honestly-built codebase**. The core proxy data path (HTTP/CONNECT + SOCKS5), routing/matching, all four load-balancing strategies, token-bucket + bandwidth rate limiting, IP access control, disk/memory/tiered caching, active health checks, and log rotation are all genuinely implemented and wired — not stubs. The real backends (direct, http_proxy, socks5_proxy, wireguard, openvpn) are real, the PIA and Mullvad-WireGuard and NordVPN provider clients work end-to-end, and the checked-in `AUDIT.md` is unusually candid: every one of its nine "fixed" claims held up under independent inspection. TODO/FIXME markers are rare and the production panics are legitimate fail-fast guards.

The problems cluster into four themes:

1. **UI/config integration gaps** — several fully-working Go features (TOTP/HOTP/MFA, negotiate/SPNEGO, network/session/mitm config, listener mTLS, per-route weights, health thresholds) cannot be configured from the admin dashboards at all, and setting the documented `api.token` breaks *both* dashboards because neither UI can supply a token.
2. **Silent config-save/reload defects** — the server's `detectChangedSections()` omits `access_control`, `cache`, and several restart-required sections, so security-relevant changes are written to disk, reported as `requires_restart=false`, yet never applied to the running server.
3. **Broken/fabricated crypto material in two VPN providers** — ProtonVPN's and Mullvad's embedded OpenVPN CA certificates are corrupted (fail x509 parsing), ProtonVPN ships a fabricated tls-auth key, and the P2P mesh session crypto reuses deterministic keys with a nonce that restarts at 0 (ChaCha20-Poly1305 nonce reuse) plus a fail-open inbound-peer path.
4. **Observability & documentation drift** — the entire cache Prometheus subsystem is dead code, monitoring docs describe a metric schema that doesn't exist (alerts that silently never fire), and six auth docs still teach a config syntax the server hard-rejects at startup.

### The three maintainer questions, answered directly

**(a) Why does the Web UI font look like an old default?**
Root cause found and reproduced. `web/server/src/index.css:1` starts with `@reference "tailwindcss";` (Tailwind v4's *import-without-emit* mode) combined with legacy v3 `@tailwind base/components/utilities` directives. This suppresses emission of the Tailwind base/theme layer, so the compiled CSS (`internal/api/server/static/assets/index-6ZTXHU31.css`) contains **no `--font-sans`/`--default-font-family` variable, no Preflight reset, and never maps `fontFamily.sans: ['Inter', …]` from `tailwind.config.js` to anything**. The `<body>` carries only `bg-bifrost-bg text-gray-100 antialiased` with no font-family class, so all body/heading text falls back to the browser default serif (Times-like). The `@fontsource/inter` files load fine and are served correctly — they are simply never referenced by any applied rule. Only `.font-mono` (JetBrains Mono) renders as intended, which is why the effect looks inconsistent. This is purely the **server** dashboard; the client dashboard's font handling is correct.

**(b) Can the admin panel configure everything?**
No. The server Config UI covers most of `ServerConfig` well, but **three whole config sections — `network`, `session`, `mitm` — plus `auth.negotiate` have no TypeScript type and no visual form** (editable only via the raw-YAML tab). Additional gaps: listener mTLS (`client_auth`/`client_ca_file`), per-route load-balancing weights, and health-check debounce thresholds are not exposed. Worse than coverage is the **save path**: `access_control` and `cache` changes are saved but never hot-reloaded and falsely report `requires_restart=false`, and restart-required edits to `auto_update`/`health_check`/`network`/`session`/`mitm` also report no restart needed.

**(c) Are all auth plugins actually implemented?**
Mostly yes. The cryptographic plugins — **native, ldap, oauth, jwt, mtls, kerberos, apikey, hotp, totp** — are genuinely functional, and none silently allow-all (only `none` allows all, by design). The negotiate/SPNEGO middleware is real and wired. But there are notable holes:
- **NTLM always fails closed** — every Type 3 message is rejected; it is still selectable in the UI with a full config form and no warning.
- **`system` (PAM) fails closed** on Linux in the default and Docker builds (no `pam` build tag), yet is offered as "System (PAM)".
- **JWT HMAC (HS256/384/512)** is accepted in the algorithm list but there is no symmetric-key source, so HMAC verification always fails.
- **`mfa_wrapper`** advertises a by-name provider format in its `DefaultConfig`/`ConfigSchema` that `Create()` hard-rejects; only the (externally-documented) inline format works.
- **`negotiate`** is not a registered plugin (it is HTTP middleware) — configs using `mode: negotiate` or expecting a `negotiate` provider will not work.
No authentication **bypass** was found — every questionable path fails closed rather than open.

### Credit where due
- Correct, DNS-leak-avoiding remote hostname resolution in the direct/http/socks5 backends.
- PIA CA is validated fail-closed at init (`mustParsePIACertPool`); NordVPN validates the operator-supplied CA fail-closed.
- Handlers correctly guard nil dependencies and return proper status codes; every endpoint the two Web UIs call actually exists (no orphaned UI calls / 404s).
- WireGuard backend uses a proper userspace netstack with in-tunnel DNS.
- VPN userspace TCP actually includes out-of-order reassembly (stronger than `AUDIT.md` claims).
- Multi-hop peer relay and ICE are honestly disclosed as unimplemented in both code and config validation.

---

## 2. Web UI Issues

### 2.1 Server dashboard — FONT ROOT CAUSE (lead item)

**Inter font is never applied to any element — Tailwind v4 base/Preflight layer absent from built CSS.** [medium]
`web/server/src/index.css:1-5` → built `internal/api/server/static/assets/index-6ZTXHU31.css`.
The `@reference "tailwindcss";` directive puts Tailwind in reference-only (no-emit) mode, so the base/theme layer is never output. In the compiled CSS: `box-sizing:border-box` = 0 occurrences, `sans-serif`/`system-ui`/`ui-sans-serif` = 0, no `--font-sans`/`--default-font-family` variable, and the only applied font-family rule is `.font-mono{font-family:JetBrains Mono,…}`. All 28 `font-family:Inter` hits live inside `@font-face src` blocks and are never referenced by an applied rule. `tailwind.config.js` defines `fontFamily.sans` but it is never emitted; `<body>` has no font-sans class. Rebuild produced a byte-identical broken CSS, confirming it reproduces from current source.
**Fix direction (described, not applied):** migrate `index.css` to the Tailwind v4 idiom — drop `@reference` (which is for isolated/component stylesheets) in favor of a single `@import "tailwindcss";` that emits Preflight + theme, or port `fontFamily.sans` into a v4 `@theme` block and ensure a `font-family` is applied to `html`/`body` (e.g. add `font-sans` to the body class). Then rebuild and confirm the compiled CSS contains a `--font-sans`/`--default-font-family` and a Preflight reset.

**Tailwind Preflight CSS reset is missing entirely (same root cause).** [medium]
Same file/build artifact. No `box-sizing:border-box`, no default margin/padding resets; the only `@layer base` rules are the project's own (`html{scroll-behavior:smooth}`, body min-height, scrollbar styles). Consequence: browser-default heading/list/form styling leaks through, producing subtle cross-browser spacing/alignment inconsistencies. Fixed by the same change as the font item.

**Duplicate `<title>` element in `index.html`.** [low]
`web/server/index.html:8-9` (and built static copy) contains `<title>Bifrost Server Dashboard</title>` twice consecutively. Invalid HTML; browsers use the first. Purely cosmetic/spec-compliance.

### 2.2 Server dashboard — auth/token integration

**Server Web UI never populates the API token; dashboard 401s when auth enabled.** [medium]
`web/server/src/api/client.ts:59,256-266`; `internal/api/server/server.go:280-307`.
`fetchJSON` only adds `Authorization: Bearer` if `localStorage['bifrost_api_token']` exists, but `setApiToken`/`getApiToken`/`clearApiToken` are exported and never imported anywhere; there is no login/token-entry component. `APISection.tsx` edits only the server-side config value, not localStorage. With `api.token` set, the SPA shell loads (static assets are unauthenticated) but every `/api/v1/*` call returns 401. Workaround only via devtools console or upstream reverse proxy. Fail-closed, opt-in-only, hence medium.

**WebSocket connections never send the auth token; live updates fail when `api.token` is set.** [medium]
`web/server/src/hooks/useWebSocket.ts:23-24`; `web/server/src/components/Mesh/MeshEventLog.tsx:94-98`; server route `internal/api/server/server.go:189-199`.
WS URL is `…/api/v1/ws` with no `?token=`. When a token is configured the WS handler is inside the auth group and `authMiddleware` accepts a token only via header or `?token=` — which the UI never provides, and browsers can't set the Authorization header on a WS handshake. The stats WS then reconnects every 3s forever (spamming 401s) but degrades gracefully to REST polling; the **mesh event log does not reconnect** and simply shows nothing with no fallback (audit's "same reconnect spam" for mesh is *overstated*, but the "shows nothing" conclusion holds).

**Config editor renders garbled validation messages.** [low] (audit rated medium — *overstated*)
`web/server/src/components/Config/ConfigEditor.tsx:157-160,447,26`.
The claimed "silent no-op" is refuted: `Config.tsx:151-161` fires a toast per validation error and the save is correctly aborted, so the user *does* get feedback and no bad config is written. The genuine bug is a **type mismatch** — the frontend types `errors` as `string[]` but the backend returns `[]ValidationError` objects `{section, message}` (`config_handlers.go:189-195`), so each toast renders as `Validation: [object Object]` instead of the real message. Cosmetic formatting defect only.

### 2.3 Client dashboard

**Client Web UI has no API-token support; setting `api.token` breaks the entire client dashboard.** [high]
`web/client/src/api/client.ts:35-67`; `internal/api/client/server.go:491-518`.
Client `fetchJSON` sends only `Content-Type` + `X-Requested-With`, no Authorization; grep for token-sending code in `web/client/src` returns zero. Yet the client UI itself offers an API Token field (`WebUISection.tsx:58`) and the server enforces it with a constant-time compare returning 401. Setting the token makes every REST call and the SSE log stream (`Logs.tsx` `new EventSource('/api/v1/logs/stream')`, which never appends the supported `?token=` fallback) return 401, with no login prompt to recover. Rated high because it fully bricks the client dashboard the moment the operator uses a field the UI advertises.

**Settings "Reload" button always fails with HTTP 503 (ConfigReloader never wired).** [medium]
`internal/client/client.go:160` → `internal/api/client/server.go:1506`; UI `web/client/src/pages/Settings.tsx:250-256`.
`apiclient.New` is built without `ConfigReloader` (grep confirms it is never set in `internal/client`), so `handleReloadConfig` always returns 503 "config reload not supported". The Reload button is rendered unconditionally and shows the error toast on every click. Convenience action only — config edits still work via the separate `ConfigUpdater`/Save path.

**Cache tab/page is permanently empty — client has no caching capability.** [low]
`internal/client/client.go:160`; nav `TabNav.tsx:6`; page `Cache.tsx`; `internal/config/client.go`.
`ClientConfig` has no cache field and `apiclient.New` is called without a `CacheManager`, so `handleCacheStats` returns `{Enabled:false, StorageType:"none"}` and entries are always empty. The UI ships a full Cache nav tab and management page with a permanently-disabled "Clear All" button. Endpoints degrade gracefully (200), so it is a misleading dead surface, not a crash.

**Client `/logs` and `/logs/stream` return traffic-debug entries, not application logs.** [low]
`internal/api/client/server.go:1542-1594,1690-1754`.
Entries are built from `a.debugger.GetLastEntries` and labeled `source:"traffic_debug"`; the UI honestly labels this. The real gap is in `docs/.../api/client.mdx:836-909`, which titles the section generically, omits the `source` field, advertises `warn`/`debug` level filters the code can never produce, and shows a fabricated application-log-style streaming example.

---

## 3. Admin Panel Config-Coverage Matrix

| Config section | UI status | Notes |
|---|---|---|
| `server` (listeners/timeouts/TLS enable/cert/key) | **Partial** | Full except listener mTLS `client_auth`/`client_ca_file` (not in TS type or `ServerSection.tsx`). |
| `backends` (all 9 types, weight/priority/health) | **Full** | Well-covered incl. backend-level weight. |
| `routes` | **Partial** | No per-route load-balancing `weights` map; selecting "Weighted" yields empty weights → degrades to round-robin unless backend weights seeded. |
| `auth.providers` (10 plugin types) | **Partial** | Read+write for the 10 listed; but hotp/totp/mfa_wrapper are registered yet absent from the dropdown. |
| `auth.negotiate` (SPNEGO/Kerberos/NTLM middleware) | **None** | No TS type, no form; Windows-domain SSO can only be enabled via raw YAML. |
| `rate_limit` + `bandwidth` | **Full** | |
| `access_control` | **Broken** | Full form, but save path never applies/hot-reloads changes and falsely reports `requires_restart=false` (see §7 Bugs). |
| `access_log` / `metrics` / `logging` / `web_ui` / `api` / `auto_update` | **Full** | Read+write forms present. |
| `cache` | **Broken** | Full CRUD form, but cache-only saves are never hot-reloaded and report `requires_restart=false`. |
| `health_check` (global) | **Partial** | No `healthy_threshold`/`unhealthy_threshold`; restart-required edits report no restart. |
| `network` (ipv6/keepalive/dial_timeout/max_connections) | **None** | No TS type, no form; raw-YAML only (round-trips via `{...defaultConfig, ...config}`). |
| `session` (Redis store/addr/db/duration/cleanup) | **None** | No TS type, no form; raw-YAML only. Blocks multi-replica shared sessions via UI. |
| `mitm` (enabled/ca_cert/ca_key/leaf_ttl/max_cached_certs) | **None** | No TS type, no form; raw-YAML only. |

Client-side config coverage additionally has dead controls: **Auto-Update** toggle (checker never started), **Server health-check/retry-delay** and **Tray** options (not hot-applied and no restart badge) — see §7.

---

## 4. Auth Plugin Implementation Matrix

| Plugin | Status | Evidence |
|---|---|---|
| `none` | **Functional** (allow-all by design) | The only intentional allow-all path. |
| `native` | **Functional** | Real credential validation; no allow-all. |
| `ldap` | **Functional** | |
| `oauth` | **Functional** | |
| `jwt` | **Partial** | RSA/EC verification works; HS256/384/512 accepted in alg list + verify switch but no symmetric-key source, so HMAC always fails with "invalid key type for HMAC" (`jwt.go:462-468,191-201,628-645`). Not exploitable (alg allowlist blocks RS↔HS confusion). |
| `mtls` | **Functional** | Provider works; but listener-level mTLS cannot be enabled from the UI. |
| `kerberos` | **Functional** (password path) | Chain provider does password auth; SPNEGO/Windows-domain only via the negotiate middleware (`kerberos.go:231-244,333`). |
| `apikey` | **Functional** | |
| `hotp` | **Functional but not UI-configurable** | Registered (`cmd/server/main.go`), fully implemented; absent from UI auth-type list. |
| `totp` | **Functional but not UI-configurable** | Same as hotp. |
| `mfa_wrapper` | **Partial / metadata-broken** | Works only with inline `primary`/`secondary` blocks; `DefaultConfig`/`ConfigSchema` advertise a by-name format that `Create()` hard-errors (`internal/auth/mfa/plugin.go:45-48,80-88,91-139`). Correct format IS documented externally (authentication.mdx:429-459), so "unusable without source" is *overstated*. Not in UI. |
| `ntlm` | **Fail-closed (dead end)** | `handleType3` and `ValidateAuthenticate` unconditionally return `ErrVerificationUnsupported`; rejects 100% of clients (`internal/auth/plugin/ntlm/ntlm.go:200-203,268-281,566`). Still selectable in UI with full form and no warning. |
| `system` (PAM) | **Fail-closed in default/Docker build** | `pam_stub.go:40-45` `validateLinux` logs a warn and returns false unless built with `linux && cgo && pam`. Docker (`CGO_ENABLED=0`, no `-tags pam`) and `make build` both omit it. Offered as "System (PAM)" with a PAM Service field, no UI warning. |
| `negotiate` | **Not a plugin (middleware)** | Not registered via `RegisterPlugin`; real SPNEGO/NTLM handshake lives in `internal/server/negotiate.go` driven by `auth.negotiate.*`, which has no UI. Docs `mode: negotiate` examples are doubly broken (see §9). |

---

## 5. Backend Implementation Status

| Backend / provider | Status | Notes |
|---|---|---|
| `direct` | **Functional (solid)** | Correct stats; remote hostname resolution avoids DNS leaks. |
| `http_proxy` | **Functional (solid)** | |
| `socks5_proxy` | **Functional (solid)** | |
| `wireguard` | **Functional (solid)** | Userspace netstack, in-tunnel DNS. |
| `openvpn` | **Functional, disclosed leak caveats** | Spawns openvpn binary + management interface; host-routing egress unless Linux-only, root-required, off-by-default `leak_proof_routing`; DNS still uses host resolver (`openvpn.go:104-124`). |
| PIA | **Functional (end-to-end)** | Real token auth, CN-pinned `/addKey` TLS, port forwarding, embedded CA validated fail-closed at init. |
| Mullvad — WireGuard | **Functional** | Live key registration, valid API. |
| Mullvad — OpenVPN | **Broken** | Embedded `mullvadCACert` fails `x509.ParseCertificate` ("malformed algorithm identifier"); no validation. Only bites operators who explicitly pick OpenVPN (default is WireGuard). Fails at connect time silently (`internal/vpnprovider/mullvad/client.go:409`). |
| NordVPN — OpenVPN | **Functional (operator CA)** | Requires operator-supplied CA, validated fail-closed. |
| NordVPN — WireGuard | **Functional, out-of-band key** | NordLynx fixed `10.5.0.2/32` + user-supplied private key; no in-product key registration (inherent to NordVPN API). |
| ProtonVPN — WireGuard (api mode) | **Broken/unlikely** | SRP auth implemented against unrealistic mock, omits PGP modulus signature verification, wrong password-hash scheme; unlikely to authenticate against live API (`client.go:462`, `srp.go:93,282`). |
| ProtonVPN — OpenVPN (default) | **Broken** | Embedded `ProtonVPNCACert` fails x509 parse ("malformed certificate"), fabricated `ProtonVPNTLSAuth` static key (repeating lines), and template hardcodes `script-security 2` + host `update-resolv-conf` scripts (`servers.go:243-245,261,296`). Default protocol/auth is OpenVPN/manual, so the default path never connects. |

---

## 6. Unimplemented / Stub / TODO Inventory

**Dead code / never instantiated**
- `internal/cache/metrics.go:44` (`NewMetrics`) + `internal/cache/cache.go:15` — entire cache Prometheus subsystem never called from production; `Manager` has no `*Metrics` field.
- `internal/p2p/ice.go:99-105,394-444` — `ICEAgent` fully implemented + unit-tested but never wired; `checkConnectivity` uses a plaintext `BIFROST_ICE_PROBE` echo, not STUN.
- `internal/p2p/relay.go:542-638` (`RelayRouter`, `PeerRelay`, `PeerRelayedConnection`) — multi-hop peer relay never wired; `wrapRelayMessage`/`unwrapRelayMessage` never set `SrcPeerID`/TTL; rejected by config (`internal/mesh/config.go:247-248`).
- `internal/api/server/config_handlers.go:255-264` (`handleGetConfigTimestamp`) — unrouted; returns `time.Now()` not the config file mtime.
- `internal/api/server/websocket.go:157-160` (`AddWebSocketRoutes`), `internal/api/server/server.go:126-170` (`Router()`, partial), `setWebSocketHub` — no non-test callers; only `RouterWithWebSocket` is wired.

**Stub functions that report false success**
- `internal/device/device.go:217-233` (`GenerateMAC`) — doc says "random", body hardcodes `02:BF:00:00:00:01`. Dead code (prod uses `GenerateRandomMAC`), latent L2-collision footgun.
- `internal/device/tap_windows.go:372-383` (`SetMACAddress`) — returns nil but only updates `t.mac`, never changes adapter MAC. No prod callers today.

**Explicit TODO / not-supported guards**
- `internal/backend/openvpn.go:118-124` — `TODO(proxy): route OpenVPN backend DNS through the tunnel`.
- `internal/proxy/socks5.go:408-421` — BIND and UDP ASSOCIATE return `socks5ReplyCmdNotSupported` (spec-correct feature limitation).
- `internal/backend/leakproof_other.go:7` — non-Linux `Install` returns `ErrLeakProofUnsupported`.

---

## 7. Bugs & Correctness Issues (severity-ordered)

1. **[high] `access_control` changes saved to disk but never applied; API falsely reports `requires_restart=false`.** `internal/api/server/config_handlers.go:204-239` (+ auto-reload gate `:146`). `detectChangedSections` never compares `current.AccessControl`; an access_control-only save yields `changedSections=[]`, so `reloadConfig()` is never called and `requiresRestart=false`, even though `Server.ReloadConfig` (`server.go:857-869`) *would* hot-apply the whitelist/blacklist. Operator adds an IP block, sees "saved", but the rule is not enforced until a later manual reload/restart. Security-relevant.
2. **[high] ProtonVPN OpenVPN embedded CA is malformed → default ProtonVPN path never connects.** `internal/vpnprovider/protonvpn/servers.go:261`, consumed `client.go:373`. `x509.ParseCertificate` fails; interpolated into `<ca>` with no validation. Default protocol is `openvpn`, default auth `manual`. openvpn subprocess fails to start with a cryptic CA error and no early diagnostic.
3. **[medium] Mullvad OpenVPN embedded CA is malformed.** `internal/vpnprovider/mullvad/client.go:409`. Same failure mode as #2, but only on the opt-in OpenVPN protocol (default WireGuard works). Fails silently at generation, aborts at connect.
4. **[medium] Restart-required changes to `auto_update`/`health_check`/`network`/`session`/`mitm` report `requires_restart=false`.** `config_handlers.go:204-248`. `detectChangedSections` omits these; `ReloadConfig` doesn't apply them either, so edits are silently inert with no restart prompt.
5. **[medium] `cache` changes saved but not hot-reloaded from the save path.** `config_handlers.go:204-239`. No `Cache` comparison; cache toggles/rules written to YAML but not applied to the live server; response says `requires_restart=false`. (`ReloadConfig:894-900` would apply them if reached.)
6. **[medium] Cache hits recorded as HTTP 500 in metrics and access logs.** `internal/proxy/http.go:364-373,213-221`. The cache-served branch never sets `entry.StatusCode`, so the deferred closure defaults it to 500 and records `bifrost_requests_total{status="500"}`. Inflates error-rate dashboards; client still gets a correct 200. Only when caching enabled.
7. **[medium] `backend` label always empty on connection and byte-transfer metrics.** `internal/server/server.go:1001,1089,1200`. `RecordBytes("", …)` / `RecordConnection("http"/"socks5", "")` always pass empty backend even though the name is known at request time (`util.WithBackend`). Per-backend Prometheus breakdown non-functional across 5 metrics.
8. **[medium] ProtonVPN SRP (api/WireGuard) auth against unrealistic mock; omits modulus signature verification.** `client.go:462`, `srp.go:93,282`. Real `/auth/info` returns a PGP clear-signed modulus (plain base64 decode fails); wrong hash scheme; no signature check (theoretical SRP-downgrade gap). ProtonVPN WireGuard effectively unusable against live API.
9. **[medium] ProtonVPN OpenVPN template runs host resolv.conf scripts with `script-security 2`.** `servers.go:243-245`. Rewrites the host's global `/etc/resolv.conf` on tunnel-up (Debian/Ubuntu), and is fatal to openvpn on hosts lacking the script (RHEL/Alpine/most containers).
10. **[medium] Client Server & Tray settings change with no restart warning but are not hot-applied.** `internal/client/client.go:557-576,621-637`, `restartRequiredFields:117-126`. `retry_delay`/health-check/tray edits show "Saved" with no restart banner but only take effect after manual restart; the client Health Check block is in fact entirely unconsumed (dead config).
11. **[medium] Auto-Update settings are a dead toggle.** `internal/updater/updater.go:181` (`StartBackgroundChecker` never called in prod); daemon never constructs an Updater. Enabling Auto-Update has no runtime effect.
12. **[low] `/status` always reports `bytes_sent=0`, `bytes_received=0`, `active_connections=0`.** `internal/api/client/server.go:662-687`; wiring `client.go:160`. Counter funcs never set, so guarded branches skipped. Dashboard doesn't render these three today, so limited visible impact.
13. **[low] Client `updateConfig` hot-applies `auto_update.channel/enabled` but silently drops `check_interval`.** *(overstated)* `client.go:660-667`. Value is NOT lost — it persists to YAML — and the whole in-memory AutoUpdate config is inert at runtime anyway. Real defect: internal inconsistency.
14. **[low] Active-connection gauge `done()` not deferred.** *(overstated)* `internal/server/server.go:1089-1093,~1200`. Claimed monotonic gauge leak is refuted — there is no `recover()`, so an unrecovered panic crashes the process and resets the gauge. Purely a defensive-coding nit.

---

## 8. Security Issues (severity-ordered)

1. **[high] P2P session keys are deterministic + nonce restarts at 0 → ChaCha20-Poly1305 nonce reuse across every reconnect.** `internal/p2p/crypto.go:229-277`; handshake randomness at `:154,:193` is transmitted but never mixed into key derivation. `sharedSecret = X25519(static priv, static pub)`, keys via `deriveKey(secret,"send"/"recv")` with nil HKDF salt, `sendNonce` starts at 0 each session, `NewCryptoSession` recreated on every `Connect` (`connection.go:262`). Any peer pair observed across a reconnect leaks plaintext XOR and the Poly1305 one-time key, enabling frame forgery on the mesh data plane. No forward secrecy. `AUDIT.md:38-41` presents this as a completed fix. (Minor: reconnection is driven by the higher-layer connect path, not `connectionMonitor` alone.)
2. **[high] Responder accepts inbound P2P handshakes from unknown/unauthorized public keys and injects their frames into the tunnel device.** `internal/p2p/manager.go:586-592,653` → `internal/mesh/node.go:1031-1045`. Unknown keys get a synthetic `incoming-<addr>` ID and proceed through `ProcessHandshakeInit`; decrypted `markerData` payloads flow straight to `writeToDevice`/`macTable.Learn`. A `mesh.SecurityConfig.AllowedPeers` field exists but is never read (dead config). Any host that can reach the mesh UDP port and knows the (non-secret, discovery-distributed) public key can inject arbitrary IP/Ethernet frames. Fail-open authorization gap not disclosed in `AUDIT.md`.
3. **[medium] Replay protection accepts replayed frames within a 1024-nonce window (effectively inert).** `internal/p2p/crypto.go:301-310`. Single `atomic.Uint64`, no sliding-window bitmap; exact replays and any nonce ≤1024 behind max are accepted, and a low nonce drags the counter backward. Compounds #1.
4. **[medium] OpenVPN backend leaks DNS outside the tunnel.** `internal/backend/openvpn.go:118-124`. Hostname resolution uses the host OS resolver; `leak_proof_routing` (source-IP policy routing) doesn't cover resolver dials. Honestly documented; steers privacy users to WireGuard. Off-by-default.
5. **[low] Leak-proof egress routing is off by default, Linux-only, runtime-unvalidated.** `internal/backend/leakproof.go:31`, `leakproof_other.go:7`, `openvpn.go:104-124`. Disclosed design limitation, fails closed when enabled.

---

## 9. Broken / Placeholder Endpoints & Surfaces

- **[high] Client dashboard fully broken under `api.token`** — every REST call + SSE stream 401s (see §2.3).
- **[high] Server dashboard `/api/v1/*` 401s under `api.token`** — no token-entry UI (see §2.2). *(Rated high in-UI impact; adjudicated medium as opt-in/fail-closed.)*
- **[medium] Client "Reload" button → always HTTP 503** (`ConfigReloader` unwired; §2.3).
- **[medium] Server mesh coordinator API is always-on, in-memory only; `MeshConfig.Enabled` is dead; networks never persisted.** `internal/api/server/mesh.go:35-45,159-169`; `server.go:94,275-277`. `NewMeshAPI()` takes no config and is always mounted; `grep MeshConfig` finds no references. Every mesh network + peer is lost on restart, no operator toggle. (Routes are token-authenticated when a token is set.)
- **[low] Dead/stub API code** — unrouted `handleGetConfigTimestamp` returns fake time; unused `setWebSocketHub`/`AddWebSocketRoutes`/partial `Router()` (§6).
- **[low] `config.saved` WebSocket event broadcast but no UI consumer.** `config_handlers.go:156,251-252` vs `web/server/src/api/types.ts:570-574`. (Also `config.reload`, `connection.new`, `connection.close` are defined-but-unconsumed.)

---

## 10. Doc-vs-Code Mismatches (severity-ordered)

1. **[high] Documented auth config examples are rejected by the server (legacy `auth.mode`).** `docs/src/content/docs/security.mdx:102-141` (+ `configuration.mdx:58`, `troubleshooting/connections.mdx:300`, `troubleshooting/authentication.mdx:89`, `troubleshooting/faq.mdx`). `AuthConfig.Validate` (`internal/config/server.go:494-499`) hard-rejects any `mode:` and any top-level `native/system/ldap/oauth` block, via `LoadAndValidate` at startup (`cmd/server/main.go`). Copying these guides yields a server that exits with "legacy auth.mode is no longer supported". Six docs affected.
2. **[high] Entire `configuration/authentication.mdx` uses rejected `mode:` syntax (kerberos/mtls/negotiate).** `authentication.mdx:156,272,356,496,612,725,784`. All 7 config blocks fail to load; `auth.kerberos:`/`auth.mtls:` aren't even fields (silently dropped by non-strict unmarshal). The dedicated Kerberos/mTLS/Negotiate guide is 100% non-functional. (`auth.negotiate:` *is* a real field, but blocks still set `mode: negotiate`.)
3. **[high] monitoring.mdx documents a Prometheus schema that doesn't match the code.** `docs/src/content/docs/monitoring.mdx:46-126` vs `internal/metrics/prometheus.go:56-207`. Nonexistent series (`bifrost_connections_errors_total`, `bifrost_bytes_total`, `bifrost_backend_healthy`, `bifrost_backend_connections_active`, `bifrost_bandwidth_bytes_per_second`, `bifrost_memory_bytes`); wrong labels (`bifrost_requests_total` is `{protocol,method,status}` not `{method,backend,status}`; `bifrost_request_size_bytes` label is `protocol` not `direction`). Copy-paste alerts `BifrostHighErrorRate` and critical `BifrostBackendDown` evaluate against missing metrics and **silently never fire**; panels render empty. Doc-only, caps at high.
4. **[medium] Two contradictory authentication docs; AUDIT calls the broken set "authoritative".** `authentication.mdx` (correct `providers[]`) vs `configuration/authentication.mdx` (rejected `mode:`); `AUDIT.md:98`. Readers can't tell which syntax is valid.
5. **[medium] Docs advertise mesh `relay_via_peers: true`, but config validation rejects it.** `internal/mesh/config.go:247-248` vs `docs/.../mesh-networking.mdx:421,579`. Copying the full config example produces a fatal (but loud, self-remediating) startup error.
6. **[medium] `system` (PAM) offered as a working UI option but fails closed in default/Docker builds.** `pam_stub.go:40-45`; `AuthSection.tsx:23` (see §4).
7. **[low] Docs show `mode: negotiate` although negotiate is not a registered plugin.** `configuration/authentication.mdx:356,725,784`; `AUDIT.md:78-79`. Doubly broken (`mode:` rejected AND unregistered); SPNEGO SSO *is* supported via `auth.negotiate.enabled` middleware, so only the syntax is wrong.
8. **[low] Docs architecture diagram claims NTLM validates against a Domain Controller.** `docs/.../configuration/authentication.mdx:50` (`NTLMAuth -->|Validate| DC`) + stale `docs/dist/.../authentication/index.html:132`. Contradicts the same file's honest "fails closed" note (`:371-382`) and the always-reject code.
9. **[low] Built-in log rotation is fully implemented but undocumented; docs steer users to external logrotate.** `internal/logging/rotate.go` + `logging.go:22-26,111-130` vs `deployment.mdx:253`; `CLAUDE.md` even asserts "No built-in log rotation". `max_size_mb`/`max_backups` are valid config keys documented nowhere.
10. **[low] AUDIT understates VPN userspace TCP: claims "in-order only (no reassembly)" but out-of-order reassembly exists.** `AUDIT.md:92-93` vs `internal/vpn/tcpreasm.go` + `vpn.go:495`. Code is stronger than documented (windowing/SACK/congestion control genuinely absent).
11. **[low] NordVPN WireGuard uses hardcoded client address/DNS + out-of-band private key.** `internal/vpnprovider/nordvpn/client.go:337-367`. Inherent to NordVPN's lack of a public NordLynx key-registration API; documented in-code.

---

## 11. Prioritized Backlog (severity-ranked)

**Critical / High**
1. **Server config save: `access_control` changes silently not applied, reported as no-restart** — add `AccessControl` to `detectChangedSections` and the reload path. Security control unenforced. (`config_handlers.go:204-239`)
2. **P2P session crypto: deterministic keys + nonce-from-0 → ChaCha20-Poly1305 nonce reuse** — mix handshake randomness/ephemeral keys into KDF, use unique nonces per (key) lifetime; add forward secrecy. (`p2p/crypto.go:229-277`)
3. **P2P inbound handshake accepts unauthorized peers and injects frames into TUN/TAP** — enforce `SecurityConfig.AllowedPeers`/known-key allowlist before accepting. (`p2p/manager.go:586-592`)
4. **ProtonVPN OpenVPN CA malformed → default path never connects** — replace/validate the embedded CA; fail fast at config-gen. (`protonvpn/servers.go:261`)
5. **Client dashboard fully broken when `api.token` set** — add token entry + Authorization/`?token=` on REST, SSE, and WS. (`web/client/src/api/client.ts:35-67`)
6. **Server dashboard 401s when `api.token` set** — wire `setApiToken`/login UI and send WS `?token=`. (`web/server/src/api/client.ts`, `useWebSocket.ts:23-24`)
7. **Six auth docs teach server-rejected `auth.mode` syntax** — rewrite all `mode:`/top-level-block examples to `auth.providers[]`. (`security.mdx`, `configuration/authentication.mdx`, troubleshooting docs)
8. **monitoring.mdx alerts/panels reference nonexistent metrics** — reconcile doc schema with `internal/metrics/prometheus.go`; fix alert queries.

**Medium**
9. `cache` and `auto_update`/`health_check`/`network`/`session`/`mitm` config saves report `requires_restart=false` and aren't applied — fix `detectChangedSections`/`hasRestartRequiredChanges`.
10. Mullvad OpenVPN CA malformed (opt-in path). (`mullvad/client.go:409`)
11. ProtonVPN fabricated tls-auth key + `script-security 2` host-resolv scripts. (`protonvpn/servers.go:243-245,296`)
12. ProtonVPN SRP auth: PGP modulus parsing + signature verification + correct hash scheme. (`protonvpn/srp.go`)
13. Add embedded-provider-CA parse tests / init guards for Mullvad + ProtonVPN (mirror PIA's `mustParsePIACertPool`).
14. Cache hits logged/counted as HTTP 500 — set `entry.StatusCode=200` on cache-served path. (`proxy/http.go:364-373`)
15. Empty `backend` label on connection/byte metrics — forward backend name to `recordMetrics`. (`server.go:1001`)
16. SOCKS5 traffic missing from request/duration/size/byte metrics — add `RecordMetrics` to `SOCKS5HandlerConfig`.
17. Client Reload button always 503 — wire `ConfigReloader` or hide the button.
18. Client Auto-Update dead toggle — start `StartBackgroundChecker` in the daemon or remove the UI.
19. Client Server/Tray edits: add restart badges or hot-apply; client Health Check block is dead config.
20. Expose `network`/`session`/`mitm`/`auth.negotiate` in the admin UI (TS types + forms).
21. Server mesh coordinator: honor an `Enabled` toggle and persist networks/peers across restart.
22. P2P replay window (1024) — add a sliding-window seen-set. (`p2p/crypto.go:301-310`)
23. OpenVPN DNS leak — route backend DNS through tunnel (`TODO(proxy)`).
24. Mesh `relay_via_peers` doc example rejected by validator — fix docs.
25. Two contradictory auth docs / `system`-PAM & `mode: negotiate` doc mismatches.
26. Listener mTLS (`client_auth`/`client_ca_file`) and per-route weights not in UI.

**Low**
27. Server dashboard font/Preflight root cause — migrate `index.css` off `@reference` so Tailwind base + Inter are emitted. (Cosmetic but the actual reported symptom.)
28. Config validation-error toasts render `[object Object]` — align `errors` type with backend `[]ValidationError`.
29. Client Cache tab is a permanent dead surface; hide until a `CacheManager` is wired.
30. Client `/status` always-zero counters; `/logs` doc advertises unsupported filters.
31. Health-check debounce thresholds + HTTPS scheme/insecure_skip_verify unreachable from config.
32. Dead code cleanup: cache Prometheus subsystem, `ICEAgent`, `RelayRouter`, `handleGetConfigTimestamp`, unused `Router()`/WS helpers, `GenerateMAC` stub, Windows `SetMACAddress` stub.
33. Undocumented built-in log rotation (+ correct `CLAUDE.md`); NTLM DC diagram + stale `docs/dist`; duplicate `<title>`; unconsumed `config.saved`/`config.reload`/connection WS events; AUDIT VPN-TCP "no reassembly" claim; SOCKS5 BIND/UDP-ASSOCIATE feature limitation.

---

*Relevant primary source paths (absolute):*
- `/Users/rennerdo30/Development/simple-proxy-server/web/server/src/index.css`, `/Users/rennerdo30/Development/simple-proxy-server/web/server/tailwind.config.js`
- `/Users/rennerdo30/Development/simple-proxy-server/internal/api/server/config_handlers.go`, `.../internal/server/server.go`
- `/Users/rennerdo30/Development/simple-proxy-server/internal/p2p/crypto.go`, `.../internal/p2p/manager.go`, `.../internal/mesh/node.go`
- `/Users/rennerdo30/Development/simple-proxy-server/internal/vpnprovider/protonvpn/servers.go`, `.../internal/vpnprovider/mullvad/client.go`
- `/Users/rennerdo30/Development/simple-proxy-server/web/client/src/api/client.ts`, `/Users/rennerdo30/Development/simple-proxy-server/web/server/src/api/client.ts`
- `/Users/rennerdo30/Development/simple-proxy-server/internal/auth/plugin/ntlm/ntlm.go`, `.../internal/auth/plugin/jwt/jwt.go`, `.../internal/auth/mfa/plugin.go`
- `/Users/rennerdo30/Development/simple-proxy-server/docs/src/content/docs/monitoring.mdx`, `.../docs/src/content/docs/security.mdx`, `.../docs/src/content/docs/configuration/authentication.mdx`