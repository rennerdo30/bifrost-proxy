# Mobile app audit — `mobile/`

Audited at base `ba1e826` (branch `master`). Scope: the 16 non-`node_modules` source files under
`mobile/`, its Expo/TS configuration, the two orphaned native files, and the client REST API the app
targets (`internal/api/client/server.go`).

---

## 1. Verdict

**No, this app cannot be shipped, and the native VPN is not the reason.** The blocking thing is that
the REST integration — the app's entire actual purpose — has demonstrably never been run against a
real Bifrost client: every mutating request is rejected with `403` because the app omits the
`X-Requested-With` header the client API requires
(`mobile/src/services/api.ts:95-101` vs `internal/api/client/server.go:547-559`), the server-select
endpoint it calls does not exist, and the three response types it is built around
(`StatusResponse`, `VPNStatus`, `ServerInfo`) do not match what the Go handlers actually emit — so
most of what the UI renders is permanently `N/A` and every button is a no-op.

The native on-device VPN is genuinely, honestly documented as out of scope, and it is not reachable —
but for a different reason than the docs claim, and that difference matters (§4).

---

## 2. Build and toolchain reality

The two CI gates (`.github/workflows/ci.yml:225-245` runs only `npm run typecheck` and
`npm run doctor` for `mobile/` — no lint, no tests, no native build) both pass cleanly:

```
$ npm run typecheck        # tsc --noEmit
(no output, exit 0)

$ npm run doctor           # CI=1 npx expo-doctor
Running 20 checks on your project...
20/20 checks passed. No issues detected!

$ npx eslint . --ext .ts,.tsx     # not run by CI, but clean
(no output, exit 0)
```

There is **no test suite at all** — no `test` script in `mobile/package.json:6-14`, no `jest`
dependency, no test files. `mobile/README.md:22-24` states this openly. So a green CI proves
compilation and config sanity and nothing else.

### Can a binary be produced?

**Android: yes.** I ran a real build in this worktree (JDK 17, Android SDK 36):

```
$ cd mobile && npx expo prebuild --no-install --platform android
The android project is malformed, project files will be cleared and reinitialized.
- Clearing android
✔ Cleared android code
- Creating native directory (./android)
✔ Created native directory
✔ Finished prebuild

$ cd mobile/android && ./gradlew :app:assembleDebug --no-daemon
BUILD SUCCESSFUL
$ ls -la app/build/outputs/apk/debug/app-debug.apk
-rw-r--r--  1 ... 141828843 ... app-debug.apk

$ ./gradlew :app:lintVitalRelease --no-daemon
BUILD SUCCESSFUL in 1m
```

So an installable Android APK exists, and even the release lint gate passes. See §4 for what the
`prebuild` line "Clearing android" destroyed on the way.

**iOS: not verifiable here, and probably not without a paid Apple account.** `expo prebuild
--platform ios` succeeds and generates `ios/BifrostVPN.xcodeproj` plus
`ios/BifrostVPN/BifrostVPN.entitlements` containing
`com.apple.developer.networking.networkextension = ["packet-tunnel-provider"]`
(from `mobile/app.json:26-30`). That entitlement is only grantable through a provisioning profile
with the Network Extension capability, which requires a paid Apple Developer account — and the app
has no Network Extension target to justify it. **I did not attempt an `xcodebuild` archive**, so I
cannot state as fact that signing fails; but requesting an entitlement no profile carries is the
standard cause of a signing failure, and the app does not need the entitlement at all today.

**EAS Build: impossible as committed.** `mobile/app.json:46-50` sets
`extra.eas.projectId` to `00000000-0000-0000-0000-000000000000`. `eas build` requires a real project
id. `mobile/README.md:106` admits this.

### Other toolchain notes

- `mobile/eslint.config.mjs:20-26` registers only `@typescript-eslint`. There is no
  `eslint-plugin-react-hooks`, so the incomplete hook dependency lists in the code
  (e.g. `mobile/src/screens/SettingsScreen.tsx:183-188`) are never flagged.
- The three app icons are byte-identical placeholders (`mobile/assets/icon.png`,
  `adaptive-icon.png`, `splash.png` — all 61357 bytes), so nothing here is store-submission ready.
- `mobile/ios/BifrostVPN/Info.plist` (generated) sets `NSAllowsLocalNetworking: true` but has **no**
  `NSLocalNetworkUsageDescription`. Since the app's whole job is reaching a client on the LAN
  (`http://192.168.x.x:7383`), iOS 14+ local-network privacy will block or crash that. I verified the
  key's absence from the generated plist; I did **not** run on a device to observe the failure.

---

## 3. Feature-by-feature

State legend: **works** = does what it claims against the real API · **partial** = renders and wires
up, but a material part is broken or inert · **stub** = renders, does nothing real · **absent**.

| Screen / subsystem | State | Evidence | What finishing it requires |
|---|---|---|---|
| App shell (nav, theme, query client, toasts) | works | `mobile/App.tsx:34-65`, `mobile/src/navigation/RootNavigator.tsx:114-140` | Nothing. Clean, complete, has a loading gate on `initializeAPIConfig`. |
| Toast component | works | `mobile/src/components/Toast.tsx:140-162` | Add `accessibilityLiveRegion`/`role="alert"` — `docs/.../mobile-client.mdx:448` claims errors use the alert role; the toast has no a11y props at all (`Toast.tsx:112-133`). ~1h. |
| `StatusCard` | works | `mobile/src/components/StatusCard.tsx:10-34` | Nothing. |
| `utils/status.ts` | works | `mobile/src/utils/status.ts:10-39` | Nothing. |
| Home — connect/disconnect | partial | `mobile/src/screens/HomeScreen.tsx:86-110`, `178-184` | Handler and mutations are real, but `api.enableVPN`/`disableVPN` return `403` (CSRF, §5). Add the header. ~1h. |
| Home — loading/error states | **absent** | `HomeScreen.tsx:32-48` destructures only `data`; no `isLoading`, no `isError` for any of the three queries | When the client is unreachable the primary screen silently shows "Not Connected" and `0 B` — a false negative, indistinguishable from a real disconnected state. The only error surface (`:253-264`) needs a *successful* response carrying `last_error`. Add query-error handling. ~4h. |
| Home — split-tunnel pre-sync | partial | `HomeScreen.tsx:51-84` | Swallows every error (`.catch(() => {})` ×4) and only ever **adds** rules — disabled or deleted entries are never removed server-side, so remote rules drift monotonically. Needs a replace-semantics sync. ~1d. |
| Servers — list | partial | `mobile/src/screens/ServersScreen.tsx:19-29`, `168-191` | Fetch/loading/error/empty/pull-refresh are all properly implemented (the best screen in the app). But it keys on `item.id` (`:171`) and the server's `ServerInfo` has **no `id` field** (`internal/api/client/server.go:83-90`), so every key is `undefined`. Switch to `name`. ~2h. |
| Servers — selection | **stub** | `ServersScreen.tsx:31-37`, `mobile/src/services/api.ts:266-267` | Calls `POST /servers/{id}/select`, which does not exist (§5) → 404, and `{id}` is `undefined`. On success it only sets local state (`:33-36`), never reconciled against the server. Repoint to `POST /api/v1/server/select` with `{"server": name}`. ~2h. |
| Stats — byte counters | works | `mobile/src/screens/StatsScreen.tsx:77-88` | Nothing; `bytes_sent`/`bytes_received` do exist on `vpn.VPNStats`. |
| Stats — "Connection Details" + "Network" | **stub** | `StatsScreen.tsx:112-115`, `137-140` | Reads `tunnel_type`, `encryption`, `port`, `mtu`, `local_ip`, `gateway`, `dns_servers`, `interface_name` — **none exist** on `vpn.VPNStats` (`internal/vpn/vpn.go:31-45`). Eight rows hardcoded to `N/A` forever. Requires extending the Go VPN status payload first. ~1w (server-side work). |
| Stats — session duration | **stub** | `StatsScreen.tsx:45-50`, `:97` | Computed from `connected_since`, which does not exist; `VPNStats` has `uptime` instead. Always `N/A`. ~1h once repointed to `uptime`. |
| Stats — "Server Status" | **stub** | `StatsScreen.tsx:126-129` | Reads `status.server_status`; the handler emits `server_connected` (bool) and `vpn_status` (`server.go:698-711`). Always "Unknown". ~1h. |
| Stats — error state | **absent** | `StatsScreen.tsx:62-71` handles only `isLoading` | Same false-negative problem as Home: an unreachable client renders a full page of zeros and `N/A`. ~2h. |
| Settings — load/error | works | `mobile/src/screens/SettingsScreen.tsx:190-209` | Nothing. |
| Settings — Auto-connect / Connection Alerts | **stub** (mislabelled) | `SettingsScreen.tsx:97-104`, `222-231`, `306-315` | These write `tray.auto_connect` / `tray.show_notifications` — the **desktop tray** config of the remote client. They have no phone-side effect: there is no auto-connect-on-launch code and no notification code anywhere (no `expo-notifications` in `mobile/package.json:15-27`), despite `app.json:21-24,43` requesting `remote-notification` background mode and `POST_NOTIFICATIONS`. Either implement locally or relabel. ~3d. |
| Settings — VPN Mode toggle | partial | `SettingsScreen.tsx:106-113` | Real `PUT /config` call, blocked by CSRF (§5). ~1h. |
| Settings — server address save | partial | `SettingsScreen.tsx:117-160` | Validates, persists, tests connectivity, and reports — genuinely the most finished flow. Two gaps: `setServerUrl` hardcodes `http://` (`api.ts:57`) so an HTTPS client is unreachable; and the `useEffect` at `:183-188` omits `serverAddress`/`apiConfig` from its deps and can overwrite what the user is typing. ~4h. |
| Settings — Kill Switch | **absent** | documented at `docs/src/content/docs/mobile-client.mdx:228-229`; no such control in `SettingsScreen.tsx` | Docs overstate. Remove from docs, or implement (needs a real on-device tunnel first — i.e. not feasible). |
| Settings — Clear Cached Data | partial | `SettingsScreen.tsx:162-175`, `api.ts:274` | Clears the *remote client's* debug entries only. Never touches local storage, although `clearStoredServerConfig` and `clearStoredSplitTunnelConfig` exist for exactly that (`mobile/src/services/storage.ts:83-90`, `155-162`) and are dead code. ~1h. |
| Settings — auth / API token | **absent** | `api.ts:8-11`, `99-101` define and send a `token`, but nothing ever sets one | No input field, no storage key (`storage.ts:5-9`), and `setAPIConfig` (`api.ts:45`) is never called from any screen. The app **cannot authenticate**, so it cannot manage any client with `api.token` set. See §5. ~1d. |
| Split Tunneling — mode / add / remove | partial | `mobile/src/screens/SplitTunnelingScreen.tsx:169-400` | All handlers are real: validation, confirm dialogs, local persistence, optimistic UI, per-mutation toasts, empty states. But every server call is CSRF-blocked, so in practice the screen is local-only. ~1h once CSRF is fixed. |
| Split Tunneling — server rules never displayed | **stub** | `SplitTunnelingScreen.tsx:57-61` destructures `{ isLoading, refetch }` and **discards `data`** | The screen fetches `/vpn/split/rules` and throws the response away; everything rendered comes from AsyncStorage. The user can never see what the client's rules actually are. Compounded by the response shape mismatch (§5). ~1d. |
| Split Tunneling — per-entry `enabled` toggle | partial | `SplitTunnelingScreen.tsx:234-242`, `305-313`, `392-400` | Toggling only writes local storage; the flag is never sent to the server, and is honoured solely by the best-effort pre-connect sync on Home. Semantics are undefined if the phone is not the last thing to connect. ~1d. |
| Persistence (`storage.ts`) | works | `mobile/src/services/storage.ts` | Server URL and split-tunnel config both round-trip correctly, with error handling. Genuinely finished. **Dead code:** `getStoredServerName`/`setStoredServerName`/`getStoredServerConfig` (`:43-78`) — the `SERVER_NAME` key is never written by any screen. Does not persist an API token (see above). |
| Native VPN bridge | **stub, and dead code** | `mobile/src/native/BifrostVpn.ts`, `mobile/src/native/index.ts` | See §4. |
| i18n | **absent** | every user-facing string is an inline English literal | The repo convention calls for English + German. No i18n library, no message catalogue. Retrofitting across 5 screens: ~3d. |
| Tests | **absent** | no `test` script (`package.json:6-14`), no test files | `README.md:22-24` documents this. ~1w for meaningful coverage. |

---

## 4. The native VPN path

The task framing was: if the insecure path can be reached, that is a security finding. **It cannot be
reached — but the reason is not the one the docs give, and the real reason is fragile.**

### Verifying `docs/src/content/docs/mobile-client.mdx:10-20`, clause by clause

| Doc claim | Verdict |
|---|---|
| "the app is a remote control, not an on-device tunnel" (`:10-12`) | **True.** Every screen talks only to `src/services/api.ts`; nothing imports `src/native/`. |
| `PacketTunnelProvider` / `BifrostVpnService` are "non-functional placeholders" (`:13-15`) | **True.** |
| "unbuildable skeletons" (`:15-16`) | **True, and understated** — see below. Neither file is in any build, and `expo prebuild` deletes both. |
| "would forward raw packets without a WireGuard/Noise handshake (i.e. cleartext, not secure)" (`:16-17`) | **True.** `BifrostVpnService.kt:177-246` reads raw IP packets from the TUN fd and `socket.send()`s them over a bare `DatagramSocket`. `PacketTunnelProvider.swift:172-195` does the same via `createUDPSession` + `writeDatagram`. No key exchange, no cipher, no authentication anywhere in either file. |
| "the native VPN path is gated off" (`:18`) | **True in effect, but not by the mechanism claimed.** The documented gate is `isNativeVpnAvailable()` (`BifrostVpn.ts:100-102`) / `selectVpnMode()` (`native/index.ts:33-35`). Neither is ever called: `grep` for `BifrostVpn`, `selectVpnMode`, `isNativeVpnAvailable`, `buildNativeVpnConfig` across `mobile/src/screens`, `mobile/src/components`, `mobile/App.tsx` returns **zero hits** outside `src/native/` itself. The entire bridge is dead code. What actually prevents the raw-UDP forwarder from running is that the native sources are not compiled at all. |

### `expo prebuild` deletes both native files

This is the concrete mechanism, and it is not documented anywhere:

```
$ npx expo prebuild --no-install --platform android
The android project is malformed, project files will be cleared and reinitialized.
- Clearing android
✔ Cleared android code

$ git status --short mobile/android/
 D mobile/android/app/src/main/java/com/bifrost/vpn/BifrostVpnService.kt

$ npx expo prebuild --no-install --platform ios
The ios project is malformed, project files will be cleared and reinitialized.
- Clearing ios

$ git status --short mobile/ios/
 D mobile/ios/BifrostVPN/PacketTunnelProvider.swift
```

Because `mobile/android/` and `mobile/ios/` are bare source fragments with no Gradle or Xcode
project, Expo classifies them as malformed and wipes them before writing the template. The iOS case
is worse than accidental: the app slug produces the target directory `ios/BifrostVPN/`, which is
*exactly* where `PacketTunnelProvider.swift` lives — the placeholder occupies the path the generated
main app target claims. `mobile/README.md:100-105` tells the reader to run `npx expo prebuild`, which
is the command that destroys the work.

So `mobile/README.md:47-54`'s warning is accurate, and the repo is *safer* than it documents. But the
safety is accidental. The plumbing fix an engineer would reach for first — copying the Kotlin file in
via a `withDangerousMod` step so it survives prebuild — would, on its own, make the raw-UDP forwarder
compile and be OS-reachable, because the manifest wiring is already in place and unconditional:

### The dangling `<service>` in the shipped APK

`mobile/plugins/withBifrostVpn.js:37-77` unconditionally injects the VPN service into the manifest.
After prebuild the class is gone but the declaration remains, and **this does not fail any build**:

```
$ grep -o "com.bifrost.vpn.BifrostVpnService" \
    mobile/android/app/build/intermediates/merged_manifest/debug/.../AndroidManifest.xml
com.bifrost.vpn.BifrostVpnService

$ find mobile/android/app/build/tmp/kotlin-classes -name "BifrostVpnService*"
(nothing — only MainActivity.class and MainApplication.class were compiled)

$ ./gradlew :app:lintVitalRelease --no-daemon
BUILD SUCCESSFUL in 1m
```

Consequences of shipping that APK:

1. The app advertises itself to Android as a VPN provider (the `android.net.VpnService`
   intent-filter, `withBifrostVpn.js:58-62`) and appears in Settings → VPN.
2. If a user selects it — or configures Always-on VPN — the OS tries to start a class that is not in
   the APK. Expect `ClassNotFoundException`. With Always-on + "Block connections without VPN", that
   is a device-wide connectivity failure the user cannot easily attribute.
3. `app.json:26-30` requests the iOS Network Extension entitlement for an extension that does not
   exist.

**None of this is a confidentiality breach today** — no tunnel is ever established, so no cleartext
is forwarded. It is a robustness and provisioning defect, plus a booby trap for the next engineer.

### Bugs in the placeholder code, for whoever picks it up

Beyond the missing crypto, neither placeholder would work even as an insecure forwarder:

- **Android, fatal:** `BifrostVpnService.kt:177-246` creates **two independent** `DatagramSocket`s —
  one in the read thread (`:178`), one in the tunnel thread (`:217`). Each binds its own ephemeral
  local port, so the server's replies arrive on the sending socket and are read by nobody. The
  receive path can never deliver a packet.
- **Android, fatal:** `VpnService.protect(socket)` is never called on either socket. Their traffic is
  routed back into the TUN they are servicing — an immediate routing loop.
- **Android, minor:** `bytesOut += length` (`:199`) and `bytesIn += packet.length` (`:233`) are
  non-atomic read-modify-write on `@Volatile` fields (`:56-57`) from two threads.
- **iOS, fatal:** `startConnection` (`:134-141`) requires `serverAddress` to be `"host:port"` and
  errors otherwise — but the bridge contract documents `serverAddress` as the host *without* the port
  (`BifrostVpn.ts:31`) and passes the port separately as `serverPort` (`:32`), which the Swift never
  reads. Every start attempt would fail with `invalidServerAddress`.
- **iOS, minor:** `pendingStartCompletion` is assigned (`:26`) and never read; `TunnelStatus`
  byte counters are hardcoded to `0` (`:94-95`).
- `withBifrostVpn.js:84-91`'s iOS mod is a self-declared no-op that returns its input unchanged.

---

## 5. Server-side API alignment

Cross-checked `mobile/src/services/api.ts` against the route table in
`internal/api/client/server.go:291-370` / `:400-510` and `docs/src/content/docs/api/client.mdx`.

### Blocker: every mutation is rejected

`internal/api/client/server.go:543-559` requires `X-Requested-With: XMLHttpRequest` on every
`POST`/`PUT`/`DELETE`/`PATCH`, and it is applied on both router variants
(`:261` for `Handler()`, `:296` for `HandlerWithUI()`). `docs/src/content/docs/api/authentication.mdx:62-65`
documents this as a hard requirement. The mobile `fetchJSON` sets only `Content-Type`
(`mobile/src/services/api.ts:95-101`) and never that header.

Every write the app makes therefore returns `403 CSRF validation failed`: VPN enable/disable, server
select, config update, cache clear, and all eight split-tunnel mutations. **The app is read-only
against any current client build.** This is a one-line fix and the single highest-value change in the
report.

### Blocker: no authentication support

`internal/api/client/server.go:510-541` guards the whole API with a bearer token when `api.token` is
configured. The mobile client has the plumbing (`api.ts:8-11`, `99-101`) but nothing sets a token:
no UI field, no storage key, and `setAPIConfig` is never called outside `api.ts`. The app can only
talk to an **unauthenticated** client, over **plaintext HTTP** (`api.ts:57` hardcodes the `http://`
scheme). Documented nowhere.

### Endpoint that does not exist

| Mobile call | Reality |
|---|---|
| `POST /servers/{id}/select` (`api.ts:266-267`) | **404.** The route is `POST /api/v1/server/select` (`server.go:303`, `:410`) taking `{"server": "<name>"}` in the body (`server.go:1843-1852`). `docs/.../api/client.mdx:172-180` documents it correctly; `docs/.../mobile-client.mdx:281` documents the app's wrong form, so the app matches the wrong doc. |

### Endpoints that exist and match

`GET /health`, `GET /status`, `GET /servers`, `GET /vpn/status`, `POST /vpn/enable`,
`POST /vpn/disable`, `GET /vpn/split/rules`, `PUT /vpn/split/mode`, `POST|DELETE /vpn/split/apps`,
`POST|DELETE /vpn/split/domains`, `POST|DELETE /vpn/split/ips`, `GET|PUT /config`,
`POST /config/reload`, `DELETE /debug/entries` — all present (`server.go:297-347`). Paths are right;
methods are right; the payloads are where it falls apart.

### Response-shape mismatches (why the UI is full of `N/A`)

| Mobile type | Server truth | Effect |
|---|---|---|
| `ServerInfo.id: string` (`api.ts:151`) | `ServerInfo` has **no** `id` — only name/address/protocol/is_default/latency_ms/status (`server.go:83-90`), matching `docs/.../api/client.mdx:140-160` | Every list key and select argument is `undefined` (`ServersScreen.tsx:171`, `:53`). |
| `StatusResponse.server_status` (`api.ts:128`) | Handler emits `server_connected` (bool) and `vpn_status` (`server.go:698-711`) | "Server Status" is permanently "Unknown" on Stats (`StatsScreen.tsx:126-129`) and Settings (`SettingsScreen.tsx:344-352`). |
| `VPNStatus.{enabled, tunnel_type, interface_name, local_ip, gateway, dns_servers, mtu, port, encryption, connected_since}` (`api.ts:133-148`) | `GET /vpn/status` returns `vpn.VPNStats` (`server.go:1006-1013`), whose fields are status/uptime/bytes_*/packets_*/active_connections/tunneled/bypassed/dns_*/last_error (`internal/vpn/vpn.go:31-45`). **None** of the ten exist. | Nine Stats rows plus session duration are hardcoded `N/A` forever. Only `status`, `bytes_sent`, `bytes_received`, `last_error` actually resolve. |
| `SplitTunnelConfig` lowercase keys (`api.ts:172-177`) | `internal/vpn/SplitTunnelConfig` and `AppRule` carry **only `yaml:` tags** (`internal/vpn/splittunnel.go:48-72`), so `encoding/json` emits `Mode`/`Apps`/`Domains`/`IPs`/`AlwaysBypass` and `Name`/`Path` | The response is untypeable by the app. Masked only because `SplitTunnelingScreen.tsx:57` discards `data`. Also breaks the web dashboard and contradicts `docs/.../api/client.mdx:586-600`. |

The last two rows are **server-side or documentation defects**, not mobile ones —
`docs/.../api/client.mdx:490-510` documents a rich VPN status object
(`tunnel_type`, `interface_name`, `ip`, `dns`, `mtu`, `port`, `encryption`, `connected_at`) that the
Go code does not produce. Notably the mobile types match **neither** the code nor the docs (mobile
says `local_ip`/`dns_servers`/`connected_since`; the docs say `ip`/`dns`/`connected_at`) — evidence
the mobile types were written from a third source, or from the ASCII mockup, and never validated.

### Client endpoints the app should arguably use and does not

- `GET`/`POST /api/v1/settings` (`server.go:304-305`) — the purpose-built quick-settings surface
  (`QuickSettings`: `auto_connect`, `show_notifications`, `vpn_enabled`, `current_server`), which is
  exactly what the Settings screen wants. The app instead pokes the raw `tray` config through
  `PUT /config`.
- `GET /api/v1/version` (`server.go:298`) — the app derives version from `/status` instead.
- `GET /api/v1/vpn/connections` (`server.go:336`) — real per-connection data for the Stats screen,
  which currently has nothing real to show beyond byte counters.
- `GET /api/v1/logs`, `/logs/stream`, `/cache/*`, `/mesh/*`, `/routes/*`,
  `/config/{validate,defaults,export,import}`, `/debug/errors` — all unused. Reasonable scoping for a
  phone, not defects.

Dead methods on the mobile side: `api.connect`, `api.disconnect`, `api.reloadConfig` (`api.ts:270-271`,
`:258`) are defined and never called from any screen.

---

## 6. Honestly-documented limitations — do not re-audit

These are all accurate as written. Credit where due: this documentation is unusually candid, and
every claim I checked in this list held up.

1. **Remote control, not an on-device tunnel** — `docs/.../mobile-client.mdx:10-12`,
   `mobile/README.md:3-6`. True.
2. **Native files are non-functional placeholders forwarding cleartext raw UDP** —
   `docs/.../mobile-client.mdx:13-17`, `mobile/README.md:49-54`,
   `mobile/src/native/BifrostVpn.ts:14-18`, `mobile/plugins/withBifrostVpn.js:20-23`. True, and
   understated (§4).
3. **The native path is not to be relied on for confidentiality** —
   `docs/.../mobile-client.mdx:18`. True.
4. **iOS Network Extension target cannot be added by a config plugin; deferred** —
   `mobile/plugins/withBifrostVpn.js:11-18`, `mobile/README.md:86-93`. True; the plugin's iOS mod is
   an explicit no-op.
5. **A real WireGuard data path is required before enabling anything native** —
   `mobile/README.md:83-88`, `109-114`. True.
6. **No test runner; typecheck + lint are the only gates** — `mobile/README.md:22-24`. True (CI runs
   typecheck + doctor, not lint — `ci.yml:239-245`).
7. **`extra.eas.projectId` is a placeholder and must be set via `eas init`** —
   `mobile/README.md:106`. True (`app.json:48`).
8. **Native module `BifrostVpn` is unimplemented; the TS interface is the spec** —
   `mobile/README.md:94-99`, `BifrostVpn.ts:64-84`. True.

### Where the docs overstate reality

- `docs/.../mobile-client.mdx:170-212` — the Stats mockup shows Protocol, Encryption, Port, MTU,
  Local IP, Gateway, DNS and Interface populated, and the note at `:209-212` asserts these are
  "reported over the REST API". **They are not reported by any endpoint** (`internal/vpn/vpn.go:31-45`).
  The note defuses the wrong objection: it explains that the fields describe the remote client rather
  than the phone, while the real problem is that they are always empty.
- `docs/.../mobile-client.mdx:228-229` — "Kill Switch" toggle. Not implemented.
- `docs/.../mobile-client.mdx:231-233` — shows Split Tunneling as a toggle *plus* a Configure button;
  the code has only the button (`SettingsScreen.tsx:251-264`).
- `docs/.../mobile-client.mdx:272-283` — the endpoint table lists
  `POST /api/v1/servers/{id}/select`, which does not exist.
- `docs/.../mobile-client.mdx:345-357` — "Screen Reader: Full support", "Accessibility Labels: All
  interactive elements". Mostly earned (Home, Servers, Stats and Settings are thoroughly labelled),
  but the Split Tunneling switches have no labels (`SplitTunnelingScreen.tsx:576-582`, `:643-649`,
  `:710-716`) and the toast has no a11y props at all, contradicting `:448`.
- `docs/.../mobile-client.mdx:225-227,243-245` — "Auto-connect: connect on app launch" and
  "Connection Alerts: notify on connect/disconnect" describe phone behaviour the app does not have.

### Where the docs understate reality

- Nothing says the app **cannot authenticate** — so it cannot manage a secured client at all.
- Nothing says **every write currently fails** the API's CSRF check.
- Nothing says `npx expo prebuild` — the command `mobile/README.md:100-105` instructs the reader to
  run — **deletes both native placeholder files**.
- Nothing says the shipped APK declares a VPN service class that is not in the binary.

---

## 7. Prioritised work to finish it

Ordered by value per unit of effort. Items 1-4 are what stand between "renders nicely" and "actually
works"; they are also cheap.

| # | Work | Size |
|---|---|---|
| 1 | Send `X-Requested-With: XMLHttpRequest` from `fetchJSON` (`api.ts:95-101`). Unblocks every mutation in the app. | 1 h |
| 2 | Fix server selection: call `POST /api/v1/server/select` with `{"server": name}`; drop `ServerInfo.id` and key the list on `name` (`api.ts:151,266`, `ServersScreen.tsx:53,171`). | 3 h |
| 3 | Realign `StatusResponse` and `VPNStatus` with what the handlers emit — `server_connected`/`vpn_status`, `uptime` instead of `connected_since` — and delete the eight rows the API cannot supply, or mark them explicitly unavailable rather than `N/A`. | 1 d |
| 4 | Add API-token support: a Settings field, a `storage.ts` key, `setAPIConfig` on load, and an HTTPS/scheme choice for the base URL (`api.ts:57`). Without this the app cannot manage a secured client. | 1-2 d |
| 5 | Add query error/offline states to Home and Stats so an unreachable client is distinguishable from a disconnected VPN (`HomeScreen.tsx:32-48`, `StatsScreen.tsx:62-71`). | 1 d |
| 6 | Make the native scaffold honest: either delete `mobile/ios/`, `mobile/android/`, `src/native/` and the manifest injection in `withBifrostVpn.js:37-77` outright, or make the `<service>` injection conditional on the native module actually being present. As committed, the APK declares a class it does not contain. | 4 h (delete) / 1 d (gate) |
| 7 | Add `NSLocalNetworkUsageDescription` to `app.json` `ios.infoPlist`, and set a real `extra.eas.projectId` (`app.json:46-50`). Prerequisites for any iOS build reaching a LAN client. | 2 h |
| 8 | Make the Split Tunneling screen show server truth: add `json:` tags to `internal/vpn.SplitTunnelConfig`/`AppRule` (`splittunnel.go:48-72` — also fixes the web dashboard and the API docs), then stop discarding `data` at `SplitTunnelingScreen.tsx:57` and reconcile local vs remote. | 2-3 d |
| 9 | Replace the additive pre-connect sync (`HomeScreen.tsx:51-84`) with replace semantics, and surface sync failures instead of swallowing them. | 1-2 d |
| 10 | Either implement Auto-connect and Connection Alerts on the phone (`expo-notifications`, launch hook) or relabel them as remote-client settings; likewise drop the unused `remote-notification` background mode and `POST_NOTIFICATIONS`. | 3 d |
| 11 | Correct the docs: the Stats field claims, Kill Switch, the endpoint table, and the accessibility claims (§6). | 4 h |
| 12 | Retrofit i18n (English + German) across all five screens. | 3 d |
| 13 | Stand up a test runner (`jest-expo` + React Native Testing Library) and cover `api.ts`, `storage.ts`, `utils/status.ts` and the screen state machines. Add `npm run lint` to the mobile CI job (`ci.yml:239-245`). | 1 w |
| 14 | Real app icons and a distinct splash asset (`mobile/assets/` — all three files are byte-identical). | 4 h |
| 15 | On-device WireGuard (`gomobile bind` of the existing Go backend, or WireGuardKit + wireguard-android). Only after 1-7. Needs a paid Apple account and device testing. | 4-8 w |

### What I did not verify

- No iOS build or device run: no `xcodebuild` archive, no signing attempt, no on-device check of the
  local-network permission behaviour. The iOS statements in §2 are inferences from the generated
  project, flagged as such.
- No end-to-end run against a live Bifrost client. The API findings come from reading the Go handlers
  and struct tags, not from observed HTTP traffic — but the CSRF middleware, the missing `id` field
  and the absent `VPNStats` fields are all plain in the source and hard to read another way.
- I did not audit the app under Expo Go (only prebuild + Gradle).
