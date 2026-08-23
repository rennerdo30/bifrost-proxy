# Web dashboard audit — unfinished code and missing implementations

Scope: `web/server/src` and `web/client/src`. Base `ba1e826` (master).
Audit only — no code was changed.

**Method.** Both dashboards were built (`npm ci && npm run build`, both clean; lint at
baseline — server 2 `Toast.tsx` warnings, client 3) and driven in headless Chrome via
puppeteer-core against real `bifrost-server` and `bifrost-client` binaries started from
`configs/server-config.example.yaml` and `configs/client-config.example.yaml`. Every
finding below is tagged **[live]** (observed in the browser or against the running
binary) or **[read]** (traced through source only). Classification: **(a)** genuinely
unfinished, **(b)** deliberately scoped out, **(c)** fine / not a defect.

---

## 1. Verdict

**Server dashboard — feature-complete in surface area, but three of its nine pages are
broken in the configuration they were written for.** Config, Clients and Mesh are
genuinely good: real loading/empty/error states, a compile-time section-parity guard, an
auth-plugin availability system that honestly greys out providers the binary cannot use.
Config coverage is now near-total — 17 of 18 top-level config keys have a dedicated form,
and all eight items from #277/#281 are genuinely reachable and round-trip. But: the
**Request Log page crashes to the ErrorBoundary the moment request logging is enabled**
(`RequestLogStats` type drift, §5), the **Cache page silently 404-loops with the shipped
example config** while leaving its destructive buttons live (§2), the **Config Generator
emits a client config the client rejects outright** (§2), and the **skip link blanks the
whole app** (§7). The blocking gaps are all of the same kind: the UI declares a contract
the Go side never agreed to, and no error state catches the mismatch — errors render as
empty states across five of nine pages.

**Client dashboard — less developed, and the two gaps that matter are hard failures, not
missing features.** Traffic, Routes, Logs and the disabled-state rendering for VPN/Mesh/Cache
are honest and well built (better empty states than the server dashboard, in fact).
But **expanding Settings → Mesh Networking destroys the entire Settings page** (a
`TypeError` from nanosecond durations, §2), and the **whole `vpn` config subtree and
`/vpn/split/rules` are served in PascalCase**, so every VPN control is write-only —
it displays fabricated defaults and never shows what is actually configured (§5). The
**Cache tab is confirmed a permanent dead surface** (§2): there is no client-side cache
anywhere in the codebase, not merely an unwired manager. Blocking gaps: the Mesh settings
crash, the VPN read path, and the absence of any error state on VPN/Mesh/Logs queries.

Neither dashboard has an i18n mechanism; all copy is hardcoded English. Consistent
across the repo, so noted once here rather than per-finding.

---

## 2. Dead surfaces

| Surface | Why it cannot work | Evidence | Hide or implement? |
|---|---|---|---|
| **Server: Config Generator page** (whole page) | Emits a schema that does not exist. `local.http_listen`/`socks5_listen` (real: `proxy.http.listen`), `routes[].pattern` (real: `routes[].domains []string`), `action: proxy` (real: `server`\|`direct`), top-level `auth` (real: `server.username/password`). The untouched default output fails validation. **[live]** `bifrost-client validate` on the copy-pasted output → `configuration invalid: route must have at least one domain pattern` | `web/server/src/pages/ConfigGenerator.tsx:11-18`; `web/server/src/components/ConfigGenerator/GeneratorForm.tsx:32-39,52-74`; vs `internal/config/client.go:37-38,67,185-193`; `internal/router/client.go:15-17` | **Implement** — rewrite the emitter against `ClientConfig`. Currently it hands operators a file that cannot start. (a) |
| **Server: Cache page** when `cache:` is absent/disabled — i.e. with the shipped example config | `cacheAPI` is nil so `/api/v1/cache/*` is never mounted; all four queries 404 forever. The "Cache is disabled" banner is gated on `stats && !stats.enabled`, and `stats` is `undefined` on error, so **the banner is unreachable in exactly the deployment it was written for**, and Purge Domain / Clear All / Add Rule stay enabled. **[live]** 4× `HTTP 404` on `/cache/stats`, `/cache/entries`, `/cache/rules`, `/cache/presets`; page renders five empty skeleton rows permanently, no error, no banner | `internal/api/server/server.go:352-354` (conditional mount); `internal/config/server.go` has no `cache:` in `configs/server-config.example.yaml`; `web/server/src/pages/Cache.tsx:38-61` (no `error`/`isError` on any of 4 queries), `:158` (`cacheDisabled` gate), `:196-235,422-437` (live buttons) | **Implement** the error branch — the disabled banner already exists, it just needs to fire on 404 too. (a) |
| **Server: Mesh peer detail / topology / "Connected" counter** | The coordinator only ever sends `mesh.PeerInfo` = `{id, name, public_key, virtual_ip, endpoints, metadata}`. No endpoint anywhere sends `status`, `connection_type`, `latency`, `last_seen`, `joined_at`, `bytes_*`. The UI re-declares them locally as `ExtendedPeer` and renders them | `internal/mesh/discovery.go:52-59`; `internal/api/server/mesh.go:345-356`; vs `web/server/src/components/Mesh/MeshPeerDetails.tsx:149-190`, `MeshPeerList.tsx:133-142`, `MeshTopologyGraph.tsx:23-39,214`, `web/server/src/pages/Mesh.tsx:107-110,177-182` | **Hide** the Connection/Throughput cards and the Connected counter until the coordinator sends peer telemetry. Verified **[live]**: "Connected — `-`". (a) |
| **Client: Cache tab** (whole tab) | **Confirmed and stronger than previously reported: there is no client-side cache at all.** `internal/config/client.go` has no `Cache` field; `grep -rni cache internal/client/` → zero hits. The one non-test construction of the client API never passes `CacheManager`, and there is no setter or functional-option path, so `a.cacheManager` is nil in every reachable path. **[live]** GET `/cache/stats` → `200 {"enabled":false,"storage_type":"none",…}`, GET `/cache/entries` → `200 {"entries":[],…}`, POST `/cache/clear` → `503 cache not configured`, DELETE `/cache/entries/{k}` → `503` | `internal/api/client/server.go:60-66,148,188,217` (declared), `internal/client/client.go:213-243` (the only `apiclient.New`, no `CacheManager`), `:1956-1978` (nil-safe 200s), `:2053-2076` (503s); UI `web/client/src/pages/Cache.tsx`, `components/Cache/CacheStats.tsx:23-108`, `components/Cache/CacheEntries.tsx`; tab at `components/Layout/TabNav.tsx:6`, route `App.tsx:24-28` | **Hide.** ~590 lines of UI + 4 API methods + 4 handlers permanently inert. Because both GETs return 200, the page renders full management chrome with plausible zeros rather than failing — the worst of the three options. (a) |
| **Client: Settings → Mesh Networking section** | Mesh durations are `time.Duration` with plain json tags, so they arrive as integers (`heartbeat_interval: 30000000000`). `FormDuration.parseDuration` calls `duration.match(...)` on them → `TypeError`. **[live]** clicking the section throws `TypeError: e.match is not a function` and replaces the **entire Settings page** with "Error loading Settings — This section encountered an error"; every other settings section becomes unreachable until reload | `internal/mesh/config.go:68,71,83,126`; `web/client/src/components/form/FormDuration.tsx:22`; `web/client/src/components/Settings/MeshSection.tsx:82,87,141` | **Implement** — a `Duration` marshaller on the Go side (as `internal/config` already has) plus a numeric guard in `parseDuration`. Note the existing nanosecond fallback at `FormDuration.tsx:27-34` is dead code: it only runs for *strings* that failed the regex, and ns values arrive as numbers. (a) |
| **Server: `mesh` config section** | A first-class Go config section (`/config/meta` lists it) with no TS field and no form. Reachable only via raw YAML | `internal/config/server.go:36`; `internal/api/server/config_handlers.go:35,113,346`; vs `web/server/src/api/types.ts:651-669`, `components/Config/sectionMeta.ts:25-43` | **Implement.** See §8 for why the compile-time guard missed it. (a) |
| Server: Mesh tab when `mesh.enabled: false` | Routes unmounted; the tab stays, the list shows its normal empty state, only Create Network errors | `internal/api/server/server.go:356-358`; `components/Layout/TabNav.tsx:55-63` | Milder version of the Cache problem — add a disabled affordance. (a, minor) |
| Client: VPN / Mesh tabs when disabled in config | Manager is nil; handlers degrade to `{"status":"disabled"}` / `[]`, enable → 400. `vpn.enabled` is restart-required. **[live]** both pages render a correct, explanatory disabled state | `internal/client/client.go:138-147`; `internal/client/mesh.go:34-37`; `web/client/src/pages/VPN.tsx:225-247`, `pages/Mesh.tsx:176-186` | **(c) fine** — legitimate config/restart requirement, honestly surfaced. |
| Server: auth providers marked unavailable/unimplemented | Deliberate: `/api/v1/auth/plugins` reports build capability; the UI greys out and explains | `internal/api/server/auth_plugins.go:35-62,140-144`; `components/Config/sections/AuthSection.tsx:118-163,399,455` | **(c) fine** — the reference example of an honest dead end in this repo. |

---

## 3. Controls with no effect

| Control | Effect | Evidence |
|---|---|---|
| **Server: Route "Move up / Move down"** | Reorders the `routes` array but never touches `route.priority`. The list is rendered sorted by priority, and `internal/router` also sorts by priority — so the button marks the section **Modified** and changes nothing the user or the server can observe. (a) | `web/server/src/components/Config/sections/RoutesSection.tsx:41-49,52,106-127`; `internal/router/router.go:145` |
| **Server: Cache preset toggle-off** | `handleDisablePreset` sets `rule.Enabled = false` but keeps the rule; `handleListPresets` computes enabled-ness as `if rule.Preset != ""` and never reads `rule.Enabled`. The refetch re-renders the preset as **Active**. Toast says "disabled", UI says enabled. (a) | `internal/api/server/cache_handlers.go:475-479,557`; `web/server/src/components/Cache/CachePresetsList.tsx:67-79`; `pages/Cache.tsx:142-156` |
| **Server: Add Backend — Priority field** | `BackendConfig.Priority` is read nowhere in the codebase. Inert in the runtime dialog *and* in the persisted config form. (a) | `web/server/src/components/Backends/AddBackendDialog.tsx:237-245`; `internal/config/server.go:100` |
| **Server: Add Backend — Weight and Health Check sub-form** | `handleAddBackend` reads only `Name`/`Type`/`Config`/`Enabled`. `Weight` is consumed only by `seedRouteWeights()` at config load; `HealthCheck` only by startup registration. Both inert for runtime adds. (a) | `internal/api/server/server.go:654-724`; `internal/config/server.go:596,643-649`; `internal/server/server.go:323`; UI `AddBackendDialog.tsx:247-255,278-285` |
| **Server: Edit a runtime-added backend → data loss** | Edit = `removeBackend` + `addBackend`, and the prefill falls back to `config: {}` whenever `backendConfigs` (sourced from the config *file*) lacks the name — which is always true for a backend added through this same dialog, or whenever that fetch silently failed. Saving replaces a working WireGuard/OpenVPN backend with an empty-config one. No warning. (a) | `web/server/src/pages/Backends.tsx:28-38` (`catch { /* silently fail */ }`), `:49-58`, `:75-93` |
| **Server: Test Backend default target** | Defaults to `https://www.google.com`, but the handler passes it to `b.Dial(ctx,"tcp",target)`, which needs `host:port` (its own fallback is `google.com:443`). An untouched dialog always reports `Test Failed / missing port in address`. (a) | `web/server/src/components/Backends/TestBackendDialog.tsx:13,52,57`; `internal/api/server/server.go:779-803` |
| **Server: `api.allowed_origins` textarea cannot take a newline** | `value` is `.join('\n')`; `onChange` splits, trims and `filter(len>0)`, so the trailing `\n` from pressing Enter is discarded and the caret cannot leave line 1. Multi-entry input only works by pasting. (a) | `web/server/src/components/Config/sections/APISection.tsx:129-145` |
| **Server: Save stays enabled with invalid raw YAML** | On a parse failure the editor keeps the last successfully-parsed config and sets `rawError`; the Save button never checks `rawError`. Clicking Save writes the last valid parse while the textarea shows the operator's broken, intended edit. (a) | `web/server/src/components/Config/ConfigEditor.tsx:388-399,673-676` |
| **Server: `handleValidate` reports failures as valid** | `catch { return { valid: true } }`. A failed `/config/validate` call is reported as a valid config and the save proceeds. (a) | `web/server/src/pages/Config.tsx:208-210`; compounded by `ConfigEditor.tsx:310-312` |
| **Server: `auth.negotiate` is dropped by any provider-list edit** | `ConfigEditor.tsx:531` is `onChange={(auth) => updateConfig({ auth })}` — a whole-object replace. Five of the six `onChange` sites in `AuthSection` pass only `{ providers }`; TS `AuthConfig` has exactly two fields, so `negotiate` is definitively dropped from the payload. `handleSaveConfig` decodes a full `ServerConfig` and writes `negotiate: null`. Because the Kerberos provider must exist *before* it can be picked in the Negotiate dropdown, the natural setup order hits this. (a) | `web/server/src/components/Config/sections/AuthSection.tsx:210,219,229,238,251` (bare `{providers}`) vs `:497` (`{...config, negotiate}`); `components/Config/ConfigEditor.tsx:531`; `web/server/src/api/types.ts:465-468`; `internal/api/server/config_handlers.go:152-163`. **[read]** — my browser repro of the full save round-trip did not complete (the sticky save bar was outside the region I scripted), so this one is traced, not observed |
| **Server: Mesh topology canvas click** | `canvas.width = cssWidth*dpr` **and** `ctx.scale(dpr,dpr)`; node positions are computed from `canvas.width` (device px) while hit-testing uses CSS px. On any retina display nodes land off-screen and `onSelectPeer` never fires. Correct only at dpr=1. (a) | `web/server/src/components/Mesh/MeshTopologyGraph.tsx:59-63,141-143,265-288,291-310` |
| **Server: Setup Guide ports are hardcoded** | `httpPort='8080'`, `socks5Port='1080'`, used in ~30 copyable commands. The server's actual defaults are 7080/7180 — **[live]** the running server logged `HTTP proxy listening :7080` / `SOCKS5 :7180` while the guide told me to configure 8080/1080. The page never fetches `/api/v1/config`. (a) | `web/server/src/components/SetupGuide/SetupGuide.tsx:52-53` and 30 uses at `:119-230`; `configs/server-config.example.yaml` |
| **Server: Setup Guide Copy buttons** | `handleCopy` has no catch, and `navigator.clipboard` is undefined on a non-secure origin — which is how this dashboard is normally reached (plain HTTP on a LAN IP). Every Copy button in the guide silently does nothing. `YamlPreview.tsx:18-27` handles the same case correctly. Also `opacity-0 group-hover:opacity-100` with no `group-focus-within`, so it is invisible on keyboard focus and unreachable on touch. (a) | `web/server/src/components/SetupGuide/SetupGuide.tsx:13-17,24-29` |
| **Server: "Configuration" link on Backends leaves the SPA** | `<a href="/config">` under a `HashRouter`. **[live]** clicking it → `http://127.0.0.1:7092/config#/dashboard`: lands on **Dashboard, not Config**; `BASE_PATH` becomes `/config`, so every API call goes to `/config/api/v1/…`, which returns **`200 text/html`** (verified by curl) because `spaOrAPINotFound` only guards a leading `/api/`. The dashboard silently degrades — stats cards vanish, the WebSocket label flips to "Polling", and **no request logs an error**, which is precisely the failure mode the comment at `internal/api/server/server.go:275-284` was written to prevent. (a) | `web/server/src/pages/Backends.tsx:159`; `web/server/src/App.tsx:17`; `internal/api/server/server.go:282-293` |
| Server: `isDeleting` label unreachable | `ConfirmModal` calls `onConfirm()` then `onClose()` synchronously, so the modal unmounts before `isDeleting` is ever true. (a, minor) | `web/server/src/pages/Backends.tsx:22,61,70,230`; `components/Config/ConfirmModal.tsx:78-81` |
| Server: Clear-request-log has no confirm and no catch | Destructive action, no `ConfirmModal`, no `try`/`catch` — a failure is an unhandled rejection with no feedback. (a) | `web/server/src/pages/RequestLog.tsx:25-28` |
| Server: generator auth toggle stale closure | `setUseAuth()` then `updateConfig()`, which reads `useAuth` from the pre-toggle render closure. Ticking "Enable" does not add the `auth:` block until the next keystroke. (a, minor) | `web/server/src/components/ConfigGenerator/GeneratorForm.tsx:67,179-186` |
| **Client: whole VPN Settings section is write-only** | `internal/vpn/config.go` and `splittunnel.go` carry `yaml:` tags and **no `json:` tags**. **[live]** `GET /api/v1/config` returns `"vpn":{"Enabled":…,"TUN":…,"SplitTunnel":…,"DNS":…}` while the form reads `enabled`/`tun`/`split_tunnel`/`dns`. Every control shows its hardcoded fallback regardless of the file. Writes still land (yaml keys are snake_case and `UpdateNode` matches on those), so values persist but never display — the form appears to reset itself. (a) | `internal/vpn/config.go:9-41`, `internal/vpn/tun.go:17-21`, `internal/vpn/splittunnel.go:49-73`; `internal/api/client/server.go:1266-1274`; `web/client/src/components/Settings/VPNSection.tsx:18-19,33,43-134` |
| **Client: VPN page split-tunnel panel** | Same root cause. **[live]** `GET /vpn/split/rules` → `{"Mode":"","Apps":null,"Domains":null,"IPs":null,"AlwaysBypass":null}`. So `splitRules?.mode` is `undefined`: **neither mode button ever highlights, and the hint text always shows the "include" wording** — I observed "Only listed items will use the VPN" displayed while the config says `mode: exclude`. Adding a domain returns 201 + a success toast and the entry never appears. (a) | `internal/api/client/server.go:1052-1058`; `web/client/src/pages/VPN.tsx:301,310,321,348,391,403,458` |
| **Client: VPN "Details" grid shows fabricated values** | `vpn.VPNStats` has no `tunnel_type`/`interface_name`/`local_ip`/`gateway`. **[live]** `/vpn/status` → `{status,uptime,bytes_*,packets_*,active_connections,…}` only. The grid therefore always prints the literals `TUN` and `bifrost0` and two `-` — invented data presented as live status. `status === 'running'` at `:140` is also dead (no such status exists). (a) | `internal/vpn/vpn.go:23-45`; `web/client/src/api/client.ts:121-133`; `web/client/src/pages/VPN.tsx:140,180-197` |
| **Client: mesh `keepalive_interval` input** | UI reads/writes `mesh.connection.keepalive_interval`; the Go tag is `keep_alive_interval`. **[live]** confirmed in the served config. Broken both directions — never read back, and the write inserts a bogus key that nothing consumes. (a) | `internal/mesh/config.go:129`; `web/client/src/api/client.ts:341`; `components/Settings/MeshSection.tsx:135-136` |
| **Client: FormDuration mis-renders any composite Go duration** | `parseDuration` accepts only `^(\d+)(ms\|s\|m\|h)$`, but `config.Duration.MarshalJSON` emits `time.Duration.String()`. **[live]** the server sends `proxy.http.idle_timeout: "1m0s"` (60s) and the form displays **`0` `sec`**. Editing then saves the wrong value. Affects any duration ≥ 1 minute anywhere in client Settings. (a) | `web/client/src/components/form/FormDuration.tsx:22`; `internal/config/server.go:469-471`; `internal/config/client.go:100` |
| **Client: Edit-Route modal always opens blank** | `useState(() => {…})` written where `useEffect` was intended. The modal is mounted unconditionally, so its initialisers run once with `route === null`; the setter calls inside the lazy initialiser never execute. Clicking Edit on any route shows an empty form; submitting says "Route name is required". (a) | `web/client/src/components/Routes/RouteManager.tsx:167-181,671` |
| **Client: `/connect`, `/disconnect`, `/server/select` acknowledge success and do nothing** | `Connector`/`Disconnector`/`ServersGetter`/`ServerSelector` are never wired in the only `apiclient.New` call. Multi-server is unfinished at both ends (`ClientConfig.Servers` exists, no UI, not in the TS model). (a) | `internal/client/client.go:213-243`; `internal/api/client/server.go:1799-1827,1857-1861`; `internal/config/client.go:17,55-62` |
| **Client: settings persisted but never applied in-memory → visible revert** | `Client.updateConfig` hot-applies a whitelist but writes the whole update map to YAML; Settings then invalidates and re-reads the in-memory config, so non-whitelisted fields visibly snap back while the file holds the new value. Affects `server.health_check.*`, `proxy.http.write_timeout`/`idle_timeout`, `proxy.socks5.read_timeout`/`max_connections`, `logging.time_format`, `auto_update.check_interval`, all nested `mesh.*`. (a) | `internal/client/client.go:699-954,758-799,816-826,867-874,918-951`; `web/client/src/pages/Settings.tsx:45` |
| **Client: settings persisted but consumed by nobody** | `debug.filter_domains` — `internal/debug.Config` has only `MaxEntries/CaptureBody/MaxBodySize`. `api.enable_request_log`/`request_log_size`/`websocket_max_clients` — read only by the *server*. `web_ui.enabled`/`web_ui.listen` — the client never starts a separate listener; used only as a fallback for the tray's "Open Web UI" URL. **[live]** confirmed: the client logged `API/Web UI server listening 127.0.0.1:7383` (= `api.listen`) despite `web_ui.listen: 127.0.0.1:7382`. (a) | `internal/debug/logger.go:13-18`; `internal/client/client.go:130-134,245-250,1085-1092`; UI `DebugSection.tsx:50-56`, `WebUISection.tsx:26-79` |
| **Server: same `web_ui` problem** | On the server side `WebUI.Enabled`/`.Listen` are read by **nothing** outside the config API itself — the dashboard is always served from `api.listen` and `r.Get("/", staticHandler)` is unconditional. **[live]** `web_ui.listen: :7081` with `enabled: true` → served on `:7082`, nothing on `:7081`. So the entire Web UI config section is inert. (a) | `grep -rn WebUI internal cmd --include='*.go'` → only `internal/config`, `internal/api/server/config_handlers.go`, and `internal/client`; `internal/api/server/server.go:264` |
| **Client: `AutoUpdateSection` warning banner is false** | Says "not yet performed by the client daemon … no runtime effect". The daemon does run the checker. (a) | `web/client/src/components/Settings/AutoUpdateSection.tsx:21-27` vs `internal/client/client.go:316-320,334-360` |
| **Client: "Reset to defaults" is destructive and incomplete** | PUTs the whole `DefaultClientConfig`. `Routes` is nil in the defaults → `"routes": null` is written straight to the YAML, **wiping every route from the file**, and bypassing the add/remove path so the live router is not reloaded. The PascalCase `vpn` sub-map is appended as dead keys, so Reset does not reset VPN and pollutes the file. (a) | `web/client/src/pages/Settings.tsx:94-102`; `internal/config/node.go:98-115`; `internal/client/client.go:707-755` |
| **Client: Settings never validates before saving** | `api.validateConfig` (`/config/validate`, which returns restart warnings) exists and is called from nowhere. (a) | `web/client/src/api/client.ts:438` |
| Client: broken in-app links | Four "go to Settings" links use path hrefs under a `HashRouter` — same class as the server's Backends link. (a, trivial) | `web/client/src/pages/VPN.tsx:227,244`; `pages/Mesh.tsx:176,186` |
| Client: cache list double-filters; `offset`/`domain` params unused | Filters with the debounced value, then again with the undebounced one; the counter counts the doubly-filtered set. `getCacheEntries` is called with `limit` only, so "pagination" re-fetches an ever-growing limit. Moot while the cache is dead. (a, minor) | `web/client/src/pages/Cache.tsx:38,70-83`; `components/Cache/CacheEntries.tsx:74-81,110` |
| Server: `handleUpdateRule` reads only `enabled` | Matches exactly what `api.updateCacheRule` sends. **(c) not a defect** — checked because it looked like one. | `internal/api/server/cache_handlers.go:391-435`; `web/server/src/api/client.ts:189-193` |
| Server: per-route weights round-trip | Read, written, pruned on save, and consumed by the router. **(c) fine.** | `components/Config/forms/RouteForm.tsx:64-94,234-257`; `internal/router/router.go:57,183-192` |

---

## 4. API alignment

### 4a. Frontend calls with no server handler

There are **no unconditional 404s** in either dashboard — every path the frontends call is
registered somewhere. The failures are all **conditional mounts**, and neither UI has an
error state to catch them:

| Call | Condition under which it 404s | Verified |
|---|---|---|
| `GET /api/v1/cache/stats` | `cache.CacheManager` nil, i.e. no `cache:` section or `cache.enabled: false` — **the shipped `configs/server-config.example.yaml` has no `cache:` section at all** | **[live] 404** |
| `GET /api/v1/cache/entries` | same | **[live] 404** |
| `GET /api/v1/cache/entries/{key}` | same | [read] |
| `DELETE /api/v1/cache/entries/{key}` | same | [read] |
| `DELETE /api/v1/cache/entries?confirm=true` | same | [read] |
| `DELETE /api/v1/cache/domain/{domain}` | same | [read] |
| `GET/POST /api/v1/cache/rules`, `PUT/DELETE /api/v1/cache/rules/{name}` | same | **[live] 404** on GET |
| `GET /api/v1/cache/presets`, `POST /api/v1/cache/presets/{name}/{enable,disable}` | same | **[live] 404** on GET |
| all `GET/POST/PATCH/DELETE /api/v1/mesh/networks…` (11 paths) | `mesh.enabled: false` (defaults true, so normally mounted) | [read] — mounted and 200 in my run |
| `GET /proxy.pac`, `GET /wpad.dat` (Setup Guide links) | `pacGenerator` nil; also the two `<a href>` are absolute and ignore `BASE_PATH`, so they break behind any reverse-proxy mount point | **[live] 200** here; href bug [read] at `SetupGuide.tsx:54,77,85` |
| **any call after clicking Backends → "Configuration"** | `BASE_PATH` becomes `/config`, so calls go to `/config/api/v1/…`, which returns **`200 text/html`** rather than a 404 — worse than a 404, since `res.json()` throws and nothing is logged | **[live]**, see §3 |

Registration sites: `internal/api/server/server.go:352-358`, `internal/api/server/cache_handlers.go:29-42`,
`internal/api/server/mesh.go:68-84`. Client-side: no conditional mounts — all
`/api/v1/*` client paths are registered unconditionally (`internal/api/client/server.go:291-368`)
and **[live]** all 21 I probed returned 200.

### 4b. Server endpoints with no frontend consumer

| Endpoint | Note |
|---|---|
| `GET /api/v1/routes/`, `POST /api/v1/routes/`, `DELETE /api/v1/routes/{name}` (server) | No binding in `web/server/src/api/client.ts` at all. Routes are edited only through the config path. (b/c — API-only surface) |
| `POST /api/v1/logout` (server) | No client binding. **[live] 404** anyway with no session manager configured. (c) |
| `POST /api/v1/login` (server) | No client binding; the dashboard uses bearer tokens. (b) |
| `GET /api/v1/settings`, `POST /api/v1/settings` (client) | No binding in `web/client/src/api/client.ts`; the dashboard uses `/config` instead. (a — duplicate surface) |
| `POST /api/v1/connect`, `POST /api/v1/disconnect`, `GET /api/v1/servers`, `POST /api/v1/server/select` (client) | No consumer, **and** the dependencies are never wired, so they no-op successfully. Multi-server is unfinished at both ends. (a) |
| `GET /api/v1/vpn/dns/cache` (client) | No consumer. (a, minor) |
| `GET /api/v1/debug/memory` (client) | No consumer and no TS type. (c — diagnostic) |
| `GET /debug/pprof/*` (client) | Diagnostic. (c) |

Dead client-side API methods (declared, never called): server — `getBackend`, `getBackendStats`,
`getCacheEntry`, `getMeshNetwork`, `getMeshPeer`, `registerMeshPeer`, `updateMeshPeer`,
`sendMeshHeartbeat`, `getConfig`, `getStatus` (`web/server/src/api/client.ts:99,105,106,133,169,210,225,229,237,252`);
client — `getHealth`, `getAllEntries`, **`validateConfig`**, `getMeshStats`,
`getMeshConnectedPeers`, `getMeshPeer`, `getMeshNetwork`
(`web/client/src/api/client.ts:381,387,438,529,533,534,536`). Peer register/update/heartbeat
are the client daemon's job, so (b); the rest is dead code (c) except `validateConfig` (a, §3).

Also dead: `web/server/src/hooks/useValidation.ts` exports `validateAll`, `getFieldProps`,
`setErrors`, `hasErrors` — zero consumers across all 11 call sites; `useWebSocket.ts:86-89`
returns `lastMessage` and `send`, neither consumed.

---

## 5. Type drift

Fields **the UI reads that the server never sends** are the damaging class. Ranked:

| # | TS | Go | Consequence |
|---|---|---|---|
| 1 | `RequestLogStats.total_requests`, `.total_bytes_sent`, `.total_bytes_recv`, `.top_hosts`, `.requests_by_method`, `.requests_by_status` (`web/server/src/api/types.ts:79-87`) | `RequestLog.Stats()` returns **only** `{enabled, count, max_size}` (`internal/api/server/requestlog.go:133-144`) | **Hard crash.** `stats.total_requests.toLocaleString()` at `web/server/src/pages/RequestLog.tsx:128` and `stats.top_hosts.slice(0,3)` at `:141`. The guard is `stats?.enabled`, which Go *does* send as `true` whenever logging is on, so it never protects. **[live]** with `api.enable_request_log: true` the page renders "Something went wrong" and the console shows `TypeError: Cannot read properties of undefined (reading 'toLocaleString')`. The page is unusable in the only configuration where it has data — and the empty state it shows otherwise tells you to enable exactly that flag. TS also declares none of the three fields Go actually sends. |
| 2 | `VPNSettings`/`TunConfig`/`DNSSettings`/`SplitTunnelConfig`/`AppRule` (`web/client/src/api/client.ts:145-155,264-291`) | `internal/vpn/config.go:9-41`, `tun.go:17-21`, `splittunnel.go:49-73` — **`yaml:` tags only, no `json:` tags** → `Enabled`, `TUN`, `SplitTunnel`, `DNS`, `Mode`, `Apps`, `IPs` | Whole subtree invisible to the UI. **[live]** confirmed on both `/config` and `/vpn/split/rules`. Write path still works (yaml keys), so the form is write-only. See §3. |
| 3 | `VPNStatus.enabled`, `.tunnel_type`, `.interface_name`, `.local_ip`, `.gateway`, `.dns_servers`, `.connected_since`, `.last_error` (`web/client/src/api/client.ts:121-133`) | none exist in `vpn.VPNStats` (`internal/vpn/vpn.go:31-45`) | Fabricated values rendered as live status. **[live]** confirmed. |
| 4 | `MeshPeer.status`, `.connection_type`, `.latency`, `.last_seen`, `.joined_at`, `.bytes_sent`, `.bytes_received` (`web/server/src/api/types.ts:927-935`) | `mesh.PeerInfo` (`internal/mesh/discovery.go:52-59`) has none | Permanently blank cards, always-gray topology nodes, "Connected" stuck at 0. Optional + guarded, so degraded rather than crashing. **[live]** observed as `-`. |
| 5 | `RouteTestResult.matched_route` (`web/client/src/api/types.ts:55`) | `handleTestRoute` returns only `{domain, action}` (`internal/api/client/server.go:841-858`) | Dead "Matched route" row in two places. **[live]** `/routes/test?domain=example.com` → `{"action":"server","domain":"example.com"}`. The router knows the match; the handler drops it. |

JSON-tag name mismatches (real bugs):

| TS | Go tag | Consequence |
|---|---|---|
| `MeshConnectionConfig.keepalive_interval` (`web/client/src/api/client.ts:341`) | `keep_alive_interval` (`internal/mesh/config.go:129`) | Broken both directions. **[live]** |
| `VPNConnection.started_at` (`web/client/src/api/client.ts:140`) | `start_time` (`internal/vpn/vpn.go:57`) | Always `undefined`; not currently rendered, so latent |

Unit mismatches:

| TS | Go | Reality |
|---|---|---|
| `DebugEntry.duration_ms: number` (`web/client/src/api/types.ts:35`) | `Duration time.Duration \`json:"duration_ms"\`` with no marshaller (`internal/debug/entry.go:18`) | **nanoseconds** → the Traffic table's duration column is off by 10⁶. `/logs` uses `.Milliseconds()` for the same-named field (`internal/api/client/server.go:1602`), so the two endpoints disagree with each other |
| `MeshDiscoveryConfig.heartbeat_interval?: string`, `peer_timeout?`, `STUNConfig.timeout?`, `MeshConnectionConfig.connect_timeout?` | `time.Duration`, plain tags | ns integers → the `FormDuration` crash in §2. **[live]** `heartbeat_interval: 30000000000` |
| `backend.Stats.Latency`, `.Uptime` | `time.Duration` | ns; not declared in TS, so latent |

Server sends, TS does not declare (UI-relevant):

| Go | Consequence |
|---|---|
| `ServerConfig.Mesh` (`internal/config/server.go:36`) | See §8. Survives save only because `ConfigEditor` spreads the fetched object |
| `logging.Config.MaxSizeMB`, `.MaxBackups` (`internal/logging/logging.go:23,26`) | Log rotation — implemented, documented — unreachable from **both** dashboards |
| `auth.PluginInfo.DefaultConfig`, `.ConfigSchema` (`internal/auth/registry.go:78-79`) | The server offers form prefill data the UI ignores |
| `ClientConfig.Servers`, `.SystemProxy` (`internal/config/client.go:17,25`) | See §8 |
| `APIConfig.allowed_origins` (client TS) | Absent from the client's `APISettings` |
| `vpn.VPNStats.uptime/packets_*/active_connections/tunneled_connections/bypassed_connections/dns_queries/dns_cache_hits` | Real telemetry the VPN page could show instead of the fabricated placeholders |

`AuthConfig.Mode/Native/System/LDAP/OAuth` are omitted from TS deliberately —
`AuthConfig.Validate()` rejects them (`internal/config/server.go:686-698`) and
`types.ts:461-464` says so. **(c) not drift.** Frontend-only view models
(`AnyBackendConfig`, the per-vendor backend forms) likewise. `MeshRoute` and
`MeshNodeStats` in the *server* `types.ts` are copies of the client daemon's shapes
with no server endpoint and no importer — dead code (c).

Verified clean (walked field by field): server — `Backend`, `ServerStats`, `HealthResponse`,
`StatusResponse`, `VersionInfo`, `RequestLogEntry`, `TLSConfig`, `ClientAuthMode`,
`ListenerConfig`, `ServerSettings`, `HealthCheckConfig`+`HealthCheckScheme`, `BackendConfig`,
`RouteConfig` (incl. `weights`), all auth config types, `AuthProviderType` (13 ≡ 13
`RegisterPlugin` calls), `NegotiateConfig`, `RateLimitConfig`, `AutoUpdateConfig`, all cache
types, `AccessLogConfig`, `MetricsConfig`, `APIConfig`, `NetworkConfig` (`ipv6?: boolean|null`
correctly models `*bool`), `SessionConfig`, `MITMConfig`, config save/validate types,
`Connection`, `ClientSummary`, `StatsEventData`, `BackendHealthEventData`, all mesh
request/response types. Client — `VersionInfo`, `StatusResponse`, `Route`, `CacheStats`,
`CacheEntry`, `MeshStatus`, `MeshPeer`, `MeshRoute`, `MeshNetwork`, `ConfigUpdateResponse`,
`LogEntry`, `ProxySettings`, `ServerConnection`, `DebugSettings`, `TraySettings`,
`AutoUpdateSettings`, `MeshDeviceConfig`, `TURNConfig`, `MeshSecurityConfig`.

---

## 6. Unconsumed events

### Main server WebSocket `/api/v1/ws`

| Event | Produced by Go | Consumed by frontend |
|---|---|---|
| `stats.update` | `internal/server/server.go:1106` (const `internal/api/server/websocket.go:374`) | **yes** — `web/server/src/hooks/useStats.ts:13-22` |
| `backend.health` | `internal/server/server.go:1099` (`websocket.go:370`) | **yes** — `useStats.ts:23-24` |
| `connection.new` | `internal/server/server.go:1495` (`websocket.go:371`) | **NO** — one broadcast **per proxied connection**, parsed at `useWebSocket.ts:40`, stored in `lastMessage`, dropped. `useStats`'s `if/else if` chain has no branch. Costs a `setLastMessage` re-render per connection |
| `connection.close` | `internal/server/server.go:1521` (`websocket.go:372`) | **NO** — same |
| `config.reload` | `internal/server/server.go:1044` (`websocket.go:373`) | **NO** — the Config page does not refetch on an external reload (SIGHUP, or another admin's save), so it keeps showing stale config |
| `config.saved` | `internal/api/server/config_handlers.go:256`, const at `:388` | **NO — and not even declared in TS.** Absent from `WS_EVENT_*` and from the `WSEventType` union (`web/server/src/api/types.ts:758-769`). Its payload `{changed_sections, requires_restart, hot_reloaded_sections, restart_required_sections}` has no TS interface either |

**2 of 6 consumed; 4 broadcast to every connected dashboard and discarded.** Root cause for
`config.saved` specifically: its constant lives in `config_handlers.go:388` rather than the
`const` block at `websocket.go:369-375`, and `types.ts:756-757` claims to mirror
"the server constants in internal/api/server/websocket.go". `WSEvent.data` is `unknown`
(`types.ts:774`), so nothing is type-checked at this boundary; only the two consumed events
have payload interfaces. `ConnectionEvent{protocol,host,backend,client_ip}`
(`websocket.go:384-389`) has no TS counterpart.

### Mesh coordinator WebSocket `/api/v1/mesh/networks/{id}/events`

| Event | Produced | Consumed |
|---|---|---|
| `join` | `internal/api/server/mesh.go:307-317` | yes — `web/server/src/components/Mesh/MeshEventLog.tsx:48-54,111` |
| `update` | `mesh.go:436-445` | yes |
| `leave` | `mesh.go:478-485` | yes |
| `{"error":"network not found"}` | `mesh.go:533` | **NO** — parsed as a `MeshPeerEvent` with `type === undefined`, falls through every `switch`, appended to the log as a blank row. No TS type for the error frame. (a, minor) |

Note this socket still uses `golang.org/x/net/websocket` — the library the main hub was
migrated *off* because of the control-frame desync documented at `websocket.go:277-284`.
Out of scope here, but flagged.

### Client SSE `/api/v1/logs/stream`

Both frame kinds are consumed: the `{"type":"connected"}` handshake is explicitly filtered
(`web/client/src/pages/Logs.tsx:30`) and log entries are appended (`:31`). The client
dashboard has **no WebSocket at all** — this SSE stream is its only push channel.
One inconsistency: the SSE path puts `source:"traffic_debug"` inside `fields`
(`internal/api/client/server.go:1766`) while the polled `/logs` puts `source` at the
response top level (`:1611`), and `LogsResponse` declares neither — so streamed rows show
an extra `source:` chip that polled rows don't. (a, cosmetic)

---

## 7. Missing loading / empty / error states

The uniform failure mode in both dashboards is that **errors render as empty states**.
No infinite spinners were found — every skeleton is gated on `isLoading`, which resolves on
error; the query's `error` is then simply never read.

### Server

| Page | Loading | Empty | Error |
|---|---|---|---|
| Dashboard | yes (`components/Dashboard/StatsCards.tsx:55`, `BackendHealth.tsx:10`) | yes (`BackendHealth.tsx:26`) | **none** — `useStats` returns `error` (`hooks/useStats.ts:47`), `pages/Dashboard.tsx:7` discards it; cards show `0` forever |
| Backends | yes (`components/Backends/BackendList.tsx:15`) | yes (`:66`) | **none** (`pages/Backends.tsx:13`) — a 401/500 renders "No backends configured" |
| Request Log | yes (`components/RequestLog/RequestTable.tsx:62`) | yes (`:94`) + a correct "logging disabled" state (`:38`) — **[live]** verified | **none** (`pages/RequestLog.tsx:12`); and see §5 #1 for the crash |
| Clients | yes (`:225-229`) | yes (`:247,:284`) | **yes** (`:199-224`, with Try Again) — the reference implementation |
| Cache | yes (all three lists) | yes (all three lists) | **none** on any of 4 queries — **[live]** the 404 case renders permanent empty skeleton rows |
| Mesh | yes (`MeshNetworkList.tsx:18`, `MeshPeerList.tsx:75`) | yes (4 sites) — **[live]** good | **none** for networks/peers; the event-log WS has a Live/Disconnected dot (`MeshEventLog.tsx:164-169`) but a failure is indistinguishable from "no events yet" |
| Config | yes (`ConfigEditor.tsx:404`, with `aria-busy`) | n/a | **yes** ×2 (`pages/Config.tsx:336-346`, `ConfigEditor.tsx:418-431`) — best on the site |
| Config Generator | n/a | n/a | own banner (`YamlPreview.tsx:50-69`), bypassing the project's Toast convention |

Swallowed errors: `pages/Config.tsx:208-210` (`return {valid:true}` on validation failure —
see §3), `pages/Backends.tsx:33-35` (`/* Silently fail */`, feeds the data-loss path),
`pages/RequestLog.tsx:25-28` (no catch on a destructive clear),
`components/SetupGuide/SetupGuide.tsx:13-17` (no catch on clipboard),
`ConfigEditor.tsx:298-335` (async onClick handlers with no catch → unhandled rejections).
Benign: `hooks/useTheme.ts:29,80`, `utils/validation.ts:146,165`, `MeshPeerDetails.tsx:64`,
`MeshEventLog.tsx:77`, `Config.tsx:226`. (c)

### Client

| Surface | Loading | Empty | Error |
|---|---|---|---|
| Traffic | yes (`pages/Traffic.tsx:104-108`) | yes (`components/Traffic/TrafficTable.tsx:33-42`) | yes (`:96-103`) |
| Routes page | yes (`pages/Routes.tsx:26-30`) | yes (`components/Routes/RoutesList.tsx:8-17`) | yes (`:18-25`) |
| RouteManager (Settings) | yes (`:491-497`) | yes (`:580-587`) | yes (`:499-505`) |
| Cache | yes (`pages/Cache.tsx:110-118,133-141`) | yes (`CacheEntries.tsx:141-146`) | yes (`:84-107`) — unreachable, both GETs are 200 |
| **VPN** | text-only (`:159`) | yes (4 sites) | **none** on any of 3 queries (`pages/VPN.tsx:17-32`) — only mutation errors are surfaced |
| **Mesh** | text-only (`:77`) | yes (3 sites) | **none** on status/peers/routes (`pages/Mesh.tsx:14-30`) |
| **Logs** | yes (`:190-193`) | yes (`:194-207`) | **none** — `isError` never destructured (`pages/Logs.tsx:15`); a failing `/logs` renders "No logs yet" |
| Settings | yes (`:169-176`) | n/a | yes (`:178-188`) — but see the Mesh-section crash in §2, which takes the whole page down |
| Header | "Loading…" (`components/Layout/Header.tsx:30`) | n/a | **none** — a status fetch failure is indistinguishable from "Server Disconnected" (`:15,36-39`) |

Misleading empty state: `TrafficTable.tsx:39-40` says "Requests will appear here as they are
proxied" even when `debug.enabled` is false and the debugger is nil, so nothing will ever
appear. (a, minor)

### Accessibility gaps indicating unfinished work

- **The skip link blanks the app** — `web/server/src/components/Layout/Layout.tsx:11` is
  `<a href="#main-content">` inside a `HashRouter` (`App.tsx:17`). Activating it rewrites the
  hash to `#main-content`, HashRouter reads that as pathname `main-content`, no route matches
  (`App.tsx:18-31` has no `*` catch-all) and `<Routes>` renders null. **[live] confirmed:**
  URL becomes `…/#main-content` and `<main>` goes from 252 characters to **0** — a blank
  page. The one control provided exclusively for keyboard users destroys the dashboard, and
  the missing catch-all means any stale hash does the same. (a) **Highest-impact a11y bug.**
- **Dialog inconsistency (server).** `components/Config/Modal.tsx` is exemplary:
  `role="dialog"` + `aria-modal` + `aria-labelledby` (`:123-125`), full Tab/Shift-Tab trap
  (`:35-75`), Escape (`:47`), initial focus (`:86-91`), focus restore (`:98-100`),
  `aria-hidden` backdrop (`:117`). Four hand-rolled dialogs have **none** of the ARIA, **no**
  focus trap and **no** focus restore: `Config/ConfirmModal.tsx:47-52` (Escape only),
  `Cache/AddCacheRuleDialog.tsx:126-131` (Escape only),
  `Cache/PurgeDomainDialog.tsx:66-71` (Escape + autoFocus),
  `Mesh/CreateNetworkDialog.tsx:75-83` (**not even Escape**). `ConfirmModal` is the gate on
  *every* destructive action in the dashboard and is the least accessible of the four. (a)
- **Icon buttons without `aria-label`** — violates the stated project convention:
  `components/Cache/AddCacheRuleDialog.tsx:257-269,277-289,297-309` (three toggle pills with
  no text, no label, no `role="switch"`, no `aria-checked` — unusable non-visually);
  `components/Config/backend-forms/SOCKS5ProxyBackendForm.tsx:53-57` and
  `HTTPProxyBackendForm.tsx:53-57` (password reveals — the identical control at
  `sections/APISection.tsx:70-75` and `Layout/ApiTokenButton.tsx:87-92` *does* carry one, so
  these two were simply missed). Toggles that have a label but lack `role="switch"`/
  `aria-checked`: `CacheRulesList.tsx:123-135`, `CachePresetsList.tsx:67-79`. **[live]** my DOM
  sweep of every rendered page found no *rendered* icon button missing a label — all of the
  above sit inside dialogs and forms my sweep did not open, so this is [read].
- **`<div onClick>` / `<tr onClick>` as buttons** (no `role`, `tabIndex` or key handler):
  server — `components/Mesh/MeshPeerList.tsx:114-121`, `MeshNetworkList.tsx:55-62`
  (**mesh network selection is mouse-only, and everything else on the page is gated on it**),
  `components/RequestLog/RequestTable.tsx:136-140`, `components/Cache/CacheEntryList.tsx:131-135`
  (the row expander is the only route to the "Purge host" button at `:208-216`).
  Client — `components/Cache/CacheEntries.tsx:150-154`, `pages/Mesh.tsx:262-269`, and the SVG
  topology nodes at `pages/Mesh.tsx:573-578,610-615` (`onClick` on `<g>`).
- **Client modals**: `ConfirmModal.tsx:46-89` and `Layout/ApiTokenDialog.tsx:84-143` have
  Escape and scroll-lock but no ARIA, no trap, no restore, and the token input is not focused
  on open; `RouteManager.tsx:66-155,215-304` have **no Escape handler at all**. All four use a
  `<div onClick>` backdrop.
- **Orphaned labels (client)** — no `htmlFor`/`id`, so the control has no accessible name:
  `components/form/FormTagInput.tsx:66` vs input `:95-103`; `components/form/FormDuration.tsx:65`
  vs `:70,:83`. `FormInput`/`FormNumber`/`FormSelect`/`FormPassword` all use `useId` correctly —
  these two are the outliers.
- **Theme-unaware hardcoded colours** despite a working light theme:
  server `components/Toast.tsx:13-22` (`background: rgb(30 41 59)` — toasts stay dark in light
  mode), `Config/forms/RouteForm.tsx:236,240`, `Layout/ApiTokenButton.tsx:68,74,90`;
  client `pages/Mesh.tsx:544,551,560,581,596,616,617,623,633` (the whole topology SVG is
  dark-only), `Layout/ApiTokenDialog.tsx:86` (`bg-black/60` where everything else uses the
  themed `bg-bifrost-overlay`).
- `confirm()` used instead of the project's `ConfirmModal`/Toast convention:
  `web/client/src/pages/Cache.tsx:57`, `components/Cache/CacheEntries.tsx:69`.
- **(b), documented:** `hooks/useUnsavedChanges.ts` hooks only `beforeunload` because
  `useBlocker` is unavailable under `HashRouter` (comment at `:6-9`). Real residual gap:
  switching tabs discards Config/Settings edits with no prompt — the most likely way to lose
  them. Present in both dashboards.
- Good, for contrast (c): `Config/Section.tsx:107-121` uses `inert` + `aria-hidden` on
  collapsed panels; `AuthSection.tsx:141-154` puts availability reasons in `sr-only` text;
  `TabNav.tsx:96` / client `TabNav.tsx:22` have `aria-label`; `ConfigEditor.tsx:439-463` uses
  proper `role="tablist"`/`aria-selected`; client `FormToggle.tsx:26-28` uses
  `role="switch"`+`aria-checked`; both Toasts have `role="alert"`/`aria-live`.

### TODO / stub markers

Both dashboards are essentially free of them. Server: **213 raw grep hits → 200 noise**
(160 `placeholder=` JSX attributes, ~38 `placeholder:` keys in the
`AuthProviderConfigForm.tsx:26-102` field-descriptor tables, 2 Tailwind
`placeholder-bifrost-muted` classes), **13 signal — all of it the deliberate
auth-availability feature** described in §2, i.e. **(c)**. Client: **42 raw hits → 39
noise**, 3 real: the false `AutoUpdateSection.tsx:21-26` banner (a, §3), the accurate
`RouteManager.tsx:358` note that there is no `PUT /routes/{name}` (b), and the
`useUnsavedChanges.ts:6-9` `HashRouter` explanation (b). **Zero `TODO`, `FIXME`, `XXX`,
`HACK`, `WIP` or "coming soon" anywhere in either `src` tree.** The marker counts in the
brief are almost entirely the HTML `placeholder` attribute.

---

## 8. Config coverage

### Server: 17 of 18 top-level keys have a dedicated form

All eight items attributed to #277/#281 are **genuinely reachable and wired** — verified as
rendered, clickable, round-tripping (read from config *and* written into the save payload),
and read by Go:

| Item | Rendered | Reachable | Round-trips | Go reads it |
|---|---|---|---|---|
| `network` | `sections/NetworkSection.tsx:41-101`, mounted `ConfigEditor.tsx:559`, nav `sectionMeta.ts:137` | yes — **[live]** seen under "Traffic & Performance" | `ConfigEditor.tsx:561` | `internal/server/server.go:81,95,110,1131,1259`; `internal/backend/factory.go:28,35` |
| `session` | `sections/SessionSection.tsx:49-143`, mounted `:589`, nav `:157` | yes — **[live]** under "Platform" | `:591` | `internal/server/server.go:384,558` |
| `mitm` | `sections/MITMSection.tsx:47-111`, mounted `:539`, nav `:124` | yes — **[live]** under "Security & Access", with the CA warning | `:541` | `internal/server/server.go:272-284` |
| `auth.negotiate` | `auth-forms/NegotiateForm.tsx:29-128`, mounted `AuthSection.tsx:493-499` | yes — **[live]** rendered below the provider list, no extra click | `AuthSection.tsx:497` — **but see the drop bug in §3** | `internal/server/negotiate.go:21-84` |
| listener mTLS | `sections/ServerSection.tsx:18-51` (`ClientAuthFields`), mounted `:223`/`:328` | yes (2 clicks: expand Server → Enable TLS) | `:112-124` | `internal/server/tls.go:13-16` |
| per-route `weight` | `forms/RouteForm.tsx:234-257` (when `load_balance==='weighted'`); backend default `forms/BackendForm.tsx:216-225` | yes (Routes → edit → Load Balance → Weighted) | `:83-94`, pruned on save `:64-73` | `internal/config/server.go:649-679` |
| health-check `scheme` / `insecure_skip_verify` | global `sections/HealthCheckSection.tsx:123-153`; per-backend `forms/HealthCheckForm.tsx:111-142` | yes, both (gated on `type==='http'` / `scheme==='https'`) | shared `healthCheck.ts` helpers so the two forms cannot drift | `internal/health/http.go:32,39` |
| `api.allowed_origins` | `sections/APISection.tsx:125-158`, with a `*` warning at `:152` | yes | `:134` — **but see the newline bug in §3** | `internal/server/server.go:594,601`; validated `internal/config/server.go:612-626` |

**No UI beyond raw YAML:**

| Key | Class | Note |
|---|---|---|
| `mesh` (`enabled`, `state_path`) | **(a)** | The one whole section with no form and no TS field. Real, consumed config (`internal/api/server/server.go:121-128`, `internal/server/server.go:581`), and the Go side is complete (`config_handlers.go:35,113,346` + a coverage test). **The compile-time guard that exists to prevent exactly this cannot catch it:** `sectionMeta.ts:53-61` compares `CONFIG_SECTION_KEYS` against the *hand-written TS* `ServerConfig` (`types.ts:643-661`), which is also missing `mesh` — the two wrong things agree, so it compiles. The guard's own comment cites `network`/`session`/`mitm` as the bug it was added for. Fix: drive the guard from the Go struct, as `internal/api/server/config_sections_test.go:133` does. Side effect today: a mesh save reports the raw key `mesh` in the toast, since `sectionLabel` has no label for it |
| `logging.max_size_mb`, `logging.max_backups` | **(a)** | Implemented (`internal/logging/rotate.go`), absent from `LoggingConfig` in `types.ts:558-564` *and* from `LoggingSection.tsx`. Same gap in the client |
| `auth` provider type `mfa_wrapper` | **(a)** | Selectable (`AuthSection.tsx:46-51`) and seeded with a default config (`:96-106`), but `FIELD_SCHEMAS` (`auth-forms/AuthProviderConfigForm.tsx:24-104`) has no entry, so `:161-163` returns `null` — the panel renders nothing |
| `cache.storage.disk.shard_count` | (a, minor) | Typed (`types.ts:505`), hardcoded to 256 in three defaults (`CacheSection.tsx:85,103,136`), no control |
| `auth.mode`/`native`/`system`/`ldap`/`oauth` (top-level legacy forms) | **(b)** | `AuthConfig.Validate()` rejects them (`internal/config/server.go:686-698`); documented at `types.ts:461-464` |
| secrets (`api.token`, `session.redis.password`, LDAP `bind_password`, OAuth `client_secret`) | **(c)** | Masked password inputs exist; `GET /config` returns them unredacted so there is no wipe-on-save |

**Save path.** Clean on the Go side: the UI PUTs the whole document
(`ConfigEditor.tsx:319` → `pages/Config.tsx:131-133`), `handleSaveConfig` decodes a full
`ServerConfig` and ignores nothing (`internal/api/server/config_handlers.go:46-49,152-160`),
and `detectChangedSections` is table-driven over all 18 sections including `mesh`
(`:325-347`), enforced by `config_sections_test.go:133`. Client-side dirty *tracking* misses
`mesh` (`ConfigEditor.tsx:229-231` iterates `CONFIG_SECTIONS` only), so a raw-YAML mesh edit
is saveable but gets no "Modified" chip and no hot-reload/restart attribution.

### Client: several keys with no UI at all, and no raw-YAML fallback

Confirmed: **there is no raw-YAML editor in `web/client/src`** (no `js-yaml`, no raw
textarea). The only fallback is Export → edit the file → Import
(`pages/Settings.tsx:105-167`), which makes the gaps below harder to work around than on
the server.

| Key | Class | Note |
|---|---|---|
| `system_proxy` | **(a)** | Zero references in `web/client/src` and absent from the TS `ClientConfig`, yet Go implements a live runtime toggle (`internal/client/client.go:882-915`) that nothing can reach |
| `servers` (`[]NamedServer`) | **(a)** | No UI, not in the TS model; the `/servers` and `/server/select` endpoints that operate on it are also unwired (§4b) |
| `logging.max_size_mb`, `max_backups` | (a) | Same as server |
| `server.tls`, `server.health_check.*` | (a) | `health_check` has a form but is not applied in-memory (§3); `tls` has no form |
| `proxy.socks5.write_timeout`/`idle_timeout`, `proxy.http.max_connections`, `proxy.*.tls` | (a) | Partial `ProxySection` coverage |
| `web_ui.base_path`, `api.allowed_origins` | (a) | Typed or implied, no control |
| mesh `turn.*`, `stun.timeout`, `connection.relay_via_peers`, `device.name`, `device.mac_address`, `security.allowed_peers` | (a) / (b) | `turn.*` is typed (`api/client.ts:325-334`) but never rendered. `relay_via_peers` is correctly **not** exposed — `internal/mesh/config.go:113-120` rejects it until implemented (b) |
| `tray.window_x`/`window_y` | **(c)** | Internal window geometry |
| `mesh.security.private_key` | **(c)** | Key material, correctly not editable |

---

## 9. Client vs server parity

What the server dashboard has that the client lacks:

| Capability | Gap intentional? |
|---|---|
| **Raw-YAML config tab** | **No.** On the server it is the escape hatch that makes the `mesh` gap survivable; on the client the equivalent gaps (`system_proxy`, `servers`, `vpn` display, `turn.*`) have no escape hatch at all beyond export/import. |
| **Section-level hot-reload vs restart-required badges**, and a `changed_sections` save response | Partly. The client's `PUT /config` does return `restart_required`/`restart_fields`, and sections carry a `RESTART REQUIRED` chip (**[live]** observed), but there is no per-section change attribution and **no pre-save validation call at all** (§3). |
| **A compile-time config-coverage guard** (`sectionMeta.ts:53-61` + `config_sections_test.go`) | No — and its absence shows: the client has strictly more uncovered config keys than the server. |
| **WebSocket push** (stats, backend health) | Defensible. The client's only push channel is the log SSE stream; everything else polls. For a single-user local daemon that is a reasonable trade — but note 4 of the server's 6 WS events are unconsumed anyway (§6), so the server's advantage is smaller than it looks. |
| **A real error state on most pages** | **No.** `pages/Clients.tsx` is the best error handling in either dashboard; the client's VPN, Mesh and Logs pages have none. |
| **Focus-managed modal primitive** (`Config/Modal.tsx`) | No. The client has four hand-rolled dialogs and no equivalent primitive — though note the server only uses its own primitive in four of eight dialogs. |
| Setup guide / PAC helper / config generator | Yes, intentional — server-side concerns. (And both of the server's are broken; see §2, §3.) |

What the **client** does better, and the server should copy: honest disabled-state banners on
VPN/Mesh/Cache (**[live]** verified — the server's Cache page has one but it is unreachable);
consistently better empty states; `aria-label` on every rendered icon button;
`role="switch"`/`aria-checked` on toggles (`FormToggle.tsx:26-28`); a `useId`-based form-field
library.

Overall: the client dashboard is less developed **in coverage**, but its defects are
concentrated in two Go-side serialisation problems (missing `json` tags, unmarshalled
durations) rather than spread through the UI. Fixing those two would close most of the
functional gap.

---

## 10. Corrections to `AUDIT-FINDINGS.md` (2026-07-02)

That document is a useful lead list and a misleading status report. Verified corrections:

| Its claim | Status now |
|---|---|
| §5 "`network`, `session`, `mitm` have no TypeScript type and no visual form … raw-YAML only" (`AUDIT-FINDINGS.md:169-171`) | **Fixed.** All three have dedicated, reachable sections with full field coverage (5/5, 9/9, 5/5). **[live]** confirmed in the rendered Config page. |
| §1 "auth.negotiate … cannot be configured from the admin dashboards at all" (`:68`) | **Fixed** — `NegotiateForm.tsx` is rendered and reachable. But a **new** bug was introduced alongside it: any provider-list edit drops `negotiate` from the save payload (§3). |
| §1 "listener mTLS (`client_auth`/`client_ca_file`) … not exposed" | **Fixed** — `ServerSection.tsx:18-51`, gated behind Enable TLS. |
| §1 "per-route load-balancing weights … not exposed" | **Fixed** — `RouteForm.tsx:234-257`, and they round-trip and are consumed by the router. |
| §1 "health-check debounce thresholds are not exposed" | **Fixed** — `HealthCheckSection.tsx` covers 9/9 fields including both thresholds. `scheme`/`insecure_skip_verify` were added too. |
| §2 headline "`detectChangedSections()` omits `access_control`, `cache`, and several restart-required sections, so security-relevant changes are written to disk, reported as `requires_restart=false`, yet never applied" (`:69,:239,:242,:403,:416`) | **No longer reproduces.** `detectChangedSections` is now table-driven over all 18 sections (`internal/api/server/config_handlers.go:325-347`) with a coverage test that fails if a `ServerConfig` field is added without a table entry (`internal/api/server/config_sections_test.go:133`). This was the document's #1 finding; it is stale. |
| §3 "each toast renders as `Validation: [object Object]`" (`:132`) | **Fixed** — no `[object Object]` toast path remains. (One caveat on my own evidence: my headless run captured `[ErrorBoundary] Error caught: [object Object]`, but that is Chrome's console *text extraction* of an object passed as a second argument to `console.error` (`web/client/src/components/ErrorBoundary.tsx:31`) — not a rendered string, and not a defect.) |
| §1 / §9 "setting `api.token` breaks *both* dashboards because neither UI can supply a token" | Already annotated as fixed in that document, and confirmed: both have token dialogs, both send `Authorization: Bearer`, and both append `?token=` to WS/SSE URLs. |
| §7 "Server mesh coordinator API is always-on; `MeshConfig.Enabled` is dead; networks never persisted" (`:306`) | **Fixed on the Go side** — `mesh.enabled` gates the mount (`internal/api/server/server.go:121-128,356-358`) and `state_path` persists networks. **Still true on the UI side**: neither field has a form (§8). |
| §1 "TOTP/HOTP/MFA … cannot be configured from the admin dashboards" | **Partly fixed.** `mfa_wrapper` is now a selectable provider type with a seeded default config, but `FIELD_SCHEMAS` has no entry so the config panel renders nothing (§8). Half-done. |
| Its line numbers generally | Stale throughout, as its own header warns. Everything above was re-derived from `ba1e826`. |

Findings in that document I did **not** re-check (out of scope): the VPN-provider CA material,
the P2P/mesh session crypto, JWT algorithm confusion, and the mesh `relay_via_peers` docs
mismatch.

---

## 11. Prioritised work

Sizes: **S** ≤ half a day, **M** 1–3 days, **L** ≥ a week.

**Blocking — the dashboard is broken in a default or near-default configuration**

1. **S — Fix `RequestLogStats`.** Either make `RequestLog.Stats()` return the six fields the
   UI reads, or reduce the UI to `{enabled, count, max_size}`. Today enabling
   `api.enable_request_log` — the exact thing the page's own empty state instructs — crashes
   the page. `internal/api/server/requestlog.go:133-144`, `web/server/src/api/types.ts:79-87`,
   `pages/RequestLog.tsx:128,141`. Add a smoke test that renders each page against a real
   handler response.
2. **S — Fix the skip link.** Use a programmatic focus handler instead of an `href` hash, and
   add a `*` catch-all route so no hash can blank the app.
   `web/server/src/components/Layout/Layout.tsx:11`, `App.tsx:18-31`.
3. **S — Add `json` tags (and a `Duration` marshaller) to `internal/vpn` and `internal/mesh`.**
   One change closes the client's VPN write-only form, the split-tunnel mode display, the
   `FormDuration` crash that takes down the whole Settings page, and the mesh
   `keep_alive_interval` mismatch. `internal/vpn/config.go`, `tun.go`, `splittunnel.go`,
   `internal/mesh/config.go:68,71,83,126,129`. Also guard `parseDuration` against numbers
   (`web/client/src/components/form/FormDuration.tsx:22`) and teach it composite Go durations
   (`"1m0s"` currently renders as `0 sec`).
4. **S — Spread `config` in `AuthSection`'s five provider handlers.** Data loss on a security
   feature. `web/server/src/components/Config/sections/AuthSection.tsx:210,219,229,238,251`.
5. **S — Stop reporting validation failures as valid.** `web/server/src/pages/Config.tsx:208-210`.

**High — visibly wrong or destructive**

6. **S — Make the Cache page's disabled banner fire on 404**, and disable Purge/Clear/Add Rule
   when the queries fail. `web/server/src/pages/Cache.tsx:38-61,158`.
7. **M — Rewrite the Config Generator against the real `ClientConfig` schema**, and add a test
   that pipes its output through `config.LoadClient` + `Validate`.
   `web/server/src/pages/ConfigGenerator.tsx`, `components/ConfigGenerator/GeneratorForm.tsx`.
8. **S — Fix the backend Edit path.** Refuse to edit (or warn loudly) when the source config
   is unavailable, instead of silently substituting `config: {}` and destroying the backend on
   save. Stop swallowing the `getFullConfig` error. `web/server/src/pages/Backends.tsx:28-38,75-93`.
9. **S — Fix client "Reset to defaults."** Omit `routes` from the payload rather than sending
   `null`, and route the reset through the add/remove path so the live router reloads.
   `web/client/src/pages/Settings.tsx:94-102`.
10. **S — Fix the two `HashRouter` link classes:** `pages/Backends.tsx:159` (which silently
    breaks `BASE_PATH` for the rest of the session) and the four client links. While there,
    make `spaOrAPINotFound` reject any path *containing* `/api/v1/` rather than only a leading
    `/api/`, so this class of mistake fails loudly. `internal/api/server/server.go:282-293`.
11. **S — Fix the cache preset enabled-ness computation** so toggling off sticks.
    `internal/api/server/cache_handlers.go:475-479`.
12. **S — Make route reorder change `priority`**, or remove the buttons.
    `web/server/src/components/Config/sections/RoutesSection.tsx:41-49`.
13. **S — Read the real listen addresses in the Setup Guide** instead of hardcoding 8080/1080,
    respect `BASE_PATH` on the PAC links, and add a clipboard fallback + `group-focus-within`.
    `web/server/src/components/SetupGuide/SetupGuide.tsx:13-17,24-29,52-54,77,85`.
14. **S — Fix the client Edit-Route modal** (`useState` → `useEffect`).
    `web/client/src/components/Routes/RouteManager.tsx:174-181`.

**Medium — real gaps, no user-visible breakage today**

15. **M — Add error states** to the server Dashboard/Backends/RequestLog/Cache/Mesh queries and
    the client VPN/Mesh/Logs queries. `pages/Clients.tsx:199-224` is the pattern to copy.
16. **M — Add the `mesh` config section to the server UI**, and re-base the parity guard on the
    Go struct so it can actually catch the next omission.
    `web/server/src/components/Config/sectionMeta.ts:53-61`, `api/types.ts:651-669`.
17. **S — Either consume or stop broadcasting `connection.new`/`connection.close`**, wire
    `config.reload` to refetch the Config page, and declare + consume `config.saved`. Move
    `EventConfigSaved` into the `websocket.go` const block so `types.ts` stays honest.
18. **S — Remove the three inert inputs from Add Backend** (Priority, Weight, Health Check) or
    make `handleAddBackend` honour them. `components/Backends/AddBackendDialog.tsx:237-285`.
19. **S — Fix the Test Backend default target** to `host:port`.
    `components/Backends/TestBackendDialog.tsx:13`.
20. **M — Hide the client Cache tab** (or state plainly that client-side caching does not
    exist). ~590 lines of inert UI. Alternatively implement client caching, which is an L.
21. **M — Accessibility pass:** give `ConfirmModal`, `AddCacheRuleDialog`, `PurgeDomainDialog`
    and `CreateNetworkDialog` the `Config/Modal.tsx` treatment; add `aria-label` to the five
    unlabelled icon buttons; convert the seven `<div>`/`<tr>`/`<g>` click handlers to real
    buttons — mesh network selection being mouse-only blocks the whole page for keyboard users.
22. **S — Block Save on `rawError`** in the Config editor, and add a confirm + error handling to
    the Request Log clear. `ConfigEditor.tsx:673-676`, `pages/RequestLog.tsx:25-28`.
23. **S — Fix the `allowed_origins` textarea** so Enter works. `sections/APISection.tsx:129-145`.
24. **S — Decide what `web_ui.enabled`/`web_ui.listen` mean.** On both server and client they
    are read by nothing and the dashboard is always served from `api.listen`. Either honour them
    or drop the section and document that the UI rides on the API listener.
25. **S — Hide the Mesh peer Connection/Throughput cards and the Connected counter** until the
    coordinator sends peer telemetry, or extend `mesh.PeerInfo`.
26. **S — Add `logging.max_size_mb`/`max_backups` to both dashboards**; add a `mfa_wrapper`
    entry to `FIELD_SCHEMAS`; expose client `system_proxy` and `servers`.

**Low**

27. **S** — `MeshTopologyGraph` devicePixelRatio bug (clicks never register on retina).
28. **S** — `DebugEntry.duration_ms` is nanoseconds; the Traffic table is off by 10⁶, and the
    `/logs` endpoint uses milliseconds for the same field name.
29. **S** — Handle the mesh WS `{"error":…}` frame; fix the generator's stale closure; remove
    the false `AutoUpdateSection` banner; delete the dead `useValidation`/`useWebSocket`
    exports and the dead `MeshRoute`/`MeshNodeStats`/`MeshPeer` types from the server
    `types.ts`; theme-fix `Toast.tsx` and the client mesh SVG; add `htmlFor` to
    `FormTagInput`/`FormDuration`.

---

## What I did not check

Proxying itself (no traffic was pushed through either binary); TLS/mTLS and the auth
providers (no certificates or directories were configured); VPN and mesh with real
privileges (macOS, unprivileged, tray disabled — `bifrost-client` also SIGTRAPs on startup
in a headless session with `tray.enabled: true`, via `fyne.io/systray`, which is an
environment limitation rather than a dashboard finding); Windows and Linux; light-theme
rendering (only the dark default was exercised); the `desktop/`, `mobile/` and `openwrt/`
front-ends and the `docs/` site; and the non-dashboard findings in `AUDIT-FINDINGS.md`
(VPN-provider CA material, P2P session crypto, JWT). Server-side dialogs and multi-step
forms were audited by reading, not clicking — my browser sweep covered every top-level page
and the client Settings sections, not every modal.
