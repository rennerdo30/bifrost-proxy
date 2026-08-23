# Desktop App Audit — Bifrost Proxy

Scope: `desktop/` (Wails app), `internal/tray/`, `internal/service/`.
Base: `master` @ `ba1e826`. Audit host: macOS (arm64). Audit only — nothing was fixed.

## 1. Verdict

**Not shippable.** The blocking thing is that `desktop/` does not compile at all: `desktop/go.sum` is
missing the `github.com/ProtonMail/go-srp` entry that the parent module now requires, so
`go build ./...` inside `desktop/` fails before it reaches any of the app code
(`desktop/go.sum` has 0 `go-srp` lines vs. 2 in the root `go.sum`). This went unnoticed because CI
builds only the desktop *frontend* and never compiles the desktop Go module
(`.github/workflows/ci.yml:201-221`), and `release.yml` never builds the desktop app at all.

Behind that, the app logic has four defects that would each be release-blocking on their own: the
Connect/Disconnect pair **panics the process** on the third click (`internal/client/client.go:489`
closes an already-closed channel), the "Connected" state and the whole traffic-statistics panel are
**fabricated** rather than read from counters that already exist, the "VPN Mode" toggle reports
success even when **zero routes were installed** (a silent traffic leak, §6), and the Edit-server
dialog opens blank. Separately, `docs/src/content/docs/desktop-client.mdx` describes roughly twice the
application that exists — system tray, Quick GUI, logs viewer, split-tunnel editor, keyboard
shortcuts, auto-start and downloadable binaries are all documented and none of them exist.

The parts that *are* good are genuinely good: the server CRUD backend (`desktop/app.go:462-711`),
`internal/service/` install/uninstall/status on all three platforms, and the Windows SCM runner.

---

## 2. Build reality

| Target | Command | Result |
|---|---|---|
| Desktop frontend | `cd desktop/frontend && npm ci && npm run build` | **PASS** (exit 0) |
| Desktop Go module | `cd desktop && go build ./...` | **FAIL** (exit 1) |
| Root Go module | `go build ./...` | FAIL — pre-existing, web UI not built |
| `internal/tray` tests | `go test ./internal/tray/...` | **PASS** |
| `internal/service` tests | `go test ./internal/service/...` | **PASS** |

`desktop/` is its own Go module (`desktop/go.mod:1`,
`module github.com/rennerdo30/bifrost-proxy/desktop`) with `replace github.com/rennerdo30/bifrost-proxy => ../`
(`desktop/go.mod:11`). It therefore needs its own `go.sum` covering the parent's transitive deps,
and that has drifted.

Frontend build (clean):

```
> bifrost-quick-access@1.0.0 build
> tsc && vite build
vite v8.2.1 building client environment for production...
✓ 24 modules transformed.
dist/index.html                   0.82 kB │ gzip:  0.43 kB
dist/assets/index-0xOJDz8n.css   18.27 kB │ gzip:  3.91 kB
dist/assets/index-BMCNm4M1.js   234.14 kB │ gzip: 69.20 kB
✓ built in 633ms
[exited with code 0]
```

Desktop Go module, run **after** `frontend/dist` existed (so the `embed` error is not the cause):

```
$ cd desktop && go build ./...
../internal/vpnprovider/protonvpn/srp.go:10:2: missing go.sum entry for module providing
    package github.com/ProtonMail/go-srp (imported by
    github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/protonvpn); to add:
	go get github.com/rennerdo30/bifrost-proxy/internal/vpnprovider/protonvpn@v0.0.0-...
../internal/api/client/webui.go:13:12: pattern all:static: no matching files found
exit status 1
```

Two distinct problems in that output:

1. **`go-srp` missing from `desktop/go.sum`** — a hard blocker. The parent module gained a ProtonVPN
   SRP dependency; `desktop/go.sum` was never regenerated. Verified: `grep -c go-srp desktop/go.sum`
   → `0`; `grep -c go-srp go.sum` → `2`.
2. **`all:static` embed pattern** — `internal/api/client/webui.go:13` embeds a directory that only
   exists after `web/client` is built. This is a build-ordering requirement, not a defect, but it
   means `cd desktop && go build` can never succeed from a fresh clone without first building the
   *client* web UI. `make desktop-build` (Makefile:276) does not do that — it only runs
   `npm install` in `desktop/frontend` (Makefile:288-290).

Not verified: whether `wails build` succeeds. Per instructions I did not install the Wails CLI. Since
plain `go build` fails, `wails build` cannot succeed either.

### Committed build artifact

`desktop/desktop` is a **15.6 MB Mach-O arm64 executable tracked in git** (`git ls-files desktop/`
lists it). `.gitignore:39` covers `dist/` but nothing excludes this binary. It should be deleted and
ignored.

### CI/release coverage gap

- `.github/workflows/ci.yml:201` — job `desktop-ui` runs `npm ci`, lint and build in
  `desktop/frontend` only (lines 212-221). **No job compiles the `desktop` Go module.**
- `.github/workflows/release.yml` — no `desktop` references at all. The docs promise downloadable
  `bifrost-desktop-*` binaries (`docs/src/content/docs/desktop-client.mdx:25-30`) that no workflow
  produces. `make desktop-build-all` (Makefile:280-286) would name them `bifrost-quick-*`, so even
  the filenames in the docs are wrong.

---

## 3. Wails binding matrix

Bindings come from `main.go:49-51` (`Bind: []interface{}{app}`), which exposes every exported method
on `*App`. The frontend does **not** import the generated `wailsjs` wrappers — it declares
`window.go.main.App` by hand (`desktop/frontend/src/hooks/useClient.ts:4-33`) and calls through that.
`grep -rn wailsjs desktop/frontend/src/` returns nothing.

| Binding (`desktop/app.go`) | Implemented? | Called by frontend? | Evidence |
|---|---|---|---|
| `Connect` | Yes, but unsafe on restart | Yes | `app.go:274`; `useClient.ts:235` |
| `Disconnect` | Yes, but unsafe on restart | Yes | `app.go:295`; `useClient.ts:249` |
| `GetStatus` | **Partial — 3 fields hardcoded to 0** | Yes | `app.go:312`; `useClient.ts:167` |
| `GetServers` | **Partial — `Latency` never set** | Yes | `app.go:359`; `useClient.ts:190` |
| `SelectServer` | Yes | Yes | `app.go:413`; `useClient.ts:264` |
| `AddServer` | Yes | Yes | `app.go:462`; `useClient.ts:278` |
| `UpdateServer` | Yes | Yes | `app.go:536`; `useClient.ts:289` |
| `DeleteServer` | Yes | Yes | `app.go:619`; `useClient.ts:301` |
| `SetDefaultServer` | Yes | Yes | `app.go:678`; `useClient.ts:315` |
| `GetQuickSettings` | Yes | Yes | `app.go:714`; `useClient.ts:204` |
| `UpdateQuickSettings` | **Partial — 3 of 4 prefs are inert** | Yes | `app.go:735`; `useClient.ts:329` |
| `GetProxySettings` | Yes | Yes | `app.go:861`; `useClient.ts:218` |
| `UpdateProxySettings` | Yes | Yes | `app.go:895`; `useClient.ts:341` |
| `RestartClient` | Yes | Yes | `app.go:928`; `useClient.ts:354` |
| `EnableVPN` | Yes | Yes | `app.go:753`; `useClient.ts:372` |
| `DisableVPN` | Yes | Yes | `app.go:775`; `useClient.ts:374` |
| `OpenWebDashboard` | Yes | Yes | `app.go:797`; `useClient.ts:387` |
| `IsConnected` | Yes | **No** — never called | `app.go:832`; absent from `useClient.ts` bodies |
| `Quit` | **No — inert, fakes success** | Yes | `app.go:825-829`; `useClient.ts:396`, `App.tsx:73` |
| `GetProxyAddresses` | Yes | **No** — never called, and not even declared in the frontend's type | `app.go:843` |
| `GetAPIBaseURL` | **Does not exist in Go** | Declared + mocked, never invoked | `useClient.ts:28`, `useClient.ts:144`; no match in `app.go` |

### Findings from the matrix

**`Quit` is a stub that fakes success.** `app.go:825-829` saves preferences and returns `nil`. Its
comment says "The Wails runtime will handle the actual quit", but nothing calls
`runtime.Quit(ctx)` — `grep -rn "wailsapp/wails/v2/pkg/runtime" desktop/` returns **nothing**. The
header X button (`App.tsx:72-81`) therefore resolves successfully and the window stays open. There is
no error for the UI to surface.

**`GetAPIBaseURL` is a phantom binding.** Declared on the `window.go.main.App` interface
(`useClient.ts:28`) and implemented in the dev mock (`useClient.ts:144`) with no counterpart in
`app.go`. Nothing calls it today, so it is latent rather than broken — but it means the hand-written
interface is not a truthful description of the Go surface, and TypeScript cannot catch that.

**The generated bindings are stale.** `desktop/frontend/wailsjs/go/main/App.js` is missing
`AddServer`, `UpdateServer`, `DeleteServer` and `SetDefaultServer` (the file ends at line 67 with
`UpdateQuickSettings`). Because the frontend bypasses these wrappers entirely, the staleness is
harmless *today* — Wails generates the real `window.go` surface at build time from `Bind` — but the
checked-in `wailsjs/` directory is misleading dead code, and anyone who starts importing from it will
get missing functions.

---

## 4. Frontend gaps

| Gap | Severity | Evidence |
|---|---|---|
| **Edit-server dialog opens blank.** `ServerDialog` seeds its form from `server?.name` etc. via `useState` (`ServerManager.tsx:25-30`) with no re-sync effect. The `if (!isOpen) return null` guard is *after* the hooks (`ServerManager.tsx:52`), so the instance never unmounts and there is no `key` prop on the mount site (`ServerManager.tsx:513-519`). It mounts once with `server === undefined`, so the Edit form always shows empty fields; saving then fails validation ("Server name is required"). The Add dialog has the mirror bug: after adding a server, reopening Add still shows the previous values. | **High** — Edit is effectively unusable | `ServerManager.tsx:25-30,52,513-519` |
| **Every server status badge reads "Unknown".** Go emits `"available"` and `"connected"` (`app.go:375,378,393,395`); `getStatusColor`/`getStatusLabel` only handle `online`/`offline`/`busy` (`status.ts:10-37`). Every row falls through to the default branch: grey dot, label "Unknown". | High — status UI never works | `app.go:375`; `status.ts:11-21,26-36`; rendered at `ServerManager.tsx:441-444`, `ServerSelector.tsx:90-93,154-157` |
| **Dead disable-rule.** `ServerSelector.tsx:142` disables rows where `server.status === 'offline'`; Go never emits `"offline"`. | Low | `ServerSelector.tsx:142`; `app.go:375` |
| **Traffic panel shows permanent zeros.** `StatusIndicator.tsx:94,100,106` render `bytes_sent`, `bytes_received`, `active_connections`. `GetStatus` never assigns those fields (`app.go:316-355`), so they are always 0 — displayed as live telemetry behind an up/down/lightning icon set. | **High** — fabricated data | `app.go:316-355`; `StatusIndicator.tsx:87-110` |
| **Latency display is dead code.** `GetServers` never sets `Latency` (`app.go:381-389`), so `latency_ms` is always `undefined` and both `{...latency_ms && ...}` blocks never render. The dev mock supplies 45/120/200 ms, so it looks implemented when run in a browser. | Medium | `app.go:381-389`; `ServerSelector.tsx:108-110,165-167`; mock at `useClient.ts:114-116` |
| **Inert "Add Server" button.** `ServerSelector`'s empty state renders a prominent "Add Server" button wired to `onAddServer` (`ServerSelector.tsx:60-68`); `App.tsx:119` passes `() => {/* Handled by ServerManager below */}`. In the exact first-run case where the user has no servers, that button does nothing. | Medium | `ServerSelector.tsx:60-68`; `App.tsx:119` |
| **"Auto-connect" toggle does nothing.** Persisted at `app.go:737`, but `startup()` (`app.go:118-131`) never reads `preferences.AutoConnect`. | Medium — setting fakes success | `app.go:737`; `app.go:118-131`; UI at `QuickSettings.tsx:195-200` |
| **"Start minimized" toggle does nothing.** Persisted at `app.go:738`; `main.go:55` hardcodes `StartHidden: false` and never consults preferences. Its description says "Start in system tray" — there is no tray (§5). | Medium — setting fakes success | `app.go:738`; `main.go:55`; UI at `QuickSettings.tsx:202-207` |
| **"Notifications" toggle does nothing.** Persisted at `app.go:739`; `desktop/` contains no notifier and never imports `internal/tray`. | Medium — setting fakes success | `app.go:739`; UI at `QuickSettings.tsx:209-214` |
| **Saving any setting re-issues a VPN state change.** `UpdateQuickSettings` ends with `if settings.VPNEnabled { return a.EnableVPN() }; return a.DisableVPN()` (`app.go:746-749`). Toggling "Notifications" therefore calls `EnableVPN`/`DisableVPN` as a side effect. | Medium | `app.go:746-749` |
| **`EnableVPN`/`DisableVPN` take a read lock to mutate state.** `a.mu.RLock()` at `app.go:754` and `app.go:776` guard operations that start/stop the VPN. | Low — lock discipline | `app.go:754,776` |
| **No keyboard shortcuts.** Docs specify six (`desktop-client.mdx:186-195`). The only `keydown` handlers are Escape-to-close in the dropdown and two dialogs. | Low (docs mismatch) | `ServerSelector.tsx:51`, `ServerManager.tsx:45,292` |
| Mock API serves fake servers/stats when `window.go` is absent (`useClient.ts:91-148`) | Fine — (c) | dev-mode only, gated on `isWails()` |
| Loading skeletons, empty states, error banner, a11y labels | Fine — (c) | `StatusIndicator.tsx:8-45`, `QuickSettings.tsx:138-155`, `App.tsx:86-99`, `ServerManager.tsx:408-421` |

### Fabricated connection state (the worst of these)

`app.go:339` sets `status.ServerConnected = a.clientCfg.Server.Address != ""` — i.e. *"a server
address string is non-empty"*, not *"we are connected"*. That value drives
`useClient.ts:174-175`, which sets `connectionStatus = 'connected'`, which drives the big
`ConnectButton` into its green "Connected" state (`ConnectButton.tsx:11,36-38,74-77`) and unlocks the
traffic panel (`StatusIndicator.tsx:87`).

So: configure any address, and the app reports **Connected** with a green shield whether or not the
server is reachable. The real check exists and is used elsewhere —
`internal/client/client.go:216-218` passes `c.serverConn.IsConnected(...)` into the client's own API
server. The desktop app just does not call it.

---

## 5. Tray

### The SVG-vs-drawn-circles question: confirmed

`internal/tray/icons.go` draws the icons in Go. `createIcon` (`icons.go:35-99`) allocates a 64×64
RGBA image and fills a radius-28 circle pixel by pixel, plus an anti-aliased rim (`icons.go:60-72`)
and a highlight ellipse (`icons.go:77-94`), then PNG-encodes it. The four states are just four fills
of that same circle (`icons.go:27-30`): green, grey, amber, red.

Meanwhile four hand-drawn assets exist and are completely unused:

- `assets/tray-icon-connected.svg`
- `assets/tray-icon-disconnected.svg`
- `assets/tray-icon-warning.svg`
- `assets/tray-icon-error.svg`

Proof they are unreferenced:

- `grep -rn "go:embed" internal/tray/` → **no matches**. There is not a single embed directive in the
  package.
- `grep -rn "tray-icon"` across all `*.go`/`*.json`/`*.yml`/`*.md` → **no matches anywhere in the
  repo**.
- `internal/tray/tray.go:6` has a blank `_ "embed"` import with nothing to embed — a vestige of the
  intended SVG path.

This is category **(a) genuinely unfinished**: the designed icons were committed, the embed import
was added, and the wiring was never done. The user sees a flat coloured dot instead of the Bifrost
mark. (Note that switching to SVG is not a drop-in change: `fyne.io/systray` wants PNG on
macOS/Linux and ICO on Windows, so the SVGs need rasterising first.)

### The rest of the tray surface

| Item | State | Evidence |
|---|---|---|
| `Status: <state>` menu item | Real; disabled label, updated on connect/disconnect | `tray.go:136-137,170,179` |
| `Connect` / `Disconnect` | Real; show/hide swap plus icon state change | `tray.go:141-143,164-180` |
| `Quick Access` | Real, and **honestly** conditional — omitted when `ShowQuickGUI` is false, leaving `quickClicked` nil so its `select` case can never fire (`tray.go:147-153,182-186`). Deliberate and documented. | `tray.go:63-66,147-153` |
| `Open Dashboard` | Real | `tray.go:154,187-190` |
| `Quit` | Real — invokes callback then `adapter.Quit()` | `tray.go:158,192-196` |
| ICO conversion for Windows | Real BMP/DIB encoder, unit-tested | `ico.go:23-140`; `ico_test.go` |
| Notifications | Real per-platform (osascript / notify-send / PowerShell balloon) | `notify.go:29-53` |
| **`Run(ctx)` ignores its context** | `func (t *Tray) Run(ctx context.Context)` never uses `ctx` (`tray.go:115-117`). Cancelling it does not stop the tray. | `tray.go:115-117` |
| **Click-handler goroutine never exits** | The `for { select { ... } }` at `tray.go:161-199` has no done/ctx case, so it outlives `Quit()`. | `tray.go:161-199` |
| **`onExit` is empty** | `func (t *Tray) onExit() { // Cleanup }` — no cleanup performed. | `tray.go:202-204` |
| `Notify` reports success once the process *starts* | `cmd.Start()` then async `Wait()` (`notify.go:47-52`). A notification suppressed by macOS permissions still returns nil. Defensible, but it is not delivery confirmation. | `notify.go:47-52` |

### The tray is not in the desktop app at all

`grep -rn "internal/tray" --include='*.go'` matches only `internal/client/client.go:24` and
`internal/client/notify_test.go:10`. **`desktop/` never imports `internal/tray`.** The tray belongs
entirely to the CLI client.

Yet `desktop/main.go:54` comments `// Start hidden for tray-first experience` (with
`StartHidden: false`), the "Start minimized" toggle is described as "Start in system tray"
(`QuickSettings.tsx:206`), and `docs/.../desktop-client.mdx:123-141` documents a six-item tray menu
with four icon states for the desktop app. None of it exists there.

---

## 6. Platform coverage matrix

Legend: **real** = implements the behaviour · **honest-stub** = returns a non-nil error so the caller
learns it failed (acceptable) · **fake-success** = returns nil/zero while doing nothing (defect).

| Feature | linux | darwin | windows | Evidence |
|---|---|---|---|---|
| Service install | real (systemd unit + `daemon-reload` + `enable`) | real (launchd plist + `launchctl load`) | real (`sc create` + description) | `service.go:173-204`, `292-323`, `360-379` |
| Service uninstall | real | real | real | `service.go:206-224`, `325-338`, `381-393` |
| Service status | real (`systemctl is-active`) | real (`launchctl list`) | real (`sc query`) | `service.go:226-239`, `340-356`, `395-410` |
| Service start/stop | **not implemented anywhere** — no `Start`/`Stop` on `Manager`; install prints instructions for the user to run by hand | same | same | `service.go:202` (`"Start with: sudo systemctl start %s"`), `service.go:377` |
| Service run / signal handling | real (SIGINT/SIGTERM + SIGHUP reload) | real (same file, `!windows`) | real (genuine SCM handler: `svc.IsWindowsService`, `Interrogate`, `Stop`/`Shutdown`, StartPending→Running) | `runner_unix.go:19-51`; `runner_windows.go:21-100` |
| Tray icon format | real (PNG passthrough) | real (PNG passthrough) | real (PNG→ICO conversion) | `icons_other.go:6-8`; `icons_windows.go:17-23` |
| Tray SVG assets → icon | **unfinished on all three** — circles drawn in Go, SVGs unused (§5) | same | same | `icons.go:35-99` |
| Tray backend without CGo | honest-ish: `noopSystrayAdapter` is a documented no-op used only under `//go:build !cgo`; `Run` invokes `onReady` then returns | same | same | `adapter_nocgo.go:7-38`; real path `adapter.go:1-55` |
| Desktop notifications | real (`notify-send`) | real (`osascript`) | real (PowerShell balloon) | `notify.go:29-53` |
| Open web dashboard | real (`xdg-open`) | real (`open`) | real (`rundll32 url.dll,...`); other GOOS → honest error | `app.go:804-814` |
| TAP `SetMACAddress` | n/a | n/a | **honest-stub — verified** | `tap_windows.go:377-382` |
| VPN route setup (behind the desktop "VPN Mode" toggle) | **fake-success (partial)** | **fake-success** | **fake-success** | `routes_linux.go:70-122`; `routes_darwin.go:58-123`; `routes_windows.go:112-128` |
| System proxy set/clear | real (`gsettings`) | real (`networksetup`) | real (registry) — but change-broadcast result discarded | `sysproxy_linux.go:42,72`; `sysproxy_darwin.go:42,77`; `sysproxy_windows.go:28,52,67-72` |
| TUN/TAP MTU configuration | real | real | **fake-success** — error discarded with `_ = output` | `tun_windows.go:109-119`; `tap_windows.go:251-261` |
| Split-tunnel process lookup | real (`/proc`) | real (`lsof`) | real (`GetExtendedTcpTable`), with one fake-success fallback | `process_linux.go:25`; `process_darwin.go:24`; `process_windows.go:90,266-301` |

### `SetMACAddress` — the known example, verified

The claim holds, and it is a model (b). `internal/device/tap_windows.go:377-382`:

```go
func (t *windowsTAP) SetMACAddress(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return ErrInvalidMACAddress
	}
	return ErrSetMACUnsupported
}
```

`ErrSetMACUnsupported` is defined at `internal/device/device.go:218`. The doc comment
(`tap_windows.go:369-376`) explains both the platform reason and the history: *"This used to update
only the in-memory copy and return nil, which told the caller the adapter MAC had changed when
nothing on the wire had — so it now fails closed."* That is exactly the right shape for a stub.

### Fake-success cases reachable from the desktop app

These matter here because the desktop app's "VPN Mode" toggle calls `vpnMgr.Start(a.ctx)`
(`app.go:766`), which runs the platform route manager.

1. **A VPN that installed zero routes reports success — on all three platforms.** In
   `routes_darwin.go` exclude mode, both default-override routes are warn-only
   (`routes_darwin.go:73-75`: `slog.Warn("failed to add default route", …)`); include-mode routes
   (`:96-98`), bypass routes (`:62-65`) and DNS (`:112-116`) likewise. `Setup` then logs
   `slog.Info("routes configured for VPN", …)` and `return nil` (`routes_darwin.go:118-124`).
   `routes_windows.go:112-128` is identical. `routes_linux.go` is the least bad — the TUN-subnet
   route *is* fatal (`routes_linux.go:57-59`) — but all split-tunnel, bypass and DNS failures still
   warn-and-continue. Consequence: the toggle flips to "on", `GetStatus` reports
   `vpn_enabled: true`, and traffic continues over the physical interface. This is the
   highest-consequence fake success found, because the failure mode is a silent traffic leak.
2. **`internal/service` `Status*` launders execution failures into confident status strings.**
   `statusSystemd` returns `"installed (inactive)", nil` on any `systemctl` error
   (`service.go:232-235`); `statusLaunchd` returns `"installed (not running)", nil`
   (`service.go:346-349`); `statusWindows` returns `"not installed", nil` on any `sc.exe` error
   (`service.go:396-400`). A missing binary, a PATH problem or a permissions error is indistinguishable
   from a real answer.
3. **Windows TUN/TAP MTU is silently dropped.** `tun_windows.go:109-119` and
   `tap_windows.go:251-261` both do `if output, err := cmd.CombinedOutput(); err != nil { /* non-fatal */ _ = output }`
   and then return nil — the error is not even logged. The device comes up with the wrong MTU and
   `configure` reports success.
4. **The non-CGo tray adapter pretends a tray exists.** `adapter_nocgo.go:23-26`:
   `Run` logs `slog.Warn("system tray not available (built without CGo)")` and then **calls
   `onReady()`**, so the app proceeds to build a full menu against no-op items. `Quit()` is empty
   (`adapter_nocgo.go:35`), and `AddMenuItem` returns a `noopMenuItem` whose `Clicked()` channel is
   never written to (`adapter_nocgo.go:31-33`), so handlers block forever. This is a *borderline*
   case — a tray is genuinely impossible without CGo and the warning is logged — but `Run`'s
   signature returns nothing, so no caller can detect it. Listing it as fake-success rather than
   honest-stub because `onReady()` is invoked.
5. **Windows `platformIcon` swallows conversion failure.** `icons_windows.go:18-21` returns the raw
   PNG when `pngToICO` fails — and the function's own doc comment
   (`icons_windows.go:6-10`) states that Windows `LoadImage` cannot reliably load PNG-based ICO
   entries. The caller gets a non-empty icon and a broken tray glyph. Low severity (our generated
   inputs should always convert) but the fallback is dishonest by its own documentation.
6. **`windowsProcessLookup.getProcessInfo` returns a partial record with nil error** when
   `OpenProcess` fails (`process_windows.go:266-301`, `return info, nil // Return what we have`) —
   `Name`/`Path` empty, so split-tunnel app-name rules silently never match.
7. **`sysproxy_windows.go:67-72` discards both return values** of
   `procInternetSetOption.Call(...)`, so `SetProxy`/`ClearProxy` return nil even when running
   applications never pick up the change.

Also worth recording as scope facts: there is **no autostart implementation anywhere in the repo**
(despite `docs/.../desktop-client.mdx:197-252` documenting "Start with Windows" / "Start at Login"
settings), and **no firewall/killswitch code** on any platform.

`internal/device`'s TAP/TUN creation for unsupported platforms (`tap_other.go:6-8`,
`tun_other.go:6-8`) and `sysproxy_other.go:15-21` are all proper honest stubs returning
`ErrTAPNotSupported` / `ErrDeviceNotSupported` / `ErrNotSupported`.

### Real defects found in `internal/service/`

- **`launchdPath()` can delete an installed plist.** `service.go:283-287` probes writability of
  `/Library/LaunchDaemons` by `os.OpenFile(daemonPath, O_WRONLY|O_CREATE, 0644)` and then
  `os.Remove(daemonPath)`. If a real service plist is already installed at that path, the open
  succeeds and the remove **deletes the live plist** — a destructive side effect inside a
  path-resolution getter, triggered by merely calling `Status()`.
- **User-facing output via `fmt.Printf` in a library package** (`service.go:201-202`, `320-321`,
  `336`, `376-377`, `391`) — bypasses `log/slog` and is not translatable, against the project's own
  conventions.

### Not verifiable on this host

I audited the Windows and Linux paths by reading source only. The following need a real host:
`sc create` actually producing a startable service, `systemctl enable` behaviour, `notify-send`
presence on a given desktop, tray rendering under GNOME/KDE AppIndicator, PNG→ICO acceptance by
`LoadImage`, and whether `wails build` succeeds on any platform.

---

## 7. Honestly-documented limitations — category (b)

These are deliberate, documented, and should **not** be counted as unfinished work:

1. **Windows `SetMACAddress`** returns `ErrSetMACUnsupported` with a comment explaining both the
   driver limitation and the fact that it previously faked success. `tap_windows.go:369-382`,
   `device.go:215-218`.
2. **Non-CGo tray adapter.** `adapter_nocgo.go` is a no-op behind `//go:build !cgo`, labelled
   "no-op adapter used when CGo is not available" (`adapter_nocgo.go:20-21`). A tray is impossible
   without CGo; degrading to inert rather than failing the build is the right call, and the real
   implementation sits behind `//go:build cgo` (`adapter.go:1`).
3. **Tray "Quick Access" hidden when `ShowQuickGUI` is false.** Not merely disabled — the menu item
   is never created and `quickClicked` stays nil so the callback is unreachable. The comment states
   this explicitly. `tray.go:63-66,147-153`.
4. **`Tray.Notify` no-ops on a nil notifier**, documented at `tray.go:104-106`.
5. **`OpenWebDashboard` returns an error on unknown `GOOS`** rather than silently succeeding.
   `app.go:812-813`.
6. **Dev-mode mock API** (`useClient.ts:91-148`) is gated on `isWails()` and clearly named `mockAPI`;
   its `console.log` calls are `import.meta.env.DEV`-guarded. Legitimate dev tooling.
7. **Service start/stop delegated to the operator.** `Install()` prints the exact command to run
   (`service.go:202,377`). Honest, though a `Start()`/`Stop()` on `Manager` is an obvious gap.

### Not category (b): the documentation over-promises

`docs/src/content/docs/desktop-client.mdx` and `SPECIFICATION.md:1585-1631` describe features that do
not exist in `desktop/`. This is the inverse of an honest limitation — the docs claim *more* than the
code delivers:

| Documented | Reality |
|---|---|
| System Tray with 6 menu items + 4 icon states (`desktop-client.mdx:123-141`) | `desktop/` never imports `internal/tray` |
| Quick GUI always-on-top compact window (`:103-121`) | One fixed 340×580 window (`main.go:37-42`) |
| Connection Dashboard, "Real-time statistics" (`:14`) | Counters hardcoded to 0 (§4) |
| Split Tunneling visual rule editor (`:16`) | Absent |
| Logs Viewer / real-time log streaming (`:17`) | Absent |
| Recent Connections table (`:92-97`) | Absent |
| 6 keyboard shortcuts (`:186-195`) | None (only Escape-to-close) |
| "Start with Windows" / "Start at Login" settings (`:197-252`) | No such setting in `QuickSettings.tsx` |
| Config at `%APPDATA%\Bifrost\config.yaml` (`:149-151`) | `<UserConfigDir>/bifrost/client-config.yaml` (`app.go:252-258`) — different directory case and filename |
| Downloadable `bifrost-desktop-*` binaries (`:25-30`) | No release job builds them; Makefile would name them `bifrost-quick-*` |

---

## 8. Prioritised work to finish it

Sizes: **XS** <1h · **S** ~half a day · **M** 1-2 days · **L** 3+ days.

### P0 — blockers

1. **Regenerate `desktop/go.sum`** so the module compiles (`cd desktop && go mod tidy`), and add a
   CI job that runs `go build ./...` inside `desktop/` (after building `web/client` for the
   `all:static` embed). Without the CI job this will silently re-break on the next parent-module
   dependency change. — **S**
2. **Fix the Disconnect→Connect→Disconnect panic.** `internal/client/client.go:489` does
   `close(c.done)`, but `c.done` is allocated only in `New` (`client.go:164`) and never recreated in
   `Start` (`client.go:169-176`). Sequence: `Disconnect` → Stop closes `done`; `Connect` → Start sets
   `running = true` and re-binds listeners; `Disconnect` again → Stop closes the already-closed
   channel → **`panic: close of closed channel`**, process dies. Reachable by clicking the main
   Connect button three times (`app.go:303` → `app.go:285` → `app.go:303`), and also from
   `shutdown()` (`app.go:139`) after one Disconnect/Connect cycle. Note this is *also* a
   fake-success: even before the panic, the second `Start` returns nil while every goroutine
   selecting on `c.done` (`client.go:406,584,619`) exits immediately, so background loops are dead.
   Fix by re-making `done` in `Start` (or guarding with `sync.Once`/a `closed` flag) and adding a
   Stop→Start→Stop regression test. — **S**
3. **Stop fabricating the connected state.** Replace
   `status.ServerConnected = a.clientCfg.Server.Address != ""` (`app.go:339`) with the real check
   already used at `internal/client/client.go:216-218`
   (`c.serverConn.IsConnected(ctx)`); expose it via a method on `*client.Client`. — **S**
4. **Make VPN route setup fail closed.** `RouteManager.Setup` currently warns and returns nil on
   every route failure, then logs "routes configured for VPN"
   (`routes_darwin.go:118-124`, `routes_windows.go:112-128`, `routes_linux.go:70-122`). Decide which
   routes are load-bearing — at minimum the default-override pair in exclude mode
   (`routes_darwin.go:73-75`) — and return an error when they fail, so the desktop toggle can refuse
   to report "VPN on" while traffic leaks over the physical interface. — **M**
5. **Delete the committed 15.6 MB `desktop/desktop` binary** and add it to `.gitignore`. — **XS**

### P1 — visible defects

6. **Wire the real traffic counters.** `*client.Client` already exposes `BytesSent()`
   (`client.go:79`), `BytesReceived()` (`client.go:82`) and `ActiveConnections()` (`client.go:86`).
   `GetStatus` (`app.go:316-355`) simply never calls them. This is pure wiring, not missing data. — **XS**
7. **Fix the Edit/Add dialog state.** Add `key={editingServer?.name ?? 'new'}` at the mount sites
   (`ServerManager.tsx:505-519`) or a `useEffect` that re-seeds the form when `server`/`isOpen`
   changes. Currently Edit always opens blank and Add retains stale values. — **XS**
8. **Reconcile the server-status vocabulary.** Go emits `available`/`connected` (`app.go:375-395`);
   `status.ts:10-37` handles `online`/`offline`/`busy`. Pick one set, define it as shared constants,
   and drop the dead `status === 'offline'` rule (`ServerSelector.tsx:142`). — **XS**
9. **Make `Quit` actually quit.** Import `github.com/wailsapp/wails/v2/pkg/runtime` and call
   `runtime.Quit(a.ctx)` in `app.go:825-829`. — **XS**
10. **Honour the three inert preferences, or remove the toggles.** `AutoConnect` (`app.go:737`),
   `StartMinimized` (`app.go:738`) and `ShowNotifications` (`app.go:739`) are persisted and never
   read. Either implement them (auto-connect in `startup()`; `StartHidden` from prefs in
   `main.go:55`; a notifier) or delete the switches from `QuickSettings.tsx:195-214`. Leaving a
   toggle that saves but does nothing is the worst of the three options. — **S**
11. **Wire the empty-state "Add Server" button** at `ServerSelector.tsx:60-68` — hoist
    `ServerManager`'s `setShowAddDialog` (or lift the dialog into `App`) instead of passing the
    no-op at `App.tsx:119`. — **XS**
12. **Stop toggling the VPN on every settings save** (`app.go:746-749`); only act when
    `VPNEnabled` actually changed. While there, switch `EnableVPN`/`DisableVPN` from `RLock` to
    `Lock` (`app.go:754,776`). — **XS**
13. **Fix `launchdPath()`'s destructive probe** (`service.go:283-287`) — use `unix.Access`/a
    `os.Stat` + `geteuid` check, or probe a temp filename, instead of creating and deleting the real
    plist path. — **XS**

### P2 — completeness and honesty

14. **Use the tray SVGs, or delete them.** Rasterise `assets/tray-icon-*.svg` at build time (PNG for
    macOS/Linux, ICO via the existing `ico.go` for Windows) and embed them, replacing `createIcon`
    (`icons.go:35-99`). If that is out of scope, remove the four unused assets and the vestigial
    `_ "embed"` import (`tray.go:6`) so the intent is not misleading. — **M**
15. **Rewrite `docs/src/content/docs/desktop-client.mdx` and `SPECIFICATION.md:1585-1631`** to
    describe the app that exists. Nine documented feature areas are absent (§7 table). — **S**
16. **Give the desktop app a tray**, or drop the tray language from `main.go:54` and
    `QuickSettings.tsx:206`. `internal/tray` is already adapter-abstracted and tested, so reuse is
    cheap. — **M**
17. **Add `Start()`/`Stop()` to `service.Manager`** so the CLI need not print instructions
    (`service.go:202,377`). — **S**
18. **Add a desktop build to `release.yml`** and align artifact names with the docs
    (`bifrost-desktop-*` vs. the Makefile's `bifrost-quick-*`, Makefile:283-286). — **S**
19. **Regenerate or delete `desktop/frontend/wailsjs/`.** It is missing four bindings
    (`App.js` ends at line 67) and the frontend does not use it. Either regenerate and import from
    it — which would also give real type-checking against the Go surface and catch the phantom
    `GetAPIBaseURL` (`useClient.ts:28`) — or delete it as dead code. — **S**
20. **Tray lifecycle hygiene:** honour `ctx` in `Run` (`tray.go:115-117`), give the click-handler
    goroutine a termination case (`tray.go:161-199`), and either implement or remove the empty
    `onExit` (`tray.go:202-204`). — **XS**
21. **Replace `fmt.Printf` in `internal/service/`** with `log/slog` and i18n-able strings
    (`service.go:201-202,320-321,336,376-377,391`). — **XS**
</content>
