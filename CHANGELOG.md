# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `bifrost-server service start|stop` and `bifrost-client service start|stop`
  now control an installed systemd, launchd, or Windows service directly. The
  commands preserve the platform tool's exit failure and diagnostic output,
  instead of forcing operators to copy platform-specific instructions after
  installation
- Default `read_timeout` (30s), `write_timeout` (30s) and `idle_timeout` (60s) on
  the SOCKS5 listener, mirroring the HTTP listener, so its handshake is bounded
  out of the box
- `GET /api/v1/config` now reports `idle_timeout` for the HTTP listener and all
  three timeouts for the SOCKS5 listener, which it previously omitted
- `api.allowed_origins`: browser origins permitted to open `/api/v1/ws`, for
  reverse proxies that rewrite `Host` (Home Assistant Ingress, Traefik, nginx,
  Cloudflare Tunnel). Entries are host or `scheme://host` patterns with
  shell-style wildcards; unusable entries are rejected at startup. A single `"*"`
  disables the check entirely as a documented, startup-warned escape hatch,
  replacing what used to be the silent default
- `GET /api/v1/auth/plugins` reports every registered auth plugin with an
  availability state (`available`, `build_disabled`, `unimplemented`) and a
  reason. The server dashboard uses it to label providers honestly instead of
  hard-coding a list that had drifted from the code and could not express
  build-dependent truths
- Mobile app: API token entry in Settings. The app could previously only manage
  an *unauthenticated* client — the bearer-token plumbing existed but nothing
  ever set a token. The token is persisted with AsyncStorage, sent as
  `Authorization: Bearer`, never displayed after saving and never logged, and can
  be cleared from the same screen. A `401` is now reported as an authentication
  failure rather than a generic error
- Mobile app: `https://` client addresses. The base URL hardcoded the `http://`
  scheme, making a TLS-terminated client unreachable. Addresses may now be a bare
  `host:port` (HTTP), an explicit `http://`/`https://` URL, or a bracketed IPv6
  literal; the implicit port is omitted for `https`
- Mobile app: `npm test` runs service-layer unit tests on Node's built-in test
  runner with no new dependencies, covering the CSRF header on every mutation,
  the server-select route and body, token persistence and scheme handling. The
  suite now also covers split-tunnel reconciliation and replace semantics, the
  connection-status helpers, and the translation catalogue; mobile CI runs
  `npm run lint` and `npm test` alongside the existing typecheck and
  `expo-doctor` checks
- Mobile app: German translations. Every string on all five screens — including
  accessibility labels, hints and toasts — resolves through a typed catalogue in
  `src/i18n.ts`, and the language follows the device locale. Counts and
  durations use locale-aware formatting. A key missing its German translation is
  a compile error, so English text cannot leak into a German build
- The server dashboard's auth provider list gained `mfa_wrapper`, which was
  registered and working but missing from the UI entirely, with a default config
  in the inline `primary`/`secondary` format the server actually accepts
- Config files support `${NAME:-fallback}`, which uses the environment variable
  when it is set and non-empty and the literal fallback otherwise. The
  shell-style form previously looked supported and was not: `os.ExpandEnv` read
  `NAME:-fallback` as one variable name, so `listen: ":${HTTP_PORT:-8080}"`
  quietly became `listen: ":"`
- Config files support `$$` as an escape for a literal dollar sign in front of a
  `{` or another `$`. It is only needed for a value that must literally contain
  `${`; a lone `$`, as in a bcrypt hash, needs no escaping
- `BIFROST_CONFIG_ALLOW_UNKNOWN_KEYS=1` downgrades unknown configuration keys
  from a startup failure to a warning naming each key and its line. It exists so
  an obsolete key cannot keep a previously running deployment from starting
  during an upgrade, and it is transitional: fix the config file rather than
  keeping the variable set

### Changed
- Windows- and macOS-tagged Go code is now analysed by CI. Every job runs on
  `ubuntu-latest`, so those files were cross-compiled but never linted, because
  `golangci-lint` and `staticcheck` analyse only the host platform unless `GOOS`
  says otherwise. A `lint-cross-platform` matrix job closes that gap. It
  immediately surfaced two test packages that did not compile for Windows at all
  (`internal/tray` referenced CGo-only symbols from an untagged file;
  `internal/auth/plugin/system` tested the `!windows` authenticator from an
  untagged file), plus 36 real findings in never-linted code — among them an
  unchecked rollback in the Windows updater that could leave no executable in
  place, and a `splitHostPort` whose error return was never non-nil, making
  every call site look like it handled a failure that could not happen
- The four `audit/` reports have been retired. Every actionable finding they
  raised is fixed and verified on `master`; the remaining deferred items (the
  on-device mobile VPN, the inert `max_load`/`auto_select` provider knobs, and
  the platforms CI cannot execute) moved to `ISSUES.md`, which no longer depends
  on the audit directory. Git history preserves the reports
- Desktop completion pass: tagged releases now build the Wails app on native
  Linux, Windows, and macOS runners and attach consistently named
  `bifrost-desktop-*` artifacts (including a universal macOS bundle). The
  process tray now honors application-context cancellation, terminates its
  click worker on exit, and its Quick Access item restores the Wails window —
  so a Start-minimized launch always has a route back to the UI. Unused tray
  SVGs and stale generated `wailsjs` bindings were removed; the frontend uses
  the live Wails binding surface directly. The desktop docs and specification
  now describe only the controls and telemetry the compact app actually ships,
  distinguish local lifecycle/system proxy/VPN actions, and document native
  build requirements and real release names
- Mobile app honesty pass: the Expo config plugin no longer injects an
  Android `<service>` entry for a VPN service class that does not exist in the
  project — declaring it made the app eligible for Always-on-VPN in system
  settings, which would break all device networking when enabled. The plugin
  now checks for the Kotlin source in the generated project and skips the
  injection with a warning when it is absent. `app.json` drops the unused
  `remote-notification` background mode, the `POST_NOTIFICATIONS` permission,
  and the iOS Network Extension entitlement (the app is a remote control, not
  an on-device VPN), and gains the `NSLocalNetworkUsageDescription` iOS
  requires for local-network access. The Auto-connect and Connection Alerts
  settings are now labelled as remote-client settings instead of implying
  phone-side behavior, split-tunneling rule switches and toasts got
  accessibility labels/roles, and the mobile docs no longer claim stats the
  API does not report
- **Mobile split tunneling now reflects and replaces the remote policy.** The
  screen fetched `GET /vpn/split/rules` and discarded the response, so it showed
  only what the phone remembered; it now reconciles the two, importing rules
  added elsewhere and keeping locally parked rules visible but disabled. The
  pre-connect sync was additive, so a rule disabled on the phone stayed in force
  on the client — it now *replaces* the client's active rules with the enabled
  local policy (removing stale ones) and is fail-closed: any failed operation
  aborts before the VPN is enabled and names the rule and operation that failed,
  instead of connecting with a partially applied policy
- Mobile assets are three distinct images instead of three copies of one file.
  The Android adaptive icon is now a transparent foreground whose artwork stays
  inside the platform's 66% safe-zone circle (a baked-in background became a
  squircle inside a squircle once Android applied its mask), and the splash is
  its own centred composition. `app.json` no longer carries a fabricated
  all-zero EAS `projectId` that looked configured while pointing at nothing —
  run `eas init` to link the project before the first build
- **Breaking:** a configuration key that no setting corresponds to is now
  rejected at load time, naming the key, its line and its config block, instead
  of being ignored. A misspelled key (`listem` for `listen`) or an obsolete one
  used to load without a word of complaint, leaving the operator to conclude that
  the *setting* does not work — which is also why a long list of documented keys
  that nothing reads went unnoticed for so long. This applies to every load path:
  server and client startup, `config validate`, hot reload, and the dashboard's
  config API. **Compatibility:** every shipped example config and both `init`
  templates load cleanly, so a config file that matches the documentation is
  unaffected; a hand-edited file carrying a typo or a key from an older release
  will now fail to start. The error names the offending keys and the whole file
  is checked in one pass, so the fix is one edit. If a deployment must come up
  immediately, set `BIFROST_CONFIG_ALLOW_UNKNOWN_KEYS=1` to turn the failure back
  into warnings and clean up afterwards
- **Breaking:** the unknown-key rejection now reaches the dynamic sections the
  YAML decoder cannot see into: `backends[].config` and
  `auth.providers[].config` are validated against the exact keys their backend
  type or provider plugin reads, including nested blocks (a WireGuard `peer`, a
  native `users` entry, an `mtls` `subject_mapping`, an inline `mfa_wrapper`
  authenticator). This closes a fail-open: `disabledd: true` on a native user
  used to load cleanly, validate cleanly, and leave the supposedly disabled
  user able to authenticate. The same schemas back startup, `validate`, and
  the dashboard's save and validate endpoints; the escape hatch above applies
  identically. Two of our own test fixtures carried such dead keys (an apikey
  `username` that the plugin never read), which is the failure mode in miniature
- **Breaking:** a config file must contain exactly one YAML document. Content
  after a `---` separator used to be silently ignored; it is now an error
- The server dashboard's config save and validate endpoints reject unknown JSON
  fields instead of dropping them, so validation reports exactly what save and
  startup would refuse
- Client config updates through `PUT /api/v1/config` reject unknown keys before
  anything is applied or persisted. Previously the update reported success,
  wrote the bogus key to disk, and the next strict reload refused the whole
  file — a 200 that bricked the config
- The client API's comment-preserving save path now escapes dollar signs in the
  values it inserts, matching `config.Save`: a literal `${...}` credential
  saved from the dashboard survives the reload instead of being expanded, while
  pre-existing `${VAR}` references in untouched parts of the file keep working
- **Breaking:** environment-variable expansion in config files no longer expands
  bare `$NAME` references — only `${NAME}` and `${NAME:-fallback}`. This is what
  makes a literal `$` in a value safe. A config file that relied on `$NAME` will
  now keep the text verbatim; the loader logs a warning, with the line number,
  whenever it leaves a bare `$NAME` that does name a variable set in the
  environment. All documented examples already use the `${NAME}` form
- A reference to a variable that is not set still expands to the empty string,
  but now logs a warning naming the variable and the line instead of failing
  silently. Use `${NAME:-fallback}` where an empty value is not acceptable
- `config.Save` escapes dollar signs that would be read back as a reference, so a
  value containing `${` survives a dashboard save and the reload that follows
- **Breaking:** the listener timeout triad now does what it says. `read_timeout`,
  `write_timeout` and `idle_timeout` are declared on every listener, defaulted in
  both shipped config templates, present in every example config and documented
  across six pages — and none of them was applied. `idle_timeout` was read
  nowhere in the codebase; `write_timeout` was read once, only so the config API
  could echo it back; `read_timeout` was quietly passed through as the
  **outbound** dial timeout, which the troubleshooting docs explicitly said it
  was not. The SOCKS5 listener read no timeout at all, so a client could open a
  connection, never send a handshake byte, and hold a goroutine and a file
  descriptor for as long as it liked. All three are now real socket deadlines on
  both listeners:
  - `read_timeout` — an absolute bound on a complete inbound request arriving
    (HTTP request line and headers, or the whole SOCKS5 handshake) measured from
    the client's first byte, then a per-read bound for the request body. It
    covers the TLS handshake on TLS-terminated listeners and every decrypted
    request on a MITM-intercepted tunnel, so neither a stalled handshake nor a
    trickled decrypted header can pin a connection
  - `write_timeout` — a **no-progress** bound: each window of `write_timeout`
    must deliver at least one byte to the client, so a streaming response
    (server-sent events, a chunked feed, a large download) is never truncated
    while it keeps moving — even to a very slow receiver — while a client that
    has stopped reading entirely is timed out within one window. (On a
    TLS-terminated listener a stalled window is fatal, a Go TLS constraint; a
    progressing response is still never cut off)
  - `idle_timeout` — a bound on a connection with nothing in flight: accepted
    but silent, or between exchanges on a kept-alive (including intercepted)
    loop. It deliberately does NOT reap an established opaque `CONNECT` tunnel
    or SOCKS5 relay — a quiet-but-open tunnel (SSH, IMAP IDLE, a WebSocket
    without pings) is valid traffic
  - `tunnel_idle_timeout` (new, off by default) — the explicit opt-in that
    reaps an established tunnel in which *neither* direction has carried data
    for the period; an actively transferring tunnel is never interrupted

  The same triad now also applies to the client's `proxy.http` and
  `proxy.socks5` listeners (default `0` = disabled there), and the client no
  longer repurposes `proxy.http.read_timeout` as its outbound dial timeout.

  One consequence to check before upgrading. **Outbound dials no longer follow
  `read_timeout`**: a backend's own `connect_timeout` wins, then
  `network.dial_timeout`, then a 30s default — and a backend-specific value is
  no longer silently capped at 30s by the handler. If you raised `read_timeout`
  to work around slow backend connects, move that value to
  `network.dial_timeout` or the backend's `connect_timeout`
- **Breaking:** an **enabled** auth provider whose plugin can never authenticate
  is now refused at config validation instead of being accepted and then
  rejecting every login. This affects `ntlm` (no credential source exists to
  verify a client response), a provider of `type: negotiate` (SPNEGO is
  middleware under `auth.negotiate.*`, not a provider), and `mfa_wrapper` using
  the by-name `primary_provider`/`mfa_provider` format. Each error explains what
  to use instead. Consequently an `auth.negotiate` block naming an
  `ntlm_provider` now fails at startup. Kerberos SSO was working in those
  deployments — it was only the NTLM *fallback* that silently rejected every
  client — so the fix is to set `allow_ntlm: false` and remove `ntlm_provider`,
  keeping `kerberos_provider` as it was. Disabled providers are not checked, so
  disabling a bad provider in the dashboard remains a way out
- The `system` (PAM) provider now reports at startup, and in the dashboard, that
  it cannot authenticate when the binary was built without the PAM backend — the
  default `make build` and the Docker image both are. It is deliberately *not*
  refused, because the same configuration is correct on Windows, on macOS, and in
  a `-tags pam` Linux build
- `POST /api/v1/config/validate` and `PUT /api/v1/config` now validate auth
  providers against the plugin registry, and check the `auth.negotiate` block's
  provider references. Previously only the config shape was checked, so the
  dashboard could save an auth config that broke the next restart and still
  report success
- `mfa_wrapper` now validates its inline `primary`/`secondary` blocks against the
  plugin registry instead of only checking that a `mode` was named. A block
  naming an unknown mode, or a mode without the config that mode requires, used
  to validate cleanly and then fail at startup
- HTTPS health checks are now configurable: `health_check.scheme` (`http`/`https`)
  and `health_check.insecure_skip_verify`, on both the global block and
  per-backend overrides, editable from the server dashboard (the per-backend
  health check editor also gained the de-bounce thresholds, previously
  global-only). The health checker already supported both; only the config
  plumbing was missing, so HTTPS probes were impossible to configure
- `health_check` blocks are validated instead of silently ignored: an unknown
  `scheme`, a `scheme`/`insecure_skip_verify` on a non-HTTP check, or
  `insecure_skip_verify` without `scheme: https` is now rejected at startup and
  on save. Only the two new fields are validated, so existing configs are
  unaffected
- `PUT /api/v1/config` and the `config.saved` WebSocket event now return
  `hot_reloaded_sections` and `restart_required_sections`, so clients no longer
  have to guess which of their changes took effect
- Server dashboard configuration editor: sections are grouped (Core, Security &
  Access, Traffic & Performance, Observability, Platform) with a filterable
  sidebar, per-section "Modified" markers, a pre-save summary splitting changes
  into "applies immediately" and "needs restart", a Discard action, and
  expand/collapse-all controls
- TUN-based VPN mode with split tunneling support
  - App-based rules (include/exclude applications by name)
  - Domain-based rules with pattern matching
  - IP/CIDR-based rules
  - DNS interception and caching
- OpenWrt compatibility with resource optimizations
- OpenWrt UCI-managed configuration: the procd init script can generate
  `/etc/bifrost/config.yaml` from `/etc/config/bifrost` when `main.managed` is
  set to `1`, mapping the core HTTP/SOCKS5/logging/access-log/metrics/web-ui/api
  options (opt-in; defaults to leaving the YAML file untouched)
- Authentication plugin system with new providers:
  - API Key authentication (`apikey`) - header-based token auth
  - JWT token authentication (`jwt`) - with JWKS support and claims mapping
  - TOTP one-time passwords (`totp`) - Google Authenticator compatible
  - HOTP counter-based OTP (`hotp`) - YubiKey compatible
  - mTLS certificate authentication (`mtls`) - client certificates, smart cards
  - Kerberos/SPNEGO authentication (`kerberos`) - enterprise SSO
  - NTLM message parser (`ntlm`) - **non-functional; fails closed** (cannot verify responses, so it rejects every login — use Kerberos for Windows domain SSO)
  - MFA wrapper for two-factor auth (`mfa_wrapper`) - combine primary auth + OTP
- Session management with memory and Redis stores
- Negotiate handler for HTTP SPNEGO handshakes (enabled via `auth.negotiate`; Kerberos only — the NTLM path always fails closed)
- Desktop client application (Wails-based)
  - Cross-platform support: Windows, macOS, Linux
  - Native system tray integration
  - Quick GUI for connection management
  - Live connection statistics
- Mobile client application (React Native/Expo)
  - iOS and Android support
  - Server selection and management
  - Real-time VPN status and statistics
  - Settings persistence
- Web client enhancements
  - VPN page with split tunneling management
  - Settings page with configuration editor
  - Logs page with SSE streaming for real-time logs
- **Automatic Updates**
  - New `update` command for client and server
  - Improved release detection and version comparison
  - Support for stable and prerelease channels
- **System Service Management**
  - New `service` command to manage Bifrost as a system service
  - Native support for systemd (Linux), launchd (macOS), and Windows Service (SCM)
- **System Proxy Support**
  - OS-level proxy configuration on Windows (registry/WinINET), macOS
    (`networksetup`), and Linux/GNOME (`gsettings`); unsupported desktops
    return `ErrNotSupported` instead of silently succeeding
  - Toggle system proxy via Web UI and Quick Settings
- **Configuration Preservation**
  - AST-based YAML updates to maintain comments and formatting
  - Preserves user-added documentation in configuration files
- Server `mesh` config block for the mesh coordinator API: `mesh.enabled`
  (default `true`) mounts or removes the `/api/v1/mesh/*` routes, and
  `mesh.state_path` persists coordinator networks and peers across restarts
  (atomic `0600` write; peer virtual IPs are re-pinned on startup so a restart
  does not renumber a running mesh). Previously the coordinator was
  unconditionally mounted and purely in-memory
- `API.Router()` now registers the same routes as `RouterWithWebSocket` instead
  of a hand-maintained subset that silently omitted the cache and mesh routes
- Windows TAP `SetMACAddress` now returns `ErrSetMACUnsupported` instead of
  reporting success while changing nothing but an in-memory field
- Authentication system refactored to plugin architecture
- Auth providers now registered via `auth.RegisterPlugin()`
- Enhanced VPNStatus API response with connection details
- System proxy support extended beyond Windows to macOS (`networksetup`) and
  Linux/GNOME (`gsettings`); unsupported desktops now return `ErrNotSupported`
  instead of reporting a successful no-op
- Repaired the original logo rather than replacing it. The rainbow span and the
  plated circle are unchanged, as are all five gradient colours; six defects
  were fixed. The packet dots straddled the arch's lower edge - they sat 4.7
  units inside a band spanning 93.7-105.7 - and now sit on its centreline. The
  dashed flow lines started below the arch and ended above it, cutting through
  the span, and are now one curve concentric to it. The gradient ran red,
  yellow, teal, blue, green, so hue reversed at the final stop and the
  right-hand node disagreed with the arch end it attached to. The hub was a disc
  whose centre was filled with the plate colour, showing as a dark blob on any
  other surface, and is now a ring seated on the crown rather than floating over
  it. The mark also had no accessible name. A separate simplified cut
  (`assets/icon.svg`) backs favicons, app icons and the tray, because at 16px
  the full mark's arch stroke is 0.96px and its packets and flow dashes vanish
  entirely. `assets/logo-light.svg` and `assets/logo-dark.svg` are gone: the
  mark carries its own plate, so surface variants served no purpose, and only
  the README's `<picture>` referenced them

### Removed
- Vestigial convenience constructors superseded by the `…With…` variants the
  production code calls: `metrics.NewCollector`, `router.NewLoadBalancer`,
  `NewMeshAPI`, `NewWebSocketHub`, `health.DefaultConfig`, and
  `device.CreateTUN`/`CreateTAP`/`ParseDeviceType`. The tests that used them now
  construct through the same entry points production does, so they exercise the
  shipped path
- Dead code the audit identified as unreachable: the `internal/auth` HTTP
  middleware (a parallel authentication abstraction the live proxy never used,
  whose `tryClientCert` implied mTLS-via-middleware was the real path when it
  is not), the duplicate exported range parser in `internal/cache` (the live
  code has its own private one), the unused `internal/util` error-wrapping and
  network helpers, and the cache rule/preset/key extract-method leftovers that
  the live loader had already inlined. Around 1,100 lines.

  Four symbols in the middleware file were **not** dead and were preserved
  rather than deleted with it: `ExtractProxyBearerToken`, used by the HTTP
  proxy's authentication path, and the `ContextKey` type with
  `ClientCertContextKey` / `ClientCertChainContextKey`, which the proxy sets and
  the mtls auth plugin reads. The audit's "remove the whole file" verdict was
  wrong on those, and the correction is recorded in the commit that made it.

  Package coverage rose where dead code was removed (`internal/auth` 92.7% →
  97.0%, `internal/util` 92.4% → 97.8% after restoring a lost `IsTimeout` test
  and making `OpenURL` testable without launching a browser)
- The client API's duplicate route table. `(*API).Handler` and
  `addAPIRoutes` maintained a second copy of every route by hand, kept alive
  only by tests, and it had already drifted from the production
  `HandlerWithUI` — that drift is what left the static UI without CSP,
  X-Frame-Options and nosniff. The 172 tests that exercised the duplicate now
  run against the production handler, so the thing under test is the thing
  that ships
- More dead code from the audit's removal list: `backend.CopyBidirectional`
  (a third copy of a function the proxy already provides),
  `proxy.CopyBidirectionalWithStats` with the `CopyStats` type and its
  `TotalBytes`/`Throughput` methods (no caller wanted the stats variant), and
  the write-only `start_time`/`domain` context plumbing in `internal/util` —
  the proxy set both values on every request and nothing ever read them back,
  so the setters, getters and their context keys are all gone
- Dead API helpers `AddWebSocketRoutes`, `setWebSocketHub` and the unrouted
  `handleGetConfigTimestamp` (which returned `time.Now()` instead of the config
  file's modification time — use `GET /api/v1/config/meta`)
- `device.GenerateMAC`, whose doc comment promised a random address while the
  body returned the hardcoded `02:BF:00:00:00:01`. Use
  `device.GenerateRandomMAC`, which the production paths already used

### Fixed
- **A proxied WebSocket is no longer torn down every `read_timeout` seconds.**
  After a `101 Switching Protocols` the connection becomes an opaque tunnel, so
  it must leave request/response deadline accounting behind — the `CONNECT` path
  called `enterTunnel()` but the plain-HTTP `Upgrade` path did not. The per-read
  `read_timeout` and per-write `write_timeout` stayed armed, so any socket quiet
  for longer than either was closed. With the shipped 30s defaults that meant a
  dashboard WebSocket proxied through Bifrost died roughly every 30 seconds and
  the browser reconnected forever: a live access log showed 262 upgrade requests
  to `/api/v1/ws` over 18 hours, a median of 34 seconds apart.
  `tunnel_idle_timeout` now covers the Upgrade tunnel as well, since a parked
  Upgrade is no less parkable than a parked `CONNECT`; it remains off by default
- The VPN configuration was invisible over the API. `vpn.Config`, `TUNConfig`,
  `SplitTunnelConfig`, `AppRule` and `DNSConfig` carried only YAML tags, so JSON
  responses used Go field names (`{"Enabled":…,"TUN":…,"SplitTunnel":…}`) while
  every client reads the documented snake_case keys. `GET /api/v1/vpn/split/rules`
  returned `{"Mode":"","Apps":null,…}`, so the client dashboard's split-tunnel
  panel highlighted no mode and always showed the `include` wording even when the
  configured mode was `exclude`; the VPN Settings form was write-only, showing
  hard-coded fallbacks while saves landed correctly and appeared to reset. All of
  these structs now carry `json:` tags matching their YAML keys
- Mesh and VPN duration settings serialised as raw nanosecond integers
  (`heartbeat_interval: 30000000000`). The client dashboard's duration input calls
  `String.match()` on the value, so the number threw a `TypeError` that replaced
  the **entire** Settings page with an error boundary, not just the mesh section.
  `mesh.discovery.heartbeat_interval`, `mesh.discovery.peer_timeout`,
  `mesh.stun.timeout`, `mesh.connection.connect_timeout`,
  `mesh.connection.keep_alive_interval` and `vpn.dns.cache_ttl` now serialise as
  duration strings (`"30s"`, `"1m30s"`), matching the convention `internal/config`
  already used for every other duration. Input still accepts a bare nanosecond
  number — including the integral scientific-notation floats (`3e+11`) that a
  numeric value picked up on its way through the config API — so payloads and
  files written against the old shape keep working
- The compatibility promise above now actually holds on the primary PUT path: a
  legacy numeric duration sent to `PUT /api/v1/config` used to decode as
  `float64`, persist as YAML scientific notation, and make the next config load
  fail — a 200 response that bricked the reload. The API now decodes numbers
  losslessly (integral numbers stay integers all the way to disk), and the
  comment-preserving config writer no longer copies a quoted style onto a value
  whose type changed, which is what turned integers into strings
- JSON exports written before the VPN and mesh structs carried `json:` tags can
  be imported again: the legacy Go field names (`SplitTunnel`, `CacheTTL`,
  `InterceptMode`, `AlwaysBypass`, `NetworkID`, `HeartbeatInterval`,
  `KeepAliveInterval`, …) are accepted on input alongside the canonical
  snake_case keys, instead of being silently dropped and reset to defaults —
  which could invert split-tunnel behavior on import. A document naming both
  spellings with different values is rejected as ambiguous; output stays
  canonical
- The client dashboard's duration inputs now parse the composite strings the API
  actually emits: `time.Duration.String()` renders five minutes as `"5m0s"`,
  which the previous single-component parser displayed as `0 sec` (affecting VPN
  Cache TTL and the mesh timeouts). An unreadable value now shows an inline
  error instead of being coerced to zero. The mesh Keepalive field also
  read/wrote `keepalive_interval`, a key the server never emits — it now uses
  the documented `keep_alive_interval` and defaults to the server's real 25s
- A validation request that fails no longer reports the configuration as
  valid: the server dashboard's pre-save validation swallowed request errors
  and returned `{valid: true}`, letting a save proceed on the strength of a
  network hiccup
- Editing a backend whose source configuration could not be loaded is refused
  with an explanation. Edit is implemented as remove-then-add, and the dialog
  used to silently substitute an empty config — saving destroyed the backend's
  settings (WireGuard keys, credentials) with a success toast
- Unmatched paths CONTAINING `/api/v1/` get a JSON 404 instead of the SPA
  page. A leading-prefix-only check let a corrupted base path (`/config/api/…`)
  fall through to index.html, where the 200 + text/html made every missing
  route look healthy
- The client dashboard's "Reset to defaults" no longer nulls out the routes
  section: the defaults payload carries `routes: null`, which was persisted
  verbatim
- Disabling a cache preset sticks in the dashboard: the enabled computation
  counted a preset as enabled whenever its rule existed, ignoring the disabled
  flag the toggle had just set
- Route reordering in the config editor changes route priority. The buttons
  reordered array positions while both the router and the display order are
  driven by priority, so they did nothing visible or effective
- The Setup Guide shows the server's real listener ports instead of hardcoded
  8080/1080 — ports the shipped config never uses — and the PAC links respect
  a sub-path deployment; the copy button works without a secure context and is
  reachable by keyboard
- The client dashboard's Edit Route dialog shows the route being edited: the
  form was seeded with a `useState` call whose initializer runs once, so
  editing a second route displayed the first one's values
- The Add Backend dialog stops offering a Priority field (the setting has no
  effect anywhere) and labels Weight and Health Check with when they actually
  take effect; the Test Backend dialog defaults to a host:port target instead
  of a URL the endpoint always rejected
- The traffic debugger's `duration_ms` field carries milliseconds: the raw
  `time.Duration` marshaled as nanoseconds under that name, making the traffic
  table off by a factor of a million
- The HTTP forward proxy is honest about its HTTP/1.1, one-request-per-
  connection nature and follows the RFCs it silently violated: hop-by-hop
  headers (the RFC 7230 §6.1 set plus everything named in `Connection`) are
  stripped in both directions instead of traveling to the origin; the proxy
  appends itself to `Via` (§5.7.1); responses carry `Connection: close`
  instead of implying persistence and then closing (clients retried into
  unexpected EOFs); a plain-HTTP `Upgrade` (WebSocket) becomes an opaque
  tunnel after the origin's `101` — it used to forward the 101 and close both
  connections with zero post-upgrade bytes ever crossing; and an h2c
  prior-knowledge request is rejected with a clean 505 instead of being
  mis-parsed into a dial of ":80" and an HTTP/1.1 502 on a would-be HTTP/2 wire
- A TURN-relayed P2P connection is actually connected before being reported:
  the manager used to build it, log "relay connection established", fire the
  connected callback and count the peer — while Send returned ErrNotConnected
  forever and the connection monitor never reaped the stuck state. On connect
  failure the peer's endpoints are tried in turn and the failure is surfaced
- The tiered cache no longer double-counts every disk hit as a memory miss: a
  workload served entirely from disk reported a hit rate of 0.5 instead of
  1.0, skewing any alert keyed on it by up to 2×. Per-tier views stay
  available; the combined stats now reflect the tiered lookup outcome
- The memory cache reaps expired entries on a timer. CleanupExpired existed
  with no caller, so expired entries lingered until LRU pressure pushed them
  out and reported sizes over-counted indefinitely
- `bifrost-server` and `bifrost-client` release their log file handle on
  shutdown — the documented `logging.Close()` contract nothing honored; with a
  file output every restart leaked the previous handle
- The 11 documented pprof endpoints exist on the client's production handler
  (behind the API token when one is set). They were registered only on a
  test-only duplicate handler; the production static catch-all answered 404 to
  the exact diagnostics the docs give copy-paste commands for
- `tools/hashpw` exists. Three documentation pages instruct operators to run
  it to mint a `password_hash`, and the program was never in the repository
- Windows self-updates no longer leak a stale `.old` binary forever: the
  cleanup helper existed on every platform with no caller and now runs at
  updater start
- The `system` auth provider reports `build_disabled` on Unix platforms
  without a password backend (the BSDs, Solaris) instead of "available" with
  every login failing as invalid credentials
- The Apache access-log format logs the request target (host+path) in the %r
  position instead of only the host, so requests to the same host no longer
  log identically
- `logging.time_format` is applied. The field was documented, defaulted and
  shown in the monitoring docs — and never read: slog's handlers used their own
  fixed timestamp format, so the setting was pure decoration
- Malformed split-tunnel rules are configuration errors instead of silent
  drops. `IPMatcher.Add` returned nil for an entry that parsed as nothing, the
  engine discarded every per-rule error at construction, and in include mode
  the default action is bypass — so a typo'd include rule sent that traffic
  OUTSIDE the tunnel in cleartext with nothing logged. `split_tunnel.ips`,
  `.apps`, `.domains` and `.always_bypass` are all validated now, an app rule
  needs a name or a path, and an unparsable IP entry is an error at the matcher
  level too
- An unusable route domain pattern (duplicate within a route, or beyond the
  matcher's pattern limit) is rejected at config validation instead of being
  silently dropped by the router — a dropped pattern sent those domains to the
  default backend. Runtime drops that still occur (a hot-reload race) are
  logged with the pattern and reason instead of a code-comment shrug. The same
  pattern on two different routes stays legal
- An unknown `health_check.type` is a configuration error. The checker factory
  silently substituted a bare TCP connect — which reports green for a backend
  whose application layer is dead — and `Checker.Type()` then answered "tcp",
  hiding the substitution from the API as well
- `health_check.timeout` is honored by ping checks. The subprocess flags were
  hardcoded to 5s (and the manager wrapped 10s), so `timeout: 1s` still blocked
  5–10s per probe and failure detection ran 5–10× slower than configured
- `network.ipv6` / address-family restrictions are honored by the `http_proxy`
  and `socks5_proxy` backends, which hardcoded "tcp" for the proxy dial while
  `direct` and `wireguard` obeyed the setting
- `mesh.stun.timeout` reaches the STUN client (it was parsed and never passed;
  the NAT detector used the connect timeout), and **the entire `mesh.turn`
  block works for the first time**: the TURN credentials were assigned to a
  manager field nothing read, so with `turn.enabled: true` no TURN client was
  ever created and relay selection always failed with nothing saying why. A
  second and later configured TURN server is still unused, and now says so in
  the log
- `client.servers` selection support (see the server-selection change) plus:
  `server.tls`, `proxy.http.tls`, `proxy.socks5.tls` and client-side
  `max_connections` are refused with actionable errors instead of silently
  ignored — a client `server.tls.enabled: true` used to yield a PLAINTEXT
  upstream connection with no warning
- Mullvad and PIA log a warning when `max_load` is configured: neither
  provider's API integration populates server load, so the filter can never
  trip — the setting currently has no effect
- The server dashboard's OAuth `required_claims` field submits the
  claim→value map the Go parser expects. It used to submit a string list,
  which the parser silently discarded — the dashboard looked configured while
  nothing reached the setting
- `backends[].priority` is documented as having no effect (backend selection is
  driven entirely by `routes[].priority`) and removed from the shipped
  examples; `web_ui.base_path` is documented as optional in every setup (the
  dashboard derives its prefix from the browser URL; the Go server does not
  consume the value); the `debug.filter_domains` template comment now says
  NOT YET IMPLEMENTED instead of describing a working option
- P2P latency is now measured instead of fabricated: keep-alive PONGs record
  the actual PING round-trip (previously the PONG was discarded and the stored
  "latency" was however long a socket write took), relayed connections gained
  the same keep-alive measurement (previously always 0), and the mesh node
  refreshes routing metrics with the measured values during maintenance — so
  inbound and relayed peers no longer permanently score as the cheapest route
  and relay selection can order relays by real latency
- Relayed peer connections now report the peer address they were established
  to instead of a blank endpoint in `/api/mesh/peers`
- NAT detection no longer hard-codes its results: `is_behind_nat` is computed
  by checking whether the STUN-observed address is held by a local interface
  (a machine with a public IP now correctly reports no NAT and NAT type
  `none`), and the never-tested `hairpin` field is gone from the NAT info
- The Windows TUN device no longer busy-spins when the interface is idle:
  reads wait on WinTun's read-wait event instead of hammering
  `ERROR_NO_MORE_ITEMS`, which also ends the error-log flood from the VPN read
  loop on an idle tunnel
- **VPN route setup no longer reports success after failing.** On macOS and
  Windows, `RouteManager.Setup` warned on every failed route and returned nil,
  so the desktop VPN toggle showed the VPN as on while traffic kept flowing
  over the physical interface. Any failure — a bypass route, either of the two
  default-override routes that ARE the tunnel, an include route, or (with the
  built-in DNS enabled) DNS configuration — is now fatal, rolls back whatever
  was already installed, and surfaces the exact command output. A route that
  already exists is recognized per platform and treated as the desired state,
  not a failure. Linux, which already made the TUN route fatal, gets the same
  treatment for the rest. (Platform caveat: verified by compilation and unit
  tests of the classification logic; the Linux/Windows runtime paths were not
  executed on this development machine)
- VPN route setup deadlocked on the DEFAULT configuration: `Setup` called the
  exported `AddBypassRoute` while already holding the manager's mutex, and the
  default config ships three `always_bypass` entries — so on macOS, Windows
  and Linux alike the first bypass route self-deadlocked the setup before any
  route was installed
- **Windows per-app split tunneling can match connections now.** The port
  byte-order conversion widened to uint32 before shifting, pushing the port's
  high byte into bits 16–23 instead of wrapping it, so the computed value never
  matched a Windows MIB-table entry for any port above 255 and per-app rules
  classified nothing. The conversion is a shared, cross-platform-tested helper
  now, checked against the definitional big-endian encoding
- **The OpenVPN crash detector can actually fire.** It polled
  `cmd.ProcessState`, which stays nil until `Wait` is called — and only `Stop`
  called `Wait` — so a dead tunnel kept reporting healthy until the next
  manual stop. One goroutine now owns `Wait` per process; an exit while the
  backend is supposed to be running marks it unhealthy and surfaces the exit
  status in the backend stats, while an orderly `Stop` (which closes the stop
  channel before signaling the process) is never misreported as a crash
- `bifrost-server service status` (and the client equivalent) no longer
  launders tool-execution failures into confident states: "systemctl is not on
  PATH" read exactly like "the service is stopped", and a missing `sc.exe`
  read as "not installed". A tool that ran and answered non-zero is still a
  meaningful state (systemd's non-active states are now reported verbatim); a
  tool that could not be executed at all is an error
- Windows TUN/TAP MTU configuration failures were discarded with `_ = output`
  and not even logged, leaving an MTU mismatch to surface later as blackholed
  large packets with nothing pointing at the cause. They are warnings now,
  with the requested MTU and the tool output
- **One peer leaving the mesh disabled networking for the whole node.**
  `DirectConnection.Close` closed the P2P manager's shared UDP socket, which it
  does not own, so the first disconnect left the node unable to send or receive
  any datagram or accept any new peer — while the receive worker busy-spun on the
  closed socket, logging in a hot loop. The socket is now closed only by the
  manager, the receive worker stops instead of retrying a permanently closed
  socket, and a connection that loses the inbound race is closed rather than
  leaking its worker goroutines
- Documentation: every YAML example in the docs is now one the server/client
  actually accepts. Removed config keys that do not exist and were therefore
  silently dropped by the loader (`access_log.fields`,
  `server.http.forward_auth_headers`, `cache.memory`/`cache.disk` outside
  `cache.storage`, `rate_limit.burst`, listener `enabled`/`address`/
  `connect_timeout`/`max_idle_conns*`, top-level `websocket:`/`connection_limits:`,
  `vpn.mode`/`vpn.interface_name`/`vpn.mtu`/`vpn.split`, `vpn.dns.servers`,
  `vpn.dns.intercept_port`, `debug.log_level`), corrected auth-provider options to
  the schema each plugin parses (mTLS `ca_cert_file`/`allowed_subjects`, JWT
  `algorithms` plus a real key source, apikey `header_name`, list-shaped TOTP/HOTP
  `secrets`, `mfa_wrapper` requiring both `primary` and `secondary`), and split
  the blocks that contained duplicate YAML keys — those made the loader hard-fail,
  so pasting them prevented startup
- Documentation: `monitoring.mdx` now matches the Prometheus registry, including
  the `bifrost_cache_*` series (exported whenever `cache.enabled` is set) and the
  note that `bifrost_connections_active` always carries an empty `backend` label.
  Two Mermaid diagrams in the architecture guide that failed to parse in the
  browser now render
- Documentation: `${VAR:-default}` was shown as supported env-var interpolation,
  but expansion is `os.ExpandEnv`, so it silently yields an empty string
- A config save that changed both a hot-reloadable and a restart-required section
  skipped the hot-reload entirely, so e.g. a new `access_control` blocklist saved
  alongside a listener change stayed unenforced until a restart. The
  hot-reloadable part is now always applied
- The server dashboard wrongly reported hot-reloaded `access_control`,
  `rate_limit` and `cache` saves as "restart required" (`routes` was the only
  section it classified correctly). Section hot-reloadability now comes from
  `GET /api/v1/config/meta` and the save response instead of a client-side list
  that both had the wrong membership and mangled its lookup keys
- Importing a configuration file left the dashboard editor holding the
  pre-import config, so every section showed as modified and saving would have
  reverted the import
- The "Health Check" link in the configuration sidebar scrolled nowhere: its
  anchor was derived from an older section heading. Section anchors are now
  derived from the config section name and can no longer drift from the heading
- Collapsed configuration sections kept their form fields in the tab order and
  in the accessibility tree, so keyboard and screen-reader users walked through
  the fields of all 17 collapsed panels
- The unsaved-changes navigation warning never fired, because the dashboard only
  tracked edits while a save was already in flight
- If auto-reload failed after a config save, the API still reported the sections
  as applied; it now reports them as needing a restart
- `GET /api/v1/config/meta` duplicated its hot-reloadable flags in a second hand-
  maintained list that could disagree with the save path; both now derive from
  one table
- Client `/api/v1/status` now reports real traffic counters. `bytes_sent`,
  `bytes_received` and `active_connections` were hardwired to zero because the
  client never supplied the API's counter callbacks; they are now fed from the
  HTTP and SOCKS5 proxy handlers
- `auto_update` is no longer a dead toggle on the server. `Server.Start` now
  constructs the updater and starts the background checker when
  `auto_update.enabled` is set (honouring `channel` and `check_interval`, with
  the interval clamped to a 1 hour minimum), logs available updates at `INFO`
  level, and stops the checker on graceful shutdown
- `cache_bytes_served_total{source="origin"}` is now recorded. It had no
  production writer, so it stayed at zero and the bandwidth-saved ratio against
  `{source="cache"}` could not be computed. Bytes are counted for every response
  fetched from the origin while the cache is enabled, cacheable or not
- Cache hits are no longer reported as HTTP 500. The cache-served branch never
  set a status code, so the access log and `bifrost_requests_total` recorded
  `status="500"` for every hit while the client correctly received 200. Hits now
  record the status actually written (200, or 206 for range requests) and carry
  the synthetic backend label `cache`
- VPN manager nil pointer panics when disabled or uninitialized
- Auto-updater reliability issues with non-SemVer releases
- Improved error handling in API server
- Cross-compilation support for VPN mode on all platforms
- Removed CGo dependency from darwin process lookup
- Restored .gitkeep files for static directories

### Security
- The server dashboard no longer keeps the API token in `localStorage` when a
  session store is configured. Signing in POSTs the token once to
  `/api/v1/login` and thereafter authenticates with the **HttpOnly** session
  cookie the server already knew how to issue — script cannot read that cookie,
  whereas any XSS on the page could read the stored bearer token. The cookie
  also authenticates the WebSocket handshake, so no credential is placed in a
  URL. Signing out destroys the session server-side, and an expired session
  prompts for the token again instead of failing every page. The server half of
  this flow was built and config-gated but had no client; without a `session:`
  block the dashboard still falls back to the bearer token and says so
- `POST /api/v1/login` and `/api/v1/logout` are now mounted unconditionally, so
  a server with no session store answers the handlers' `503 "not enabled"`
  instead of a bare `404`. While the routes were conditionally registered those
  `503` branches were unreachable, and a client could not distinguish "feature
  disabled" from "wrong URL". Registering `/login` also had to move after the
  middleware chain: chi requires every `r.Use` on a mux to precede its first
  route, and the no-token branch installs CSRF middleware on that router — with
  a session manager and no token configured, the old placement would have
  panicked at startup
- Both proxy listeners now bound an idle client, closing a slowloris-style
  resource exhaustion. A client could previously connect to the HTTP or SOCKS5
  listener and either send nothing at all or trickle request headers forever,
  pinning one goroutine and one file descriptor per connection with no timeout
  of any kind to reclaim them — the configured `read_timeout` and `idle_timeout`
  were never applied. Reaching the `max_connections` ceiling this way denied
  service to legitimate clients. See the listener-timeout entry under *Changed*
- `/api/v1/ws` now verifies the WebSocket `Origin`. WebSockets are exempt from
  both the same-origin policy and CORS, so any web page loaded in a browser that
  could reach a Bifrost instance was previously able to open a socket and read
  the live traffic stream — and when no `api.token` is configured that route has
  no authentication either. An `Origin` whose host matches the request `Host` is
  always accepted (the dashboard Bifrost itself serves, needing no
  configuration); anything else must be named in the new `api.allowed_origins`;
  a request with no `Origin` header at all is still accepted, since non-browser
  clients do not send one and a web page cannot suppress its own. This was a
  long-standing gap rather than a regression: the previous implementation only
  checked that `Origin` parsed as a URL and never compared it to the host
- The `api.token` is no longer written to the request log. Both dashboards
  authenticate their WebSocket and SSE connections with `?token=`, because
  browsers cannot set headers on those transports, and the request logger printed
  the URL verbatim — so the token was logged on every WebSocket upgrade and every
  log-stream reconnect. The parameter is now lifted out of the URL before any
  logging happens; it still authenticates the request
- Config values containing a dollar sign are no longer silently truncated. The
  loader expanded environment variables by running `os.ExpandEnv` over the whole
  file, so any `$` followed by word characters was read as a variable reference:
  the password `p@ss$word123` loaded as `p@ss`, and the bcrypt hash
  `$2a$10$N9qo…` loaded as `a0`. There was no escape syntax, and YAML quoting
  could not help, because expansion ran on the raw bytes before parsing. Every
  credential in a config file — proxy passwords, LDAP bind passwords, API keys,
  `password_hash` values — was at risk of being corrupted into something that
  then failed authentication with no indication why. Expansion now recognizes
  only `${NAME}`, `${NAME:-fallback}` and the escape `$$`; every other dollar
  sign is literal
- The PIA provider's embedded OpenVPN CA certificate was not PIA's. It parsed as
  X.509 with the right structure and subject, but 711 of its 1967 DER bytes had
  been replaced — 300 bytes at the tail of the RSA modulus and 414 of the 512
  signature bytes — so its self-signature did not verify and its public key was
  not the one PIA signs with. That constant is both the `<ca>`
  block of generated PIA OpenVPN profiles and the TLS trust root for PIA's
  `/addKey` and port-forwarding endpoints, so PIA OpenVPN, WireGuard key
  registration and port forwarding could not have worked. Replaced with PIA's
  published `ca.rsa.4096.crt`, now fingerprint-pinned and signature-checked by
  tests
- ProtonVPN API-mode login now verifies the PGP signature of the SRP modulus
  returned by `/auth/info` against Proton's modulus-signing key. Previously the
  modulus was taken on trust (and mis-parsed), so a tampered response could have
  substituted an attacker-chosen SRP group
- Provider OpenVPN CA certificates and `tls-auth` keys are validated fail-closed
  wherever they are used: a PEM block that is not a parseable X.509 CA, a
  self-issued certificate whose signature does not verify, an expired
  certificate, or a placeholder `tls-auth` key is now refused instead of being
  written into a profile
- The client dashboard's static UI responses now carry the same global
  security headers as the server dashboard (CSP, X-Frame-Options, nosniff).
  The production handler had silently drifted from a test-only duplicate route
  table that had them
- Brute-force protection actually ships: `auth.brute_force` wraps the whole
  provider chain with failed-login lockout (exponential backoff, per
  username+source). The implementation existed, fully tested, with no config
  key and no caller — a security control the project believed it shipped and
  did not
- **A configured but unusable mTLS CRL no longer fails open.** An unreadable
  or unparsable `crl_file` was a one-line startup warning, after which every
  certificate the CRL was supposed to revoke kept authenticating. It is now a
  fatal startup/creation error: if revocation checking is configured it works,
  or the provider refuses to run. Remove `crl_file` to run without revocation
  checking — it is never disabled implicitly
- **`oauth.required_claims` is enforced.** The setting was parsed and surfaced
  in the dashboard but never read, so a deployment gating access on, say,
  `hd: example.com` was letting every active token through. Both validation
  paths (introspection and userinfo) now enforce it with exact semantics:
  missing claims fail, strings compare exactly, booleans and numbers compare
  by canonical text, array claims match by string membership (`aud`-style),
  object-valued claims never match. Deployments with no `required_claims` (or
  the empty map the default template shipped) are unaffected. Claim values are
  never logged or echoed in errors
- **Disconnecting and reconnecting the client crashed the process.** The client's
  internal shutdown channel was allocated once, when the client was created, and
  closed by every `Stop`, so a stop/start/stop sequence closed it twice and
  panicked with "close of closed channel". Three clicks of the desktop app's
  Connect/Disconnect button were enough. Before the crash the restart was also a
  silent no-op: the second start reported success while every background loop
  watching the already-closed channel exited immediately, so the server health
  monitor never probed again. Each run now gets its own shutdown channel,
  listeners and API server, and a stopped client can be started again cleanly
- Start and Stop are serialized for their complete duration: a Start racing a
  Stop used to be admitted the moment the running flag flipped, bring up a
  fresh run, and then have that run's VPN, mesh, updater, system proxy and
  connection drain dismantled by the tail of the old Stop. A dedicated
  lifecycle lock now holds the new Start out until the previous teardown has
  entirely finished
- **The system tray is now an honest process-lifetime resource.** The tray
  library (fyne.io/systray) can only ever run once per process — a second run
  exits immediately on Linux and its quit is guarded by a package-global
  once — but the client created a new tray on every Start and quit it on every
  Stop, leaking one click-loop goroutine per restart cycle and leaving a dead
  icon after the first stop. The tray is now created once, survives every
  Stop/Start cycle (Stop just flips the icon to disconnected), and its
  callbacks always target the currently registered client, so it also survives
  a full client rebuild. A data race on the tray's status field, between the
  client's stop path and the tray's own click loop, was fixed along the way
- A client start that could not bind its HTTP or SOCKS5 listener left the client
  reporting itself as running, so the desktop app's Connect button (which only
  starts a client that is not already running) reported success from then on
  while nothing was listening. A failed start now rolls back: listeners are
  closed, background goroutines are joined, and the client reports not running
- **The desktop app's connection indicator was fabricated.** It reported
  "Connected", with the green shield, whenever a server address was configured —
  reachable or not. It now performs a real, short reachability probe against the
  configured server, the same check the client's own API already used
- **Desktop server selection now switches the live connection.** SelectServer
  used to mutate only the configuration, so every future dial (and the status
  probe) kept using the previous upstream while the UI displayed the new one;
  it now goes through the client's own selection, which reconfigures the live
  connection and persists the choice. GetServers stopped labeling the selected
  server "connected" merely because the local client process was running — the
  selected entry now carries a real probed status and the rest are "available"
- The desktop Quit control actually quits (it saved preferences and returned);
  Auto-connect and Start minimized are honored (both were persisted by their
  toggles and never read — the client always started at launch and the window
  always opened visible; Auto-connect defaults to on, preserving the previous
  behavior); the Notifications toggle was removed, because the desktop app has
  no notifier and a switch that saves a preference nothing reads is worse than
  no switch
- Saving the desktop quick settings no longer bounces the VPN as a side
  effect: the VPN is touched only when its toggle actually changed, and the
  enable/disable paths take the write lock they mutate state under
- Desktop server statuses render correctly: the frontend styled
  online/offline/busy — a vocabulary the backend never emits — so every server
  showed the fallback style; it now understands connected/disconnected/
  available. The Edit Server dialog opens with the server's values (it kept
  its initial state forever, so Edit opened blank and Add retained stale
  values), and the empty-state "Add Server" button opens the Add dialog
  instead of being wired to a comment
- The desktop Connect button follows the local client lifecycle instead of
  upstream reachability. When the upstream went down, the button flipped to
  "Connect" — but clicking it was a no-op on the already-running client, and
  the server list simultaneously said "Connected". A running client with an
  unreachable upstream now shows a distinct amber state whose action is
  Disconnect
- The desktop app's traffic panel rendered permanent zeros as live telemetry.
  Bytes sent, bytes received and active connections are now read from the
  client's existing counters
- Mobile app: every write failed with `403 CSRF validation failed`. The client
  API requires `X-Requested-With: XMLHttpRequest` on `POST`/`PUT`/`DELETE`/
  `PATCH`, which both web dashboards send and the app did not — so VPN
  enable/disable, server selection, config updates, cache clearing and all eight
  split-tunnel writes were silently inert. The header is now sent on every
  request
- Mobile app: server selection called `POST /servers/{id}/select`, which does not
  exist, with an `id` that was always `undefined` because `ServerInfo` has no
  such field. It now calls `POST /api/v1/server/select` with
  `{"server": "<name>"}`, and the server list is keyed on `name`
- `GET /api/v1/servers` and `POST /api/v1/server/select` now work against the
  real client, not just the desktop app: the client never supplied the server
  list or selector, so the list was always `[]` and a select was acknowledged
  with 200 while changing nothing. The client now reports its `servers:` config
  (credentials excluded; only the selected entry is probed for reachability),
  and selection reconfigures the live upstream connection and persists through
  the comment-preserving save path. An API built without a selector answers
  501 instead of the previous fake success
- Mobile app: adding a split-tunnel domain sent `{"domain": ...}` where the
  handler decodes `{"pattern": ...}`, so every domain rule — from the Split
  Tunneling screen and the pre-connect sync alike — was rejected with
  HTTP 400. The request body now matches the handler
- Mobile app: the `StatusResponse` and `VPNStatus` types matched neither the Go
  handlers nor the API docs, so the Stats screen showed a permanent `N/A` for
  nine rows and the session duration, and "Server Status" was permanently
  "Unknown". Both types now mirror what the handlers emit: `server_connected`
  and `vpn_status` instead of the non-existent `server_status`, and `vpn.VPNStats`
  (`uptime`, packet counters, tunneled/bypassed connections, DNS counters)
  instead of ten fields the API never returned
- Mobile app: an unreachable client was indistinguishable from an idle one. Home
  and Stats rendered "Not Connected" with `0 B` on a failed fetch; both now
  report the failure, name the address they could not reach, and offer a retry
- Mobile app: the Settings server-address field could overwrite text as the user
  typed it, because an effect copied the remote client's *upstream* server
  address into the input on every config refetch
- The server dashboard's Request Log page crashed to the error boundary as soon
  as `api.enable_request_log` was turned on — the exact thing its own empty state
  told operators to do. The page reads aggregate counters that
  `GET /api/v1/requests/stats` never sent, so the first render threw
  `TypeError: Cannot read properties of undefined`. The endpoint now reports
  `total_requests`, `total_bytes_sent`, `total_bytes_recv`, `requests_by_method`,
  `requests_by_status` and `top_hosts` alongside the existing `enabled`, `count`
  and `max_size`, and the dashboard's types match it field for field. Clearing
  the log also resets the running totals
- The server dashboard's Cache page went into a silent 404 loop on any server
  started without a `cache:` section — including the shipped example config. The
  cache API is only mounted when caching is configured, and the page had no error
  state, so it showed permanent loading skeletons, no explanation, and live
  Purge Domain / Clear All / Add Rule buttons. It now reports "Caching is
  disabled or not configured" — the server omits the cache API both when the
  `cache:` section is absent and when it is present with `enabled: false`, and
  the page cannot tell the two apart — disables the destructive actions, stops
  polling the missing endpoints and surfaces other failures with a retry. The
  Mesh page gained the same treatment for `mesh.enabled: false`
- `GET /api/v1/requests/stats` no longer sizes its aggregation maps to the ring
  buffer length. On a full buffer at the maximum configured size, every poll
  allocated on the order of 170 MB while holding the lock request logging
  writes under; the maps now grow with the number of distinct methods, status
  codes and hosts instead
- The "Skip to main content" link blanked the whole dashboard in both the server
  and the client UI. Both run under a `HashRouter`, where the URL fragment *is*
  the route, so following the link set the route to `main-content`, matched
  nothing and rendered an empty page — the one control provided exclusively for
  keyboard users destroyed the page for them. The link now moves focus
  programmatically, and both routers have a catch-all so no stale hash can blank
  the app
- The Backends page's "Configuration" link left the single-page app: a path
  `href` under a `HashRouter` reloaded the dashboard at `/config`, which made
  every later API call go to `/config/api/v1/…`. Those paths are answered with
  `200 text/html`, so the dashboard degraded silently — empty stats, WebSocket
  dropping to polling, nothing logged. It now navigates within the router, as do
  the four equivalent "go to Settings" links on the client's VPN and Mesh pages
- `/api/v1/ws` accepted a DNS-rebound `Host`. The origin check relies on the
  WebSocket library's same-origin shortcut, which accepts any request whose
  `Origin` host equals the request `Host`; an attacker controlling a DNS name
  could serve a page from it, re-point the name at a Bifrost address, and arrive
  with both headers agreeing. The `Host` must now itself be unforgeable by
  rebinding — an IP literal, a loopback name, or listed in
  `api.allowed_origins`. **Behaviour change:** reaching the dashboard by any
  other hostname (an mDNS name such as `bifrost.local`, or an internal DNS
  record) now requires that host in `api.allowed_origins`; the refusal names the
  setting. `allowed_origins: ["*"]` still disables the check entirely
- A `ca_cert` holding a valid certificate followed by `</ca>` and further
  OpenVPN directives passed validation and was then written into the generated
  profile verbatim, closing the `<ca>` element early and promoting the smuggled
  lines to top-level directives. Profiles now embed the re-encoded certificates,
  so what is emitted is exactly what was validated. No privilege boundary was
  crossed — writing `ca_cert` already implies control of the backend's `binary`
  and `extra_args` — but the guarantee the validator claims now holds
- `api.allowed_origins` accepted `"*"` alongside specific entries, e.g.
  `["https://app.example", "*"]`, which reads as a narrow grant while disabling
  origin checking altogether. The wildcard must now be the only entry
- ProtonVPN API authentication (required for ProtonVPN WireGuard) could not
  succeed against the live API. `/auth/info` returns the SRP modulus as a PGP
  clear-signed message, which was decoded as plain base64, and the proofs used
  textbook SRP-6a over big-endian SHA-512 instead of Proton's little-endian,
  2048-bit expanded-hash, bcrypt-verifier scheme. The exchange now uses Proton's
  own SRP implementation and is pinned to Proton's published test vectors.
  Note: end-to-end verification against the live API was not possible without
  real account credentials
- VPN provider OpenVPN CA certificates supplied via `ca_cert` were only checked
  with `pem.Decode`, so a PEM block containing anything that is not valid DER
  produced a profile the `openvpn` subprocess rejected with an opaque "cannot
  load CA certificate". `ca_cert` and `tls_auth_key` are now validated at
  config-load time (backend construction) and again at profile generation, with
  an actionable error naming the field
- **Mesh P2P handshakes are now authenticated.** Each handshake message carries an
  HMAC-SHA256 authenticator keyed from the static-static X25519 secret, so a host
  must prove it holds the static private key for the public key it claims. Peer
  public keys are distributed by discovery and are not secrets, so previously
  anyone who could reach the mesh UDP port and knew a peer's key could complete a
  handshake in its name, take over that peer's connection slot and endpoint, and
  blackhole it
- **Replayed mesh handshakes are rejected.** Handshake initiations carry a
  strictly increasing timestamp and are refused if not newer than the last one
  accepted for that public key, and handshake responses must echo the timestamp
  of the initiation they answer, so a captured handshake cannot be replayed to
  hijack a connection slot or resurrect old key material
- **Mesh session keys are bound to the handshake transcript.** Key derivation now
  mixes both static public keys, both ephemeral public keys and the handshake
  timestamp into the HKDF info string, so the two ends derive matching keys only
  if they agree on every handshake input
- **Peer authorization is revoked when a peer leaves the mesh.** It previously
  lasted for the lifetime of the process, leaving a departed peer's (non-secret)
  public key able to open new inbound sessions and inject frames into the local
  TUN/TAP device
- `mesh.security.require_encryption: false` was silently ignored; it is now
  normalized to `true` with a warning, so the setting cannot imply a plaintext
  mesh transport that does not exist
- The startup log now states which peer-authorization stance is in effect
  (`allowed_peers` enforced, or discovery-announced peers only), and each inbound
  rejection is logged with its reason
- Mesh data frames whose unused upper nonce bytes are non-zero are rejected, so a
  peer cannot craft distinct nonces that alias a single replay-window slot

> [!IMPORTANT]
> The mesh handshake wire format changed (both messages are now a fixed 105
> bytes). Mesh peers must be upgraded together: a peer running an older build
> cannot complete a handshake with an upgraded one, and logs
> `invalid handshake init: unexpected length (incompatible peer version?)`. The
> handshake has no version-negotiation field, so there is no mixed-version
> fallback. Nothing outside the mesh data plane is affected.

## [1.0.0] - 2026-01-16

### Added
- Initial release of Bifrost Proxy
- HTTP and HTTPS CONNECT proxy support
- SOCKS5 proxy support with authentication
- Multiple backend types:
  - Direct connections
  - WireGuard tunnels (userspace)
  - OpenVPN tunnels (process management)
  - HTTP proxy upstream
  - SOCKS5 proxy upstream
- Domain-based routing with pattern matching
  - Exact match (example.com)
  - Wildcard subdomain (*.example.com)
  - Catch-all (*)
- Authentication modes:
  - None (open proxy)
  - Native (bcrypt passwords)
  - LDAP/Active Directory
  - System (PAM/Directory Services - Linux/macOS only)
- Rate limiting with token bucket algorithm
- Bandwidth throttling
- IP access control (whitelist/blacklist)
- Health checking (TCP, HTTP, Ping)
- Load balancing (Round Robin, Least Connections, IP Hash)
- Prometheus metrics endpoint
- Access logging (JSON, Apache combined format)
- REST API for server and client
- Web UI dashboards with documentation links
- WebSocket support for live updates
- CLI control commands
- System tray integration
- Docker support with docker-compose
- GitHub Actions CI/CD
- Cross-platform builds (Linux, macOS, Windows)
- Systemd and launchd service files
- Self-update capability for binaries
- Comprehensive documentation with MkDocs and GitHub Pages

### Fixed
- Docker health checks now use 127.0.0.1 to avoid IPv6 resolution issues
- Docker client container now has proper configuration with 0.0.0.0 bindings

### Security
- Secure password hashing with bcrypt
- TLS support for listeners
- LDAP over TLS with certificate validation
- System authentication returns explicit error on unsupported platforms (Windows)

### Documentation
- Added platform support matrix for system authentication
- Added Windows authentication troubleshooting guide
- Added Mermaid diagram support

---

## Release Notes

### Upgrade Guide

When upgrading between versions, please note:

1. **Configuration Changes**: Review the configuration documentation for any new required fields or deprecated options.

2. **Breaking Changes**: Major version updates may include breaking changes. Check the changelog for migration steps.

3. **Database Migrations**: If applicable, run any necessary database migrations before starting the new version.

### Support

- For issues: https://github.com/rennerdo30/bifrost-proxy/issues
- Documentation: https://github.com/rennerdo30/bifrost-proxy/wiki
