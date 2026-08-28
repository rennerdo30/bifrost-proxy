# Go backend audit — unfinished code and missing implementations

**Scope:** `internal/` and `cmd/`, excluding `internal/tray/`, `internal/service/`, and the two web
dashboards. **Base:** `master` @ `ba1e826`. **Date:** 2026-08-23.

Every claim below is cited to `file:line` against that commit. Findings are classified as:

- **(a) genuinely unfinished** — the feature does not work and nothing tells the operator so.
- **(b) scoped out, honestly disclosed** — does not work, and code or `docs/` says so.
- **(c) fine** — works; listed only where a previous audit claimed otherwise.

---

## 1. Verdict

The data path is real. HTTP/CONNECT and SOCKS5 proxying, domain routing and matching, all four
load-balancing strategies, rate limiting, access control, the memory/disk/tiered cache, active health
checks, session storage, MITM interception, and the five production backends are genuinely
implemented — not stubs. The auth plugin surface is unusually honest: plugins that cannot work in a
given build report `AvailabilityBuildDisabled` / `AvailabilityUnimplemented` and are refused at
config validation rather than failing quietly at first login. Log rotation, IPv6 address-family
selection, and the network tuning block are all wired.

Two corrections to that generous summary before the gaps. First, the HTTP proxy is **HTTP/1.1-only
and serves exactly one request per connection** — it advertises a persistent connection and then
closes it (§5, tested). That is on the hottest path in the product and is nowhere disclosed. Second,
**IPv6 is claimed unconditionally in `SPECIFICATION.md:42` and is not delivered**: full-tunnel VPN
routes only `0.0.0.0/1` + `128.0.0.0/1` so all IPv6 bypasses the tunnel, and the domain matcher
truncates every IPv6 literal at its last colon so IPv6 routing rules can never match (§5, tested).

The remaining gaps cluster in three places, and they share one shape: **a knob the operator can turn
that is not connected to anything.**

1. **The listener timeout triad does nothing.** `read_timeout`, `write_timeout` and `idle_timeout`
   are declared on every listener, defaulted in both shipped config templates, present in all six
   example configs, and documented across six `docs/` pages — two of which prescribe tuning them to
   fix hangs and connection churn. `idle_timeout` is read nowhere in the module. `write_timeout` is
   read once, to print itself back out. `read_timeout` is silently repurposed as the *outbound dial*
   timeout, which the same doc page explicitly says it is not. Proven empirically: §2.
2. **Failures that report success.** On macOS and Windows a VPN whose routes could not be installed
   still reports `StatusConnected`; per-app split tunnelling on Windows silently never matches
   because of a byte-order bug; the OpenVPN backend's crash detector is structurally incapable of
   firing, so a dead tunnel reports healthy forever. §6, §7.
3. **Silent config loss at the loader.** Unknown and misspelled keys are accepted without a word,
   and any config value containing `$` followed by word characters is truncated by whole-file
   `os.ExpandEnv`. Both proven by test. §2.

Most of these are wiring rather than architecture. The exceptions are HTTP/1.1 keep-alive (§5.1),
which needs a request loop and hop-by-hop handling, and dual-stack addressing (§5, item 10), where
`vpn/tun.go:19`, `device/device.go:86` and `backend/wireguard.go:157` each hold a single address — a
real design change.

Credit where it is due, because it makes the gaps easier to trust: the subsystems that are genuinely
unimplemented — mesh multi-hop peer relay, NTLM verification, ICE — are all **disclosed in code and
fail closed**, with `mesh/config.go:257-258` rejecting `relay_via_peers` outright and NTLM refused at
the plugin, authenticator, and factory layers. SOCKS5's CONNECT-only scope is documented down to the
`0x07` reply byte and its practical consequences. The auth availability machinery
(`internal/auth/availability.go`) is a genuinely good piece of design. `internal/sysproxy` is the
cleanest package in the tree: every platform either does the work or returns `ErrNotSupported`, and
every caller checks. Those are the patterns the findings below should be brought to.

One systemic caveat: **`docs/` is more optimistic than the code in several places** — ICE and TURN
relay are documented as working (`docs/mesh-networking.mdx:15,121,194-240,387-428`), `:808` instructs
the reader to enable the flag that startup rejects, `performance.mdx:201` suggests HTTP/2, and the
listener-timeout pages prescribe tuning inert knobs. A doc that confidently describes something that
does not work costs more than no doc at all, because it sends operators looking for their own mistake.

One process finding: **`go build ./...` does not succeed on a fresh clone.** `internal/api/client/webui.go:13`
and `internal/api/server/webui.go:36` use `//go:embed all:static`; `.gitignore:49-52` excludes those
directories and negates a `.gitkeep` that was never committed (`git ls-files internal/api/*/static`
returns nothing). The web UIs must be built first. `make build` does this via `web-sync`, so it is
not a break in practice, but it means CI-style `go build ./...` / `go vet ./...` over the whole
module cannot run standalone, on any platform.

---

## 2. Config fields that do nothing

### Sweep method (reproducible)

`git grep` over field names is unreliable here — `Enabled`, `Port` and `Timeout` appear on dozens of
unrelated structs. Instead the sweep is **type-checker based**:

1. Load every package in the module with `golang.org/x/tools/go/packages` at
   `NeedTypes|NeedTypesInfo|NeedSyntax|NeedDeps`, `Tests: true` (0 load errors).
2. Collect every struct field carrying a `yaml:` tag in a target config package.
3. Walk every `ast.SelectorExpr` in every package, resolve it through `TypesInfo.Selections`, and
   record the use site whenever the selected `*types.Var` is one of those fields. This resolves
   through embedding and pointer receivers and cannot be fooled by same-named fields on other types.
4. Bucket use sites into *outside the config package*, *inside the config package* (i.e. validation
   and defaulting only), and *tests*.

Run over the five packages that declare operator-facing YAML structs: `internal/config`,
`internal/logging`, `internal/mesh`, `internal/vpn`, `internal/cache` — plus `health`, `accesslog`,
`ratelimit`, `updater`, `p2p`, `accesscontrol`, `debug`, `router` for completeness. That is the
complete YAML surface: `ServerConfig` (`internal/config/server.go:18`) and `ClientConfig`
(`internal/config/client.go:14`) embed types from exactly those packages.

Candidates were then confirmed by hand, because a field can legitimately be read only through an
accessor method (which selector analysis does not see). Three such false positives were cleared and
are **not** reported: `NetworkConfig.IPv6` (read via `AddressFamily()`, `internal/server/server.go:1131,1259`),
`SessionConfig.Store` (via `StoreType()`, `internal/server/server.go:386`), and
`MITMConfig.CACertFile`/`CAKeyFile` (via `LoadCA()`, `internal/server/server.go:275`).

### Findings

| Field (YAML path) | Where parsed | Read anywhere? | Operator-visible consequence |
|---|---|---|---|
| `server.http.idle_timeout`, `server.socks5.idle_timeout`, `proxy.http.idle_timeout`, `proxy.socks5.idle_timeout` | `internal/config/server.go:66` | **No** — zero selector hits in the entire module, tests included | **(a)** Documented on 6 doc pages, defaulted to 60s in both templates (`internal/config/templates.go:14,132`) and all example configs. `docs/troubleshooting/connections.mdx:234-246` and `performance.mdx:169,182` tell operators to raise it to fix hangs and connection churn. Idle CONNECT tunnels are held open until a peer closes; nothing reaps them. |
| `server.http.write_timeout` (+ socks5 / client equivalents) | `internal/config/server.go:65` | **Display only** — `internal/server/server.go:825`, inside `GetSanitizedConfig` | **(a)** The value is echoed back by the config API so it looks applied. No write deadline is ever set. Prescribed by `connections.mdx:234-241`. |
| `server.http.read_timeout` (+ equivalents) | `internal/config/server.go:64` | **Read, but as something else** — `internal/server/server.go:1127` and `internal/client/client.go:572` pass it as `HTTPHandlerConfig.DialTimeout` | **(a)** Silently redefined from "inbound read deadline" to "outbound connect timeout". `connections.mdx:247-249` says the opposite in as many words: *"Outbound dial timeouts are a property of the backend, not the listener."* Raising `read_timeout` to fix a slow client instead lengthens backend connect attempts. The SOCKS5 listener reads no timeout at all. |
| `web_ui.base_path` | `internal/config/server.go:273` | **No** | **(a)**, but milder than it looks — worth stating precisely. `docs/configuration.mdx:179-182` documents it with reverse-proxy guidance and the dashboard has a form field with a leading-`/` validator (`web/server/src/components/Config/sections/WebUISection.tsx:14,20,55`). However the SPA already derives its prefix client-side from `window.location.pathname` (`web/server/src/api/client.ts:46`), so **sub-path serving genuinely works** behind a reverse proxy without the operator setting anything. The Go field is pure decoration: harmless if set, unnecessary if not. The cheapest correct fix is to delete the field and the doc line, not to implement it. |
| `logging.time_format` | `internal/logging/logging.go:19` | **No** — `Setup()` (`:66-105`) never touches it | **(a)** Documented as a working option in `docs/configuration.mdx:119` ("Go time layout for the timestamp") and shown in `monitoring.mdx:403`. Defaulted to an RFC3339-with-ms layout at `:35`. `slog`'s handlers use their own fixed timestamp format, so the timestamp layout is not configurable at all. |
| `backends[].priority` | `internal/config/server.go:100` | **No** | **(a)** Appears in the primary example in `docs/configuration.mdx:33,38` and in the shipped configs. Backend selection is driven entirely by `routes[].priority` (`internal/router/router.go:145`). Two backends distinguished only by `priority` behave identically. |
| `servers[]` — the whole `NamedServer` block (`name`, `address`, `protocol`, `username`, `password`, `is_default`) | `internal/config/client.go:55-62` | **Validation only** — `internal/config/client.go:165-181`; zero reads outside the config package | **(a)** Multi-server management is fully parsed and carefully validated (duplicate names, `host:port` form, protocol enum) and then never consulted. The client always uses the single `server:` block. An operator who defines named servers with `is_default: true` gets no error and no effect. |
| `server.tls` (client → upstream) | `internal/config/client.go:45` | **No** — zero reads, zero test reads | **(a)** The client reads `Address`, `Protocol`, `Username`, `Password`, `Timeout`, `RetryCount`, `RetryDelay` from `ServerConnection` (`internal/client/client.go:118-124`) and never `TLS`. `internal/backend/httpproxy.go` contains no TLS handling at all. `server.tls.enabled: true` yields a plaintext upstream connection with no warning. Security-relevant. |
| `proxy.http.tls`, `proxy.socks5.tls` (client listeners) | `internal/config/server.go:63`, reused by `ClientProxySettings` | **No on the client** | **(a)** `ListenerConfig` is shared between server and client. The server honours `TLS`; the client calls plain `net.Listen("tcp", …)` (`internal/client/client.go:187,200`). A TLS block on a client listener is silently ignored. |
| `proxy.http.max_connections`, `proxy.socks5.max_connections` (client) | `internal/config/server.go:67` | **No on the client** | **(a)** Same struct-reuse issue. The server enforces it (`internal/server/server.go:1186,1311`); the client has no accept-side limit. |
| `mesh.stun.timeout` | `internal/mesh/config.go:83` | **No** | **(a)** `internal/mesh/node.go:377-390` builds `p2p.ManagerConfig` and passes `STUN.Servers` but never `STUN.Timeout`; the TURN timeout on the adjacent line is hardcoded to `30 * time.Second` (`node.go:373`). |
| `mesh.turn.*` — the **entire** TURN block (`enabled`, `servers[].url/username/password`) | `internal/mesh/config.go:86-96` | **Set, then dropped on the floor** | **(a)** `internal/mesh/node.go:369-381` builds a `p2p.TURNConfig` and assigns it to `ManagerConfig.TURNConfig` (`internal/p2p/manager.go:74`) — which **nothing ever reads**. `NewP2PManager` constructs the relay manager from `config.RelayConfig` only (`internal/p2p/manager.go:174`), and it is `RelayConfig.TURNConfig` (`internal/p2p/relay.go:59`) that `NewRelayManager` consumes (`relay.go:120-121`). `ManagerConfig.RelayConfig` is left at `DefaultRelayConfig()` with a nil TURN config. **Consequence:** with `turn.enabled: true` and valid credentials, `RelayManager.Start` returns immediately (`relay.go:129-131`), no TURN client is ever created, and `GetBestRelay` always returns `ErrRelayNotAvailable`. Mesh relaying is inoperative and nothing says why. Also makes the "only `servers[0]` is used" truncation at `node.go:367-368` moot. |
| `auth.providers[].config.required_claims` (oauth) | `internal/auth/plugin/oauth/oauth.go:194-203`, declared `:154`, schema `:136` | **Parsed, never enforced** — no read outside two tests | **(a)**, security-relevant. `introspectToken` (`:320-387`) checks only `active` + scopes; `getUserInfo` (`:390-437`) checks nothing. An operator restricting a provider by `aud`/`iss` gets no restriction — every token the IdP calls active is accepted, and `ValidateConfig` (`:73`) reports success. Doubly broken: the dashboard submits a `stringlist` (`web/server/src/components/Config/auth-forms/AuthProviderConfigForm.tsx:49`) but the parser accepts only a map, so the value is discarded before it reaches the unenforced field. |
| `auth.providers[].config.verify_time` (mtls) | `internal/auth/plugin/mtls/mtls.go:224` | **Read, but inert** — `:388-390` | **(a)**, cosmetic. `opts.CurrentTime` is set only when the flag is true; `crypto/x509` treats the zero value as `time.Now()`, so validity is checked either way. Fails closed, so not a security hole — but the UI checkbox (`AuthProviderConfigForm.tsx:67`) does nothing and an operator will chase a phantom misconfiguration. |
| `health_check.timeout` when `type: ping` | `internal/health/ping.go:20-23,33` | **Stored, never read** | **(a)** The subprocess uses hardcoded `-w 5000` / `-W 5000` / `-W 5` (`:47-51`) and the manager wraps a hardcoded 10s (`internal/health/manager.go:141`). `timeout: 1s` still blocks 5-10s per probe, so failure detection is 5-10× slower than configured while the setting appears accepted. |
| `health_check.type` (unrecognised values) | `internal/health/checker.go:65-66` | **Silently substituted** | **(a)** `default: return NewTCPChecker(cfg)` with no log, and `HealthCheckConfig.Validate` (`internal/config/server.go:408-440`) never validates `Type`. A typo (`htpp`) or an unsupported value (`grpc`) yields a bare TCP connect that reports green for a backend whose application layer is dead — and `Checker.Type()` then answers `"tcp"`, hiding the substitution from the API too. |
| `backends[].config.max_load`, `.auto_select` (mullvad, pia) | `internal/backend/mullvad.go:204-211`; `internal/backend/pia.go:254-261` | **Read, but inert** | **(a)** `Server.Load` is hardcoded to 0 by both providers (`internal/vpnprovider/mullvad/servers.go:54`; `pia/servers.go:70`), so the filter guard `MaxLoad > 0 && s.Load > MaxLoad` (`internal/vpnprovider/cache.go:152`) never trips and `sortByLoad` (`:245-254`) is a no-op. `max_load: 30` always yields the same first API-order relay while `"selected server"` is logged as if the criteria applied. (`Server.Latency` is likewise never written by any provider.) |
| `network.ipv6` / address family, for the proxy-chaining backends | `internal/config/network.go:21` | **Read, but two backends discard it** | **(a), partial.** `internal/server/server.go:1131,1259` correctly pass `AddressFamily()` down as `DialNetwork`, but `HTTPProxyBackend.Dial` (`internal/backend/httpproxy.go:88`) and `SOCKS5ProxyBackend.Dial` (`internal/backend/socks5proxy.go:99`) ignore the `network` argument and hardcode `"tcp"` / `LookupPort("tcp", …)` (`socks5proxy.go:224`). `ipv6: false` is therefore honoured by `direct` and `wireguard` but not by upstream-proxy backends. |
| `tray.window_x`, `tray.window_y` | `internal/config/client.go:88-89` | **No** | **(a)** Reported for completeness; `internal/tray/` is another agent's scope, but the sweep covers the whole module and found no reader there either. |
| `debug.filter_domains` | `internal/config/client.go:78` | **No** | **(b)** Honestly disclosed as `not yet implemented` / `(reserved)` in `docs/features/traffic-debugging.mdx:122,136`. **But** the shipped template (`internal/config/templates.go:59`) and `configs/client-config.example.yaml:56` describe it as *"Only capture traffic for these domains (optional)"* with no caveat, and `docs/desktop-client.mdx:182-184` lists it among the settings the debug section "controls". Disclosure should be pushed into the templates. |
| `auth.native`, `auth.system`, `auth.ldap`, `auth.oauth` and all their sub-fields (`LDAPAuth.*`, `OAuthAuth.*`, `NativeAuth.Users`, `SystemAuth.*` — 21 fields) | `internal/config/server.go:192-228` | **Outer pointer only, for rejection** | **(b)** Correct and deliberate: `internal/config/server.go:688-691` and `internal/server/server.go:415-421` hard-reject the legacy block with a migration message. The sub-fields exist purely so the shape parses. Consider collapsing them to `map[string]any` so the sweep stops flagging 21 phantom fields. |

### Two loader defects that make any config field unreliable

Both proven with a throwaway test in `internal/config` (written, run, deleted):

**Unknown and misspelled keys are accepted silently.** `internal/config/config.go:30` uses
`yaml.Unmarshal`, not a `yaml.Decoder` with `KnownFields(true)`.

```
=== RUN   TestAuditUnknownKeysSilentlyIgnored
    PROVEN: typo'd key accepted silently; Server.HTTP.Listen="" (empty => listener would not bind)
--- PASS
```

The input was `server.http.listem: ":9999"` (one-letter typo) plus a wholly invented top-level key.
Neither produced a diagnostic. **(a)** — the highest-leverage single fix in this report, because it
converts every future config mistake from silent to loud.

**Any value containing `$` is truncated.** `internal/config/config.go:28` applies `os.ExpandEnv` to
the whole file *before* YAML parsing, so `$` in a literal value is treated as a variable reference.

```
=== RUN   TestAuditExpandEnvMangling
    PROVEN: literal secret "p@ss$word123" loaded as "p@ss"
--- PASS
```

`docs/configuration.mdx:310-317` discloses the *adjacent* gotcha (`${VAR:-default}` expands to
empty) but not this one, and there is no escape syntax — YAML quoting cannot help, because expansion
runs on raw bytes first. A password, API key, or bcrypt hash containing `$` is silently corrupted and
authentication then fails for no visible reason. **(a)**, security-relevant.

### Fields read but ineffective (a class the sweep cannot see)

Selector analysis proves a field is *read*; it cannot prove the read has an effect. Two confirmed
instances, both from reading the consuming code:

- `vpn.split_tunnel.ips`, `.apps`, `.always_bypass` — parsed and passed to the matcher, but
  `SplitTunnelConfig.Validate()` (`internal/vpn/splittunnel.go:76-84`) validates only `Mode`, and the
  per-entry errors from `IPMatcher.Add` / `AppMatcher.AddRule` are discarded at
  `internal/vpn/splittunnel.go:116,125,144`. A malformed CIDR is dropped with no log and no startup
  error. In `include` mode the default action is bypass (`:231`), so a dropped include rule sends that
  traffic **outside** the tunnel in cleartext. **(a)**, security-relevant.
- `routes[].domains` — `matcher.New` discards every `AddPattern` error
  (`internal/matcher/matcher.go:40`, comment: *"Silently skip invalid patterns during construction"*).
  An invalid pattern, or any pattern past `MaxPatterns = 5000`, is dropped without a log; those
  domains fall through to the default backend. **(a)** — disclosed in a code comment, not to the
  operator.

---

## 3. Incomplete interface implementations

A complete `^type X interface` sweep finds **35 interface declarations** in scope; `cmd/` declares
none. Method bodies were read; tests and names were deliberately not used as evidence.

**Legend:** REAL · STUB-HONEST (clear not-supported error) · **STUB-SILENT** (zero value / nil / no-op
while the caller believes it worked — a defect) · NO-OP-BY-DESIGN (nothing to do, e.g. `Close` on a
stateless type).

Fully-REAL implementations are collapsed to one row; methods are enumerated only where something is
not REAL.

### `backend.Backend` (8 methods) — `internal/backend/backend.go:14`

| Implementation | Method | Status | file:line | Note |
|---|---|---|---|---|
| `*DirectBackend` | all 8 | REAL | `direct.go:79-200` | real dialer, ctx-deadline narrowing, live atomics |
| `*WireGuardBackend` | all 8 | REAL | `wireguard.go:72-262` | netstack TUN, in-tunnel DNS, honours `network` |
| `*MullvadBackend` | all 8 | REAL | `mullvad.go:97-427` | real delegate build/swap |
| `*NordVPNBackend` | all 8 | REAL | `nordvpn.go:102-453` | |
| `*PIABackend` | all 8 | REAL | `pia.go:125-517` | port forwarding fails closed (`:549-556`) |
| `*ProtonVPNBackend` | all 8 | REAL | `protonvpn.go:117-474` | |
| `*HealthWrappedBackend` | all | REAL | `health_override.go:32-79` | decorator |
| `*HTTPProxyBackend` | `Dial` | REAL, ignores `network` | `httpproxy.go:88` | see §2 (`network.ipv6` partial) |
| | other 7 | REAL | `httpproxy.go:78-227` | |
| `*SOCKS5ProxyBackend` | `Dial` | REAL, ignores `network` | `socks5proxy.go:99,224` | same |
| | other 7 | REAL | `socks5proxy.go:89-363` | |
| `*OpenVPNBackend` | `IsHealthy` | **STUB-SILENT in effect** | `openvpn.go:459` | reads a flag no live code path can clear — §7.1 |
| | `Start` → `queryLocalAddress` | **STUB-SILENT** | `openvpn.go:329-357`, called `:281-284` | returns `nil` with `localAddr` still empty |
| | `Stop` | **STUB-SILENT** on the no-management path | `openvpn.go:405-455` | kills the exited `--daemon` stub, returns `nil` |
| | `Name`,`Type`,`Dial`,`DialTimeout`,`Stats` | REAL | `openvpn.go:94,99,125,181,464` | |
| `*client.ClientBackend` | `IsHealthy` | **STUB-SILENT** | `internal/client/backend.go:71-73` | `return true` even when `serverConn` is dead |
| | `Stats` | **STUB-SILENT** | `internal/client/backend.go:76-82` | fixed `Healthy:true`, all counters 0 |
| | `Start`, `Stop` | NO-OP-BY-DESIGN | `internal/client/backend.go:61,66` | stateless per-request value |
| | `Name`,`Type`,`Dial`,`DialTimeout` | REAL | `internal/client/backend.go:19,27,32,40` | |

The factory is honest: unknown type → `ErrInvalidBackendType` (`factory.go:42-61`), and every provider
validates required credentials. `leakProofRouter` (`leakproof.go:21`): Linux both REAL
(`leakproof_linux.go:88,126`); `unsupportedLeakProofRouter.Install` STUB-HONEST (`leakproof.go:38`),
`.Remove` NO-OP-BY-DESIGN (`:42`) — correct, nothing was installed.

### Auth: `Authenticator` (3) / `Plugin` (6) / `AvailabilityReporter` (1)

| Implementation | Method | Status | file:line | Note |
|---|---|---|---|---|
| `chain`, `bruteforce`, `mfa.Wrapper`, `native`, `ldap`, `apikey`, `jwt`, `kerberos`, `totp`, `hotp`, `system`(windows) | all 3 | REAL | `chain.go:49`; `bruteforce_authenticator.go:66`; `mfa/wrapper.go:103`; `plugin/native/native.go:212`; `plugin/ldap/ldap.go:234`; `plugin/apikey/apikey.go:289`; `plugin/jwt/jwt.go:306`; `plugin/kerberos/kerberos.go:233`; `plugin/totp/totp.go:336`; `plugin/hotp/hotp.go:319`; `plugin/system/system_windows.go:200` | real credential verification in every case |
| `none.Authenticator` | all 3 | REAL by contract | `plugin/none/none.go:58,65,70` | returning `anonymous` *is* the spec |
| `oauth.Authenticator` | `Authenticate` | REAL, `required_claims` unenforced | `plugin/oauth/oauth.go:248` | §2 — security-relevant |
| `mtls.Authenticator` | `Authenticate` | REAL, `verify_time` inert; CRL fails **open** | `plugin/mtls/mtls.go:285,388-390,73-77` | §7-adjacent; see below |
| `ntlm.Authenticator` | `Authenticate`, `ValidateAuthenticate` | STUB-HONEST | `plugin/ntlm/ntlm.go:223,242,320,560` | `ErrVerificationUnsupported`; refused at plugin (`:113`), authenticator, **and** factory layers |
| `system.Authenticator` (!windows) | `validateLinux` (stub build) | STUB-HONEST | `plugin/system/pam_stub.go:45-50` | warns; `AvailabilityBuildDisabled` |
| | `validatePassword` default branch | STUB-HONEST | `plugin/system/system.go:258-264` | |
| `system.plugin.Availability` | | **STUB-SILENT** on non-linux/darwin Unix | `plugin/system/system.go:92-100` | see below |
| all 11 other plugins | all 6 | REAL (`none.ValidateConfig` NO-OP-BY-DESIGN, `none.go:33`) | per-plugin | every `ValidateConfig` delegates to a real parser |
| `negotiate.AuthenticatorGetter` | — | **zero implementations** | `internal/auth/negotiate/handler.go:53-55` | declared, never implemented, never referenced — see §4 |

**An unreadable mTLS CRL fails open with one warning.** `plugin/mtls/mtls.go:73-77` logs
`slog.Warn("failed to load CRL")` and returns a working authenticator with an empty `revokedSerials`;
`validateCertificate` (`:397-403`) then finds nothing revoked. A typo'd `crl_file` means **revoked
client certificates authenticate successfully**, with no runtime signal. **(a)**, security-relevant —
this belongs in the P0 list and is the most serious single finding in the auth cluster.

**`system` auth reports "available" on Unix platforms with no password backend.** `system.go:92-100`
guards on `GOOS == "linux" && !pamCompiled`, but the file's build tag is `//go:build !windows`, so it
also compiles on the BSDs and Solaris where `validatePassword` falls to the `default:` branch and
returns false (`:258-264`). The plugin listing shows **Available**, config validation passes, no
startup warning fires, and every login fails as `ErrInvalidCredentials`. Mitigated by the Makefile
shipping only linux/darwin/windows — but `docs/troubleshooting/faq.mdx:31` advertises FreeBSD.

### Cache stores: `cache.Storage` (11 methods)

| Implementation | Method | Status | file:line | Note |
|---|---|---|---|---|
| `*DiskStorage` | all 11 | REAL | `internal/cache/disk.go` | persistence traced `Put`→`saveMetadata`(`:718`)→`loadIndex`(`:615`); real `Seek` in `GetRange`(`:386`) |
| `*MemoryStorage` | 10 of 11 | REAL | `memory.go:92,132,207,222,240,262,298,337,354,389` | `List` honours domain/offset/limit (`:316-326`); `GetRange` really slices (`:285-294`) |
| | `Start` | NO-OP-BY-DESIGN, with a gap | `memory.go:375` | starts no TTL reaper, and `CleanupExpired` (`:482`) has **no non-test caller**, so reported sizes over-count expired entries indefinitely |
| `*TieredStorage` | all 11 | REAL | `internal/cache/tiered.go` | but `Stats` is systematically skewed — below |
| all three | `attachMetrics` | REAL | `memory.go:51`, `disk.go:64`, `tiered.go:50` | |

**The tiered cache double-counts every disk hit as a memory miss.** `TieredStorage.Get`
(`tiered.go:108-114`) calls `memory.Get` (increments `missCount`, `memory.go:102`) and then
`disk.Get` (increments `hitCount`, `disk.go:202`); `Stats` sums both (`tiered.go:309-310`) into
`HitRate` (`cache.go:474-476`). With `storage.type: tiered`, a workload served entirely from disk
reports a hit rate of 0.5 instead of 1.0 — any alert keyed on cache hit rate is wrong by up to 2×.
**(a)**. Separately, `Put` (`tiered.go:118,150-162`) is *exclusive placement*, not write-through;
whether `docs/` says so was not checked.

### Health checkers: `health.Checker` (2 methods)

| Implementation | Method | Status | file:line | Note |
|---|---|---|---|---|
| `*TCPChecker` | both | REAL | `internal/health/tcp.go:28,59` | |
| `*HTTPChecker` | both | REAL | `internal/health/http.go:56,101` | scheme + `insecure_skip_verify` honoured |
| `*PingChecker` | `Check` | REAL, configured timeout dropped | `internal/health/ping.go:38` | genuinely execs `ping`; no fake always-healthy path. §2 |
| | `Type` | REAL | `internal/health/ping.go:86` | |

`health.New` silently substitutes TCP for any unrecognised type (`checker.go:65-66`) — §2.

### VPN providers: `vpnprovider.Provider` (7 methods)

| Implementation | Status | file:line | Note |
|---|---|---|---|
| `nordvpn.Client` | all 7 REAL | `nordvpn/client.go:91,96,101,106,300,336,369` | OpenVPN config fully built; fails closed without an operator CA |
| `protonvpn.Client` | all 7 REAL | `protonvpn/client.go:126,133,138,143,269,296,330` | `SupportsWireGuard()` is a genuine capability check; refuses honestly at `:297` |
| `mullvad.Client` | all 7 REAL, `max_load`/`auto_select` inert | `mullvad/client.go:103-252`; `servers.go:54` | §2 |
| `pia.Client` | all 7 REAL, same | `pia/client.go:126-404`; `servers.go:70` | §2 |
| `protonvpn.MemorySessionStore` | all 3 REAL | `protonvpn/auth.go:117,125,132` | the only impl, despite the doc at `:95` implying a file/keychain store |

Note the interface has **zero non-test consumers** and no `var _ Provider` assertions — backends hold
concrete client types. See §4.

### VPN / device / sysproxy platform interfaces

Covered in the §6 matrix. Summary of the non-REAL cells: `noopRouteManager` STUB-HONEST on
`Setup`/`AddBypassRoute`/`RemoveBypassRoute` (`routes_other.go:17,25,29`) with `Cleanup`
NO-OP-BY-DESIGN (`:21-23`, correct — `Setup` always fails so nothing was installed);
`noopProcessLookup.LookupBySocket` **STUB-SILENT** (`process_other.go:10-12`);
`windowsTAP.SetMACAddress` STUB-HONEST (`tap_windows.go:377-382`); `windowsTUN.Index` **STUB-SILENT**
but callerless (`tun_windows.go:217-219`); `sysproxy.unsupportedManager` STUB-HONEST both methods
(`sysproxy_other.go:15,19`) with every caller checking `errors.Is(err, ErrNotSupported)`.

**`sysproxy` is the cleanest cluster in the audit** — no method on any platform returns `nil` without
acting. It is the pattern the VPN route/DNS layer should be brought to.

One extra: `windowsTUN.Read` (`tun_windows.go:145-164`) never waits on `ReadWaitEvent()`, so it
hot-spins; the caller (`internal/vpn/vpn.go:314-323`) logs and continues, producing an error-log flood
when the interface is idle. REAL but pathological.

### `p2p.P2PConnection` (10 methods)

| Implementation | Method | Status | file:line | Note |
|---|---|---|---|---|
| `DirectConnection` | 8 of 10 | REAL | `p2p/connection.go:477-534,544` | real handshake, crypto, workers |
| | `Latency` | REAL value, fabricated source | `connection.go:512`, written `:464-471` | below |
| `RelayedConnection` | 8 of 10 | REAL but unreachable | `connection.go:693-758` | below |
| | `Latency` | **STUB-SILENT** | `connection.go:728` | the only `latency.Store` sites (`:335`, `:469`) are both `DirectConnection` ⇒ always 0 |
| | `RemoteAddr` | **STUB-SILENT** | `connection.go:749-751` | returns the zero `netip.AddrPort` |
| `PeerRelayedConnection` | 7 of 10 | REAL, type unwired | `p2p/relay.go:398-473` | see §4 |
| | `Receive` | **STUB-SILENT** | `relay.go:417-427` | `nil, nil` after close |
| | `RemoteAddr` | **STUB-SILENT** | `relay.go:453-455` | zero value |

**The relay path builds a connection and never connects it.** `tryRelayConnect`
(`p2p/manager.go:377-398`) calls `CreateRelayedConnection` → `NewRelayedConnection`
(`connection.go:579`, which leaves `state = New`) and returns **without ever calling
`RelayedConnection.Connect`** (`:597` — zero non-test callers). `Connect` then logs *"relay connection
established"* (`manager.go:296`) and fires `OnPeerConnected`. `Send` returns `ErrNotConnected` forever
(`:698`), and `connectionMonitor` only reaps `Failed`/`Disconnected` (`manager.go:899`), so state
`New` is never cleaned up. **Consequence:** the operator sees a connected, counted peer
(`manager.go:971,980`) that carries no traffic, with a success log line. Fails closed
security-wise; an availability and observability defect. **(a)**. Note this is downstream of the
`mesh.turn.*` finding in §2 — with TURN discarded there is no relay to connect to in the first place.

**Relayed-peer latency is always 0, and inbound direct-peer latency is fabricated.** Beyond the
`RelayedConnection.Latency` stub, `DirectConnection`'s keep-alive latency (`connection.go:464-471`)
never observes the PONG (`recvWorker` discards it, `:419-421`) and `ReadTimeout` is never set by
either construction site (`manager.go:307-313,698-704`), so for inbound peers the stored value is
however long a `WriteTo` took. Both feed `MeshNode.onPeerConnected` → `peer.SetLatency`
(`internal/mesh/node.go:1016,1021`) → `MeshRouter.AddDirectRoute`'s `pathCostFunc(latency, 1)`
(`internal/mesh/router.go:159`). **Consequence:** relayed and inbound peers always score as the
cheapest route, and `RelayManager.GetBestRelay`'s `r.Latency < best.Latency` (`relay.go:201`) can
never order relays. The zero `RemoteAddr` additionally blanks the endpoint in `/api/mesh/peers`
(`manager.go:931,948`). **(a)**.

### Remaining interfaces — all clean

| Interface | Implementations | Status |
|---|---|---|
| `router.LoadBalancer` (`router.go:169`) | `RoundRobin`, `LeastConn`, `IPHash`, `Weighted` | all REAL and genuinely distinct (`loadbalancer.go:16,41,68,104`); weighted really expands by `weight` (`:116-124`) and `seedRouteWeights` (`internal/config/server.go:645-676`) propagates the config field |
| `config.Validator` (`config.go:58`) | 7 impls | all REAL, none returns a bare `nil`. `mesh.Config.Validate` **rejects** `relay_via_peers: true` (`mesh/config.go:250-256`) — fail-closed |
| `mesh.IPAllocator` (`ipam.go:12`) | `PoolAllocator` | all 7 REAL (`ipam.go:45-285`) |
| `ratelimit.Limiter` (`limiter.go:11`) | `TokenBucket` | all 4 REAL (`token_bucket.go:31,36,52,57`) |
| `accesslog.Logger` (`logger.go:15`) | `JSONLogger`, `ApacheLogger`, `NoopLogger` | JSON both REAL (`:126,140`); Apache REAL but **lossy** — emits `Host` where `Path` belongs and drops `Entry.Path` entirely (`:156,167-178`); Noop NO-OP-BY-DESIGN (`:99,104`), returned only when disabled |
| `updater.Notifier` (`updater.go:29`) | 2 impls | both REAL (`internal/server/autoupdate.go:26`; `internal/client/client.go:443`) |
| `proxy.InterceptLogger` (`mitm_intercept.go:24`) | `*debug.Logger` | both REAL (`internal/debug/logger.go:109,133`) |
| `apiclient.VPNManager` (`api/client/server.go:43`) | `*vpn.Manager` | all 13 REAL (`internal/vpn/vpn.go:930-1236`) |
| `apiclient.MeshManager` (`api/client/server.go:69`) | `meshManagerAdapter` | all 10 REAL (`internal/client/mesh.go:13-29`; `internal/mesh/node.go:110-305`) |
| `apiclient.CacheManager` (`api/client/server.go:60`) | `*cache.Manager` | all 5 REAL but **never wired** — see §4 |
| `backend.HealthOverride`, `backend.portForwardRunner`, `cache.metricsSink`, `session.redisClient`, `proxy.tlsConnectionStater` | one real impl each (or stdlib) | REAL |
| `matcher` | declares **no** interface — `matcher.Matcher` (`matcher.go:23`) is a concrete struct | all 6 methods REAL |

### Lower-severity silent stubs, no current consumer

`NATDetector.Detect` hard-codes `isBehindNAT := true` (`internal/p2p/nat.go:122`) and
`Hairpin: false` (`:154`) as detection *results*. `windowsTUN/TAP.configure` discards the MTU `netsh`
failure (`tun_windows.go:114-117`; `tap_windows.go:256-259`) while `MTU()` reports the requested
value. `oauth.MemoryTokenStore` (`plugin/oauth/authcode.go:472,485,503`) is all-REAL but the whole
auth-code subsystem has no production caller.

---

## 4. Dead / unreachable code

### Method (reproducible)

Three independent passes, because each has a blind spot:

1. **SSA reachability** — `golang.org/x/tools/cmd/deadcode` v0.49.0, built offline from the module
   cache, with both `cmd/server` and `cmd/client` as roots:
   `deadcode -filter='' -f='{{range .Funcs}}{{.Position}}\t{{.Name}}\n{{end}}' ./cmd/...`, filtering
   GOROOT and `pkg/mod`. **236 unreachable funcs in scope, 198 exported.** Repeated for
   `GOOS=linux` and `GOOS=windows`; darwin's dead set is a strict subset of Linux's, plus 6
   platform-local entries.
2. **Textual cross-check** — a script parsing every exported decl in scope, stripping
   comments/strings/rune literals, then counting identifier occurrences across all non-test Go files
   in the module plus `desktop/`. **237 hits**, split into TEST-ONLY vs NO-USE-AT-ALL. This pass is
   necessary because **`deadcode` under-reports**: `-whylive` on `(*API).Router` answers *"reachable
   only through reflection"*, so methods on reflected types never appear in its dead list.
3. **Route diff** — every `r.Get/Post/Put/Delete/Patch/Handle/Route` in `internal/api/{server,client}`
   enumerated and diffed against callers in `web/*/src/`, `internal/cli/*/commands.go`, and `docs/`.

Branch analysis: `go vet` (including `unreachable`) is clean for all three GOOS, and
`golangci-lint 2.13.1` with `unused,staticcheck,unparam` produced **zero `SA4020`/`SA4003`/`SA9003`** —
no impossible switch cases and no dead branches. `Factory.Create`'s `default:`
(`internal/backend/factory.go:59`) was hand-checked and *is* reachable, since the add-backend API
accepts arbitrary type strings.

Every headline finding below was hand-verified with grep. The ~198-entry long tail was **not**
individually checked for reflective or `init()`-registry reachability — see "what I did not verify".

### Findings

`ICEAgent` (`internal/p2p/ice.go:142-568`) and `RelayRouter` (`internal/p2p/relay.go:562-638`) are
confirmed still unwired and are **excluded** from this table per the prior decision to keep them.

| Symbol / route | file:line | Evidence of no use | Verdict | Reasoning |
|---|---|---|---|---|
| `logging.Close()` | `internal/logging/logging.go:54` | **Zero callers anywhere** — verified independently: `git grep logging.Close` over `internal cmd desktop` returns nothing. `Server.Stop` (`internal/server/server.go:707`) and the client shutdown never call it | **COMPLETE** | `CLAUDE.md` states *"**Must call `logging.Close()` on shutdown** to release file handles"*. `rotate.go:129` has a real `Close()`. A one-line `defer logging.Close()` in both shutdown paths; deleting it would delete a documented contract and leak the log file handle on every restart. |
| `/debug/pprof/*` — 11 routes | `internal/api/client/server.go:443-455` | Registered only inside `addAPIRoutes`, which is only called from `Handler()`; production uses `HandlerWithUI()` (`internal/client/client.go:249`). `HandlerWithUI` (`:273-373`) has no pprof subtree, and its `r.Mount("/", StaticHandler())` swallows `/debug/*` | **COMPLETE** | `docs/api/client.mdx:1187-1215` documents all 11 endpoints with copy-paste `curl` / `go tool pprof` examples, as does `troubleshooting/diagnostics.mdx:406-410`. A documented diagnostic feature with no reachable implementation — and the first thing anyone reaches for when investigating the goroutine leak in §2. |
| `(*API).Handler`, `(*API).addAPIRoutes`, `securityHeadersMiddleware` | `internal/api/client/server.go:240,399,615` | Only callers are `_test.go` — **correction: `securityHeadersMiddleware` is now live**, `HandlerWithUI` uses it since the headers were moved there; only `Handler` and `addAPIRoutes` were removed | **REMOVE** — but move pprof and the headers into `HandlerWithUI` first | A duplicate hand-maintained route table that **has already drifted**: `Handler()` has pprof and global security headers, `HandlerWithUI` has neither. Consequence: the client's static UI responses carry **no CSP / `X-Frame-Options` / `nosniff`** — `apiSecurityHeaders` (`:376`) is scoped to `/api` only — whereas the server applies `securityHeadersMiddleware` globally (`internal/api/server/server.go:224`). Security-relevant. |
| `(*API).Router` | `internal/api/server/server.go:177` | Called only from `server_test.go` (28×) and `mesh_store_test.go`; hidden from `deadcode` as "reachable only through reflection" | **RESOLVED, not by deletion** | The duplication is already gone: `Router()` and `RouterWithWebSocket` both call the same `addAPIRoutes`, so there is one source of route truth and the drift this row describes can no longer happen. What remains is a thin, documented variant for embedders that mount only the REST surface — no production caller, but 73 test call sites and a real API contract. Deleting it now would churn those tests without preventing any defect. Contrast the client-side twin (`internal/api/client`), where the two tables were genuinely separate, had drifted, and that drift cost the static UI its security headers — that one was removed. |
| Brute-force protection: `BruteForceProtector`, `BruteForceAuthenticator` | `internal/auth/bruteforce.go:1-239`; `internal/auth/bruteforce_authenticator.go:1-105` | Nothing constructs either outside tests. `grep -i 'bruteforce\|brute_force'` over `internal/config/`, `configs/`, `docs/` → **zero hits**: no YAML key, no docs | **COMPLETE** | `TODO.md:986-993,1556` marks this **"✅ FIXED — No Brute Force Protection"**. It is a security control the project believes it ships and does not. `BruteForceAuthenticator` is already a drop-in `Authenticator` decorator with `Unwrap()`, so wiring is a config key plus one wrap in the chain build. **This is the highest-value item in this section.** |
| `POST /api/v1/login`, `POST /api/v1/logout`, and the `internal/auth/session` public API | `internal/api/server/server.go:231,305`; `internal/auth/session/manager.go:142,162,172,257,281,287` | No caller anywhere: `web/server/src/api/client.ts:61-66` reads `localStorage['bifrost_api_token']` and sends `Authorization: Bearer`; `internal/cli/server/commands.go` never hits `/login`. `ValidateSession`, `DestroyUserSessions`, `ListUserSessions`, `OptionalMiddleware` are test-only | **COMPLETE** | The server half of the token-exchange → HttpOnly-cookie flow is fully built and config-gated (`buildSessionManager`, `internal/server/server.go:384`), but the SPA half was never written — so the dashboard still keeps a bearer token in `localStorage`, which is exactly what the session flow exists to avoid. Note this also means the entire `session.*` config block (§2 cleared it as "read via `StoreType()`") is reachable but never exercised in practice. |
| `HashPassword` ×2 | `internal/auth/helpers.go:13`; `internal/auth/plugin/native/native.go:279` | Both test-only; no CLI command, no `cmd/` caller | **COMPLETE** (one) + **REMOVE** (the duplicate) | Verified independently: `docs/authentication.mdx:118`, `troubleshooting/authentication.mdx:82` and `troubleshooting/faq.mdx:140` all tell users to run `go run github.com/rennerdo30/bifrost-proxy/tools/hashpw password`, and **`tools/` does not exist in the repo**. A documented `python3 -c "import bcrypt…"` alternative sits alongside, so users are not fully blocked — but there is no *shipped* way to mint a `password_hash` for `native` auth while two identical bcrypt helpers sit unused. Wire one into the CLI. |
| `internal/auth/middleware.go` — the whole 385-line file (`NewMiddleware`, `Handler`, `ProxyHandler`, `Authenticate`, `AuthenticateForProxy`, `SetAPIKeyAuth`, `MultiAuthHandler`, `MultiProxyAuthHandler`, `tryClientCert`, `setUserContext`, `GetUserInfo`, `GetClientCert`, `ExtractBearerToken`) | `internal/auth/middleware.go:43-370` | Zero non-test references to `NewMiddleware` / `Middleware{`. Production auth is inline: `internal/proxy/http.go:251-260` parses `Proxy-Authorization`, `internal/server/server.go:1448` calls `s.authenticator.Authenticate` | **REMOVE** | A parallel abstraction for a job the live code already does differently, and actively misleading: `tryClientCert` (`:330`) implies mTLS-via-middleware is the real path when it is not. Its `util` import is also what keeps several dead `internal/util` helpers looking referenced. **Correction (applied 2026-08-28):** the file was *not* wholly dead. `ExtractProxyBearerToken` is called from `internal/proxy/http.go:515`, and `ClientCertContextKey` / `ClientCertChainContextKey` (plus the `ContextKey` type) are used by `internal/proxy/http.go` and aliased by `internal/auth/plugin/mtls`. Deleting the file wholesale breaks the build. Those four symbols were preserved (`context.go`, `helpers.go`); only the middleware itself was removed. Note `ExtractBearerToken` — the Authorization-header twin — *is* dead and was removed. |
| `internal/util` dead subset — `WrapError`, `WrapErrorf`, `IsNotFound`, `IsAuthError`, `NewMultiError` + `MultiError.*`, `SplitHostPort`, `JoinHostPort`, `IsLocalAddress`, `GetOutboundIP`, `ParseCIDR`, `IPInNetworks`, `GetStartTime`, `GetDuration`, `GetDomain` | `internal/util/errors.go:25,33,41,51,61,66,73,81,92`; `network.go:16,36,41,63,77,96`; `context.go:64,72,99` | All test-only in both passes. The package *is* imported, but only for the request-ID / username / client-IP context helpers and `OpenURL` | **REMOVE** | A speculative utility layer never adopted; roughly two-thirds of the package is scaffolding with tests and no consumers. Mild irony: `util.JoinHostPort` sits unused while `internal/vpn/vpn.go:472` hand-rolls `fmt.Sprintf("%s:%d", …)` and breaks IPv6 (§5). |
| `internal/cache/range.go` — the whole 313-line file (`ByteRange`, `ParseRangeSpec`, `RangeSpec.*`, `RangeReader`, `MultipartRangeWriter`, `CoalesceRanges`, `UnsatisfiableRangeError`) | `internal/cache/range.go:25-311` | Test-only. `internal/cache/interceptor.go:293-305` has its **own private** `byteRange`/`parseByteRange` doing the live work | **REMOVE** (or consolidate `interceptor.go` onto it) | Two range parsers in one package, and the exported one has no consumer. The multipart/coalescing features it adds are promised nowhere in `docs/` or `SPECIFICATION.md`, so this is a duplicate, not an unfinished feature. |
| `LoadRulesFromConfig`, `LoadPresets`, `PresetNames`, `GetPresetInfo`, `AllPresetInfo`, `GenerateSimpleKey` | `internal/cache/rules.go:279`; `presets.go:252,277,299,315`; `key.go:150` | Test-only. `internal/cache/cache.go:61-80` (and again at `:506-520`) inlines rule/preset loading; `cache_handlers.go:468-494` hand-builds the preset response `AllPresetInfo` was written to return | **REMOVE** | Extract-method refactors written and never adopted, with the live code duplicating them — twice, in the case of rule loading. |
| `cleanupOldBinary` | `internal/updater/installer_unix.go:16` **and** `installer_windows.go:38` | No caller on any platform — dead in the darwin, linux and windows `deadcode` runs | **COMPLETE** (Windows) | The Unix body is an intentional no-op, but the Windows body removes the `.old` binaries the Windows install dance leaves behind (`installer_windows.go:11`). Never calling it means **every Windows self-update leaks a stale `.old` binary forever.** Call it once at updater start. |
| Thin constructors superseded by a `…With…` variant — `NewWebSocketHub`, `NewMeshAPI`, `NewCollector`, `NewLoadBalancer`, `Factory.SetNetwork`, `health.DefaultConfig`, `device.CreateTUN`/`CreateTAP`/`ParseDeviceType` | `internal/api/server/websocket.go:89`, `mesh.go:44`; `internal/metrics/collector.go:27`; `internal/router/router.go:177`; `internal/backend/factory.go:35`; `internal/health/checker.go:48`; `internal/device/device.go:35,173,179` | Each test-only; production calls `NewWebSocketHubWithMaxClients` (`internal/server/server.go:589`), `NewMeshAPIWithConfig` (`:123`), `NewCollectorWithInterval` (`:544`), `NewLoadBalancerWithWeights` (`router.go:57`), `NewFactoryWithNetwork`, an inline `checkCfg` (`server.go:344`), `device.Create` via `internal/vpn/tun.go:69` | **REMOVE** | Vestigial convenience constructors kept alive purely by tests. The underlying features *are* wired — weighted LB via `seedRouteWeights` → `Weights`, metrics collector at `server.go:544` — so nothing is missing behind them. |
| Duplicate copy helpers — `backend.CopyBidirectional`, `proxy.CopyBidirectionalWithStats`, `CopyStats.TotalBytes`/`Throughput` | `internal/backend/backend.go:92`; `internal/proxy/copy.go:99,118,123` | Live path is `proxy.CopyBidirectional` (`internal/proxy/http.go:357`, `socks5.go:530`) | **REMOVE** | A third copy of one function, and a stats variant no caller wants. |
| `NoiseHandshake` + methods | `internal/p2p/crypto.go:721-819` | Test-only; nothing in `internal/p2p` or `internal/mesh` references it. The live handshake is `CryptoSession` (`crypto.go:215-610`) | **REMOVE** | A second, unused handshake implementation beside the working one — and a hazard, since a future reader could wire the wrong one. |
| `AuthCodeFlow` + `MemoryTokenStore` + `AuthCodeAuthenticator` / `TokenStore`; `InteractiveLogin` | `internal/auth/plugin/oauth/authcode.go:64-511`; `InteractiveLogin` at `:401`, types at `:439,444` | `InteractiveLogin` and the two types have **no reference at all — not even tests** | **REMOVE** | The largest single dead block: a full OAuth authorization-code/PKCE flow with a callback server and interactive browser login. The shipped OAuth plugin authenticates via a different path (client-credentials / introspection). |
| `NewEthernetBroadcastHandler`, `EthernetBroadcastHandler.HandleFrame`, `mesh.DefaultRouterConfig` | `internal/mesh/broadcast.go:663,670`; `router.go:109` | Test-only; `internal/mesh/node.go:737-772` does its own frame dispatch | **REMOVE** | Mesh L2 *is* wired (`node.go` uses `frame.MACTable`, `ARPInterceptor`, `ParseEthernetFrame`, `IsBroadcast`, `IsMulticast`); these are unused alternates. |
| `internal/frame` accessor surface — `BuildARPRequestFrame`, `ARPPacket.{IsReply,String,MarshalBinary}`, `EtherType.String`, `EthernetFrame.{IsBroadcast,IsMulticast,IsUnicast,IsIPv4,IsIPv6,IsARP,IsIP,String,Clone,MarshalBinary,ExtractIPAddresses}`, `MACEqual`, `IsLocallyAdministered`, `IsGloballyUnique`, `IsUnicast`, `DefaultMACTableConfig` | `internal/frame/arp.go:147,164,187,192,207`; `ethernet.go:23,125-224,237,245,275`; `mac_table.go:35` | All test-only; `internal/frame` has exactly one importer (`internal/mesh/node.go:15`) using a small subset | **REMOVE** | "Library completeness" API for an internal-only package with one consumer. Not a feature gap — the L2 datapath works. |
| `ratelimit.FormatBandwidth`, `NewThrottledReader`, `NewThrottledWriter` + their `Read`/`Write` | `internal/ratelimit/bandwidth.go:70,182,222` | Test-only | **REMOVE** | Bandwidth throttling *is* live via `NewThrottledConn` (`internal/proxy/http.go:330,420`; `socks5.go:512`) fed from `rate_limit.bandwidth`. These are unused siblings, not the missing half. |
| `vpn.WithLogger`, `vpn.ExampleConfig`, `BuildTCPRSTPacket` (+ `buildIPv4/IPv6TCPRSTPacket`), `DefaultUDPRelayConfig` | `internal/vpn/vpn.go:112`; `config.go:129`; `packet.go:388,396,435`; `udp.go:75` | Test-only. `WithServerConnector` (`vpn.go:105`) is the only `ManagerOption` ever passed | **REMOVE** | An option that discards its argument (§7.13), a sample-config generator, and an RST-injection helper nothing calls. |
| `auth.negotiate.AuthenticatorGetter` | `internal/auth/negotiate/handler.go:52-55` | Verified independently: `git grep AuthenticatorGetter` returns **only the declaration and its doc comment** | **REMOVE** | An interface declared and never implemented or referenced by anything, tests included. |
| `hasRestartRequiredChanges` | `internal/api/server/config_handlers.go:378` | No caller; `handleSaveConfig` uses `splitChangedSections` (`:364`) + `len(restartRequired) > 0` | **REMOVE** | Superseded predicate from the `detectChangedSections` rewrite (§8). |
| `auth` misc — `ExtractBasicAuth` + `HTTPCredentials`, `IsInvalidCredentials`, `IsAuthRequired`, `IsTooManyAttempts`, `GetAllPlugins`, `GetPluginInfo`, `negotiate.GetUserInfoFromContext`, `ntlm.IsNTLMChallengeRequired` | `auth.go:38,45`; `errors.go:59,64,70`; `registry.go:61,103`; `negotiate/handler.go:435`; `plugin/ntlm/ntlm.go:649` | Both passes agree | **REMOVE** | `GetAllPlugins`/`GetPluginInfo` are shadowed by the live `handleListAuthPlugins` path. |
| `updater.Version.String`, `Version.IsPrerelease` | `internal/updater/version.go:63,124` | Test-only. `updater.go:78` calls `Channel.IsPrerelease()` — a **different type** | **REMOVE** | A name collision made these look used. |
| `vpnprovider` functional options — `mullvad.With{HTTPClient,Cache,Logger}`, `nordvpn.With{HTTPClient,BaseURL,Logger,CacheTTL}`, `pia.With{HTTPClient,Logger,CacheTTL,AddKeyTransport}`, `protonvpn.With{HTTPClient,BaseURL,CacheTTL,Logger,SessionStore}` | `mullvad/client.go:53,60,67`; `nordvpn/client.go:45,52,59,66`; `pia/client.go:74,81,88,98`; `protonvpn/client.go:57,64,71,78,85` | All test-only — they exist so tests can inject fakes | **KEEP** | Listed for completeness only. Test-injection options are a legitimate pattern and "unused in production" is their normal state. **No action recommended.** |
| `vpnprovider.ValidateCACertPEM` | `internal/vpnprovider/openvpncrypto.go:99` | Test-only | **COMPLETE** | The interesting one in that cluster. Given the malformed embedded-CA class of bug logged in `AUDIT-FINDINGS.md` §7.2/7.3, wiring this into the OpenVPN config-generation path would turn a cryptic connect-time failure into a clear startup error. Completion, not removal. |
| `ParseAuthMode`, `NewSession`, `ParseServerName`, `FormatServerName`, `newPortForwarderWithClient`, `piaPortForwardCAValid`, `pinnedTLSConfigFor` | `protonvpn/auth.go:19,187`; `protonvpn/servers.go:234,250`; `pia/portforward.go:120,300,307` | Test-only | **REMOVE** | Unadopted helpers. |
| `debug.Logger.FindByHost` | `internal/debug/logger.go:198` | Test-only | **COMPLETE or REMOVE together with `debug.filter_domains`** | This is the consumer `filter_domains` (§2) would need. The two should be decided as one unit: implement both, or delete both. |

### Categories that came up empty — reported honestly

- **CLI flags:** all 20 flag variables in `cmd/server/main.go` and `cmd/client/main.go` are read
  (`configFile` → `config.LoadAndValidate` at `:65`/`:271`, `updateChannel` → `:139`, `updateForce` →
  `:195,199`, `serviceName`/`serviceConfigPath` → `:345-375`, all `init*` → client `:89-94`).
  **No dead flags.**
- **Unreachable branches:** none confirmed. `go vet -unreachable` clean on all three GOOS; staticcheck
  produced zero `SA4020`/`SA4003`/`SA9003`.
- **Build tags:** the only non-platform tag is `pam` (`internal/auth/plugin/system/pam_linux.go:1`),
  never set by the Makefile or Docker — and this is **deliberate and already surfaced**:
  `SPECIFICATION.md:636` defines a `build_disabled` state, there is a startup warning and a UI badge,
  and `internal/auth/plugin/system/README.md` documents the opt-in build. Not a defect. **(b)**

---

## 5. Protocol and feature gaps

Most claims in this section were verified by writing and running throwaway Go tests
(`internal/{proxy,p2p,matcher}/zz_audit_*_test.go`, since deleted); those are marked **[tested]**.

### SOCKS5 — **(c) fine**, and a model of disclosure

`internal/proxy/socks5.go`. CONNECT is fully implemented (`:423`, `handleConnect` at `:454`) with
access control, per-user rate limiting, backend selection, bandwidth throttling and bidirectional
copy. **BIND (0x02)** → `sendReply(conn, socks5ReplyCmdNotSupported, nil)` at `:429-435`; **UDP
ASSOCIATE (0x03)** → same at `:436-442`; unknown command → same at `:443-449`. The reply is a correct
10-byte SOCKS5 message `05 07 00 01 00.00.00.00 00.00` (`sendReply`, `:535-557`) — not silent, not
malformed. **[tested]** — the repo's own assertions at `socks5_test.go:438,473,1297` pass.

Auth is complete: no-auth and RFC 1929 username/password (`:266-334`, including the `01 01` / `01 00`
sub-replies); `authRequired` with a client offering only 0x00 yields method `0xFF` (`:236-255`).
GSSAPI is not offered, which is correct RFC behaviour for an unsupported method. All three ATYPs are
handled — IPv4 (`:354`), IPv6 (`:361`, 16 bytes, bracketed for dialing at `:409-414`), domain (`:368`,
length-prefixed and format-validated) — with unsupported ATYP → `0x08` (`:395-397`).

**Disclosed precisely.** `docs/configuration.mdx:102-110` states CONNECT-only, names the `0x07` reply,
and lists the concrete consequences (QUIC/HTTP-3, DNS-over-UDP, WebRTC, active FTP). No "full SOCKS5"
claim exists anywhere. This is the right way to scope a feature out.

Two blemishes: `header[2]` (RSV) is never validated against `0x00`; and `:415` passes the
**unbracketed** IPv6 host to `util.GetHostFromRequest`, which only unwraps brackets
(`internal/util/network.go:106-121`), so an IPv6 target is logged as `2001:db8:`. Backend selection is
unaffected — it uses the bracketed `target` at `:456`.

### HTTP proxy — **(a) genuinely unfinished**, on four counts, all undisclosed

CONNECT (`internal/proxy/http.go:299`) and absolute-form GET (`:362`) both work. Beyond that:

1. **One request per connection — HTTP/1.1 keep-alive is broken.** `ServeConn` reads exactly one
   request (`http.go:178`) and returns, closing the conn via the `defer` at `:152`;
   `internal/server/server.go:1240` calls it once per accepted connection. **[tested]** first request
   → 200 with **no `Connection: close`** header (`Close=false`, i.e. implicit HTTP/1.1 persistence),
   then the socket closes and a second request on it gets `unexpected EOF`. The proxy tells the client
   the connection is reusable and then kills it: a spec violation that also imposes a full TCP
   handshake per request. Same on the client proxy (`internal/client/client.go:595,630`). This is the
   most consequential item in this section — it is a correctness *and* performance defect on the
   hottest path.
2. **No hop-by-hop header hygiene and no `Via`.** Only `Proxy-Connection` and `Proxy-Authorization`
   are removed (`http.go:429-430`). **[tested]** — bytes actually arriving at the origin included an
   injected `User-Agent`, plus `Connection: keep-alive, X-Custom-Hop`, `Keep-Alive: timeout=30`,
   `Te: trailers`, `Upgrade: h2c`, **and `X-Custom-Hop` itself** — a header named in `Connection:` that
   RFC 7230 §6.1 says MUST be stripped. No `Via` is appended in either direction (RFC 7230 §5.7.1
   says a proxy MUST).
3. **HTTP/2 and HTTP/3 do not exist.** No `http2`/`h2c`/`NextProtos`/`quic` anywhere in `internal/` or
   `cmd/`, and no such module in `go.mod`. h2 over an *opaque* CONNECT tunnel works, because ALPN is
   end-to-end. But an **h2c prior-knowledge client is mis-parsed**: `http.ReadRequest` accepts
   `PRI * HTTP/2.0` as an ordinary request, `req.Host` is empty, the proxy dials `":80"`, and replies
   `HTTP/1.1 502 Connection failed` — an HTTP/1.1 body written onto a wire the client expects to carry
   HTTP/2 frames.
4. **WebSocket / any `Upgrade` over plain HTTP is broken.** **[tested]** the `101 Switching Protocols`
   is forwarded to the client, then `handleHTTP` returns at `http.go:466` and both connections close;
   zero post-upgrade bytes crossed in either direction. `wss://` via CONNECT is fine (opaque copy).

**Disclosure: none.** No doc states the proxy is HTTP/1.1-only, one-request-per-connection, or that
`ws://` does not tunnel. `docs/troubleshooting/performance.mdx:201` actively advises *"Consider HTTP/2
for multiplexed connections"* as though it were an available lever.

### Mesh multi-hop relay — **(b) correctly scoped out**; the adjacent TURN path is **(a)**

Verified exactly as the brief described. `internal/mesh/config.go:257-258`:

```go
if c.Connection.RelayViaPeers {
    return errors.New("mesh: relay_via_peers is not yet supported (multi-hop peer relaying is unimplemented); set it to false")
}
```

Default `false` (`config.go:186`), and nothing half-does it: `internal/mesh/node.go:1019-1029`
explicitly declines to register connected peers as relay candidates and says why;
`RelayManager.AddPeerRelay` returns `ErrPeerNotRelayable` when the flag is off (`p2p/relay.go:222`);
`NewRelayRouter` (`relay.go:562`) has no non-test caller, and `relay.go:544-547` carries an accurate
"not wired" note. Correct posture — fail closed and say so.

**But the TURN relay fallback, which is enabled by default, is a silent no-op.** `relay_enabled`
defaults to **true** (`mesh/config.go:183`). `createTURNRelayedConnection` (`p2p/relay.go:299-311`)
returns a `RelayedConnection` in state `New`, and `RelayedConnection.Connect`
(`p2p/connection.go:597`) **has no caller outside tests** — the only `.Connect(` in the manager is
`DirectConnection` at `p2p/manager.go:331`. `P2PManager.Connect` nonetheless stores it, fires
`OnPeerConnected`, and logs *"relay connection established"* (`manager.go:286-297`), while every
`Send` returns `ErrNotConnected` (`connection.go:695-697`) and the send/recv workers were never
started. **Consequence:** when direct P2P fails, the mesh believes it has a peer and silently
blackholes its frames. **UNDISCLOSED** — `docs/mesh-networking.mdx:387-428` documents TURN relay as
working. Compounded by §2: the `mesh.turn.*` config is discarded before any of this is reached.

### ICE — **(b) honestly labelled unused**, but closer to a shell than the label implies

`internal/p2p/ice.go:101-105` carries an accurate "implemented and unit-tested in isolation but is NOT
yet wired" note, and `NewICEAgent` has no caller outside `ice_test.go`. The "deliberately kept"
framing is honest and I am **not** recommending removal. But its completeness is worse than the note
suggests, which matters for anyone planning to wire it:

- **TURN is unreachable from it.** `NewICEAgent` (`ice.go:142-149`) sets only `stunClient` and
  silently ignores `ICEConfig.TURNConfig`, so `a.turnClient` is always nil and
  `gatherRelayCandidates` (`ice.go:269`) is dead code. **[tested]** `agent.turnClient == nil` with a
  fully populated `TURNConfig`.
- **Connectivity checks are not ICE.** `checkConnectivity` (`ice.go:394-444`) sends the plaintext
  string `BIFROST_ICE_PROBE` and waits for the same bytes back — the code says so at `:397-398`. No
  responder exists in the agent, so a one-sided check fails. **[tested]** a **dumb UDP echo server**
  completes a "connectivity check" and becomes the selected pair (`connected=true`). There is no
  transaction ID, no ufrag/pwd, no MESSAGE-INTEGRITY — so this is not merely incomplete, it is
  trivially spoofable if wired as-is.
- Missing: candidate nomination / USE-CANDIDATE, controlling/controlled roles, trickle ICE,
  peer-reflexive discovery (`CandidateTypePeerReflexive` is declared and never produced), and
  per-interface sockets (all host candidates reuse one `:0` socket's port, `ice.go:238`).
- Two latent bugs: `a.conn` is written without the mutex at `ice.go:162` while read under `RLock`
  elsewhere (data race), and `ice.go:166` `netip.MustParseAddr` can panic.

**Docs overclaim it.** `docs/mesh-networking.mdx:15` ("STUN/TURN/**ICE** support"), `:121`
("STUN/TURN/ICE Implementation"), and `:194-240` — a full *"ICE … Implementation details
(`internal/p2p/ice.go`)"* section with candidate tables, a gathering diagram and the RFC 8445 priority
formula, **with no caveat**. The honest note exists only in the source. The same page also overclaims
multi-hop relay at `:17`, `:74`, `:430-452`, and at `:808` instructs the reader to *"Enable peer
relaying"* — the exact thing rejected at startup by `config.go:258` — contradicting its own disclaimer
at `:461,466`.

### IPv6 — **(c) fine** for proxy dialing and access control; **(a) genuinely unfinished** in the VPN/mesh data path

What is clean: no unchecked `.To4()` anywhere (six call sites, all nil-checked);
`internal/accesscontrol/ip.go` is fully family-agnostic; `internal/util/network.go:76-93` picks `/32`
vs `/128` correctly; dial-family selection is right and honestly three-state
(`internal/config/network.go:43-48`, threaded to `http.go:100`, `socks5.go:110`). IPv6 *targets* are
dialable.

What is broken, ranked by severity:

1. **Full-tunnel VPN leaks all IPv6.** `internal/vpn/routes_linux.go:79`, `routes_darwin.go:73`,
   `routes_windows.go:77` install only `0.0.0.0/1` + `128.0.0.0/1`. There is no `::/0` equivalent and
   IPv6 is not disabled on the host, so on any dual-stack network every IPv6-reachable destination
   bypasses the tunnel entirely. This is a privacy/kill-switch gap, not a feature gap. **Undisclosed.**
2. **IPv6 routing rules can never match.** `internal/matcher/matcher.go:113-116` unconditionally
   truncates at the last `:` to strip a port. **[tested]** pattern `2001:db8::1` vs domain
   `2001:db8::1` → **false**; `::1` vs `::1` → **false**; only `*` matches. (IPv4 is unaffected:
   `192.168.1.10` matches both with and without a port.) The router also has no CIDR matcher at all
   (`internal/router/` never calls `ParseCIDR`), so IPv6 destinations silently fall through to the
   default backend. I verified the truncation independently.
3. **All tunnelled IPv6 TCP fails.** `internal/vpn/vpn.go:472` builds the address with
   `fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)` instead of `net.JoinHostPort`; downstream
   `net.SplitHostPort` at `internal/client/server_conn.go:256` then errors "too many colons".
4. **HTTP proxy mis-parses bracketed IPv6 targets.** `http.go:303` and `:369` use
   `strings.Contains(host, ":")` as a has-port test, so `[2001:db8::1]` is treated as already having a
   port. **[tested]** `GET http://[2001:db8::1]/x` → dials the literal `[2001:db8::1]` → `missing port
   in address` → 502. With an explicit port it works. I verified both lines independently. Same
   pattern at `internal/vpn/dns.go:259,319` and `internal/api/server/pac.go:47`.
5. **TURN panics on an IPv6 peer.** `internal/p2p/turn.go:705-713,716-728` hardcode family `0x01` and
   call `netip.Addr.As4()`. **[tested]** `panic: As4 called on IPv6 address` for both
   `buildXORPeerAddress` and `buildXORPeerAddressPort` (reachable from `CreatePermission`,
   `BindChannel`, `Send`) — though only after a successful allocation.
6. **Windows IPv6 route → panic.** `internal/vpn/routes_windows.go:265-267` computes
   `uint32(0xFFFFFFFF) << (32 - bits)`, and `AddBypassRoute` normalises IPv6 to `/128` (`:128-134`)
   and calls straight through → negative shift. linux/darwin branch on `Is4()` correctly.
7. **DNS cache corrupts both families.** `internal/vpn/dns.go:184` looks up `s.cache.Get(domain)`,
   keyed on domain only (`dns_cache.go:106`), while `queryUpstream(domain, q.Qtype)` (`:193`) stores
   only that qtype's addresses. An A query then poisons the AAAA answer (and vice versa) into an empty
   NOERROR via the `Is4()`/`Is6()` filter at `:215-226`.
8. **IPv6 UDP silently dropped in VPN mode.** `internal/vpn/udp.go:77,88` listen on `0.0.0.0:0`
   (AF_INET); the IPv6 builders at `:370` are dead code.
9. **STUN XOR-MAPPED-ADDRESS for IPv6 is not de-XORed** — `internal/p2p/stun.go:352-353`, with a
   comment admitting "not fully implemented". The port *is* XORed at `:334`, so the reflexive
   candidate is garbage and is published silently.
10. **Architectural root cause: single-family addressing.** `internal/vpn/tun.go:19`,
    `internal/device/device.go:86`, and `internal/backend/wireguard.go:157` each hold exactly one
    address. The WireGuard backend advertises `AllowedIPs` including `::/0` while
    `netstack.CreateNetTUN` receives one IPv4 address, so IPv6 is dropped inside netstack. Mesh is
    IPv4-only in practice: `mesh/config.go:206-217` accepts an IPv6 `network_cidr`, but TAP is the
    default (`config.go:275`) and `internal/device/tap_linux.go:181-183` returns "only IPv4 addresses
    are supported for TAP devices"; `mesh/ipam.go:392-412` (`lastAddr` returns the *first* address for
    IPv6) and `:358-369` (host bits capped at 24) are broken for v6 too. The resolv.conf helpers in
    `routes_{linux,darwin,windows}.go:344/396/387` write `nameserver [fd00::1]` or `nameserver fd00:`.

**Disclosure: mixed, and one overclaim.** Honest and precise for the dial path
(`docs/configuration.mdx:193-201`, including the three-state explanation) and for VPN split-tunnel v6
prefixes (`vpn-mode.mdx:193-195`). But **`SPECIFICATION.md:42` claims a bare, unscoped "IPv6 /
dual-stack networking support"**, which findings 1-3 flatly contradict, and mesh IPv6 is silent —
every example is `10.100.0.0/16`.

### MITM / TLS interception — **(c) mostly fine**; **(a)** on ALPN and Upgrade

Solid and, notably, fail-closed in the places that matter: CA parsing accepts PKCS#8/EC/PKCS#1
(`internal/proxy/mitm.go:128-142`) and rejects non-CA certs (`:83`); per-host leaf minting selects
IP-vs-DNS SANs correctly (`:213-217`) with a TTL and a bounded cache (`:147-178`); **upstream
certificate validation stays on** — `InsecureSkipVerify` is never set (`mitm_intercept.go:104-119`);
SNI is handled with a documented fallback to the CONNECT host for IP literals (`:83-95`); credentials
are redacted from the debug log (`:234-267`); and config validation fails closed
(`internal/config/mitm.go:41-52`). There is **no CA auto-generation** — the operator supplies one, and
the docs say exactly that, so no false claim.

Two gaps, both **[tested]**:

- **No ALPN on either leg.** No `NextProtos` at `mitm_intercept.go:87-96` (client) or `:106-114`
  (upstream). A client offering `[h2, http/1.1]` against an origin offering the same negotiated `""`
  on **both** legs — intercepted connections silently downgrade from h2 to HTTP/1.1. Consistent with
  the HTTP/1.1-only design, but invisible to the operator.
- **Upgrade/WebSocket inside an intercepted tunnel is broken, and this is a regression relative to
  MITM-off.** `interceptExchange` (`mitm_intercept.go:139-196`) is a strict request/response loop: the
  `101` reaches the client, then post-upgrade server bytes never arrive because the loop returns to
  `http.ReadRequest` on what is now a frame stream. The same `wss://` connection tunnels fine with
  MITM disabled.

The §5 item-2 hop-by-hop and `Via` omissions also apply to the intercepted path (`req.Write` at
`:163`). **ALPN/HTTP-2, WebSocket breakage, and certificate pinning are all undisclosed**; the CA and
key-risk warnings themselves (`docs/configuration.mdx:224-241`) are accurate and appropriately blunt.

### Other protocol-shaped items

- **PAC/WPAD is implemented** (`internal/api/server/pac.go`, routed at
  `internal/api/server/server.go:258-259`, tested) — but the docs contradict themselves:
  `docs/api/server.mdx:1202-1228` documents it as shipped while
  `docs/features/system-proxy.mdx:484` lists "PAC file support" under "planned for future releases".
  Minor code issue: `pac.go:47` `strings.LastIndex(proxyHost, ":")` mangles a bracketed IPv6 host.
- **Upstream chaining is fine.** `http_proxy` (`internal/backend/httpproxy.go:109-145`, CONNECT +
  Basic `Proxy-Authorization`) and `socks5_proxy` are real. Note the HTTP-proxy backend uses CONNECT
  for *all* traffic including plain HTTP — works, but upstreams that deny CONNECT to :80 will fail.
- **Docs underclaim in one place.** `docs/features/system-proxy.mdx:73-76,194,243,480-484` and
  `ISSUES.md:20-23` describe macOS/Linux system-proxy as "Stub (no-op) / Planned", but
  `internal/sysproxy/sysproxy_darwin.go:41` really shells `networksetup` and `sysproxy_linux.go:38-48`
  really uses `gsettings` (`README.md:27` gets this right). Worth fixing so the docs are not
  discounted wholesale.

### Marker inventory

Swept with
`grep -rniE '(TODO|FIXME|XXX|HACK|not implemented|unimplemented|stub|for now|placeholder)' --include='*.go' internal cmd`
filtered through `grep -vE '^internal/(tray|service)/'`: **116 markers, 57 in non-test files, 59 in
`_test.go`, zero in `cmd/`.** Each was classified by reading the surrounding code, not the comment
text. Counts by package: `internal/auth` 11 non-test, `internal/mesh` 9, `auth/plugin/system` 9,
`internal/vpnprovider` 4, `auth/plugin/ntlm` 4, `vpnprovider/protonvpn` 3, others 1-2 each.

**The brief's "~110 TODO/FIXME/stub markers" is accurate as a count but misleading as a signal — only
10 flag genuinely unfinished functionality.** The bulk (105) are informational notes on *complete*
code: ~30 in the auth-availability machinery that exists to *name* incompleteness elsewhere, 10
anti-placeholder-crypto comments explaining why no CA or tls-auth material is embedded, 8 describing
the implemented mesh placeholder→assigned-IP handover, and 59 test-fixture identifiers
(`stubAuthenticator`, `assert.Contains(err, "not implemented")`). Two even document the *absence* of a
placeholder (`internal/client/mesh.go:19`, `internal/vpn/vpn.go:1016`) — the opposite of a gap.

The 10 that do mark unfinished work, each already covered above or self-explanatory:

| Marker | What is actually missing |
|---|---|
| `internal/mesh/config.go:258` | Multi-hop peer relay data plane. Fail-closed; **(b)** — §5 |
| `internal/p2p/relay.go:546` (+ `mesh/node.go:823`) | Hop accounting (`SrcPeerID`, TTL) and wiring into `P2PManager` — §5 |
| `internal/auth/plugin/ntlm/ntlm.go:89` | NTLM response verification — no credential source exists. Refused at three layers; **(b)** |
| `internal/auth/plugin/ntlm/ntlm.go:276` | `handleType1` never parses domain/workstation out of the Negotiate message |
| `internal/backend/openvpn.go:124` (`TODO(proxy)`) | An in-tunnel resolver; hostnames resolve via the host OS resolver, leaking DNS even with `leak_proof_routing` on. Documented in the doc comment above it; **(b)** |
| `internal/auth/session/redis.go:52` | TLS to the Redis session store — **and the doc comment at `:40-53` describes a `TLS` field that does not exist**. `NewRedisStore` builds a plain client with no `TLSConfig`, so session data crosses the network in the clear with no way to change that. **(a)**, security-relevant |
| `internal/sysproxy/sysproxy_windows.go:45` | `ProxyOverride` is never written (the call is commented out at `:46`), so `<local>` / LAN traffic is proxied unless the user's profile already had a bypass list |
| `internal/config/node.go:103` | Schema-ordered insertion — new YAML keys are appended to the end of the mapping |
| `internal/config/node.go:113` | Head comments for newly appended keys |
| `internal/vpn/vpn.go:112-116` | `WithLogger` stores nothing — §7.13 |

One marker is **stale**: `internal/vpnprovider/pia/auth.go:24` still defines
`ErrPortForwardingNotImplemented`, but PIA port forwarding **is** implemented in
`internal/vpnprovider/pia/portforward.go` with its own `ErrPortForwardingNotAvailable`. The line above
already admits it is "retained for backward compatibility"; the message is now simply false.

---

## 6. Platform stubs

Cross-platform builds of the platform-split packages pass for all three GOOS with `CGO_ENABLED=0`
(`device`, `vpn`, `sysproxy`, `backend`, `updater`, `auth/plugin/system`). The packages that import
the embedded web UI cannot be cross-built in a clean tree, but that fails identically on all three
platforms (see §1), and a `go doc -all` export-surface diff across the three GOOS values showed zero
symbol differences, so there are no platform-conditional call sites hiding there.

**Legend:** REAL · HONEST-STUB (clear not-supported error) · **FAKE-SUCCESS** (returns nil while
doing nothing — a defect) · MISSING.

| Capability | linux | darwin | windows | other |
|---|---|---|---|---|
| TUN create/configure | REAL `device/tun_linux.go:40` | REAL `tun_darwin.go:41` | REAL `tun_windows.go:30` | HONEST-STUB `tun_other.go:7` |
| TAP create/configure | REAL `tap_linux.go` | REAL `tap_darwin.go:29` | REAL `tap_windows.go:45` | HONEST-STUB `tap_other.go:7` |
| TAP `SetMACAddress` | REAL `tap_linux.go:321` | REAL `tap_darwin.go:235` | HONEST-STUB `tap_windows.go:377` | n/a |
| Route table add | REAL, fail-closed `vpn/routes_linux.go:36,57-59` | **FAKE-SUCCESS** `routes_darwin.go:36,74-108` | **FAKE-SUCCESS** `routes_windows.go:36,78-112` | HONEST-STUB `routes_other.go:18` |
| VPN DNS configure / restore | **FAKE-SUCCESS** `routes_linux.go:119-121,306-308` | **FAKE-SUCCESS** `routes_darwin.go:113-115` | **FAKE-SUCCESS** `routes_windows.go:117-119` | MISSING (Setup already errors) |
| Bypass route add/remove | REAL `routes_linux.go:170,201` | REAL `routes_darwin.go:164,195` | REAL `routes_windows.go:169,200` | HONEST-STUB |
| Process lookup from socket | REAL `vpn/process_linux.go:25` | REAL `process_darwin.go:24` | **FAKE-SUCCESS** `process_windows.go:146,150,185,221,254` | **FAKE-SUCCESS** `process_other.go:10` |
| System proxy set/clear | REAL + honest `sysproxy_linux.go:42` | REAL `sysproxy_darwin.go:42` | REAL, incomplete `sysproxy_windows.go:28,45` | HONEST-STUB `sysproxy_other.go:16,20` |
| Leak-proof egress | REAL, fail-closed `backend/leakproof_linux.go:88` | HONEST-STUB `leakproof_other.go:8` | HONEST-STUB | HONEST-STUB |
| System password auth | HONEST-STUB by default `pam_stub.go:45`; REAL with `-tags pam` `pam_linux.go:71` | REAL `system.go:269` (`dscl`) | REAL `system_windows.go:258` (`LogonUserW`) | HONEST-STUB `system.go:258-263` |
| Self-update atomic replace | REAL `installer_unix.go:11` | REAL | REAL `installer_windows.go:11` | REAL |
| ICMP ping health check | REAL `health/ping.go:51` | REAL `:49` | REAL `:47` | REAL (linux fallback) |
| Privilege / elevation pre-check | MISSING | MISSING | MISSING | MISSING |
| Firewall / kill-switch | MISSING | MISSING | MISSING | MISSING |

### FAKE-SUCCESS findings

1. **Per-app split tunnelling is dead on Windows.** `internal/vpn/process_windows.go:146,150,185,221,254`
   convert the port to network byte order as
   `uint32(local.Port())<<8 | uint32(local.Port())>>8`. Widening to `uint32` *before* shifting leaves
   the high byte at bits 16-23, but `MIB_TCPROW_OWNER_PID.dwLocalPort` carries the port in the low
   two bytes. Verified numerically: port 80 → `0x00005000` (matches), port 443 → `0x0001BB01` where
   Windows has `0x0000BB01` (does not match), port 8080 and 49152 likewise. Only ports 0-255 match,
   by accident; local ports are always ephemeral. So the table scan never hits, `findTCPv4Process`
   returns `(0, nil)`, `LookupBySocket` returns `(nil, nil)` (`:114-116`), `internal/vpn/vpn.go:363`
   discards the error, and `internal/vpn/splittunnel.go:167` gates all app matching on
   `procInfo != nil`. **Consequence:** on Windows an operator configures `split_tunnel.apps`, the
   config validates, the UI accepts it, nothing is logged at any level, and every app rule is
   silently inert. Fix is `uint32(p>>8 | p<<8)` computed at `uint16` width. **(a)**, high.
2. **macOS and Windows report the VPN connected when no route was installed.**
   `internal/vpn/routes_darwin.go:74-108` and `routes_windows.go:78-112` treat every `addRoute`
   failure as `slog.Warn` and then log *"routes configured for VPN"* at Info and `return nil`
   (`routes_darwin.go:118-123`, `routes_windows.go:122-128`). `internal/vpn/vpn.go:201-206` only
   aborts if `Setup` errors, so `vpn.go:225` sets `StatusConnected` and
   `internal/api/client/server.go:674,1876` derive `vpn_enabled` from it. Run unelevated on Windows
   (`route add` → "requires elevation") or without root on macOS: dashboard, tray and
   `bifrost-client vpn status` all report the VPN active while the routing table is untouched and
   100% of traffic egresses the physical interface. Linux fails closed here
   (`routes_linux.go:57-59`). **(a)**, high.
3. **VPN DNS configuration failure never reaches the operator, on all three platforms.**
   `routes_linux.go:119-121`, `routes_darwin.go:113-115`, `routes_windows.go:117-119` are warn-only.
   The implementations are real; when they fail (no root for `/etc/resolv.conf`, denied
   `networksetup -setdnsservers`, denied `netsh interface ip set dns`) the VPN still reports
   connected while the system resolver still points at the pre-VPN nameserver — a DNS leak presented
   as a healthy tunnel. Restore has the same hole: `routes_darwin.go:154-157` records `lastErr` and
   `vpn.go:294-298` only logs it. A narrower instance sits at `routes_linux.go:306-308`, where
   `resolvectl default-route <tun> true` — the call that makes the tunnel resolver authoritative — is
   `_ = cmd.Run()`, after which `configureDNS` returns nil and skips the `/etc/resolv.conf` fallback
   at `:312-319`. **(a)**, high.
4. **`windowsTUN.Index()` fabricates an interface index.** `internal/device/tun_windows.go:217-219`
   returns `0, nil` without querying the adapter. No callers today, and the Linux/darwin TUN types
   have no `Index()` at all — so **remove** it rather than implement it. **(a)**, latent/low.
5. **`noopProcessLookup` returns `(nil, nil)`.** `internal/vpn/process_other.go:10-12` — same class as
   #1: app rules silently never match instead of reporting unsupported. The sibling
   `noopRouteManager` (`routes_other.go:18`) gets this right by returning an error. **(a)**, low.

### Honest stubs — correct, leave alone

`pam_stub.go:45` returns false and warns, with `system.go:92-100` reporting
`AvailabilityBuildDisabled` and `:258-263` failing closed for unknown GOOS.
`leakproof_other.go:8` returns `ErrLeakProofUnsupported` and the caller kills the OpenVPN process
(`backend/openvpn.go:290-294`) rather than continuing. `sysproxy_other.go:16,20` returns
`ErrNotSupported` and `internal/client/client.go:293-301` distinguishes it from a real error, warns
the operator to configure the OS proxy manually, and sets the tray to `StatusWarning`.
`tap_windows.go:377` now refuses rather than updating an in-memory copy — the comment at `:369-376`
records that this was previously a fake-success, so the pattern is being actively cleaned up.
`vpn.go:395-404` drops and loudly warns about post-TUN bypass packets rather than pretending they
were delivered. These are the model the five findings above should be brought to.

### Missing on every platform

- **No privilege/elevation pre-check** anywhere in `internal/` or `cmd/`. `device.ErrPermissionDenied`
  exists (`internal/device/device.go:210`) and TUN creation returns it on Linux/darwin, but nothing
  checks for root/Administrator before attempting route or DNS changes — which is precisely what
  makes finding #2 reachable.
- **No firewall / kill-switch** capability (no `iptables`/`nft`/`pf`/`netsh advfirewall` in scope).
  Leak protection is policy-routing only, and Linux-only. Disclosed in `docs/`; **(b)**.

---

## 7. Swallowed errors worth fixing

Triaged hard: the ~200 `//nolint:errcheck` sites are overwhelmingly correct (teardown `Close`, type
assertions with usable zero values, HTTP response writes), and there is no bare `recover()` in
non-test code. Only cases where a **real failure becomes invisible** are listed, worst first.

| # | Site | Why the failure is invisible | Consequence |
|---|---|---|---|
| 0 | `internal/auth/plugin/mtls/mtls.go:73-77` | A CRL that cannot be loaded produces one `slog.Warn` and a working authenticator with an empty `revokedSerials`; `validateCertificate` (`:397-403`) then finds nothing revoked. | **Fails open.** A typo'd or unreadable `crl_file` means revoked client certificates authenticate successfully, with no runtime signal after the single startup warning. **High, security.** |
| 1 | `internal/backend/openvpn.go:377-401` | `monitor()` tests `cmd.ProcessState != nil && cmd.ProcessState.Exited()`. `ProcessState` is populated only by `cmd.Wait()`, and the only `Wait()` is in `Stop()` (`:434`). **Proven** with a standalone program: `ProcessState` stays `nil` for 1s after a child exits, and becomes non-nil only after `Wait()`. | The crash detector can never fire. When openvpn dies (auth failure, server drop, OOM kill) `b.running` and `b.healthy` stay true, `recordError` is never called, `IsHealthy()` (`:459`) reports healthy forever, the proxy keeps routing into a dead tunnel, and the zombie is never reaped. No log line at any level. **High.** |
| 2 | `internal/vpn/splittunnel.go:116,125,144` | `IPMatcher.Add` / `AppMatcher.AddRule` errors discarded; `Validate()` (`:76-84`) checks only `Mode`. | A typo in `split_tunnel.ips` is dropped silently. In `include` mode the default is bypass (`:231`), so the affected traffic leaves **outside** the tunnel in cleartext. A config typo becomes a traffic leak with zero signal. **High.** |
| 3 | `internal/vpn/routes_linux.go:306-308` | `_ = cmd.Run()` on `resolvectl default-route <tun> true`, then `return nil`, skipping the `/etc/resolv.conf` fallback at `:312-319`. | DNS queries keep going to the physical link's resolver — a leak — reported as success and logged nowhere. **High.** |
| 4 | `internal/updater/installer.go:194,231`; `internal/updater/download.go:53` | `io.Copy` errors are checked but `defer out.Close()` — which surfaces buffered-write failures — is discarded, and `extractTarGz`/`extractZip` `return nil` (`:202,:239`). No post-extraction checksum: `checksum.go` verifies the *archive*, not the extracted binary. `io.Copy(out, io.LimitReader(tr, 500MB))` also truncates a larger binary without error. | A partially written binary is chmodded and `atomicReplace`d over the live executable (`:55-68`) while the updater logs *"Binary updated successfully"*. **High.** |
| 5 | `internal/matcher/matcher.go:40` | `_ = m.AddPattern(p)` in `New`, comment *"Silently skip invalid patterns"*. Both callers ignore the error. | Invalid route domains, and anything past `MaxPatterns = 5000`, are dropped with no log; those domains fall through to the default backend. Callers: `router/server.go:45`, `router/client.go:48`, `cache/rules.go:259`, `cache/presets.go:265`. **Medium-high.** |
| 6 | `internal/config/node.go:35-51` (`SaveNode`) | `defer f.Close()` (`:40`) and `defer encoder.Close()` (`:44`) both discard errors; `encoder.Close()` is what flushes the final YAML document, and `os.Create` truncates in place. | On a full or read-only-remounted disk, `SaveNode` returns nil having left a truncated or empty config file. Believed by `internal/client/client.go:946` and `cmd/client/main.go:358`. **Medium.** |
| 7 | `internal/proxy/http.go:230`, `internal/proxy/socks5.go:170` | `_ = h.accessLogger.Log(*entry)` in a `defer` on every request; `JSONLogger.Log`/`ApacheLogger.Log` return the raw `os.File` write error (`internal/accesslog/logger.go:126,156,79`). | On ENOSPC, or a stale fd after an external rotate without `copytruncate`, every subsequent access-log write fails and the proxy serves traffic with no audit trail and no error anywhere. There is no error counter either — `internal/metrics` has only `bifrost_backend_errors_total`. **Medium.** |
| 8 | `internal/vpn/splittunnel.go:242,256,270` | `AddIP`/`AddRule` swallow `ErrIPRulesAtLimit`; `Manager.AddSplitTunnelIP` (`internal/vpn/vpn.go:1121-1152`) has already appended to `m.config`, and `handleVPNSplitAddIP` (`internal/api/client/server.go:1163-1188`) returns `201 Created`. | Past `MaxIPRules`/`MaxAppRules` the persisted config and the live matcher diverge: the UI lists the rule, `Decide()` never matches it, traffic keeps going the wrong way. **Medium.** |
| 9 | `internal/api/server/mesh.go:515` | `_ = network.ipAllocator.Renew(peerID)`; `PoolAllocator.Renew` (`internal/mesh/ipam.go:288-302`) returns `ErrPeerNotFound` exactly when the lease was already reaped by `Expire()` (`:305`). Handler still returns `204`. | The peer heartbeats forever while its address is free for reallocation — duplicate mesh IPs, and the one signal designed to catch it is discarded. **Medium.** |
| 10 | `internal/mesh/node.go:663-669` | `slog.Debug("device read error")` then `continue`, with no backoff. Same on the write side at `:1102,1133,1141`. | A permanently broken TUN/TAP fd turns `packetLoop` into a 100%-CPU spin while the node reports normal status. Only evidence is at debug level. **Medium.** |
| 11 | `internal/client/server_conn.go:293,305-313` | Bound-address and reply-header bytes read with `_, _ = conn.Read(buf)` rather than `io.ReadFull`, then `return nil`. | A short read leaves unconsumed SOCKS5 handshake bytes in the stream, corrupting the first bytes of tunneled payload — surfaces as intermittent unexplained TLS handshake failures after a "successful" connect. **Medium.** |
| 12 | `internal/cache/interceptor.go:417-419`; `internal/proxy/http.go:381,453` | `manager.Put` failure → `slog.Debug`. No metric. | A disk cache that cannot write at all (permissions, quota) looks like a 0% hit rate with no error at default log level. **Low-medium.** |
| 13 | `internal/vpn/vpn.go:112-116` | `WithLogger(logger *slog.Logger)` returns a `ManagerOption` with an empty body, `/* Reserved for future use */`. Pinned as intended by `vpn_test.go:231`. | A caller routing VPN logs to a separate sink gets no error and no effect. Either implement or delete the option; do not keep a no-op with a test asserting it. **Low.** |

Explicitly cleared, so the list is not padded: `internal/api/server/mesh_store.go:103-138` handles the
atomic state write correctly (checks `tmp.Close()`, chmod, rename); `internal/auth/session/store.go:239`
is fine because `Cleanup()` always returns nil; `internal/backend/leakproof_linux.go:115` is a correct
best-effort rollback behind a returned error; `internal/cache/interceptor.go:444`'s `_, _ = w.Write` is
safe because the error surfaces from the `w.Flush()` on the next line; `internal/ratelimit/bandwidth.go:129,208`
are defensible since `maxRead` is clamped to the bucket burst.

---

## 8. Corrections to `AUDIT-FINDINGS.md`

`AUDIT-FINDINGS.md` (2026-07-02, 66KB) is substantially stale and already carries its own
"line numbers are stale" banner. It remains useful as a lead list — several items here started from
it — but the following claims are **now wrong** and were verified against current code. Once these
are folded in, the file should be retired rather than maintained.

| `AUDIT-FINDINGS.md` claim | Status now | Evidence |
|---|---|---|
| §1 headline / §2.1 — Inter font never applied; Tailwind Preflight absent from built CSS | Out of my scope (web dashboard), but the artifact it cites (`internal/api/server/static/assets/index-6ZTXHU31.css`) is not in the tree at all — `internal/api/*/static` is gitignored and empty. The finding cannot be reproduced from a clean checkout as written. | `.gitignore:48-52`; `git ls-files internal/api/server/static` → empty |
| §7.1, §7.4, §7.5 — `detectChangedSections` omits `access_control`, `cache`, `auto_update`, `health_check`, `network`, `session`, `mitm`; changes saved but never applied and falsely report `requires_restart=false` | **FIXED.** Replaced by a table-driven `configSectionComparators` covering every `ServerConfig` section, with a coverage test (`TestConfigSectionsCoverServerConfig`) that fails the build when a new section is added without an entry. The save path also now deliberately reloads on mixed saves. | `internal/api/server/config_handlers.go:321-345`, `:223-252` |
| §7.6 — cache hits recorded as HTTP 500 in metrics and access logs | **FIXED.** The cache-served branch sets `entry.StatusCode = hit.StatusCode`, defaulting to 200. | `internal/proxy/http.go:388-390` |
| §7.7 — `backend` label always empty on connection and byte-transfer metrics | **FIXED.** `RecordBytes(backendName, …)` is called with the real name, and `RecordConnection` now returns a closure that takes the backend. | `internal/server/server.go:1144,1270`; `internal/metrics/collector.go:127,162` |
| §7.10 — "the client Health Check block is in fact entirely unconsumed (dead config)" | **FIXED.** `startHealthMonitor` consumes `server.health_check`; its doc comment explicitly says it "consumes the previously-dead server.health_check config block". | `internal/client/client.go:369-400` |
| §7.11 — Auto-Update is a dead toggle; `StartBackgroundChecker` never called in prod | **FIXED** on both daemons. | `internal/client/client.go:318,364`; `internal/server/autoupdate.go:79` |
| §7.12 — `/status` always reports `bytes_sent=0`, `bytes_received=0`, `active_connections=0` | **FIXED.** The counter funcs are wired from the client. | `internal/client/client.go:71,79,244`; `internal/api/client/server.go:233-235,687-694` |
| §9 — server mesh coordinator is always-on and `MeshConfig.Enabled` is dead config; networks never persisted | **FIXED.** `NewMeshAPIWithConfig(cfg.Mesh)` gates and configures it, and `mesh.state_path` persists networks/peers. | `internal/api/server/server.go:123`; `internal/api/server/mesh.go:50-55`; `internal/config/server.go:41-51` |
| §9 — client "Reload" button always returns HTTP 503 because `ConfigReloader` is unwired | **FIXED.** `ConfigReloader: c.reloadConfig` is set at the construction site, and `reloadConfig` is real — it re-loads and validates the file, then hot-applies routes, logging, and the server connection. | `internal/client/client.go:234`, `:982-1012` |
| §6 — cache Prometheus subsystem is entirely dead code | Already annotated as fixed in the file; **confirmed fixed.** | `internal/server/server.go:212` |
| §6 / §9 — `handleGetConfigTimestamp`, `setWebSocketHub`, `AddWebSocketRoutes`, `device.GenerateMAC` are dead | **FIXED** (removed by a prior cleanup pass). | absent from the tree |
| §6 — `internal/device/tap_windows.go:372-383` `SetMACAddress` returns nil but never changes the adapter MAC (fake success) | **FIXED.** Now returns `ErrSetMACUnsupported`, with a comment recording the previous fake-success. | `internal/device/tap_windows.go:369-377` |
| §8 items 1-3 + 1a-1f — P2P nonce reuse, fail-open inbound peers, inert replay window, unauthenticated handshakes, no revocation, shared-socket close | Already annotated as fixed in the file; **not independently re-verified in this pass** — flagged so nobody reads my silence as confirmation. | — |
| §4 — JWT HMAC always fails; `mfa_wrapper` advertises a by-name format `Create()` rejects; NTLM silently selectable; `system` silently fails closed | Already annotated as fixed/stale in the file; the availability machinery (`AvailabilityUnimplemented` / `AvailabilityBuildDisabled`, startup warning, `GET /api/v1/auth/plugins`) is present and is now among the more honest parts of the codebase. | `internal/auth/availability.go`; `internal/server/server.go:441-470` |
| §8b — `RelayRouter.deliverLocally` is an unauthenticated injection path, currently unreachable | **Still true**, and correctly characterised. Kept deliberately; see §5. | — |
| §7.2, §7.3, §7.8, §7.9 — ProtonVPN/Mullvad malformed embedded CAs, fabricated tls-auth key, `script-security 2` | Already annotated `[FIXED 2026-08]`; **not re-verified in this pass.** | — |
| §1 "TODO/FIXME markers are rare" | **Understated.** 116 markers in scope (57 non-test). Of those, 10 flag genuinely unfinished functionality; the rest are informational notes on complete code (notably ~30 in the auth-availability machinery and 10 anti-placeholder-crypto comments) or test-fixture identifiers. One is stale: `internal/vpnprovider/pia/auth.go:24` still defines `ErrPortForwardingNotImplemented` although PIA port forwarding **is** implemented in `internal/vpnprovider/pia/portforward.go`. | marker sweep, §5 |

One correction in the other direction: the brief's example that **`network.dial_timeout` is accepted
but never applied is itself now stale.** It is read at `internal/backend/netconfig.go:37` and applied
to the dialer at `:61-63`. The `network` block is fully wired — `keepalive` (`:36,58-60`),
`prefer_ipv6` (`:38,64-69`), `max_connections` (`internal/server/server.go:81,95`), and `ipv6` via
`AddressFamily()` (`internal/server/server.go:1131,1259`).

---

## 9. Prioritised work

Sizes are rough engineering estimates, not commitments.

### P0 — security controls and safety properties that are not there

1. **Wire brute-force protection.** `TODO.md:986-993,1556` marks it shipped; nothing constructs it and
   there is no YAML key. `BruteForceAuthenticator` is already a drop-in decorator with `Unwrap()`, so
   this is a config key plus one wrap in the chain build. *~1d.* (§4)
2. **Make an unreadable mTLS CRL fail closed.** `plugin/mtls/mtls.go:73-77` warns once and then treats
   every revoked certificate as valid. Return the error from the constructor. *~1h.* (§3, §7.0)
3. **Enforce `oauth.required_claims`, or reject it at validation.** Currently parsed, never checked, and
   exposed as a dashboard control — an operator restricting by `aud`/`iss` gets no restriction. Fix the
   UI/parser type mismatch at the same time. *~4h to enforce, ~1h to reject.* (§2)
4. **Fail closed when VPN routes or DNS cannot be installed** on macOS/Windows, matching
   `routes_linux.go:57-59`, and surface DNS failure on all three. Add the missing privilege pre-check
   so the common case gets a clear message rather than a mid-setup failure. *~1-2d.* (§6.2, §6.3)
5. **Fix the Windows split-tunnel port byte order** — one expression, five sites, with a table test
   over ports 80/443/8080/49152. Silently disables every app rule on Windows today. *~1h.* (§6.1)
6. **Validate split-tunnel and route patterns at load time** instead of discarding per-entry errors. In
   `include` mode a dropped rule sends that traffic outside the tunnel in cleartext. *~1d.* (§7.2, §7.5)
7. **Route `::/0` in full-tunnel VPN mode, or refuse to claim IPv6.** Today all IPv6 bypasses the
   tunnel while `SPECIFICATION.md:42` claims dual-stack support. Blocking IPv6 on the host when the
   tunnel is v4-only is an acceptable interim answer; silence is not. *~2-3d, or ~1h to disclose.* (§5)
8. **Apply security headers to the client's static UI.** `apiSecurityHeaders` is scoped to `/api`, and
   the global middleware lives in the dead `Handler()` path — so the client dashboard ships with no
   CSP, `X-Frame-Options`, or `nosniff`. *~2h.* (§4)

### P1 — silent wrong answers

9. **Make the OpenVPN backend detect its own child's death.** Move `cmd.Wait()` into a supervisor
   goroutine that records the exit and flips `healthy`; the current check is structurally incapable of
   firing (proven). *~4h.* (§7.1)
10. **Reject unknown config keys** — `yaml.Decoder` + `KnownFields(true)` at
    `internal/config/config.go:30`. Expect fallout in fixtures and example configs; that fallout is the
    point, and it is the single highest-leverage fix in this report. *~1d incl. cleanup.* (§2)
11. **Fix `$`-mangling of config values.** Restrict expansion to `${VAR}` with a `$$` escape, or expand
    per-scalar after parsing rather than over raw bytes. Document it either way. *~4h.* (§2)
12. **Connect or remove the TURN relay path.** `RelayedConnection.Connect` is never called, so a relayed
    peer reports connected and blackholes every frame — and the `mesh.turn.*` config never reaches the
    relay manager anyway (`ManagerConfig.TURNConfig` is write-only). Fixing both together is one
    change. *~1-2d.* (§2, §3, §5)
13. **Fix the tiered cache hit/miss accounting.** A disk-served workload reports a 0.5 hit rate; any
    alert on cache hit rate is wrong by up to 2×. *~2h.* (§3)
14. **Fix the updater's silent truncation** — check `out.Close()` and checksum the extracted binary,
    not just the archive. Also call `cleanupOldBinary` on Windows so `.old` binaries stop
    accumulating. *~4h.* (§7.4, §4)
15. **Surface access-log and cache write failures** — a counter plus a rate-limited warn. *~4h.*
    (§7.7, §7.12)
16. **Reject unrecognised `health_check.type`** instead of silently substituting a TCP probe, and honour
    the configured timeout in `PingChecker`. *~3h.* (§2)
17. **Add TLS to the Redis session store, or correct its godoc.** `internal/auth/session/redis.go:40-53`
    documents a `TLS` field that does not exist, and `NewRedisStore` builds a plain client — so session
    tokens cross the network in the clear with no way to change that, while the doc implies otherwise.
    *~3h to implement, ~10min to correct the comment.* (§5 marker inventory)

### P2 — knobs and docs that mislead operators

18. **Decide the listener-timeout triad.** Either implement `read_timeout`/`write_timeout`/`idle_timeout`
    as real deadlines on the accepted connection — which also closes the slowloris exposure proven in
    §2, where an idle client pins a goroutine and an fd indefinitely — or delete the three fields,
    rename the dial timeout honestly, and correct the six doc pages. Implementing is the better answer:
    the fields are documented, defaulted, and prescribed as a fix. *~2-3d including docs.*
19. **Resolve `server.tls` on the client.** Implement TLS to the upstream proxy or reject the block at
    validation. Security-relevant; do not leave it silently ignored. *~1d / ~1h.* (§2)
20. **Delete or reject the remaining dead config fields:** `web_ui.base_path` (delete — sub-path serving
    already works client-side), `logging.time_format`, `backends[].priority`, `servers[]`,
    `mesh.stun.timeout`, `tray.window_x/y`, `mtls.verify_time`, `max_load`/`auto_select`, and the
    client-side `tls`/`max_connections` on `ListenerConfig`. Each is small; the decision is the work,
    and rejecting at validation is strictly better than ignoring. *~2-3d for the batch.* (§2)
21. **Split `ListenerConfig`** into server and client variants, or reject the fields the client ignores.
    The shared struct is the root cause of three separate findings. *~4h.* (§2)
22. **Reconcile `docs/` with reality** — ICE and TURN relay documented as working
    (`mesh-networking.mdx:15,121,194-240,387-428`), `:808` telling readers to enable a flag startup
    rejects, `performance.mdx:201` suggesting HTTP/2, the PAC self-contradiction, and the macOS/Linux
    system-proxy underclaim. *~1d.* (§5)
23. **Ship a way to mint a `password_hash`.** Three doc pages point at `tools/hashpw`, which does not
    exist; two unused `HashPassword` helpers do. Wire one into the CLI and delete the other. *~2h.* (§4)
24. **Restore `logging.Close()` on shutdown** in both daemons, per `CLAUDE.md`. *~15min.* (§4)
25. **Restore `/debug/pprof` on the client**, or delete the two doc sections that document it. Given §2's
    goroutine-retention finding, restoring it is the better call. *~2h.* (§4)
26. **Finish or drop the session-cookie login flow.** The server half is built and config-gated; the SPA
    still keeps a bearer token in `localStorage`, which is what the flow exists to avoid. *~1-2d.* (§4)

### P3 — HTTP correctness (larger, deliberately separate)

27. **Implement an HTTP/1.1 request loop with correct hop-by-hop handling.** One request per connection,
    no `Via`, `Connection`-named headers forwarded, `Upgrade`/WebSocket dropped, h2c mis-parsed. This is
    a single coherent piece of work on the hottest path and should not be split across the items above.
    *~1-2w including tests.* (§5)
28. **Decide the IPv6 story properly** — dual-stack addressing in `vpn/tun.go`, `device/device.go`,
    `backend/wireguard.go`; fix the matcher's colon truncation and the `Contains(":")` has-port tests;
    or scope IPv6 out explicitly in `SPECIFICATION.md`. *~1-2w, or ~2h to scope out.* (§5)

### P4 — hygiene

29. Commit the `internal/api/*/static/.gitkeep` files that `.gitignore:51-52` already negates, so
    `go build ./...` and the linters work on a clean clone. *~5min.* (§1)
30. Delete the dead code marked **REMOVE** in §4. Roughly 1,500 lines across `auth/middleware.go`,
    `cache/range.go`, the `internal/util` and `internal/frame` accessor surfaces, `NoiseHandshake`,
    `AuthCodeFlow`, and the superseded constructors. Mechanical, but do it in small reviewable commits
    and keep `ICEAgent`/`RelayRouter`. *~2-3d.*
31. Push the `filter_domains` "not implemented" disclosure into `internal/config/templates.go:59` and
    the example configs — or implement it together with `debug.Logger.FindByHost`, its unused
    consumer. *~15min / ~4h.* (§2, §4)
32. Wire `vpnprovider.ValidateCACertPEM` into the OpenVPN config path so a malformed embedded CA fails
    at startup rather than at connect time. *~2h.* (§4)
33. Delete `ErrPortForwardingNotImplemented` (`internal/vpnprovider/pia/auth.go:24`) and the
    `windowsTUN.Index()` stub (`internal/device/tun_windows.go:217`). *~15min.*
34. Resolve `vpn.WithLogger` — implement or delete, and drop the test pinning the no-op. *~1h.* (§7.13)
35. Collapse the legacy `auth.native/system/ldap/oauth` structs to `map[string]any` so 21 phantom fields
    stop appearing in field sweeps. *~1h.* (§2)
36. Retire `AUDIT-FINDINGS.md` once §8 is folded into the issue tracker.

---

## What I did not verify

- **Runtime behaviour on Windows or macOS.** Every platform claim in §6 comes from reading code plus,
  for the byte-order bug, reproducing the arithmetic in isolation — not from running the client. Same
  for the Windows IPv6 route panic and the Linux-only resolv.conf/netlink paths in §5.
- **Live mesh / P2P end-to-end.** No two mesh nodes were stood up, so "the TURN relay is inert" (§3,
  §5) rests on the call graph plus `Send` returning `ErrNotConnected`, not on an observed dropped
  frame. Likewise the DNS qtype-cache bug is proven by reading `dns.go:184-207` against
  `dns_cache.go:106`, not by running a resolver.
- **The ~198-entry long tail of the dead-code scan** was not individually checked for reflective or
  `init()`-registry reachability. `deadcode`'s own answer for `(*API).Router` ("reachable only through
  reflection") proves the analysis is reflection-conservative, and the auth plugin registry registers
  via `init()`. Every finding *in the §4 table* was hand-verified with grep; the tail was not.
- **`mobile/` (React Native) as an API caller.** The route diff in §4 covered `web/*/src/`,
  `internal/cli/*/commands.go` and `docs/` — and found that `/api/v1/routes` is used by the CLI though
  the dashboard never calls it, which is exactly why "the UI doesn't call it" is not evidence of death.
  `mobile/` was not checked, so any endpoint I called unreachable could in principle have a caller
  there. The pprof and login/logout findings do not depend on this, since those routes are not
  registered on the served handler at all.
- **`desktop/` in the SSA pass.** Its `go.sum` lacks a `github.com/ProtonMail/go-srp` entry, so
  `deadcode` refuses to load it; a grep substitute showed it uses only 13 symbols, none appearing in
  §4. A symbol reachable *only* transitively from `desktop/` could still be misclassified.
- **The `AUDIT-FINDINGS.md` §8 P2P crypto remediation** and the **§7.2/7.3/7.8/7.9 VPN-provider CA
  fixes.** Both are annotated as fixed in that file; I did not independently re-derive them, and §8
  above says so explicitly rather than implying confirmation.
- **`internal/tray/` and `internal/service/`** — another agent's scope. `tray.window_x/y` is listed in
  §2 only because the module-wide sweep found no reader anywhere.
- **The web dashboards**, except for reading `web/*/src/api/` and one config form to establish the
  caller side of API and config surfaces.
- **Test-file cross-compilation** (`go vet` per GOOS) — only non-test builds were checked per platform.
- **Whether any finding here is already tracked** in `TODO.md` / `ISSUES.md`.
- **Config fields that are read but ineffective**, as a class. The type-checker sweep in §2 proves a
  field is never *read*; it cannot prove a read has an effect. Two instances were found by reading
  consuming code, but this class is not systematically covered and is where I would expect further
  findings to hide.
