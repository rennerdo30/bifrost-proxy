# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
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

### Added
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
- The server dashboard's auth provider list gained `mfa_wrapper`, which was
  registered and working but missing from the UI entirely, with a default config
  in the inline `primary`/`secondary` format the server actually accepts

### Changed
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

### Removed
- Dead API helpers `AddWebSocketRoutes`, `setWebSocketHub` and the unrouted
  `handleGetConfigTimestamp` (which returned `time.Now()` instead of the config
  file's modification time — use `GET /api/v1/config/meta`)
- `device.GenerateMAC`, whose doc comment promised a random address while the
  body returned the hardcoded `02:BF:00:00:00:01`. Use
  `device.GenerateRandomMAC`, which the production paths already used

### Changed
- `API.Router()` now registers the same routes as `RouterWithWebSocket` instead
  of a hand-maintained subset that silently omitted the cache and mesh routes
- Windows TAP `SetMACAddress` now returns `ErrSetMACUnsupported` instead of
  reporting success while changing nothing but an in-memory field

### Security
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

### Fixed
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
  Purge Domain / Clear All / Add Rule buttons. It now reports "Caching is not
  configured", disables the destructive actions, stops polling the missing
  endpoints and surfaces other failures with a retry. The Mesh page gained the
  same treatment for `mesh.enabled: false`
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

### Fixed
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

### Fixed
- Cross-compilation support for VPN mode on all platforms
- Removed CGo dependency from darwin process lookup
- Restored .gitkeep files for static directories

### Changed
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
