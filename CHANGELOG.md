# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Added
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
- Redesigned logo, favicons, tray icons and app icons around a single mark: a
  faceted span crossing between two realms, drawn on a 4-unit grid so it stays
  legible down to 16px. Light and dark variants plus a monochrome cut ship in
  `assets/`; both dashboards and the docs site now use the same favicon

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
