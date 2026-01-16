# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
