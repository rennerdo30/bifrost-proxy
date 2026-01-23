# CLAUDE.md - Development Guidelines

## Project Overview

**Bifrost Proxy** - Go-based proxy system with client-server architecture.
- **Server**: Central proxy with WireGuard/OpenVPN tunnels, forward proxy backends, caching
- **Client**: Local proxy with traffic debugging, split tunneling, VPN mode, mesh networking

**Repository**: `github.com/rennerdo30/bifrost-proxy`
**License**: MIT
**Go Version**: 1.23+

## Critical Rules

### Testing Requirements
- **ALL tests must pass before any commit** - run `go test ./...`
- **Test coverage must be as close to 100% as possible** - run `go test -cover ./...`
- No commit is complete until tests are green
- Add tests for any new functionality

### Documentation Requirements
- **Keep `docs/` up to date** when changing features
- **Keep `SPECIFICATION.md` up to date** when changing architecture or APIs
- Update `CHANGELOG.md` for user-facing changes

### Code Quality
- All code must pass `golangci-lint run`
- Use structured logging with `log/slog`
- Never log sensitive data (passwords, tokens, keys)
- Wrap errors with context: `fmt.Errorf("failed to X: %w", err)`

### Dependencies
- **Keep all dependencies up to date** - run `go get -u ./...` and `npm update` regularly
- Use Dependabot for automated dependency updates
- Review and merge dependency PRs promptly

### Diagrams
- **Always use Mermaid** for diagrams in documentation
- Mermaid is supported natively in MkDocs Material and GitHub markdown
- Avoid external diagram tools or image files when possible

## Build Commands

```bash
# Build
make build                    # Build server + client binaries
make build-all               # Cross-platform builds

# Test
go test ./...                # Run all tests (REQUIRED before commit)
go test -cover ./...         # Run with coverage report
go test -tags=integration ./... # Integration tests

# Web UIs
cd web/server && npm run build  # Server dashboard
cd web/client && npm run build  # Client dashboard

# Docker
make docker-build            # Verify Docker builds work
```

## Project Structure (Key Paths)

```
internal/
├── server/          # Main proxy server
├── client/          # Client with debug/VPN
├── backend/         # Backend implementations (direct, wireguard, openvpn, httpproxy, socks5)
├── proxy/           # HTTP and SOCKS5 proxy handlers
├── router/          # Domain matching and routing
├── auth/            # Authentication plugins (native, ldap, oauth, jwt, mtls, etc.)
├── logging/         # Structured logging with file rotation
├── config/          # YAML config parsing
├── api/server/      # Server REST API + WebSocket
├── api/client/      # Client REST API
├── mesh/            # P2P mesh networking
├── vpn/             # TUN device and split tunneling
└── cache/           # Response caching (memory/disk/tiered)

web/
├── server/          # React + TypeScript dashboard (builds to internal/api/server/static/)
└── client/          # React + TypeScript dashboard (builds to internal/api/client/static/)

docs/                # MkDocs documentation (deployed to GitHub Pages)
```

## Key Implementation Details

### Logging System (`internal/logging/`)
- Uses `log/slog` with JSON (production) or text (development) format
- Supports file rotation with max size/count
- **Must call `logging.Close()` on shutdown** to release file handles
- Log levels: debug, info, warn, error

### Web UIs
- Built with Vite + React + TypeScript + Tailwind
- Output goes to `internal/api/*/static/` (embedded in binary)
- Use Toast notifications instead of `alert()` for user feedback
- All icon buttons need `aria-label` for accessibility

### Server Configuration
- Hot-reload supported for: routes, rate limits, access control
- Restart required for: listeners, backends, TLS settings
- Config sections marked with badges in Web UI

### Graceful Shutdown
- Use `context.WithTimeout` for shutdown operations (30s default)
- Close log files, stop backends, drain connections

## Common Tasks

### Adding a Backend Type
1. Create `internal/backend/mybackend.go` implementing `Backend` interface
2. Register in `internal/backend/factory.go`
3. Add config in `internal/config/server.go`
4. Add tests in `internal/backend/mybackend_test.go`
5. Update docs

### Adding API Endpoint
1. Add handler in `internal/api/*/handlers.go`
2. Register route in `internal/api/*/server.go`
3. Add TypeScript types in `web/*/src/api/types.ts`
4. Update Web UI components
5. Update docs

### Modifying Config Schema
1. Update Go structs in `internal/config/`
2. Update TypeScript types in `web/*/src/api/types.ts`
3. Update Web UI form components
4. Update `SPECIFICATION.md`
5. Update docs

## Git Commits

**Before committing:**
1. `go build ./...` - must succeed
2. `go test ./...` - ALL tests must pass
3. `golangci-lint run` - no errors
4. Web UIs build if changed

**Commit format:** `<type>(<scope>): <description>`
Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## CI/CD

All PRs require:
- Build success (Go + Web UIs)
- All tests passing
- Lint passing
- Security scan (gosec, govulncheck)
- Docker build verification
