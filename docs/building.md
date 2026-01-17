# Building Bifrost

This guide covers building Bifrost from source for various platforms.

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.22+ | Compiler |
| Node.js | 18+ | Web UI build |
| npm | 9+ | Package manager |
| Make | any | Build automation |
| Git | any | Version control |

### Installing Prerequisites

**macOS:**
```bash
brew install go node git make
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install golang nodejs npm git make
```

**Fedora:**
```bash
sudo dnf install golang nodejs npm git make
```

**Windows (with Chocolatey):**
```powershell
choco install golang nodejs git make
```

### Verify Installation

```bash
go version      # Should show go1.22+
node --version  # Should show v18+
npm --version   # Should show 9+
make --version
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/rennerdo30/bifrost-proxy.git
cd bifrost-proxy

# Build everything (server + client + web UI)
make build

# Binaries are in bin/
ls bin/
# bifrost-server  bifrost-client
```

## Build Targets

### Development Builds

```bash
# Build both server and client (includes web UI)
make build

# Build server only
make build-server

# Build client only
make build-client

# Build stripped binaries (30-40% smaller, no debug info)
make build-stripped
```

### Cross-Platform Builds

```bash
# Build for all platforms (Linux, macOS, Windows)
make build-all

# Build for specific platform
make build-linux
make build-darwin
make build-windows
```

### OpenWrt / Embedded Builds

```bash
# Build for all OpenWrt architectures
make build-openwrt

# Build for MIPS only (big-endian + little-endian)
make build-openwrt-mips

# Build for ARM only (v6, v7, arm64)
make build-openwrt-arm
```

## Output Directories

| Directory | Contents |
|-----------|----------|
| `bin/` | Development binaries (current platform) |
| `dist/` | Cross-compiled release binaries |

## Build Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERSION` | git tag | Version string embedded in binary |
| `COMMIT` | git sha | Commit hash embedded in binary |
| `CGO_ENABLED` | 0 | Disable CGO for static binaries |

Example with custom version:
```bash
VERSION=1.0.0-custom make build
```

### Build Flags

The Makefile uses these Go build flags:

```bash
# Standard build
-ldflags "-X .../version.Version=... -X .../version.GitCommit=..."

# Stripped build (smaller binary)
-ldflags "-s -w -X .../version.Version=... -X .../version.GitCommit=..."
```

- `-s` strips the symbol table
- `-w` strips DWARF debugging info

## Manual Build Commands

If you prefer not to use Make:

### Standard Build

```bash
# Build web UI first
cd web/server && npm install && npm run build && cd ../..
cd web/client && npm install && npm run build && cd ../..

# Build Go binaries
go build -o bin/bifrost-server ./cmd/server
go build -o bin/bifrost-client ./cmd/client
```

### Cross-Compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o dist/bifrost-server-linux-amd64 ./cmd/server

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o dist/bifrost-server-darwin-arm64 ./cmd/server

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o dist/bifrost-server-windows-amd64.exe ./cmd/server

# OpenWrt MIPS (with softfloat)
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
  go build -ldflags "-s -w" -o dist/bifrost-server-linux-mipsle ./cmd/server

# OpenWrt ARM v7
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -ldflags "-s -w" -o dist/bifrost-server-linux-arm7 ./cmd/server
```

## Architecture Reference

### Supported Platforms

| OS | Architecture | Binary Suffix | Notes |
|----|--------------|---------------|-------|
| Linux | amd64 | `-linux-amd64` | Most servers/desktops |
| Linux | arm64 | `-linux-arm64` | Raspberry Pi 3+, modern ARM |
| Linux | arm (v6) | `-linux-arm6` | Raspberry Pi 1, Pi Zero |
| Linux | arm (v7) | `-linux-arm7` | Raspberry Pi 2, many routers |
| Linux | mips | `-linux-mips` | OpenWrt routers (big-endian) |
| Linux | mipsle | `-linux-mipsle` | OpenWrt routers (little-endian) |
| macOS | amd64 | `-darwin-amd64` | Intel Macs |
| macOS | arm64 | `-darwin-arm64` | Apple Silicon (M1/M2/M3) |
| Windows | amd64 | `-windows-amd64.exe` | Most Windows PCs |

### OpenWrt Architecture Detection

To determine your router's architecture:

```bash
# On the router
cat /proc/cpuinfo | head -10

# Or check OpenWrt info
cat /etc/openwrt_release
uname -m
```

| `uname -m` Output | Binary to Use |
|-------------------|---------------|
| `mips` | `bifrost-server-linux-mips` |
| `mipsel` | `bifrost-server-linux-mipsle` |
| `armv6l` | `bifrost-server-linux-arm6` |
| `armv7l` | `bifrost-server-linux-arm7` |
| `aarch64` | `bifrost-server-linux-arm64-openwrt` |

## Web UI Build

The web UI is built with Vite and embedded into the Go binary.

### Build Commands

```bash
# Install dependencies
make web-install

# Build both UIs
make web-build

# Build server UI only
make web-build-server

# Build client UI only
make web-build-client

# Development server (hot reload)
make web-dev          # Server UI
make web-dev-client   # Client UI
```

### Web UI Source

| Path | Description |
|------|-------------|
| `web/server/` | Server dashboard UI |
| `web/client/` | Client debug/traffic UI |

### Embedded Static Files

Built UI files are copied to:
- `internal/api/server/static/` (server)
- `internal/api/client/static/` (client)

These are embedded using Go's `//go:embed` directive.

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run integration tests (requires more setup)
make test-integration

# View coverage report
open coverage.html
```

## Linting

```bash
# Run linter
make lint

# Format code
make fmt
```

Requires `golangci-lint`:
```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Docker Build

```bash
# Build Docker images
make docker-build

# Build and start with docker-compose
make docker-deploy

# Rebuild with no cache
make docker-rebuild-clean
```

## Release Process

Releases are automated via GitHub Actions:

1. **Nightly builds**: Triggered on every push to `master`/`main`
2. **Tagged releases**: Triggered when a tag like `v1.0.0` is pushed

### Creating a Release

```bash
# Tag a release
git tag v1.0.0
git push origin v1.0.0
```

This triggers:
1. GoReleaser builds all platforms (including OpenWrt)
2. Creates GitHub release with binaries
3. Builds and pushes Docker images

### Manual Release Build

```bash
# Install GoReleaser
go install github.com/goreleaser/goreleaser@latest

# Build without releasing (dry run)
goreleaser release --snapshot --clean

# Check dist/ for output
ls dist/
```

## Troubleshooting

### "go: command not found"

Ensure Go is in your PATH:
```bash
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:$(go env GOPATH)/bin
```

### "npm: command not found"

Install Node.js:
```bash
# macOS
brew install node

# Ubuntu
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

### Web UI not updating

The web UI is embedded at build time. Rebuild to see changes:
```bash
make web-build
make build
```

### Binary too large

Use stripped builds:
```bash
make build-stripped
# or
make build-openwrt  # OpenWrt builds are always stripped
```

### Cross-compilation fails

Ensure CGO is disabled for cross-compilation:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build ...
```

### MIPS build fails with "softfloat required"

Some MIPS routers lack hardware floating-point. Use:
```bash
GOMIPS=softfloat go build ...
```

The `make build-openwrt-mips` target includes this automatically.

## CI/CD Integration

### GitHub Actions

The project includes these workflows:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, push | Tests, linting |
| `nightly.yml` | push to master | Nightly builds |
| `release.yml` | tag `v*` | Official releases |
| `docs.yml` | docs changes | Documentation site |

### Required Secrets

For releases:
- `GITHUB_TOKEN` (automatic)

For Docker registry (optional):
- Container registry credentials (uses GHCR by default)

## Binary Size Reference

Approximate sizes after stripping:

| Platform | Server | Client |
|----------|--------|--------|
| Linux amd64 | ~15 MB | ~12 MB |
| Linux arm64 | ~14 MB | ~11 MB |
| OpenWrt MIPS | ~12 MB | ~10 MB |
| OpenWrt ARM7 | ~11 MB | ~9 MB |
| macOS arm64 | ~15 MB | ~12 MB |
| Windows amd64 | ~16 MB | ~13 MB |

*Sizes include embedded web UI (~400KB compressed)*
