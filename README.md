# Bifrost

A production-ready, MIT-licensed proxy server with support for WireGuard and OpenVPN tunnels, domain-based routing, multiple authentication modes, and comprehensive traffic management.

## Features

- **Multiple Proxy Protocols**: HTTP, HTTPS (CONNECT), SOCKS5
- **VPN Tunnel Support**: WireGuard (userspace), OpenVPN
- **Upstream Proxy Support**: Chain through HTTP or SOCKS5 proxies
- **Domain-Based Routing**: Route traffic through different backends based on domain patterns
- **Authentication Modes**: None, Native, System (PAM/Windows/macOS), LDAP, OAuth/OIDC
- **Traffic Management**: Rate limiting, bandwidth throttling, health checks, load balancing
- **Observability**: Prometheus metrics, structured logging, access logs
- **Cross-Platform**: Windows, macOS, Linux

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│   Browser   │────▶│   Client    │────▶│       Server        │
│  / App      │     │  (local)    │     │    (central)        │
└─────────────┘     └─────────────┘     └──────────┬──────────┘
                                                   │
                    ┌──────────────────────────────┼──────────────────────────────┐
                    │                              │                              │
                    ▼                              ▼                              ▼
            ┌───────────────┐             ┌───────────────┐             ┌───────────────┐
            │   WireGuard   │             │    OpenVPN    │             │ HTTP/SOCKS5   │
            │    Tunnel     │             │    Tunnel     │             │    Proxy      │
            └───────────────┘             └───────────────┘             └───────────────┘
```

## Quick Start

### Server

```bash
# Build
make build-server

# Run with config
./bin/bifrost-server -c server-config.yaml
```

### Client

```bash
# Build
make build-client

# Run with config
./bin/bifrost-client -c client-config.yaml
```

## Configuration

See [Configuration Documentation](docs/configuration.md) for full details.

### Minimal Server Config

```yaml
server:
  http:
    listen: ":8080"
  socks5:
    listen: ":1080"

backends:
  - name: direct
    type: direct

routes:
  - domains: ["*"]
    backend: direct
```

### Minimal Client Config

```yaml
proxy:
  http:
    listen: "127.0.0.1:3128"

server:
  address: "proxy.example.com:8080"

routes:
  - domains: ["*"]
    action: server
```

## Building

### Prerequisites

- Go 1.22+
- Make
- Node.js 18+ (for Web UI)

### Build Commands

```bash
# Build everything
make build

# Build with specific targets
make build-server
make build-client

# Cross-platform builds
make build-all

# Run tests
make test

# Run linter
make lint
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Backends](docs/backends.md)
- [Authentication](docs/authentication.md)
- [API Reference](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

MIT License - see [LICENSE](LICENSE) for details.
