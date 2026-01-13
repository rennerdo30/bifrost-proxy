# Bifrost Proxy

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
- **Web Dashboard**: Real-time monitoring, config generator, setup guides

## Architecture

```mermaid
graph LR
    Browser[Browser / App] -->|HTTP/SOCKS5| Client[Client<br/>local]
    Client -->|HTTP/SOCKS5| Server[Server<br/>central]
    Server -->|Tunnel| WireGuard[WireGuard<br/>Tunnel]
    Server -->|Tunnel| OpenVPN[OpenVPN<br/>Tunnel]
    Server -->|Proxy| HTTPProxy[HTTP/SOCKS5<br/>Proxy]
    
    style Browser fill:#4a90e2,stroke:#2c5aa0,color:#fff
    style Client fill:#7b68ee,stroke:#5a4fcf,color:#fff
    style Server fill:#50c878,stroke:#3a9d5f,color:#fff
    style WireGuard fill:#ff6b6b,stroke:#d63031,color:#fff
    style OpenVPN fill:#ffa726,stroke:#f57c00,color:#fff
    style HTTPProxy fill:#26c6da,stroke:#00acc1,color:#fff
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

# Generate a config file
./bin/bifrost-client config init -s your-server:8080

# Run with config
./bin/bifrost-client -c client-config.yaml
```

## Minimal Configuration

### Server

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

### Client

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

## Web Dashboard

The server includes a built-in web dashboard accessible at the configured web UI port (default: `:8081`).

Features:

- **Dashboard**: Real-time connection stats and backend health
- **Backends**: View all configured backends and their status
- **Statistics**: Traffic metrics and request counts
- **Config Generator**: Generate client configurations with a visual form
- **Setup Guide**: Instructions for configuring browsers, system settings, and CLI tools

## Building

### Prerequisites

- Go 1.24+
- Make

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

## License

MIT License - see [LICENSE](https://github.com/rennerdo30/bifrost-proxy/blob/main/LICENSE) for details.
