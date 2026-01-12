# Getting Started with Bifrost

This guide will help you get Bifrost up and running quickly.

## Prerequisites

- Go 1.22+ (for building from source)
- Docker (optional, for containerized deployment)

## Installation

### From Binary

Download the latest release from the [releases page](https://github.com/bifrost-proxy/bifrost/releases).

```bash
# Linux (amd64)
curl -LO https://github.com/bifrost-proxy/bifrost/releases/latest/download/bifrost_linux_amd64.tar.gz
tar -xzf bifrost_linux_amd64.tar.gz

# macOS (arm64)
curl -LO https://github.com/bifrost-proxy/bifrost/releases/latest/download/bifrost_darwin_arm64.tar.gz
tar -xzf bifrost_darwin_arm64.tar.gz
```

### From Source

```bash
git clone https://github.com/bifrost-proxy/bifrost.git
cd bifrost
make build
```

### With Docker

```bash
docker pull ghcr.io/bifrost-proxy/bifrost/server:latest
docker pull ghcr.io/bifrost-proxy/bifrost/client:latest
```

## Quick Start

### Server Setup

1. Create a configuration file `server-config.yaml`:

```yaml
server:
  http:
    listen: ":8080"
  socks5:
    listen: ":1080"

backends:
  - name: direct
    type: direct
    enabled: true

routes:
  - domains: ["*"]
    backend: direct

metrics:
  enabled: true
  listen: ":9090"
```

2. Start the server:

```bash
./bifrost-server -c server-config.yaml
```

3. Verify it's running:

```bash
curl http://localhost:9090/metrics
```

### Client Setup

1. Create a configuration file `client-config.yaml`:

```yaml
proxy:
  http:
    listen: "127.0.0.1:3128"

server:
  address: "your-server:8080"

routes:
  - domains: ["*"]
    action: server
```

2. Start the client:

```bash
./bifrost-client -c client-config.yaml
```

3. Configure your browser/application to use `127.0.0.1:3128` as HTTP proxy.

## Testing the Setup

Test with curl:

```bash
# HTTP proxy
curl -x http://127.0.0.1:3128 http://httpbin.org/ip

# SOCKS5 proxy
curl --socks5 127.0.0.1:1081 http://httpbin.org/ip
```

## Next Steps

- [Configuration Guide](configuration.md) - Full configuration reference
- [Backend Guide](backends.md) - Configure WireGuard, OpenVPN, and proxy backends
- [Authentication Guide](authentication.md) - Set up authentication
- [API Reference](api.md) - REST API documentation
