# Getting Started with Bifrost

This guide will help you get Bifrost up and running quickly.

## Prerequisites

- Go 1.24+ (for building from source)
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
    listen: ":7080"
  socks5:
    listen: ":7180"

backends:
  - name: direct
    type: direct
    enabled: true

routes:
  - domains: ["*"]
    backend: direct

metrics:
  enabled: true
  listen: ":7090"
```

2. Start the server:

```bash
./bifrost-server -c server-config.yaml
```

3. Verify it's running:

```bash
curl http://localhost:7090/metrics
```

### Client Setup

#### Option 1: Generate Config from CLI

```bash
# Generate a config file with your server address
./bifrost-client config init -s your-server:7080

# Or with custom options
./bifrost-client config init \
  -s your-server:7080 \
  -p socks5 \
  --http-listen 127.0.0.1:8888 \
  -o my-config.yaml
```

#### Option 2: Generate Config from Web Dashboard

1. Open your server's web dashboard (e.g., `http://your-server:7081`)
2. Click "Config Generator" tab
3. Fill in the form and download the configuration

#### Option 3: Create Config Manually

Create a configuration file `client-config.yaml`:

```yaml
proxy:
  http:
    listen: "127.0.0.1:7380"

server:
  address: "your-server:7080"

routes:
  - domains: ["*"]
    action: server
```

#### Start the Client

```bash
./bifrost-client -c client-config.yaml
```

#### Configure Your Applications

See the **Setup Guide** tab in the web dashboard for detailed instructions, or use these common methods:

**Browser:**
- Configure your browser to use `127.0.0.1:7380` as HTTP proxy

**Environment Variables:**
```bash
export HTTP_PROXY=http://127.0.0.1:7380
export HTTPS_PROXY=http://127.0.0.1:7380
```

**Command Line:**
```bash
curl -x http://127.0.0.1:7380 https://example.com
```

## Testing the Setup

Test with curl:

```bash
# HTTP proxy
curl -x http://127.0.0.1:7380 http://httpbin.org/ip

# SOCKS5 proxy
curl --socks5 127.0.0.1:7381 http://httpbin.org/ip
```

## Next Steps

- [Configuration Guide](configuration.md) - Full configuration reference
- [Backend Guide](backends.md) - Configure WireGuard, OpenVPN, and proxy backends
- [Authentication Guide](authentication.md) - Set up authentication
- [API Reference](api.md) - REST API documentation
