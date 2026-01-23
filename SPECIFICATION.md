# Simple Proxy Server - Technical Specification

**License**: MIT License
**Repository**: https://github.com/[org]/simple-proxy-server
**Status**: Production-ready open source software

## 1. Overview

A Go-based proxy system with client-server architecture providing HTTP, HTTPS, and SOCKS5 proxy capabilities with intelligent routing and traffic debugging.

> [!IMPORTANT]
> This project is designed for production use. All components follow strict security practices, including structured logging, encrypted tunnels, and modular authentication.

### Key Features
- HTTP, HTTPS (CONNECT), and SOCKS5 proxy protocols
- VPN tunnel integration (WireGuard and OpenVPN)
- Traditional forward proxy support
- Domain-based intelligent routing
- Multiple authentication modes (none, native, system, LDAP, OAuth)
- Traffic debugging and inspection
- Cross-platform support (Windows, macOS, Linux)
- System tray integration (client)
- Docker deployment support (server)
- Production-ready with proper logging and security
- Rate limiting and bandwidth throttling
- Backend health checks with automatic failover
- Load balancing across multiple backends
- Prometheus metrics and Grafana dashboards
- IPv6 / dual-stack networking support
- Graceful shutdown with connection draining
- Hot reload without dropping connections
- IP whitelist/blacklist access control
- Structured access logging (JSON, Apache formats)

## 2. Components

### 2.1 Server (`simple-proxy-server`)

Central proxy server that handles the actual routing through different backends.

```mermaid
graph TD
    subgraph "Ingress Layers"
        H[HTTP Proxy]
        HT[HTTPS Tunnel]
        S[SOCKS5 Proxy]
    end

    subgraph "Core Logic"
        H & HT & S --> Router[Router / Matcher]
        Router -->|Domain Match| Backends
    end

    subgraph "Egress Backends"
        Backends{Backends}
        Backends --> D[Direct Connection]
        Backends --> WG[WireGuard Tunnel]
        Backends --> F[Forward Proxy]
    end

    subgraph "Management"
        CM[Config Manager]
        WUI[Web UI / REST API]
        CLI[CLI Control]
    end
```

### 2.2 Client (`simple-proxy-client`)

Local proxy that decides what traffic goes to the server vs direct. Includes system tray integration for easy access on all platforms.

```mermaid
graph TD
    subgraph "Local Listeners"
        H[HTTP Proxy]
        HT[HTTPS Tunnel]
        S[SOCKS5 Proxy]
    end

    subgraph "Traffic Handling"
        H & HT & S --> Debug[Traffic Debugger]
        Debug --> Router[Router / Matcher]
    end

    subgraph "Routing Decisions"
        Router --> Decisions{Target?}
        Decisions -->|Bypass| Direct[Direct Connection]
        Decisions -->|Tunnel| Server[Bifrost Server]
    end

    subgraph "User Interface"
        CM[Config Manager]
        WUI[Web UI]
        CLI[CLI]
        Tray[Tray Icon]
    end
```

## 3. Configuration

### 3.1 Server Configuration (`server-config.yaml`)

```yaml
# Server configuration
server:
  http_port: 7080           # HTTP/HTTPS proxy port
  socks5_port: 7180         # SOCKS5 proxy port
  bind_address: "0.0.0.0"   # Bind to all interfaces (for clients)
  web_ui_port: 7081         # Web UI port
  log_level: "info"         # debug, info, warn, error

  # Authentication for clients (see Section 12 for details)
  auth:
    mode: "none"            # none, native, system, ldap, oauth

# Network settings
network:
  # IPv6 support
  ipv6:
    enabled: true           # Enable IPv6 support
    prefer_ipv6: false      # Prefer IPv6 over IPv4 when both available

  # Connection timeouts
  timeouts:
    connect: "10s"          # Timeout for establishing connection to backend
    read: "30s"             # Timeout for reading response from backend
    write: "30s"            # Timeout for writing request to backend
    idle: "60s"             # Idle timeout before closing connection

  # Keep-alive settings
  keepalive:
    enabled: true
    interval: "30s"         # TCP keepalive probe interval
    max_idle_conns: 100     # Max idle connections per backend
    max_idle_time: "90s"    # Max time a connection can be idle

  # Connection limits
  limits:
    max_connections: 10000           # Max total connections
    max_connections_per_ip: 100      # Max connections per client IP
    max_connections_per_backend: 50  # Max connections per backend

> [!TIP]
> Use environment variables (e.g., `${OAUTH_CLIENT_SECRET}`) for sensitive credentials to avoid committing them to version control.

# Rate limiting
rate_limiting:
  enabled: true
  # Global rate limits
  global:
    requests_per_second: 1000
    burst: 100
  # Per-IP rate limits
  per_ip:
    requests_per_second: 100
    burst: 20
  # Per-user rate limits (when auth enabled)
  per_user:
    requests_per_second: 200
    burst: 50
  # Bandwidth throttling
  bandwidth:
    enabled: false
    max_mbps_per_connection: 100    # Max Mbps per connection (0 = unlimited)
    max_mbps_per_ip: 500            # Max Mbps per client IP
    max_mbps_total: 10000           # Max total bandwidth

# IP Access Control
access_control:
  # IP whitelist (if set, only these IPs can connect)
  whitelist: []
    # - "192.168.1.0/24"
    # - "10.0.0.0/8"
  # IP blacklist (these IPs are always blocked)
  blacklist: []
    # - "1.2.3.4"
    # - "5.6.7.0/24"

# Access logging
access_log:
  enabled: true
  format: "json"            # json, apache_combined, apache_common
  output: "file"            # file, stdout, both
  file: "/var/log/proxy/access.log"
  # Fields to include
  fields:
    - timestamp
    - client_ip
    - username
    - method
    - host
    - path
    - status
    - bytes_sent
    - duration
    - backend
    - user_agent
  # Sensitive header masking
  mask_headers:
    - "Authorization"
    - "Cookie"
    - "X-Api-Key"

# Backend definitions
backends:
  # Direct connection (no proxy)
  - name: "direct"
    type: "direct"

  # WireGuard tunnel
  - name: "germany"
    type: "wireguard"
    wireguard:
      config_file: "/path/to/germany.conf"
    # Health check configuration (optional, per backend)
    health_check:
      enabled: true
      interval: "30s"           # How often to check
      timeout: "5s"             # Health check timeout
      type: "tcp"               # tcp, http, or ping
      # For HTTP health checks:
      # type: "http"
      # http:
      #   url: "http://example.com/health"
      #   expected_status: 200

  - name: "japan"
    type: "wireguard"
    wireguard:
      config_file: "/path/to/japan.conf"
    health_check:
      enabled: true
      interval: "30s"
      timeout: "5s"
      type: "tcp"

  # OpenVPN tunnel
  - name: "uk-vpn"
    type: "openvpn"
    openvpn:
      config_file: "/path/to/uk.ovpn"
      auth_file: "/path/to/uk-auth.txt"  # Optional: username/password file

  # Traditional forward proxy
  - name: "us-proxy"
    type: "http"
    proxy:
      address: "proxy.example.com:7080"
      username: ""
      password: ""

  # SOCKS5 forward proxy
  - name: "socks-proxy"
    type: "socks5"
    proxy:
      address: "socks.example.com:7180"
      username: ""
      password: ""

  # NordVPN - automatic server selection with WireGuard
  - name: "nordvpn-us"
    type: "nordvpn"
    nordvpn:
      country: "US"              # ISO country code
      city: "New York"           # Optional: specific city
      protocol: "wireguard"      # wireguard or openvpn
      auto_select: true          # Auto-select best server
      max_load: 50               # Skip servers above 50% load

  # Mullvad - account number authentication
  - name: "mullvad-de"
    type: "mullvad"
    mullvad:
      account_id: "1234567890123456"  # 16-digit account number
      country: "DE"
      city: ""                   # Optional
      protocol: "wireguard"
      auto_select: true

  # PIA (Private Internet Access) - username/password auth
  - name: "pia-uk"
    type: "pia"
    pia:
      username: "p1234567"
      password: "${PIA_PASSWORD}"  # Use env var for security
      country: "UK"
      protocol: "wireguard"
      port_forwarding: true      # Enable PIA port forwarding

  # ProtonVPN - OpenVPN credentials from account portal
  - name: "proton-ch"
    type: "protonvpn"
    protonvpn:
      username: "username+pmp"   # OpenVPN/IKEv2 username from account.protonvpn.com
      password: "${PROTON_PASSWORD}"
      country: "CH"
      tier: "plus"               # free, basic, plus, visionary
      secure_core: false         # Enable Secure Core routing
      protocol: "openvpn"        # Currently OpenVPN only

# Routing rules (evaluated in order, first match wins)
rules:
  - name: "Crunchyroll via Germany"
    match:
      domains:
        - "*.crunchyroll.com"
        - "crunchyroll.com"
    backend: "germany"

  - name: "Anime via Japan"
    match:
      domains:
        - "*.funimation.com"
        - "*.animelab.com"
    backend: "japan"

  - name: "US streaming"
    match:
      domains:
        - "*.netflix.com"
        - "*.hulu.com"
    backend: "us-proxy"

  # Default rule (always last)
  - name: "Default"
    match:
      domains:
        - "*"
    backend: "direct"
```

### 3.2 Client Configuration (`client-config.yaml`)

```yaml
# Client configuration
client:
  http_port: 7380           # Local HTTP/HTTPS proxy port
  socks5_port: 7381         # Local SOCKS5 proxy port
  bind_address: "127.0.0.1" # Only local connections
  web_ui_port: 7382         # Web UI port
  log_level: "info"

# System tray configuration
tray:
  enabled: true             # Enable system tray icon
  start_minimized: false    # Start minimized to tray
  show_notifications: true  # Show desktop notifications for events
  autostart: false          # Start on system login (registers with OS)

# Server connection
server:
  address: "proxy-server.example.com:7080"
  protocol: "http"          # http, https, socks5
  auth:
    enabled: false
    username: ""
    password: ""

# Traffic debugging
debug:
  enabled: true
  log_requests: true        # Log all requests
  log_responses: true       # Log response status/timing
  log_headers: false        # Log request/response headers (verbose)
  log_body: false           # Log body content (very verbose, use with caution)
  max_body_log_size: 1024   # Max bytes to log from body
  output: "file"            # file, stdout, both
  log_file: "./traffic.log"

  # Filter what to debug
  filter:
    domains: []             # Empty = all, or specify domains to debug
    methods: []             # Empty = all, or ["GET", "POST", etc.]
    status_codes: []        # Empty = all, or [400, 500] for errors only

# Routing rules - what goes to server vs direct
rules:
  # Traffic that needs special routing goes to server
  - name: "Streaming sites via server"
    match:
      domains:
        - "*.crunchyroll.com"
        - "*.netflix.com"
        - "*.funimation.com"
    action: "server"        # Route through proxy server

  - name: "Work sites via server"
    match:
      domains:
        - "*.company.com"
    action: "server"

  # Everything else goes direct
  - name: "Default direct"
    match:
      domains:
        - "*"
    action: "direct"        # Direct connection (bypass server)
```

### 3.3 WireGuard Configuration Reference

Standard WireGuard `.conf` files:

```ini
[Interface]
PrivateKey = <base64-encoded-private-key>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <base64-encoded-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

### 3.4 OpenVPN Configuration Reference

Standard OpenVPN `.ovpn` files are supported:

```
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
# or use auth-user-pass for username/password
auth-user-pass
cipher AES-256-GCM
auth SHA256
verb 3
```

**Authentication options:**
```yaml
# Option 1: Credentials in auth file
openvpn:
  config_file: "/path/to/config.ovpn"
  auth_file: "/path/to/auth.txt"  # Contains username on line 1, password on line 2

# Option 2: Inline credentials (not recommended, use env vars)
openvpn:
  config_file: "/path/to/config.ovpn"
  username: "${OPENVPN_USERNAME}"
  password: "${OPENVPN_PASSWORD}"

# Option 3: Certificate-based (no auth file needed)
openvpn:
  config_file: "/path/to/config.ovpn"  # Contains cert/key paths
```

**Note**: The server uses an embedded OpenVPN client library or spawns the `openvpn` binary (must be installed on the system). For Docker deployments, the OpenVPN client is included in the image.

## 4. Traffic Debugging

### 4.1 Debug Log Format

```
[2024-01-15 10:30:45.123] [REQ] id=abc123 method=GET host=api.example.com path=/v1/users client=127.0.0.1:54321 route=server
[2024-01-15 10:30:45.456] [RES] id=abc123 status=200 size=1234 duration=333ms
```

With headers enabled:
```
[2024-01-15 10:30:45.123] [REQ] id=abc123 method=GET host=api.example.com path=/v1/users
  Headers: User-Agent: Mozilla/5.0, Accept: application/json, Authorization: Bearer ***
[2024-01-15 10:30:45.456] [RES] id=abc123 status=200 size=1234 duration=333ms
  Headers: Content-Type: application/json, Cache-Control: no-cache
```

### 4.2 Debug Web UI

Real-time traffic viewer showing:
- Request list with filtering/search
- Request/response details
- Timing waterfall
- Traffic statistics

### 4.3 Debug API

```
GET  /api/debug/traffic          - Recent traffic log
GET  /api/debug/traffic/stream   - WebSocket for live traffic
GET  /api/debug/traffic/:id      - Specific request details
POST /api/debug/clear            - Clear traffic log
GET  /api/debug/stats            - Traffic statistics
```

## 5. Interfaces

### 5.1 Server CLI Commands

```bash
# Start the server
simple-proxy-server start
simple-proxy-server start --config /path/to/server-config.yaml

# Stop the server (graceful)
simple-proxy-server stop

# Status
simple-proxy-server status

# Backend management
simple-proxy-server backend list
simple-proxy-server backend add --name "japan" --type wireguard --config /path/to/japan.conf
simple-proxy-server backend remove --name "japan"
simple-proxy-server backend test --name "germany"

# Rule management
simple-proxy-server rule list
simple-proxy-server rule add --name "Anime" --domain "*.crunchyroll.com" --backend "germany"
simple-proxy-server rule remove --name "Anime"

# Configuration
simple-proxy-server config show
simple-proxy-server config reload
simple-proxy-server config validate

# Service management (install as system service)
simple-proxy-server service install --config /path/to/config.yaml
simple-proxy-server service uninstall
simple-proxy-server service status

# Update management
simple-proxy-server update check
simple-proxy-server update install --channel stable
```

### 5.2 Client CLI Commands

```bash
# Start the client
simple-proxy-client start
simple-proxy-client start --config /path/to/client-config.yaml

# Stop the client
simple-proxy-client stop

# Status (includes server connection status)
simple-proxy-client status

# Rule management (client-side routing)
simple-proxy-client rule list
simple-proxy-client rule add --name "Work" --domain "*.company.com" --action server
simple-proxy-client rule add --name "Direct" --domain "*.local" --action direct
simple-proxy-client rule remove --name "Work"

# Debug commands
simple-proxy-client debug on                    # Enable debugging
simple-proxy-client debug off                   # Disable debugging
simple-proxy-client debug tail                  # Tail traffic log
simple-proxy-client debug tail --filter "crunchyroll"
simple-proxy-client debug clear                 # Clear traffic log
simple-proxy-client debug export --output traffic.har  # Export as HAR file

# Configuration
simple-proxy-client config show
simple-proxy-client config reload

# Service management (install as system service)
simple-proxy-client service install --config /path/to/config.yaml
simple-proxy-client service uninstall
simple-proxy-client service status

# Update management
simple-proxy-client update check
simple-proxy-client update install --channel stable
```

### 5.3 Server REST API

```
GET    /api/status              - Server status
GET    /api/backends            - List backends
POST   /api/backends            - Add backend
DELETE /api/backends/:name      - Remove backend
POST   /api/backends/:name/test - Test backend connectivity

GET    /api/rules               - List rules
POST   /api/rules               - Add rule
PUT    /api/rules/:name         - Update rule
DELETE /api/rules/:name         - Remove rule
POST   /api/rules/reorder       - Reorder rules

GET    /api/config              - Get config
POST   /api/config/reload       - Reload config

GET    /api/stats               - Traffic statistics
GET    /api/clients             - Connected clients (if auth enabled)
```

### 5.4 Client REST API

```
GET    /api/status              - Client status + server connection
GET    /api/rules               - List routing rules
POST   /api/rules               - Add rule
DELETE /api/rules/:name         - Remove rule

GET    /api/debug/status        - Debug status
POST   /api/debug/enable        - Enable debugging
POST   /api/debug/disable       - Disable debugging
GET    /api/debug/traffic       - Recent traffic
GET    /api/debug/traffic/stream - WebSocket for live traffic
POST   /api/debug/clear         - Clear traffic log
GET    /api/debug/stats         - Traffic statistics

GET    /api/config              - Get config
POST   /api/config/reload       - Reload config
```

## 6. Technical Details

### 6.1 Dependencies

Server:
- `golang.zx2c4.com/wireguard` - WireGuard implementation in Go
- `github.com/armon/go-socks5` - SOCKS5 server implementation
- `gopkg.in/yaml.v3` - YAML parsing
- `github.com/gorilla/mux` - HTTP routing for API
- `github.com/gorilla/websocket` - WebSocket for live updates
- `github.com/spf13/cobra` - CLI framework

Client:
- Same as server minus wireguard
- Plus traffic inspection utilities

### 6.2 HTTPS Interception (MITM) for Debugging

For full HTTPS debugging (seeing decrypted content), the client needs to:
1. Generate a CA certificate
2. User installs CA in their trust store
3. Client generates per-domain certificates on-the-fly

This is optional and requires explicit user setup. By default, HTTPS is tunneled (CONNECT method) and only metadata is logged.

### 6.3 Domain Matching

Domain patterns support:
- Exact match: `example.com`
- Wildcard subdomain: `*.example.com` (matches any.example.com, also example.com itself)
- Suffix match: `.example.com` (matches example.com and all subdomains)
- Full wildcard: `*`
- Glob patterns within labels: `sf-*.example.com` (matches sf-abc.example.com, sf-xyz.example.com)

**Glob Pattern Examples:**
| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `sf-*.example.com` | `sf-abc.example.com`, `sf-123.example.com` | `other.example.com` |
| `*-api.example.com` | `backend-api.example.com`, `v2-api.example.com` | `api.example.com` |
| `pre-*-suf.example.com` | `pre-middle-suf.example.com` | `pre-other.example.com` |
| `*.sf-*.example.com` | `sub.sf-abc.example.com` | `sf-abc.example.com` |

Matching is case-insensitive.

### 6.4 Connection Flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant C as Bifrost Client
    participant S as Bifrost Server
    participant T as Target Target

    Note over B, T: Direct Connection
    B->>C: Request
    C->>T: Connect (Direct)
    T-->>C: Response
    C-->>B: Response

    Note over B, T: Proxy Connection
    B->>C: Request
    C->>S: Encrypted Tunnel
    S->>T: Connect (Backend)
    T-->>S: Response
    S-->>C: Response
    C-->>B: Response
```

## 7. Security Considerations

- Server Web UI should be protected (firewall, auth, or localhost-only behind reverse proxy)
- Client binds to localhost by default
- WireGuard .conf files contain private keys - protect file permissions
- MITM mode requires careful handling of generated certificates

> [!CAUTION]
> WireGuard and OpenVPN configuration files contain sensitive private keys. Ensure file permissions are restricted (e.g., `chmod 600`) and they are excluded from backups where appropriate.

## 8. Platform Support

Both client and server are fully supported on all major platforms:

| Platform | Server | Client | Notes |
|----------|--------|--------|-------|
| **Linux** | Full support | Full support | Best WireGuard performance (kernel module) |
| **macOS** | Full support | Full support | wireguard-go userspace, native tray support |
| **Windows** | Full support | Full support | wireguard-go with wintun, native tray support |

### 8.1 Server Requirements
- Elevated permissions required for WireGuard tunnel creation
- Can run as systemd service (Linux), launchd (macOS), or Windows Service
- Docker container available for easy deployment

### 8.2 Client Requirements
- No special permissions required
- System tray requires GUI environment
- Can run headless (CLI-only mode) if needed

## 9. System Tray (Client)

The client includes a system tray icon for easy access on all platforms.

### 9.1 Tray Menu Options
- **Status**: Shows connection status (connected/disconnected)
- **Open Web UI**: Opens the debug/management interface in browser
- **Enable/Disable Proxy**: Quick toggle for proxy
- **Quick Rules**: Submenu to enable/disable specific routing rules
- **View Traffic**: Opens traffic debugger
- **Settings**: Opens settings panel
- **Quit**: Gracefully stops the client

### 9.2 Tray Icon States
- Green: Connected and routing through server
- Yellow: Connected but server unreachable
- Gray: Proxy disabled
- Red: Error state

### 9.3 Notifications
- Server connection established/lost
- Configuration reloaded
- Errors (connection failures, config issues)

### 9.4 Platform-Specific Implementation
- **Windows**: Uses native Win32 system tray API
- **macOS**: Uses NSStatusItem (menu bar)
- **Linux**: Uses libappindicator/StatusNotifierItem (works with GNOME, KDE, etc.)

## 10. Docker Support (Server)

The server can be deployed as a Docker container.

### 10.1 Dockerfile

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o simple-proxy-server ./cmd/server

FROM alpine:latest
RUN apk add --no-cache iptables openvpn
COPY --from=builder /app/simple-proxy-server /usr/local/bin/
COPY --from=builder /app/configs/server-config.yaml /etc/simple-proxy/config.yaml
EXPOSE 7080 7180 7081
ENTRYPOINT ["simple-proxy-server", "start", "--config", "/etc/simple-proxy/config.yaml"]
```

### 10.2 Docker Compose

```yaml
version: '3.8'
services:
  simple-proxy-server:
    build: .
    container_name: simple-proxy-server
    restart: unless-stopped
    cap_add:
      - NET_ADMIN  # Required for WireGuard
    sysctls:
      - net.ipv4.ip_forward=1
    ports:
      - "7080:7080"   # HTTP/HTTPS proxy
      - "7180:7180"   # SOCKS5 proxy
      - "7081:7081"   # Web UI
    volumes:
      - ./server-config.yaml:/app/data/config.yaml:ro
      - bifrost-data:/app/data
      - bifrost-logs:/var/log/bifrost
    devices:
      - /dev/net/tun:/dev/net/tun      # TUN device for VPN
    environment:
      - LOG_LEVEL=info
```

### 10.3 Running with Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Reload configuration
docker exec simple-proxy-server simple-proxy-server config reload
```

## 11. Health Checks & Load Balancing

### 11.1 Health Check Types

| Type | Description | Use Case |
|------|-------------|----------|
| `tcp` | TCP connection test | Basic connectivity check |
| `http` | HTTP GET request | Web service backends |
| `ping` | ICMP ping | Network-level check |

### 11.2 Health Check Configuration

```yaml
# Global health check defaults
health_checks:
  defaults:
    interval: "30s"
    timeout: "5s"
    healthy_threshold: 2      # Checks before marking healthy
    unhealthy_threshold: 3    # Checks before marking unhealthy

# Per-backend override (in backend definition)
backends:
  - name: "germany"
    type: "wireguard"
    wireguard:
      config_file: "/path/to/germany.conf"
    health_check:
      enabled: true
      interval: "15s"
      timeout: "3s"
      type: "http"
      http:
        url: "https://api.ipify.org"
        expected_status: 200
```

- Faster response to real-world issues

> [!NOTE]
> Passive health checks supplement active probing. If a backend fails multiple consecutive real requests, it is temporarily marked unhealthy even if the next active probe hasn't triggered yet.

### 11.4 Load Balancing (Multiple Backends per Rule)

When a rule specifies multiple backends, load balancing distributes traffic:

```yaml
rules:
  - name: "Streaming with failover"
    match:
      domains: ["*.crunchyroll.com"]
    backends:                    # Multiple backends for load balancing
      - name: "germany-1"
        weight: 50
      - name: "germany-2"
        weight: 50
    load_balancing:
      algorithm: "round_robin"   # round_robin, least_conn, random, ip_hash
      sticky_sessions: false     # Keep same client on same backend
```

### 11.5 Backend Status API

```
GET /api/backends/:name/health  - Get backend health status
{
  "name": "germany",
  "status": "healthy",          // healthy, unhealthy, unknown
  "last_check": "2024-01-15T10:30:00Z",
  "latency_ms": 45,
  "consecutive_failures": 0,
  "uptime_percent": 99.8
}
```

## 12. Observability & Metrics

### 12.1 Prometheus Metrics

The server exposes Prometheus-compatible metrics at `/metrics`:

```yaml
# Enable in config
metrics:
  enabled: true
  endpoint: "/metrics"
  port: 7090                    # Separate port for metrics (optional)
```

### 12.2 Available Metrics

```
# Connection metrics
proxy_connections_total{backend="germany",status="success"} 12345
proxy_connections_active{backend="germany"} 42
proxy_connections_errors_total{backend="germany",error="timeout"} 5

# Request metrics
proxy_requests_total{method="CONNECT",backend="germany"} 5000
proxy_request_duration_seconds{backend="germany",quantile="0.99"} 0.250
proxy_request_bytes_total{direction="in"} 1234567890
proxy_request_bytes_total{direction="out"} 9876543210

# Backend health
proxy_backend_healthy{backend="germany"} 1
proxy_backend_latency_seconds{backend="germany"} 0.045

# Rate limiting
proxy_rate_limit_exceeded_total{by="ip"} 100
proxy_rate_limit_exceeded_total{by="user"} 25

# System
proxy_uptime_seconds 86400
proxy_config_reload_total 3
proxy_config_reload_errors_total 0
```

### 12.3 Grafana Dashboard

Pre-built Grafana dashboard available at `assets/grafana-dashboard.json` with:
- Request rate and error rate graphs
- Backend health status
- Latency histograms
- Connection pool utilization
- Rate limiting statistics

### 12.4 Health Endpoint

```
GET /health          - Simple health check (200 OK or 503)
GET /health/ready    - Readiness check (config loaded, backends available)
GET /health/live     - Liveness check (process running)
```

## 13. Graceful Shutdown & Hot Reload

### 13.1 Graceful Shutdown

```mermaid
stateDiagram-v2
    [*] --> Running
    Running --> Stopping : SIGTERM / SIGINT
    Stopping --> Draining : Close Sockets
    Draining --> Cleanup : Drain Timeout / Finished
    Cleanup --> [*] : Terminate
```

1. **Stop accepting new connections** - Close listening sockets
2. **Drain existing connections** - Allow in-flight requests to complete
3. **Timeout** - Force close after drain timeout
4. **Cleanup** - Close VPN tunnels, flush logs

```yaml
# Configuration
shutdown:
  drain_timeout: "30s"          # Max time to wait for connections to drain
  force_timeout: "60s"          # Force shutdown after this time
```

### 13.2 Hot Reload

Reload configuration without dropping connections:

```bash
# Via CLI
simple-proxy-server config reload

# Via signal
kill -HUP <pid>

# Via API
POST /api/config/reload
```

**What can be hot-reloaded:**
- Routing rules
- Backend definitions
- Rate limiting settings
- Access control lists
- Logging configuration

**What requires restart:**
- Port bindings
- TLS certificates
- Authentication mode changes

### 13.3 Connection Draining

During reload or shutdown:
- New connections go to new config/backends
- Existing connections complete with old config
- Configurable drain timeout

```yaml
reload:
  drain_timeout: "10s"          # Drain time during hot reload
```

## 14. Authentication (Server)

The server supports multiple authentication modes for client connections.

### 14.1 Authentication Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `none` | No authentication required | Development, trusted networks |
| `native` | Server-managed users/passwords | Simple deployments |
| `system` | OS user authentication (PAM/Windows) | Single-server with OS users |
| `ldap` | LDAP/Active Directory | Enterprise environments |
| `oauth` | OAuth 2.0 / OpenID Connect | SSO integration |

### 14.2 Configuration Examples

#### No Authentication
```yaml
auth:
  mode: "none"
```

#### Native Authentication
```yaml
auth:
  mode: "native"
  native:
    users:
      - username: "user1"
        password_hash: "$2a$10$..."  # bcrypt hash
        groups: ["streaming", "work"]
      - username: "user2"
        password_hash: "$2a$10$..."
        groups: ["streaming"]
    # Optional: allow rule-based access control
    acl:
      - group: "streaming"
        backends: ["germany", "japan"]
      - group: "work"
        backends: ["*"]
```

#### System Authentication (PAM/Windows)
```yaml
auth:
  mode: "system"
  system:
    # Linux: uses PAM
    # Windows: uses Windows authentication
    # macOS: uses Directory Services
    allowed_groups: ["proxy-users", "admins"]  # OS groups allowed to use proxy
```

#### LDAP/Active Directory
```yaml
auth:
  mode: "ldap"
  ldap:
    server: "ldap://ldap.example.com:389"
    # or for LDAPS:
    # server: "ldaps://ldap.example.com:636"
    bind_dn: "cn=service,dc=example,dc=com"
    bind_password: "${LDAP_BIND_PASSWORD}"  # Environment variable
    base_dn: "dc=example,dc=com"
    user_filter: "(sAMAccountName=%s)"      # %s = username
    group_filter: "(member=%s)"             # %s = user DN
    allowed_groups:
      - "CN=ProxyUsers,OU=Groups,DC=example,DC=com"
    # TLS settings
    tls:
      skip_verify: false
      ca_cert: "/path/to/ca.crt"
```

#### OAuth 2.0 / OpenID Connect
```yaml
auth:
  mode: "oauth"
  oauth:
    provider: "generic"     # generic, google, azure, okta
    client_id: "${OAUTH_CLIENT_ID}"
    client_secret: "${OAUTH_CLIENT_SECRET}"
    # For generic provider:
    auth_url: "https://auth.example.com/authorize"
    token_url: "https://auth.example.com/token"
    userinfo_url: "https://auth.example.com/userinfo"
    # Scopes to request
    scopes: ["openid", "profile", "groups"]
    # Claim to use as username
    username_claim: "preferred_username"
    # Claim to use for group membership
    groups_claim: "groups"
    allowed_groups: ["proxy-users"]
    # Token validation
    jwt:
      issuer: "https://auth.example.com"
      audience: "simple-proxy"
```

### 14.3 Proxy-Authorization Header

Clients authenticate using the `Proxy-Authorization` header:

```
Proxy-Authorization: Basic base64(username:password)
```

For OAuth, clients can use bearer tokens:
```
Proxy-Authorization: Bearer <access_token>
```

### 14.4 Web UI Authentication

The Web UI uses the same authentication backend. Session-based authentication is used after initial login.

### 14.5 CLI for User Management (Native Mode)

```bash
# Add user
simple-proxy-server user add --username john --groups streaming,work

# Remove user
simple-proxy-server user remove --username john

# List users
simple-proxy-server user list

# Reset password
simple-proxy-server user passwd --username john

# Manage groups
simple-proxy-server user groups --username john --add admin
simple-proxy-server user groups --username john --remove streaming
```

## 15. Use Cases

### Claude Code Proxy
```yaml
# client-config.yaml
client:
  http_port: 7380
rules:
  - name: "Claude via server"
    match:
      domains: ["*.anthropic.com", "*.claude.ai"]
    action: "server"
  - name: "Default direct"
    match:
      domains: ["*"]
    action: "direct"
```

Then set `HTTP_PROXY=http://127.0.0.1:7380` for Claude Code.

### Streaming Geo-Unlock
```yaml
# server-config.yaml
backends:
  - name: "germany"
    type: "wireguard"
    wireguard:
      config_file: "/etc/wireguard/germany.conf"

rules:
  - name: "Crunchyroll Germany"
    match:
      domains: ["*.crunchyroll.com"]
    backend: "germany"
```

## 16. Documentation

### 16.1 Documentation System

The project uses [MkDocs](https://www.mkdocs.org/) with the [Material theme](https://squidfunk.github.io/mkdocs-material/) for documentation, deployed to GitHub Pages.

**Location**: `docs/` directory (Markdown source files)

**Configuration**: `mkdocs.yml`

**Build**: `make docs-build` or `make docs-serve` (local development)

**Deployment**: Automatically deployed via GitHub Actions workflow (`.github/workflows/docs.yml`)

**Live Site**: https://rennerdo30.github.io/bifrost-proxy/

### 16.2 Diagrams

All diagrams in the documentation use **Mermaid** for rendering. Mermaid provides interactive, scalable diagrams that work well in web browsers.

**Why Mermaid?**
- Native support in MkDocs Material theme
- Interactive and scalable
- Text-based (version control friendly)
- Wide variety of diagram types
- Better accessibility than ASCII art

**Usage:**

````markdown
```mermaid
graph LR
    A[Node A] --> B[Node B]
    B --> C[Node C]
```
````

**Supported Diagram Types:**
- **Flowcharts/Graphs**: `graph` or `flowchart` - For architecture, process flows
- **Sequence Diagrams**: `sequenceDiagram` - For request/response flows
- **Class Diagrams**: `classDiagram` - For code structure
- **State Diagrams**: `stateDiagram` - For state machines
- **Entity-Relationship**: `erDiagram` - For data models
- **Gantt Charts**: `gantt` - For timelines
- **Pie Charts**: `pie` - For statistics
- **Git Graphs**: `gitGraph` - For version control flows

**Example - Architecture Diagram:**

The architecture diagrams shown in sections 2.1 and 2.2 are rendered as Mermaid diagrams in the live documentation:

```mermaid
graph LR
    Browser[Browser / App] -->|HTTP/SOCKS5| Client[Client<br/>local]
    Client -->|HTTP/SOCKS5| Server[Server<br/>central]
    Server -->|Tunnel| WireGuard[WireGuard<br/>Tunnel]
    Server -->|Tunnel| OpenVPN[OpenVPN<br/>Tunnel]
    Server -->|Proxy| HTTPProxy[HTTP/SOCKS5<br/>Proxy]
```

**Best Practices:**
- Use descriptive node labels
- Add styling with `style` directives for visual clarity
- Keep diagrams focused and simple
- Choose appropriate diagram types for the content
- Test locally with `make docs-serve` before committing

**Note**: The ASCII diagrams in previous versions of this specification have been converted to Mermaid diagrams for better rendering and interactivity across all platforms.

### 16.3 Documentation Workflow

**Automatic Deployment:**
- Triggers on push to `main` branch when files in `docs/`, `mkdocs.yml`, `README.md`, `CHANGELOG.md`, or `CONTRIBUTING.md` change
- Builds documentation using Python/MkDocs
- Deploys to GitHub Pages automatically

**Manual Trigger:**
```bash
gh workflow run "Documentation"
```

**Local Development:**
```bash
# Start local server (auto-reload)
make docs-serve

# Build static site
make docs-build
```

### 16.4 Documentation Structure

The documentation is organized into the following sections:

- **Home** (`index.md`) - Overview and quick start
- **Getting Started** - Installation and setup guides
- **Configuration** - Server and client configuration
  - Overview
  - Backends (WireGuard, OpenVPN, HTTP/SOCKS5 proxies)
  - Authentication (None, Native, System, LDAP, OAuth)
  - [OpenWRT LuCI Setup Guide](file:///Users/rennerdo30/Development/simple-proxy-server/docs/openwrt.md#installation-via-luci-gui)
- **Deployment** - Docker, systemd, launchd
- **Operations**
  - CLI Reference
  - Monitoring (Prometheus, Grafana)
  - Security
  - Troubleshooting
- **API Reference** - REST API documentation
- **Development**
  - Contributing
  - Changelog

The authentication system has been refactored to use a plugin architecture, allowing for modular authentication providers that can be combined and extended.

```mermaid
graph LR
    C[Client Request] --> PM[Plugin Manager]
    subgraph "Auth Plugins"
        PM --> P1[None]
        PM --> P2[Native]
        PM --> P3[LDAP]
        PM --> P4[OAuth]
        PM --> P5[...]
    end
    P1 & P2 & P3 & P4 & P5 --> Session[Session Store]
```

### 17.1 Plugin Interface

```go
type Plugin interface {
    // Name returns the unique identifier for this plugin
    Name() string

    // Init initializes the plugin with configuration
    Init(config map[string]interface{}) error

    // Authenticate validates credentials and returns user info
    Authenticate(ctx context.Context, creds Credentials) (*User, error)

    // Close cleans up resources
    Close() error
}
```

### 17.2 Built-in Plugins

| Plugin | Description | Use Case |
|--------|-------------|----------|
| `none` | No authentication | Development, trusted networks |
| `native` | Server-managed users/passwords | Simple deployments |
| `system` | OS user authentication (PAM/Directory Services) | Single-server with OS users |
| `ldap` | LDAP/Active Directory | Enterprise environments |
| `oauth` | OAuth 2.0 / OpenID Connect | SSO integration |
| `apikey` | API key in header | Service-to-service auth |
| `jwt` | JWT token validation with JWKS | Token-based auth |
| `totp` | Time-based OTP | Google Authenticator |
| `hotp` | Counter-based OTP | YubiKey |
| `mtls` | Client certificate auth | Smart cards, certificates |
| `kerberos` | Kerberos/SPNEGO | Enterprise SSO |
| `ntlm` | NTLM authentication | Windows domain fallback |

### 17.3 MFA Wrapper

The MFA wrapper allows combining a primary authentication method with an OTP provider:

```yaml
auth:
  mode: mfa_wrapper
  mfa_wrapper:
    primary:
      mode: native
      native:
        users:
          - username: admin
            password_hash: "$2a$10$..."
    secondary:
      mode: totp
      totp:
        issuer: "Bifrost"
        secrets:
          admin: "JBSWY3DPEHPK3PXP"
```

### 17.4 Session Management

Sessions can be stored in memory or Redis:

```yaml
session:
  store: redis  # or "memory"
  redis:
    address: "localhost:6379"
    password: ""
    db: 0
  ttl: "24h"
  cookie_name: "bifrost_session"
```

## 18. VPN Mode

The client supports a TUN-based VPN mode that captures all system traffic and routes it through the proxy.

### 18.1 Overview

```mermaid
graph LR
    TUN[TUN Device<br/>bifrost0] --> Rules[Split Rules]
    Rules --> Router[Router]
    Router -->|Route| Direct[Direct Connection]
    Router -->|Route| Server[Server Connection]
    Router -->|Route| Block[Block / Drop]
```

### 18.2 Configuration

```yaml
vpn:
  enabled: true
  mode: tun
  interface_name: bifrost0
  mtu: 1420

  # DNS interception
  dns:
    enabled: true
    servers:
      - "1.1.1.1"
      - "8.8.8.8"
    cache_ttl: "5m"

  # Split tunneling rules
  split:
    mode: exclude  # "include" or "exclude"

    # App-based rules (by process name or path)
    apps:
      - name: "Slack"
        path: "/Applications/Slack.app"
      - name: "Teams"

    # Domain-based rules
    domains:
      - "*.internal.company.com"
      - "localhost"
      - "*.local"

    # IP/CIDR-based rules
    ips:
      - "192.168.0.0/16"
      - "10.0.0.0/8"
      - "172.16.0.0/12"
```

### 18.3 Split Tunneling Modes

- **Include Mode**: Only traffic matching rules goes through VPN
- **Exclude Mode**: All traffic except matching rules goes through VPN

### 18.4 Platform-Specific Notes

| Platform | TUN Support | App Rules | Notes |
|----------|-------------|-----------|-------|
| Linux | ✅ | Process matching | Requires CAP_NET_ADMIN |
| macOS | ✅ | Bundle ID matching | Uses utun interface |
| Windows | ✅ | Process path matching | Requires wintun driver |

## 19. Desktop Client

A native desktop client built with [Wails](https://wails.io/) providing a GUI for managing the proxy.

### 19.1 Features

- **Quick GUI**: Floating window for quick access to common controls
- **System Tray**: Background operation with status indicators
- **Connection Dashboard**: Real-time connection statistics
- **Server Management**: Configure and switch between servers
- **Split Tunneling**: Visual rule editor for app/domain exclusions
- **Logs Viewer**: Real-time log streaming

### 19.2 Architecture

```mermaid
graph TD
    subgraph "Wails UI System"
        FE[Frontend<br/>React] <--> BE[Backend<br/>Go Wrapper]
        Tray[Native Tray<br/>Go] <--> BE
    end

    BE <--> Core[Bifrost Client Core<br/>Go Library]
```

### 19.3 Building

```bash
# Install Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Build for current platform
cd desktop
wails build

# Build for all platforms
wails build -platform darwin/amd64
wails build -platform windows/amd64
wails build -platform linux/amd64
```

### 19.4 Quick GUI

The Quick GUI is a small floating window that provides:
- Connection status indicator
- Quick connect/disconnect toggle
- Bandwidth usage graph
- Recent connections list
- Quick access to full dashboard

## 20. Mobile Client

A cross-platform mobile client built with React Native and Expo.

### 20.1 Features

- **Home Screen**: VPN connection status and quick toggle
- **Servers Screen**: Server list with latency indicators
- **Stats Screen**: Real-time traffic statistics
- **Settings Screen**: Configuration management

### 20.2 Architecture

```mermaid
graph TD
    subgraph "Application"
        Screens[React Native Screens] --> Hooks[React Query Hooks]
        Hooks --> API[API Proxy Service]
    end

    API -->|REST| Bifrost[Bifrost Client API]
```

### 20.3 Screens

| Screen | Description |
|--------|-------------|
| Home | Connection status, VPN toggle, traffic summary |
| Servers | Server list with status, latency, selection |
| Stats | Detailed statistics, connection info, network details |
| Settings | Auto-connect, kill switch, server address, notifications |

### 20.4 Building

```bash
# Install dependencies
cd mobile
npm install

# Start development
npx expo start

# Build for iOS
npx expo build:ios

# Build for Android
npx expo build:android

# Using EAS Build (recommended)
eas build --platform ios
eas build --platform android
```

### 20.5 API Integration

The mobile client uses React Query for data fetching with automatic:
- Background refetching (configurable intervals)
- Optimistic updates for mutations
- Error handling and retry logic
- Cache invalidation on mutations

## 21. Automatic Updates

Bifrost includes a built-in update mechanism that checks GitHub for new releases.

### 21.1 Update Channels
- **stable**: Production-ready releases.
- **prerelease**: Beta and release candidates.
- **nightly**: Automated builds from the master branch (if available).

### 21.2 CLI Integration
Users can manually check for and install updates using the `update` command.
```bash
bifrost-client update check
bifrost-client update install --channel stable
```

### 21.3 Background Checks
The application can be configured to check for updates in the background at regular intervals.
```yaml
auto_update:
  enabled: true
  check_interval: "24h"
  channel: "stable"
```

## 22. System Service Management

Bifrost provides native service management for Windows (SCM), macOS (launchd), and Linux (systemd).

### 22.1 Service Commands
- `install`: Registers the binary as a system service with specified configuration.
- `uninstall`: Unregisters and removes the service.
- `status`: Displays the current service status.

### 22.2 Platform Specifics
- **Windows**: Registers as a Windows Service using the SCM. Supports START, STOP, and SHUTDOWN events.
- **macOS**: Generates and installs a `.plist` file in `~/Library/LaunchAgents`.
- **Linux**: Generates and installs a `.service` unit file in `/etc/systemd/system`.

## 23. System Proxy Support

The Bifrost client can automatically configure the operating system's proxy settings.

### 23.1 Configuration
```yaml
system_proxy:
  enabled: true
```

### 23.2 Windows Implementation
On Windows, Bifrost modifies the registry keys under `Software\Microsoft\Windows\CurrentVersion\Internet Settings` and notifies the system using `InternetSetOption` from `wininet.dll`.

## 24. Configuration Preservation

When updating configuration via the REST API or CLI, Bifrost uses an AST-based approach (using `yaml.v3`) to ensure that:
- User comments are preserved.
- Formatting and indentation are maintained.
- Only the specific requested fields are modified.
