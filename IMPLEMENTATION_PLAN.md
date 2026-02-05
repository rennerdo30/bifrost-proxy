# Bifrost - Detailed Implementation Plan

**Project**: Bifrost Proxy Server
**Version**: 1.0
**Last Updated**: 2026-01-12

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Phase 1: Project Foundation](#phase-1-project-foundation)
3. [Phase 2: Core Libraries](#phase-2-core-libraries)
4. [Phase 3: Backend System](#phase-3-backend-system)
5. [Phase 4: Proxy Protocols](#phase-4-proxy-protocols)
6. [Phase 5: Traffic Management](#phase-5-traffic-management)
7. [Phase 6: Authentication System](#phase-6-authentication-system)
8. [Phase 7: Observability](#phase-7-observability)
9. [Phase 8: Server Application](#phase-8-server-application)
10. [Phase 9: Client Application](#phase-9-client-application)
11. [Phase 10: System Tray](#phase-10-system-tray)
12. [Phase 11: Web Interfaces](#phase-11-web-interfaces)
13. [Phase 12: DevOps & Deployment](#phase-12-devops--deployment)
14. [Phase 13: Testing & Quality](#phase-13-testing--quality)
15. [Phase 14: Documentation & Release](#phase-14-documentation--release)
16. [Appendix A: Data Structures](#appendix-a-data-structures)
17. [Appendix B: API Reference](#appendix-b-api-reference)
18. [Appendix C: Error Codes](#appendix-c-error-codes)
19. [Appendix D: Configuration Reference](#appendix-d-configuration-reference)

---

## 1. Project Overview

### 1.1 Components

**Bifrost Server** (`bifrost-server`)
- Central proxy handling all routing through backends
- Manages VPN tunnels (WireGuard, OpenVPN)
- Manages forward proxy connections (HTTP, SOCKS5)
- Provides domain-based routing
- Multiple authentication modes
- Web UI for management
- REST API for automation
- CLI for administration

**Bifrost Client** (`bifrost-client`)
- Local proxy for end-user machines
- Routes traffic to server or direct based on rules
- Traffic debugging and inspection
- System tray integration
- Web UI for monitoring
- REST API for control
- CLI for management

### 1.2 Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Go | 1.22+ |
| CLI Framework | Cobra | 1.8.x |
| Config | YAML (gopkg.in/yaml.v3) | 3.0.x |
| HTTP Router | Chi | 5.x |
| WebSocket | Gorilla WebSocket | 1.5.x |
| SOCKS5 | txthinking/socks5 or custom | - |
| System Tray | fyne.io/systray | 1.x |
| WireGuard | wireguard-go + netstack | - |
| LDAP | go-ldap/ldap | 3.4.x |
| OAuth | coreos/go-oidc | 3.x |
| Metrics | prometheus/client_golang | 1.x |
| Testing | stretchr/testify | 1.9.x |

### 1.3 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BIFROST SERVER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   HTTP      │  │   SOCKS5    │  │   Web UI    │  │  Metrics    │        │
│  │  :7080      │  │   :7180     │  │   :7081     │  │   :7090     │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────┘        │
│         │                │                │                                 │
│         └────────────────┼────────────────┘                                 │
│                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         REQUEST PIPELINE                              │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │  │
│  │  │  Auth   │→│  Rate   │→│  Access │→│  Router │→│  Load   │         │  │
│  │  │Middleware│ │ Limiter │ │ Control │ │         │ │Balancer │         │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └────┬────┘         │  │
│  └───────────────────────────────────────────────────────┼───────────────┘  │
│                                                          ▼                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        BACKEND MANAGER                                │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │  │
│  │  │  Direct  │ │WireGuard │ │ OpenVPN  │ │HTTP Proxy│ │SOCKS5    │    │  │
│  │  │          │ │ Tunnel   │ │ Tunnel   │ │ Upstream │ │Upstream  │    │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Health    │  │   Access    │  │  Metrics    │  │   Config    │        │
│  │  Checker    │  │   Logger    │  │ Collector   │  │  Manager    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              BIFROST CLIENT                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   HTTP      │  │   SOCKS5    │  │   Web UI    │  │ System Tray │        │
│  │  :7380      │  │   :7381     │  │   :7382     │  │             │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────┘        │
│         │                │                │                                 │
│         └────────────────┼────────────────┘                                 │
│                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      TRAFFIC DEBUGGER                                 │  │
│  │  Log requests, responses, headers, timing, errors                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                          │                                                  │
│                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      CLIENT ROUTER                                    │  │
│  │              Domain → "server" | "direct"                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                          │                                                  │
│              ┌───────────┴───────────┐                                      │
│              ▼                       ▼                                      │
│  ┌─────────────────────┐  ┌─────────────────────┐                          │
│  │  Direct Connection  │  │  Server Connection  │                          │
│  │    (to target)      │  │  (to Bifrost Server)│                          │
│  └─────────────────────┘  └─────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.4 Request Flow Sequences

**Sequence 1: Client → Server → WireGuard → Target**
```
Browser              Client               Server              WireGuard         Target
   │                    │                    │                    │               │
   │─── HTTP CONNECT ──→│                    │                    │               │
   │                    │─── HTTP CONNECT ──→│                    │               │
   │                    │                    │── Auth Check ──→   │               │
   │                    │                    │── Route Match ──→  │               │
   │                    │                    │── Health Check ──→ │               │
   │                    │                    │─── Dial via WG ───→│               │
   │                    │                    │                    │─── TCP ──────→│
   │                    │                    │                    │←── TCP ───────│
   │                    │←── 200 OK ─────────│                    │               │
   │←── 200 OK ─────────│                    │                    │               │
   │←─────────────────── Bidirectional Tunnel ───────────────────────────────────→│
```

**Sequence 2: Client → Direct (bypass server)**
```
Browser              Client                                               Target
   │                    │                                                    │
   │─── HTTP CONNECT ──→│                                                    │
   │                    │── Route Match (action=direct) ──→                  │
   │                    │─────────────────── TCP ───────────────────────────→│
   │                    │←────────────────── TCP ────────────────────────────│
   │←── 200 OK ─────────│                                                    │
   │←───────────────────── Bidirectional Tunnel ────────────────────────────→│
```

**Sequence 3: Hot Reload**
```
Admin                Server
  │                    │
  │─── SIGHUP ────────→│
  │                    │── Parse new config
  │                    │── Validate config
  │                    │── Create new backends (if new)
  │                    │── Update router rules (atomic swap)
  │                    │── Stop removed backends
  │                    │── Keep existing connections on old config
  │                    │── New connections use new config
  │←── Reload OK ──────│
```

---

## Phase 1: Project Foundation

### 1.1 Repository Setup

**Files to create:**

| File | Purpose |
|------|---------|
| `.gitignore` | Ignore binaries, IDE files, secrets |
| `LICENSE` | MIT License text |
| `README.md` | Project overview, quick start |

**`.gitignore` contents:**
```
# Binaries
bin/
*.exe
*.dll
*.so
*.dylib

# Test files
*.test
coverage.out
coverage.html

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Config with secrets
*-config.yaml
!configs/*-config.example.yaml

# Logs
*.log
logs/

# Build
dist/
vendor/
```

### 1.2 Go Module

**Module path:** `github.com/yourusername/bifrost`

**Initial dependencies:**
- gopkg.in/yaml.v3 (config)
- github.com/spf13/cobra (CLI)
- github.com/stretchr/testify (testing)

### 1.3 Project Structure

```
bifrost/
├── cmd/
│   ├── server/
│   │   └── main.go                 # Server entry point
│   └── client/
│       └── main.go                 # Client entry point
│
├── internal/
│   ├── version/
│   │   └── version.go              # Version info
│   │
│   ├── logging/
│   │   ├── logging.go              # Logger setup
│   │   ├── context.go              # Context-based logging
│   │   └── logging_test.go
│   │
│   ├── config/
│   │   ├── config.go               # Base config loading
│   │   ├── server.go               # Server config structs
│   │   ├── client.go               # Client config structs
│   │   ├── validate.go             # Validation functions
│   │   └── config_test.go
│   │
│   ├── matcher/
│   │   ├── matcher.go              # Domain pattern matching
│   │   └── matcher_test.go
│   │
│   ├── util/
│   │   ├── context.go              # Context helpers
│   │   ├── errors.go               # Error utilities
│   │   ├── network.go              # Network utilities
│   │   └── crypto.go               # Crypto utilities
│   │
│   ├── backend/
│   │   ├── backend.go              # Interface definition
│   │   ├── errors.go               # Backend errors
│   │   ├── direct.go               # Direct backend
│   │   ├── wireguard.go            # WireGuard backend
│   │   ├── openvpn.go              # OpenVPN backend
│   │   ├── httpproxy.go            # HTTP proxy backend
│   │   ├── socks5proxy.go          # SOCKS5 proxy backend
│   │   ├── factory.go              # Backend factory
│   │   ├── manager.go              # Backend manager
│   │   └── *_test.go
│   │
│   ├── wireguard/
│   │   ├── config.go               # WG config parser
│   │   └── config_test.go
│   │
│   ├── openvpn/
│   │   ├── process.go              # OpenVPN process manager
│   │   └── process_test.go
│   │
│   ├── router/
│   │   ├── router.go               # Router interface
│   │   ├── server.go               # Server router
│   │   ├── client.go               # Client router
│   │   └── router_test.go
│   │
│   ├── proxy/
│   │   ├── http.go                 # HTTP proxy handler
│   │   ├── socks5.go               # SOCKS5 proxy handler
│   │   ├── copy.go                 # Bidirectional copy
│   │   └── *_test.go
│   │
│   ├── ratelimit/
│   │   ├── limiter.go              # Rate limiter interface
│   │   ├── token_bucket.go         # Token bucket impl
│   │   ├── bandwidth.go            # Bandwidth throttling
│   │   └── *_test.go
│   │
│   ├── accesscontrol/
│   │   ├── ip.go                   # IP matcher
│   │   ├── controller.go           # Access controller
│   │   └── *_test.go
│   │
│   ├── health/
│   │   ├── checker.go              # Health checker interface
│   │   ├── tcp.go                  # TCP health check
│   │   ├── http.go                 # HTTP health check
│   │   ├── ping.go                 # ICMP ping check
│   │   ├── manager.go              # Health check manager
│   │   └── *_test.go
│   │
│   ├── loadbalancer/
│   │   ├── balancer.go             # Load balancer interface
│   │   ├── roundrobin.go           # Round robin
│   │   ├── leastconn.go            # Least connections
│   │   ├── iphash.go               # IP hash
│   │   ├── weighted.go             # Weighted
│   │   └── *_test.go
│   │
│   ├── auth/
│   │   ├── auth.go                 # Auth interface
│   │   ├── errors.go               # Auth errors
│   │   ├── none.go                 # No auth
│   │   ├── native.go               # Native auth
│   │   ├── system.go               # System auth interface
│   │   ├── system_linux.go         # PAM
│   │   ├── system_windows.go       # Windows auth
│   │   ├── system_darwin.go        # macOS auth
│   │   ├── ldap.go                 # LDAP auth
│   │   ├── oauth.go                # OAuth/OIDC auth
│   │   ├── middleware.go           # Auth middleware
│   │   └── *_test.go
│   │
│   ├── accesslog/
│   │   ├── logger.go               # Access logger interface
│   │   ├── json.go                 # JSON format
│   │   ├── apache.go               # Apache format
│   │   └── *_test.go
│   │
│   ├── metrics/
│   │   ├── prometheus.go           # Prometheus metrics
│   │   ├── collector.go            # Metrics collector
│   │   └── *_test.go
│   │
│   ├── server/
│   │   ├── server.go               # Server core
│   │   └── server_test.go
│   │
│   ├── client/
│   │   ├── client.go               # Client core
│   │   ├── handler.go              # Request handler
│   │   ├── server_conn.go          # Server connection
│   │   └── *_test.go
│   │
│   ├── debug/
│   │   ├── entry.go                # Traffic entry
│   │   ├── storage.go              # Ring buffer storage
│   │   ├── logger.go               # Debug logger
│   │   ├── export.go               # HAR export
│   │   └── *_test.go
│   │
│   ├── tray/
│   │   ├── tray.go                 # Tray interface
│   │   ├── tray_impl.go            # Implementation
│   │   └── icons.go                # Embedded icons
│   │
│   ├── api/
│   │   ├── server/
│   │   │   ├── server.go           # API server setup
│   │   │   ├── handlers.go         # API handlers
│   │   │   ├── websocket.go        # WebSocket handler
│   │   │   └── *_test.go
│   │   └── client/
│   │       ├── server.go           # API server setup
│   │       ├── handlers.go         # API handlers
│   │       └── *_test.go
│   │
│   └── cli/
│       ├── server/
│       │   └── commands.go         # Server CLI commands
│       └── client/
│           └── commands.go         # Client CLI commands
│
├── web/
│   ├── server/                     # Server Web UI source
│   │   ├── src/
│   │   ├── public/
│   │   └── package.json
│   └── client/                     # Client Web UI source
│       ├── src/
│       ├── public/
│       └── package.json
│
├── assets/
│   ├── icons/
│   │   ├── icon-connected.png
│   │   ├── icon-disconnected.png
│   │   ├── icon-warning.png
│   │   └── icon-error.png
│   └── logo/
│       ├── logo.svg
│       └── logo.png
│
├── configs/
│   ├── server-config.example.yaml
│   └── client-config.example.yaml
│
├── docker/
│   ├── Dockerfile
│   ├── Dockerfile.client
│   └── docker-compose.yml
│
├── deploy/
│   ├── systemd/
│   │   ├── bifrost-server.service
│   │   └── bifrost-client.service
│   └── launchd/
│       └── com.bifrost.client.plist
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── release.yml
│   │   └── security.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── docs/
│   ├── getting-started.md
│   ├── configuration.md
│   ├── backends.md
│   ├── authentication.md
│   ├── api.md
│   └── troubleshooting.md
│
├── go.mod
├── go.sum
├── Makefile
├── .golangci.yml
├── .editorconfig
├── .goreleaser.yml
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SPECIFICATION.md
├── CLAUDE.md
├── IMPLEMENTATION_PLAN.md
└── NOTE.md
```

### 1.4 Makefile

**Targets:**

| Target | Description |
|--------|-------------|
| `build` | Build both server and client |
| `build-server` | Build server only |
| `build-client` | Build client only |
| `test` | Run all tests |
| `test-coverage` | Run tests with coverage report |
| `test-integration` | Run integration tests |
| `lint` | Run golangci-lint |
| `fmt` | Format code |
| `clean` | Remove build artifacts |
| `build-all` | Cross-platform builds |
| `build-linux` | Linux builds (amd64, arm64) |
| `build-darwin` | macOS builds (amd64, arm64) |
| `build-windows` | Windows builds (amd64) |
| `docker-build` | Build Docker image |
| `docker-push` | Push Docker image |
| `install` | Install to GOPATH/bin |

**Variables:**
- `VERSION` - From git describe or "dev"
- `COMMIT` - Git short SHA
- `BUILD_TIME` - UTC timestamp
- `LDFLAGS` - Inject version info

### 1.5 Linter Configuration

**`.golangci.yml` settings:**

| Linter | Purpose |
|--------|---------|
| errcheck | Check error returns |
| gosimple | Simplify code |
| govet | Suspicious constructs |
| staticcheck | Static analysis |
| unused | Unused code |
| gosec | Security issues |
| bodyclose | HTTP body close |
| noctx | Context in HTTP |
| gofmt | Formatting |
| goimports | Import organization |

---

## Phase 2: Core Libraries

### 2.1 Version Package

**Location:** `internal/version/version.go`

**Variables:**
| Variable | Type | Source |
|----------|------|--------|
| `Version` | string | ldflags or "dev" |
| `GitCommit` | string | ldflags or "unknown" |
| `BuildTime` | string | ldflags or "unknown" |

**Functions:**
| Function | Returns | Description |
|----------|---------|-------------|
| `String()` | string | "Bifrost v1.0.0 (abc123) built 2024-01-01" |
| `Short()` | string | "1.0.0" |

### 2.2 Logging System

**Location:** `internal/logging/`

**Configuration struct:**
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Level` | string | "info" | debug, info, warn, error |
| `Format` | string | "json" | json, text |
| `Output` | string | "stdout" | stdout, stderr, file |
| `FilePath` | string | "" | Path if output=file |
| `AddSource` | bool | false | Include file:line |

**Standard attribute keys:**
| Key | Type | Usage |
|-----|------|-------|
| `request_id` | string | Unique request identifier |
| `backend` | string | Backend name |
| `client_ip` | string | Client IP address |
| `username` | string | Authenticated username |
| `method` | string | HTTP method |
| `host` | string | Target host |
| `path` | string | Request path |
| `status` | int | Response status |
| `duration_ms` | int64 | Request duration |
| `bytes_sent` | int64 | Bytes sent |
| `bytes_recv` | int64 | Bytes received |
| `error` | string | Error message |

**Context functions:**
| Function | Description |
|----------|-------------|
| `WithLogger(ctx, logger)` | Add logger to context |
| `FromContext(ctx)` | Get logger from context |
| `With(ctx, args...)` | Get logger with extra attrs |

### 2.3 Configuration System

**Location:** `internal/config/`

**Server Config Hierarchy:**
```
ServerConfig
├── Server
│   ├── HTTPPort (int)
│   ├── SOCKS5Port (int)
│   ├── BindAddress (string)
│   └── WebUIPort (int)
├── Network
│   ├── IPv6
│   │   ├── Enabled (bool)
│   │   └── PreferIPv6 (bool)
│   ├── Timeouts
│   │   ├── Connect (Duration)
│   │   ├── Read (Duration)
│   │   ├── Write (Duration)
│   │   └── Idle (Duration)
│   ├── Keepalive
│   │   ├── Enabled (bool)
│   │   ├── Interval (Duration)
│   │   ├── MaxIdleConns (int)
│   │   └── MaxIdleTime (Duration)
│   └── Limits
│       ├── MaxConnections (int)
│       ├── MaxConnectionsPerIP (int)
│       └── MaxConnectionsPerBackend (int)
├── RateLimiting
│   ├── Enabled (bool)
│   ├── Global
│   │   ├── RequestsPerSecond (float64)
│   │   └── Burst (int)
│   ├── PerIP
│   │   ├── RequestsPerSecond (float64)
│   │   └── Burst (int)
│   ├── PerUser
│   │   ├── RequestsPerSecond (float64)
│   │   └── Burst (int)
│   └── Bandwidth
│       ├── Enabled (bool)
│       ├── MaxMbpsPerConnection (int)
│       ├── MaxMbpsPerIP (int)
│       └── MaxMbpsTotal (int)
├── AccessControl
│   ├── Whitelist ([]string)
│   └── Blacklist ([]string)
├── AccessLog
│   ├── Enabled (bool)
│   ├── Format (string)
│   ├── Output (string)
│   ├── File (string)
│   ├── Fields ([]string)
│   └── MaskHeaders ([]string)
├── Auth
│   ├── Mode (string)
│   ├── Native (*)
│   ├── System (*)
│   ├── LDAP (*)
│   └── OAuth (*)
├── HealthChecks
│   ├── Interval (Duration)
│   ├── Timeout (Duration)
│   ├── HealthyThreshold (int)
│   └── UnhealthyThreshold (int)
├── Metrics
│   ├── Enabled (bool)
│   ├── Endpoint (string)
│   └── Port (int)
├── Shutdown
│   ├── DrainTimeout (Duration)
│   └── ForceTimeout (Duration)
├── Backends ([]BackendConfig)
├── Rules ([]RuleConfig)
└── Logging (LoggingConfig)
```

**Client Config Hierarchy:**
```
ClientConfig
├── Client
│   ├── HTTPPort (int)
│   ├── SOCKS5Port (int)
│   ├── BindAddress (string)
│   └── WebUIPort (int)
├── Tray
│   ├── Enabled (bool)
│   ├── StartMinimized (bool)
│   ├── ShowNotifications (bool)
│   └── Autostart (bool)
├── Server
│   ├── Address (string)
│   ├── Protocol (string)
│   └── Auth
│       ├── Enabled (bool)
│       ├── Username (string)
│       └── Password (string)
├── Debug
│   ├── Enabled (bool)
│   ├── LogRequests (bool)
│   ├── LogResponses (bool)
│   ├── LogHeaders (bool)
│   ├── LogBody (bool)
│   ├── MaxBodyLogSize (int)
│   ├── Output (string)
│   ├── LogFile (string)
│   └── Filter
│       ├── Domains ([]string)
│       ├── Methods ([]string)
│       └── StatusCodes ([]int)
├── Rules ([]ClientRule)
└── Logging (LoggingConfig)
```

**Backend Config:**
| Field | Type | Required For | Description |
|-------|------|--------------|-------------|
| `Name` | string | All | Unique identifier |
| `Type` | string | All | direct, wireguard, openvpn, http, socks5 |
| `WireGuard.ConfigFile` | string | wireguard | Path to .conf file |
| `OpenVPN.ConfigFile` | string | openvpn | Path to .ovpn file |
| `OpenVPN.AuthFile` | string | openvpn | Path to auth file (optional) |
| `Proxy.Address` | string | http, socks5 | host:port |
| `Proxy.Username` | string | http, socks5 | Auth username (optional) |
| `Proxy.Password` | string | http, socks5 | Auth password (optional) |
| `HealthCheck.Enabled` | bool | All | Enable health checks |
| `HealthCheck.Interval` | Duration | All | Check interval |
| `HealthCheck.Timeout` | Duration | All | Check timeout |
| `HealthCheck.Type` | string | All | tcp, http, ping |

**Rule Config:**
| Field | Type | Description |
|-------|------|-------------|
| `Name` | string | Rule identifier |
| `Match.Domains` | []string | Domain patterns |
| `Backend` | string | Single backend name |
| `Backends` | []WeightedBackend | Multiple backends (LB) |
| `LoadBalancing.Algorithm` | string | round_robin, least_conn, ip_hash |
| `LoadBalancing.StickySessions` | bool | Sticky sessions |

**Validation rules:**
- Ports must be 1-65535
- Bind address must be valid IP
- Backend names must be unique
- Backend type must be valid
- Rules must reference existing backends
- Auth mode must be valid
- LDAP server required if mode=ldap
- OAuth client_id required if mode=oauth

### 2.4 Domain Matching Engine

**Location:** `internal/matcher/`

**Pattern types:**
| Pattern | Example | Matches | Does Not Match |
|---------|---------|---------|----------------|
| Exact | `example.com` | `example.com` | `www.example.com` |
| Wildcard | `*.example.com` | `www.example.com`, `a.b.example.com` | `example.com` |
| Full | `*` | Everything | - |

**Matching algorithm:**
1. Normalize input (lowercase, trim)
2. Check full wildcard first (fast path)
3. For wildcard patterns: compare from end
4. For exact patterns: compare all parts
5. Return first match (rules evaluated in order)

**Thread safety:**
- Use `sync.RWMutex`
- Read lock for Match()
- Write lock for Add(), Clear(), Reload()

### 2.5 Common Utilities

**Location:** `internal/util/`

**Context helpers:**
| Function | Description |
|----------|-------------|
| `WithTimeout(ctx, duration)` | Context with timeout |
| `WithRequestID(ctx, id)` | Add request ID to context |
| `RequestID(ctx)` | Get request ID from context |

**Error utilities:**
| Function | Description |
|----------|-------------|
| `Wrap(err, msg)` | Wrap error with message |
| `Is(err, target)` | Check error type |
| `As(err, target)` | Extract error type |

**Network utilities:**
| Function | Description |
|----------|-------------|
| `ParseIP(s)` | Parse IP address |
| `ParseCIDR(s)` | Parse CIDR notation |
| `MatchCIDR(ip, cidr)` | Check if IP in CIDR |
| `SplitHostPort(s)` | Split host:port |

**Crypto utilities:**
| Function | Description |
|----------|-------------|
| `RandomString(n)` | Secure random string |
| `ConstantTimeCompare(a, b)` | Timing-safe compare |
| `HashPassword(p)` | bcrypt hash |
| `CheckPassword(hash, p)` | Verify bcrypt |

---

## Phase 3: Backend System

### 3.1 Backend Interface

**Location:** `internal/backend/backend.go`

**Interface definition:**
```
Backend interface:
  - Name() string
  - Type() string
  - Dial(ctx, network, address) (net.Conn, error)
  - Start(ctx) error
  - Stop(ctx) error
  - Status() BackendStatus
```

**BackendStatus struct:**
| Field | Type | Description |
|-------|------|-------------|
| `Status` | Status | healthy, unhealthy, unknown, starting, stopping |
| `LastCheck` | time.Time | Last health check time |
| `LastError` | error | Last error encountered |
| `ConsecutiveFailures` | int | Consecutive failure count |
| `Latency` | time.Duration | Last measured latency |
| `ConnectionsActive` | int64 | Current active connections |
| `ConnectionsTotal` | int64 | Total connections handled |
| `BytesSent` | int64 | Total bytes sent |
| `BytesReceived` | int64 | Total bytes received |

### 3.2 Direct Backend

**Behavior:**
- Uses `net.Dialer` for direct TCP connections
- Configurable timeout and keepalive
- Tracks all connection statistics
- Always healthy when started

**Connection tracking:**
- Wrap `net.Conn` with tracked connection
- Increment active count on dial
- Decrement active count on close
- Track bytes on Read/Write

### 3.3 WireGuard Backend

**Dependencies:**
- `golang.zx2c4.com/wireguard` - WireGuard core
- `golang.zx2c4.com/wireguard/tun/netstack` - Userspace networking

**Config parsing:**
Parse standard WireGuard `.conf` format:
```
[Interface]
PrivateKey = base64...
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = base64...
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Startup sequence:**
1. Parse config file
2. Validate keys (base64 decode)
3. Create netstack TUN device
4. Create WireGuard device
5. Configure via IPC (private key, peers)
6. Bring up device
7. Mark as started

**Dial behavior:**
1. Check if started
2. Use `netstack.Net.DialContext()`
3. Track connection statistics

### 3.4 OpenVPN Backend

**Dependencies:**
- OpenVPN binary must be installed on system
- Management interface for control

**Startup sequence:**
1. Find free port for management interface
2. Build command line arguments
3. Spawn openvpn process
4. Connect to management interface
5. Read state changes
6. Wait for CONNECTED state
7. Extract assigned IP
8. Mark as started

**Management interface:**
- Connect via TCP to 127.0.0.1:PORT
- Parse `>STATE:` messages
- Send `signal SIGTERM` for graceful stop

**Dial behavior:**
1. Check if started and connected
2. Create `net.Dialer` with LocalAddr set to tunnel IP
3. Dial target
4. Track statistics

### 3.5 HTTP Proxy Backend

**CONNECT flow:**
1. Connect to upstream proxy (TCP)
2. Send HTTP CONNECT request
3. Add Proxy-Authorization header if configured
4. Read response
5. Verify 200 status
6. Return connection for tunneling

**Request format:**
```
CONNECT target.com:443 HTTP/1.1
Host: target.com:443
Proxy-Authorization: Basic base64(user:pass)

```

### 3.6 SOCKS5 Proxy Backend

**Dependencies:**
- `golang.org/x/net/proxy` - SOCKS5 client

**Dial flow:**
1. Create SOCKS5 dialer with upstream address
2. Configure auth if needed
3. Use dialer.DialContext()
4. Track statistics

### 3.7 Backend Factory

**Type mapping:**
| Type | Constructor |
|------|-------------|
| `direct` | `NewDirect(name, timeout)` |
| `wireguard` | `NewWireGuard(name, configPath)` |
| `openvpn` | `NewOpenVPN(name, configPath, authFile)` |
| `http` | `NewHTTPProxy(name, addr, user, pass)` |
| `socks5` | `NewSOCKS5Proxy(name, addr, user, pass)` |

### 3.8 Backend Manager

**Thread safety:**
- Use `sync.RWMutex`
- Read lock for Get(), List(), Status()
- Write lock for Load(), Add(), Remove()

**Operations:**
| Method | Description |
|--------|-------------|
| `Load(ctx, configs)` | Create backends from config |
| `StartAll(ctx)` | Start all backends |
| `StopAll(ctx)` | Stop all backends |
| `Get(name)` | Get backend by name |
| `List()` | List all backend names |
| `Status()` | Get all backend statuses |
| `Add(ctx, config)` | Add backend at runtime |
| `Remove(ctx, name)` | Remove backend at runtime |

---

## Phase 4: Proxy Protocols

### 4.1 Router System

**Server Router:**
- Input: domain name
- Output: backend name(s)
- Rules evaluated in order
- First match wins

**Client Router:**
- Input: domain name
- Output: action (server or direct)
- Rules evaluated in order
- First match wins

**Rule structure:**
| Field | Description |
|-------|-------------|
| `Name` | Rule identifier |
| `Matcher` | Domain matcher |
| `Route` | Routing decision |
| `Priority` | Evaluation order |

### 4.2 HTTP Proxy Handler

**Request types handled:**

| Method | Type | Handling |
|--------|------|----------|
| CONNECT | HTTPS tunnel | Establish tunnel, bidirectional copy |
| GET/POST/etc | Plain HTTP | Forward request, stream response |

**CONNECT handling:**
1. Parse target from request URL
2. Authenticate if required
3. Look up route
4. Dial through backend
5. Send "200 Connection Established"
6. Hijack connection
7. Bidirectional copy until EOF

**Plain HTTP handling:**
1. Parse target from absolute URL
2. Authenticate if required
3. Look up route
4. Dial through backend
5. Forward request (remove hop-by-hop headers)
6. Stream response back

**Hop-by-hop headers to remove:**
- Connection
- Keep-Alive
- Proxy-Authenticate
- Proxy-Authorization
- TE
- Trailers
- Transfer-Encoding
- Upgrade

**Error responses:**
| Code | Condition |
|------|-----------|
| 400 | Bad request (malformed) |
| 407 | Proxy auth required |
| 502 | Backend connection failed |
| 504 | Backend timeout |

### 4.3 SOCKS5 Proxy Handler

**SOCKS5 handshake:**
```
Client → Server: VER(1) NMETHODS(1) METHODS(NMETHODS)
Server → Client: VER(1) METHOD(1)
```

**Supported methods:**
- 0x00: No authentication
- 0x02: Username/password

**Username/password auth:**
```
Client → Server: VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
Server → Client: VER(1) STATUS(1)
```

**CONNECT request:**
```
Client → Server: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
Server → Client: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(var) BND.PORT(2)
```

**Address types (ATYP):**
- 0x01: IPv4 (4 bytes)
- 0x03: Domain name (1 byte length + name)
- 0x04: IPv6 (16 bytes)

**Reply codes (REP):**
| Code | Meaning |
|------|---------|
| 0x00 | Success |
| 0x01 | General failure |
| 0x02 | Connection not allowed |
| 0x03 | Network unreachable |
| 0x04 | Host unreachable |
| 0x05 | Connection refused |
| 0x06 | TTL expired |
| 0x07 | Command not supported |
| 0x08 | Address type not supported |

### 4.4 Connection Copier

**Bidirectional copy:**
1. Create two goroutines
2. Copy src→dst in one
3. Copy dst→src in other
4. Wait for both to complete
5. Return bytes transferred

**Buffer pool:**
- Use `sync.Pool` for buffers
- Buffer size: 32KB
- Reuse buffers to reduce allocations

**Timeout handling:**
- Set deadlines on both connections
- Extend deadline on activity
- Close on timeout

---

## Phase 5: Traffic Management

### 5.1 Rate Limiting

**Token bucket algorithm:**
```
- Bucket has capacity (burst)
- Tokens added at rate R per second
- Request consumes tokens
- If not enough tokens, request denied
```

**Rate limiter scopes:**
| Scope | Key | Description |
|-------|-----|-------------|
| Global | (none) | Single bucket for all requests |
| Per-IP | client IP | Bucket per unique IP |
| Per-User | username | Bucket per authenticated user |

**Per-IP/User cleanup:**
- Track last access time
- Periodically clean up stale entries
- Cleanup interval: 1 minute
- Stale threshold: 10 minutes

**Bandwidth throttling:**
- Token bucket where tokens = bytes
- Wrap connection with throttled reader/writer
- Block on Write if over limit
- Return partial Read if over limit

### 5.2 IP Access Control

**Whitelist behavior:**
- If whitelist is empty: allow all
- If whitelist has entries: only allow whitelisted

**Blacklist behavior:**
- Always checked
- Block if IP matches any blacklist entry

**Order of checks:**
1. Check blacklist first
2. If blacklist match: deny
3. If whitelist empty: allow
4. If whitelist match: allow
5. Otherwise: deny

**CIDR matching:**
- Parse CIDR notation (e.g., "192.168.1.0/24")
- Use `net.IPNet.Contains()`
- Support both IPv4 and IPv6

### 5.3 Health Checks

**Check types:**

| Type | Method | Success Criteria |
|------|--------|------------------|
| TCP | Connect | Connection established |
| HTTP | GET request | Expected status code |
| Ping | ICMP echo | Reply received |

**Health state machine:**
```
Unknown → (success) → Healthy
Unknown → (failure) → Unhealthy
Healthy → (N failures) → Unhealthy
Unhealthy → (N successes) → Healthy
```

**Default thresholds:**
- Healthy threshold: 2 consecutive successes
- Unhealthy threshold: 3 consecutive failures

**Passive health checking:**
- Track actual request failures
- Increment failure count on dial error
- Reset on successful request
- Mark unhealthy after consecutive failures

### 5.4 Load Balancer

**Algorithms:**

| Algorithm | Description |
|-----------|-------------|
| Round Robin | Cycle through backends |
| Least Conn | Pick backend with fewest active connections |
| Random | Random selection |
| IP Hash | Hash client IP for sticky sessions |
| Weighted | Respect configured weights |

**Backend selection:**
1. Filter to healthy backends only
2. Apply algorithm
3. If no healthy backends: return error
4. Track active connections

**Weighted round robin:**
```
- Backend A weight 3
- Backend B weight 1
- Sequence: A, A, A, B, A, A, A, B, ...
```

---

## Phase 6: Authentication System

### 6.1 Authentication Interface

**Authenticator interface:**
```
- Name() string
- Authenticate(ctx, Credentials) (*User, error)
- ValidateToken(ctx, token) (*User, error)
- Close() error
```

**Credentials struct:**
| Field | Type | Description |
|-------|------|-------------|
| `Username` | string | Username |
| `Password` | string | Password |
| `Token` | string | Bearer token |

**User struct:**
| Field | Type | Description |
|-------|------|-------------|
| `Username` | string | Authenticated username |
| `Groups` | []string | Group memberships |
| `Metadata` | map[string]string | Extra attributes |

### 6.2 No Authentication

**Behavior:**
- Always return success
- Return anonymous user (username: "anonymous")
- No groups

### 6.3 Native Authentication

**Storage:**
- Users stored in config file
- Password stored as bcrypt hash
- Groups as string array

**Password hashing:**
- Algorithm: bcrypt
- Cost: 12 (minimum)
- Verify with `bcrypt.CompareHashAndPassword()`

**User management CLI:**
| Command | Description |
|---------|-------------|
| `user add --username X` | Add user (prompts for password) |
| `user remove --username X` | Remove user |
| `user passwd --username X` | Change password |
| `user list` | List all users |
| `user groups --username X --add Y` | Add to group |
| `user groups --username X --remove Y` | Remove from group |

### 6.4 System Authentication

**Linux (PAM):**
- Use cgo to call PAM functions
- Service name: "bifrost"
- Authenticate via `pam_authenticate()`
- Get groups via `getgrouplist()`

**Windows:**
- Use `LogonUser()` for validation
- Use `NetUserGetLocalGroups()` for groups
- Support local and domain users

**macOS:**
- Use Open Directory framework
- Similar to PAM approach

### 6.5 LDAP Authentication

**Connection:**
- Support LDAP (port 389)
- Support LDAPS (port 636)
- Support STARTTLS
- Connection pooling for performance

**Authentication flow:**
1. Bind with service account
2. Search for user by filter
3. Extract user DN
4. Bind as user to validate password
5. Search for group membership
6. Check against allowed groups

**Config fields:**
| Field | Example |
|-------|---------|
| `Server` | `ldaps://ldap.example.com:636` |
| `BindDN` | `cn=service,dc=example,dc=com` |
| `BindPassword` | `${LDAP_PASSWORD}` |
| `BaseDN` | `dc=example,dc=com` |
| `UserFilter` | `(sAMAccountName=%s)` |
| `GroupFilter` | `(member=%s)` |

### 6.6 OAuth/OIDC Authentication

**Token validation:**
1. Receive bearer token
2. Validate JWT signature
3. Check issuer, audience, expiry
4. Extract username claim
5. Extract groups claim
6. Check against allowed groups

**OIDC discovery:**
- Fetch `.well-known/openid-configuration`
- Get token endpoint, userinfo endpoint, JWKS URI
- Cache JWKS for validation

**Supported providers:**
- Generic (manual configuration)
- Google
- Azure AD
- Okta

### 6.7 Authentication Middleware

**Proxy-Authorization header:**
```
Basic: Proxy-Authorization: Basic base64(username:password)
Bearer: Proxy-Authorization: Bearer <token>
```

**Flow:**
1. Check for Proxy-Authorization header
2. If missing and auth required: return 407
3. Parse auth scheme (Basic or Bearer)
4. Extract credentials
5. Call authenticator
6. On success: add user to context
7. On failure: return 407

**407 response:**
```
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Bifrost Proxy"
```

---

## Phase 7: Observability

### 7.1 Access Logging

**JSON format fields:**
| Field | Type | Example |
|-------|------|---------|
| `timestamp` | string | "2024-01-15T10:30:45.123Z" |
| `client_ip` | string | "192.168.1.100" |
| `username` | string | "john" |
| `method` | string | "CONNECT" |
| `host` | string | "api.example.com" |
| `path` | string | "/" |
| `status` | int | 200 |
| `bytes_sent` | int | 1234 |
| `bytes_recv` | int | 5678 |
| `duration_ms` | int | 150 |
| `backend` | string | "germany" |
| `user_agent` | string | "Mozilla/5.0..." |

**Apache Combined format:**
```
192.168.1.100 - john [15/Jan/2024:10:30:45 +0000] "CONNECT api.example.com:443 HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
```

**Header masking:**
- Replace sensitive header values with "***"
- Default masked: Authorization, Cookie, X-Api-Key
- Configurable additional headers

### 7.2 Prometheus Metrics

**Metric types and labels:**

**Counters:**
| Metric | Labels | Description |
|--------|--------|-------------|
| `bifrost_connections_total` | backend, status | Total connections |
| `bifrost_connection_errors_total` | backend, error | Connection errors |
| `bifrost_requests_total` | method, backend | Total requests |
| `bifrost_request_bytes_total` | direction | Bytes transferred |
| `bifrost_rate_limit_exceeded_total` | scope | Rate limit hits |
| `bifrost_auth_attempts_total` | provider, result | Auth attempts |
| `bifrost_config_reload_total` | - | Config reloads |
| `bifrost_config_reload_errors_total` | - | Reload errors |

**Gauges:**
| Metric | Labels | Description |
|--------|--------|-------------|
| `bifrost_connections_active` | backend | Active connections |
| `bifrost_backend_healthy` | backend | Backend health (0/1) |
| `bifrost_backend_latency_seconds` | backend | Last health check latency |
| `bifrost_uptime_seconds` | - | Server uptime |

**Histograms:**
| Metric | Labels | Description |
|--------|--------|-------------|
| `bifrost_request_duration_seconds` | backend | Request duration |

**Histogram buckets:**
- 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10

### 7.3 Health Endpoints

**GET /health**
- Returns 200 if server is running
- Returns 503 if unhealthy
- Response: `{"status": "ok"}` or `{"status": "unhealthy"}`

**GET /health/ready**
- Returns 200 if ready to accept traffic
- Checks: config loaded, at least one backend healthy
- Response: `{"ready": true, "backends": {"germany": "healthy", ...}}`

**GET /health/live**
- Returns 200 if process is alive
- Simple liveness check
- Response: `{"alive": true}`

---

## Phase 8: Server Application

### 8.1 Server Core

**Server struct fields:**
| Field | Type | Description |
|-------|------|-------------|
| `config` | *ServerConfig | Configuration |
| `backendManager` | *BackendManager | Manages backends |
| `router` | *ServerRouter | Routes domains |
| `rateLimiter` | *RateLimiterManager | Rate limiting |
| `accessController` | *AccessController | IP access control |
| `healthChecker` | *HealthChecker | Health checks |
| `loadBalancer` | LoadBalancer | Load balancing |
| `authenticator` | Authenticator | Authentication |
| `metricsCollector` | *MetricsCollector | Metrics |
| `accessLogger` | AccessLogger | Access logging |
| `httpListener` | net.Listener | HTTP listener |
| `socks5Listener` | net.Listener | SOCKS5 listener |
| `apiServer` | *http.Server | API server |

**Startup sequence:**
1. Parse and validate config
2. Setup logging
3. Create backend manager
4. Load backends from config
5. Start all backends
6. Create router, load rules
7. Create rate limiter
8. Create access controller
9. Create health checker, start checks
10. Create load balancer
11. Create authenticator
12. Create metrics collector
13. Create access logger
14. Start HTTP listener
15. Start SOCKS5 listener
16. Start API server
17. Setup signal handlers

**Shutdown sequence:**
1. Stop accepting new connections
2. Wait for drain timeout
3. Force close remaining connections
4. Stop API server
5. Stop health checker
6. Stop all backends
7. Close access logger
8. Close authenticator

### 8.2 Server REST API

**Base URL:** `http://localhost:7081/api`

**Authentication:**
- API uses same auth as proxy
- Or separate API key (configurable)

**Endpoints summary:**

| Method | Path | Description |
|--------|------|-------------|
| GET | /status | Server status |
| GET | /backends | List backends |
| POST | /backends | Add backend |
| GET | /backends/:name | Get backend |
| DELETE | /backends/:name | Remove backend |
| POST | /backends/:name/test | Test backend |
| GET | /backends/:name/health | Backend health |
| GET | /rules | List rules |
| POST | /rules | Add rule |
| GET | /rules/:name | Get rule |
| PUT | /rules/:name | Update rule |
| DELETE | /rules/:name | Remove rule |
| POST | /rules/reorder | Reorder rules |
| GET | /config | Get config |
| POST | /config/reload | Reload config |
| GET | /stats | Statistics |
| GET | /users | List users |
| POST | /users | Add user |
| DELETE | /users/:username | Remove user |
| GET | /ws | WebSocket |

**See Appendix B for full API reference with request/response schemas.**

### 8.3 Server CLI

**Command tree:**
```
bifrost-server
├── start
│   ├── --config PATH
│   ├── --log-level LEVEL
│   └── --foreground
├── stop
│   └── --pid-file PATH
├── status
│   └── --format (text|json)
├── config
│   ├── show
│   ├── validate PATH
│   └── reload
├── backend
│   ├── list [--format]
│   ├── add --name NAME --type TYPE [options]
│   ├── remove NAME
│   ├── test NAME
│   └── status NAME
├── rule
│   ├── list [--format]
│   ├── add --name NAME --domain PATTERN --backend NAME
│   ├── remove NAME
│   └── reorder NAME --position N
├── user
│   ├── list [--format]
│   ├── add --username NAME
│   ├── remove --username NAME
│   ├── passwd --username NAME
│   └── groups --username NAME (--add|--remove) GROUP
└── version
```

**Global flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `./config.yaml` | Config file path |
| `--log-level` | (from config) | Override log level |

---

## Phase 9: Client Application

### 9.1 Traffic Debugger

**TrafficEntry struct:**
| Field | Type | Description |
|-------|------|-------------|
| `ID` | string | Unique request ID |
| `Timestamp` | time.Time | Request time |
| `Method` | string | HTTP method |
| `Host` | string | Target host |
| `Port` | int | Target port |
| `Path` | string | Request path |
| `RequestHeaders` | map[string][]string | Request headers |
| `ResponseStatus` | int | Response status |
| `ResponseSize` | int64 | Response size |
| `ResponseHeaders` | map[string][]string | Response headers |
| `Duration` | time.Duration | Total duration |
| `Route` | string | "server" or "direct" |
| `Backend` | string | Backend used |
| `Error` | string | Error message |

**Ring buffer storage:**
- Fixed size (configurable, default 1000)
- Circular buffer
- Oldest entries evicted when full
- O(1) insert, O(n) search

**Query filters:**
| Filter | Description |
|--------|-------------|
| `Domain` | Match domain pattern |
| `Method` | Match HTTP method |
| `Status` | Match status code(s) |
| `TimeFrom` | After timestamp |
| `TimeTo` | Before timestamp |
| `HasError` | Only entries with errors |

**HAR export:**
- HTTP Archive format 1.2
- Export all or filtered entries
- Include headers, timing, size

### 9.2 Client Core

**Client struct fields:**
| Field | Type | Description |
|-------|------|-------------|
| `config` | *ClientConfig | Configuration |
| `router` | *ClientRouter | Routes domains |
| `serverConn` | *ServerConnection | Connection to server |
| `debugger` | *TrafficDebugger | Debug logging |
| `tray` | TrayIcon | System tray |
| `httpListener` | net.Listener | HTTP listener |
| `socks5Listener` | net.Listener | SOCKS5 listener |
| `apiServer` | *http.Server | API server |

**Request handling:**
1. Accept connection
2. Read request (HTTP or SOCKS5)
3. Extract target host
4. Generate request ID
5. Log to debugger (request)
6. Check router for action
7. If server: dial through serverConn
8. If direct: dial target directly
9. Establish tunnel
10. Bidirectional copy
11. Log to debugger (response)

**Server connection:**
- Maintain persistent connection to server
- Reconnect on failure with exponential backoff
- Backoff: 1s, 2s, 4s, 8s, 16s, 30s (max)
- Track connection state for tray icon

### 9.3 Client REST API

**Base URL:** `http://localhost:7382/api`

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | /status | Client status |
| GET | /rules | List rules |
| POST | /rules | Add rule |
| DELETE | /rules/:name | Remove rule |
| GET | /debug/status | Debug status |
| POST | /debug/enable | Enable debug |
| POST | /debug/disable | Disable debug |
| GET | /debug/traffic | Get traffic log |
| GET | /debug/traffic/:id | Get entry |
| GET | /debug/traffic/stream | WebSocket |
| POST | /debug/clear | Clear log |
| GET | /debug/stats | Statistics |
| GET | /debug/export | Export HAR |
| GET | /config | Get config |
| POST | /config/reload | Reload |

**See Appendix B for full API reference.**

### 9.4 Client CLI

**Command tree:**
```
bifrost-client
├── start
│   ├── --config PATH
│   ├── --log-level LEVEL
│   ├── --no-tray
│   └── --foreground
├── stop
├── status
│   └── --format (text|json)
├── config
│   ├── show
│   └── reload
├── rule
│   ├── list [--format]
│   ├── add --name NAME --domain PATTERN --action (server|direct)
│   └── remove NAME
├── debug
│   ├── on
│   ├── off
│   ├── tail [--filter PATTERN] [--follow]
│   ├── clear
│   ├── stats
│   └── export --output PATH
└── version
```

---

## Phase 10: System Tray

### 10.1 Tray Interface

**TrayIcon interface:**
| Method | Description |
|--------|-------------|
| `Init()` | Initialize tray |
| `SetState(TrayState)` | Update icon |
| `SetMenu([]MenuItem)` | Update menu |
| `Notify(title, msg)` | Show notification |
| `Run()` | Run event loop |
| `Quit()` | Exit tray |

**TrayState enum:**
| State | Icon Color | Meaning |
|-------|------------|---------|
| Connected | Green | Proxy running, server reachable |
| Disconnected | Gray | Proxy disabled |
| Warning | Yellow | Proxy running, server unreachable |
| Error | Red | Error state |

### 10.2 Menu Structure

```
Bifrost Client
├── Status: Connected ✓
├── ─────────────────────
├── Open Web UI
├── ─────────────────────
├── ☑ Enable Proxy
├── ☑ Route via Server
├── ─────────────────────
├── Quick Rules ▶
│   ├── ☑ Streaming
│   ├── ☑ Work Sites
│   └── ☐ Social Media
├── ─────────────────────
├── View Traffic
├── Settings
├── ─────────────────────
└── Quit
```

### 10.3 Menu Item Actions

| Item | Action |
|------|--------|
| Open Web UI | Open browser to http://localhost:7382 |
| Enable Proxy | Toggle proxy listeners on/off |
| Route via Server | Toggle between server/direct default |
| Quick Rules | Toggle individual rule enabled/disabled |
| View Traffic | Open browser to http://localhost:7382/traffic |
| Settings | Open browser to http://localhost:7382/settings |
| Quit | Graceful shutdown |

### 10.4 Notifications

| Event | Title | Message |
|-------|-------|---------|
| Server connected | Bifrost | Connected to server |
| Server disconnected | Bifrost | Server connection lost |
| Config reloaded | Bifrost | Configuration reloaded |
| Error | Bifrost Error | (error message) |

### 10.5 Icon Assets

**Required icons:**
| File | Size | State |
|------|------|-------|
| icon-connected-16.png | 16x16 | Connected |
| icon-connected-22.png | 22x22 | Connected |
| icon-connected-32.png | 32x32 | Connected |
| icon-disconnected-16.png | 16x16 | Disconnected |
| icon-disconnected-22.png | 22x22 | Disconnected |
| icon-disconnected-32.png | 32x32 | Disconnected |
| icon-warning-16.png | 16x16 | Warning |
| icon-warning-22.png | 22x22 | Warning |
| icon-warning-32.png | 32x32 | Warning |
| icon-error-16.png | 16x16 | Error |
| icon-error-22.png | 22x22 | Error |
| icon-error-32.png | 32x32 | Error |

**Embed using:**
```go
//go:embed icons/*.png
var iconFS embed.FS
```

---

## Phase 11: Web Interfaces

### 11.1 Technology Choice

**Recommended:** Svelte or React with Vite

**Reasons:**
- Component-based architecture
- Good TypeScript support
- Small bundle size (Svelte)
- Easy to embed in Go binary

### 11.2 Asset Embedding

**Structure:**
```
web/
├── server/
│   ├── src/
│   ├── dist/           # Built assets
│   └── package.json
└── client/
    ├── src/
    ├── dist/           # Built assets
    └── package.json
```

**Go embedding:**
```go
//go:embed dist/*
var webAssets embed.FS
```

**Development mode:**
- Check for `DEV_MODE` env var
- Proxy requests to Vite dev server

### 11.3 Server Web UI Pages

**Dashboard:**
| Section | Content |
|---------|---------|
| Status Card | Server status, uptime, version |
| Quick Stats | Connections, requests, bandwidth |
| Backend Status | Health status of all backends |
| Recent Activity | Last N requests |

**Backends Page:**
| Feature | Description |
|---------|-------------|
| Backend List | Table with name, type, status, stats |
| Health Indicator | Green/yellow/red dot |
| Add Backend | Form with type-specific fields |
| Edit Backend | Modify existing backend |
| Test Button | Test connectivity |
| Delete Button | Remove backend (with confirm) |

**Rules Page:**
| Feature | Description |
|---------|-------------|
| Rule List | Table with name, domains, backend |
| Priority | Visual priority indicator |
| Drag & Drop | Reorder rules |
| Add Rule | Form with domain patterns |
| Edit Rule | Modify existing rule |
| Delete Button | Remove rule (with confirm) |

**Statistics Page:**
| Chart | Data |
|-------|------|
| Requests/sec | Time series line chart |
| Bandwidth | In/out bytes time series |
| Response Times | Histogram |
| Backend Distribution | Pie chart |
| Error Rate | Time series |

**Users Page (native auth):**
| Feature | Description |
|---------|-------------|
| User List | Table with username, groups |
| Add User | Form with password |
| Edit Groups | Modify group membership |
| Reset Password | Set new password |
| Delete User | Remove user |

### 11.4 Client Web UI Pages

**Dashboard:**
| Section | Content |
|---------|---------|
| Status Card | Client status, server connection |
| Quick Stats | Requests, routed via server, direct |
| Connection Status | Server reachable indicator |

**Traffic Page:**
| Feature | Description |
|---------|-------------|
| Request List | Real-time scrolling list |
| Filters | Domain, method, status dropdowns |
| Search | Full-text search |
| Request Detail | Expandable row with headers, timing |
| Clear Button | Clear traffic log |
| Export Button | Download HAR file |

**Rules Page:**
| Feature | Description |
|---------|-------------|
| Rule List | Table with name, domains, action |
| Action Toggle | Switch server/direct |
| Add Rule | Form with domain patterns |
| Delete Button | Remove rule |

### 11.5 WebSocket Messages

**Server WebSocket (GET /api/ws):**

| Event | Payload |
|-------|---------|
| `backend_status` | `{backend: string, status: string, latency: number}` |
| `connection` | `{client: string, backend: string, host: string}` |
| `stats_update` | `{connections: number, requests: number, ...}` |
| `config_reload` | `{success: boolean, error?: string}` |

**Client WebSocket (GET /api/debug/traffic/stream):**

| Event | Payload |
|-------|---------|
| `traffic` | TrafficEntry object |
| `stats_update` | `{total: number, server: number, direct: number}` |

---

## Phase 12: DevOps & Deployment

### 12.1 Docker - Server

**Dockerfile stages:**

| Stage | Base | Purpose |
|-------|------|---------|
| builder | golang:1.22-alpine | Compile binary |
| runtime | alpine:latest | Run server |

**Runtime packages:**
- iptables (for some VPN setups)
- openvpn (OpenVPN client)

**Exposed ports:**
| Port | Service |
|------|---------|
| 8080 | HTTP proxy |
| 1080 | SOCKS5 proxy |
| 8081 | Web UI / API |
| 9090 | Metrics |

**Docker Compose:**
```yaml
services:
  bifrost-server:
    build: .
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    ports:
      - "8080:7080"
      - "1080:7180"
      - "8081:7081"
    volumes:
      - ./config:/etc/bifrost
      - ./wireguard:/etc/wireguard:ro
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:7081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### 12.2 GitHub Actions - CI

**Triggers:**
- Push to main
- Pull requests to main

**Jobs:**

| Job | Runs On | Steps |
|-----|---------|-------|
| test | ubuntu/macos/windows | checkout, setup-go, test |
| lint | ubuntu-latest | checkout, setup-go, golangci-lint |
| security | ubuntu-latest | checkout, setup-go, govulncheck |

**Test matrix:**
- OS: ubuntu-latest, macos-latest, windows-latest
- Go: 1.22

### 12.3 GitHub Actions - Release

**Triggers:**
- Tag push matching `v*`

**Jobs:**

| Job | Steps |
|-----|-------|
| release | checkout, setup-go, goreleaser |
| docker | build, push to ghcr.io |

**Artifacts:**
- bifrost-server-linux-amd64.tar.gz
- bifrost-server-linux-arm64.tar.gz
- bifrost-server-darwin-amd64.tar.gz
- bifrost-server-darwin-arm64.tar.gz
- bifrost-server-windows-amd64.zip
- bifrost-client-linux-amd64.tar.gz
- (etc.)
- checksums.txt

### 12.4 GoReleaser

**Builds:**
```yaml
builds:
  - id: server
    binary: bifrost-server
    main: ./cmd/server
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
  - id: client
    binary: bifrost-client
    main: ./cmd/client
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
```

### 12.5 Service Files

**systemd (Linux):**
```ini
[Unit]
Description=Bifrost Proxy Server
After=network.target

[Service]
Type=simple
User=bifrost
ExecStart=/usr/local/bin/bifrost-server start --config /etc/bifrost/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Phase 13: Testing & Quality

### 13.1 Unit Test Coverage Targets

| Package | Target |
|---------|--------|
| config | 90% |
| matcher | 95% |
| backend | 80% |
| router | 90% |
| ratelimit | 90% |
| accesscontrol | 90% |
| health | 80% |
| loadbalancer | 85% |
| auth | 80% |
| proxy | 75% |

### 13.2 Test Scenarios

**Config tests:**
- Parse valid config
- Parse config with env vars
- Validate missing required fields
- Validate invalid values
- Default values applied

**Matcher tests:**
- Exact match
- Wildcard subdomain match
- Full wildcard match
- No match
- Case insensitivity
- Concurrent access

**Backend tests:**
- Direct: dial success, dial failure, stats tracking
- WireGuard: config parsing, start/stop lifecycle
- OpenVPN: process spawn, state parsing
- HTTP Proxy: CONNECT flow, auth
- SOCKS5: dial through proxy

**Router tests:**
- Match first rule
- Match wildcard rule
- No match returns empty
- Rule priority order
- Add/remove rules

**Rate limiter tests:**
- Allow within limit
- Deny over limit
- Burst handling
- Per-IP isolation
- Cleanup stale entries

**Auth tests:**
- None: always succeeds
- Native: valid password, invalid password, user not found
- LDAP: mock server tests
- OAuth: mock token validation

**Proxy tests:**
- HTTP CONNECT flow
- Plain HTTP forwarding
- SOCKS5 handshake
- Auth required but missing
- Backend failure handling

### 13.3 Integration Tests

**Prerequisites:**
- Build tag: `//go:build integration`
- May require external services

**Scenarios:**
- Server starts and accepts connections
- Client connects to server
- Request flows through full pipeline
- Backend failover on failure
- Hot reload changes routes

### 13.4 End-to-End Tests

**Setup:**
- Docker Compose for test environment
- Test client making requests

**Scenarios:**
1. Start server with WireGuard backend
2. Start client pointing to server
3. Make request to streaming domain
4. Verify routed through WireGuard
5. Make request to other domain
6. Verify went direct
7. Trigger config reload
8. Verify new rules applied

### 13.5 Benchmarks

| Benchmark | Measures |
|-----------|----------|
| BenchmarkMatch | Domain matching speed |
| BenchmarkHTTPProxy | Requests per second |
| BenchmarkCopy | Throughput MB/s |
| BenchmarkRateLimit | Checks per second |

---

## Phase 14: Documentation & Release

### 14.1 README Structure

```markdown
# Bifrost

[badges]

## Features
- List of key features

## Quick Start
- One-liner to get started

## Installation
- Binary download
- Docker
- From source

## Usage
- Basic server setup
- Basic client setup

## Configuration
- Link to full config docs

## Documentation
- Links to docs/

## Contributing
- Link to CONTRIBUTING.md

## License
- MIT License
```

### 14.2 Documentation Pages

| Page | Content |
|------|---------|
| Getting Started | First-time setup tutorial |
| Installation | All installation methods |
| Server Configuration | Full server config reference |
| Client Configuration | Full client config reference |
| Backend Types | How to configure each backend |
| Authentication | Auth provider setup guides |
| API Reference | Full REST API documentation |
| CLI Reference | All CLI commands |
| Troubleshooting | Common issues and solutions |
| FAQ | Frequently asked questions |

### 14.3 Release Checklist

1. [ ] All tests passing
2. [ ] Linting passes
3. [ ] Security scan clean
4. [ ] Version updated in code
5. [ ] CHANGELOG.md updated
6. [ ] Documentation updated
7. [ ] Example configs updated
8. [ ] Create git tag
9. [ ] Push tag
10. [ ] Verify release created
11. [ ] Verify Docker image pushed
12. [ ] Announce release

---

## Appendix A: Data Structures

### A.1 Core Types

**Duration (config):**
```
Type: custom YAML type
Parses: "10s", "5m", "1h"
Stores: time.Duration
```

**Status (backend):**
```
Values: healthy, unhealthy, unknown, starting, stopping
```

**TrayState:**
```
Values: connected, disconnected, warning, error
```

### A.2 Request Context

**Context keys:**
| Key | Type | Description |
|-----|------|-------------|
| `request_id` | string | Unique request ID |
| `user` | *User | Authenticated user |
| `logger` | *slog.Logger | Request logger |
| `start_time` | time.Time | Request start |

### A.3 Error Types

| Error | Package | Description |
|-------|---------|-------------|
| `ErrBackendNotStarted` | backend | Backend not started |
| `ErrBackendStopped` | backend | Backend stopped |
| `ErrConnectionFailed` | backend | Connection failed |
| `ErrTimeout` | backend | Connection timeout |
| `ErrInvalidCredentials` | auth | Auth failed |
| `ErrUserNotFound` | auth | User not found |
| `ErrRateLimited` | ratelimit | Rate limit exceeded |
| `ErrAccessDenied` | accesscontrol | IP blocked |

---

## Appendix B: API Reference

### B.1 Server API

**GET /api/status**
```
Response 200:
{
  "status": "running",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "backends": {
    "total": 3,
    "healthy": 2,
    "unhealthy": 1
  },
  "connections": {
    "active": 42,
    "total": 10000
  }
}
```

**GET /api/backends**
```
Response 200:
{
  "backends": [
    {
      "name": "germany",
      "type": "wireguard",
      "status": "healthy",
      "latency_ms": 45,
      "connections_active": 10,
      "connections_total": 500,
      "bytes_sent": 1000000,
      "bytes_received": 5000000
    }
  ]
}
```

**POST /api/backends**
```
Request:
{
  "name": "japan",
  "type": "wireguard",
  "wireguard": {
    "config_file": "/etc/wireguard/japan.conf"
  }
}

Response 201:
{
  "name": "japan",
  "type": "wireguard",
  "status": "starting"
}

Response 400:
{
  "error": "backend name already exists"
}
```

**DELETE /api/backends/:name**
```
Response 204: (no content)

Response 404:
{
  "error": "backend not found"
}
```

**POST /api/backends/:name/test**
```
Response 200:
{
  "success": true,
  "latency_ms": 120,
  "target": "google.com:443"
}

Response 200:
{
  "success": false,
  "error": "connection timeout"
}
```

**GET /api/rules**
```
Response 200:
{
  "rules": [
    {
      "name": "streaming",
      "match": {
        "domains": ["*.netflix.com", "*.crunchyroll.com"]
      },
      "backend": "germany",
      "priority": 0
    }
  ]
}
```

**POST /api/rules**
```
Request:
{
  "name": "social",
  "match": {
    "domains": ["*.facebook.com", "*.twitter.com"]
  },
  "backend": "direct"
}

Response 201:
{
  "name": "social",
  ...
}
```

**POST /api/rules/reorder**
```
Request:
{
  "order": ["streaming", "work", "social", "default"]
}

Response 200:
{
  "success": true
}
```

**POST /api/config/reload**
```
Response 200:
{
  "success": true,
  "changes": {
    "backends_added": ["new-backend"],
    "backends_removed": [],
    "rules_changed": true
  }
}

Response 400:
{
  "success": false,
  "error": "invalid config: ..."
}
```

### B.2 Client API

**GET /api/status**
```
Response 200:
{
  "status": "running",
  "server": {
    "address": "proxy.example.com:7080",
    "connected": true,
    "latency_ms": 50
  },
  "proxy": {
    "enabled": true,
    "http_port": 3128,
    "socks5_port": 1081
  },
  "stats": {
    "requests_total": 1000,
    "requests_server": 400,
    "requests_direct": 600
  }
}
```

**GET /api/debug/traffic**
```
Query params:
- domain: filter by domain
- method: filter by method
- status: filter by status
- limit: max entries (default 100)
- offset: pagination offset

Response 200:
{
  "entries": [
    {
      "id": "abc123",
      "timestamp": "2024-01-15T10:30:45Z",
      "method": "CONNECT",
      "host": "api.example.com",
      "port": 443,
      "response_status": 200,
      "response_size": 1234,
      "duration_ms": 150,
      "route": "server",
      "backend": "germany"
    }
  ],
  "total": 500,
  "offset": 0,
  "limit": 100
}
```

**GET /api/debug/traffic/:id**
```
Response 200:
{
  "id": "abc123",
  "timestamp": "2024-01-15T10:30:45Z",
  "method": "CONNECT",
  "host": "api.example.com",
  "port": 443,
  "path": "/",
  "request_headers": {
    "User-Agent": ["Mozilla/5.0..."],
    "Accept": ["*/*"]
  },
  "response_status": 200,
  "response_size": 1234,
  "response_headers": {
    "Content-Type": ["application/json"]
  },
  "duration_ms": 150,
  "route": "server",
  "backend": "germany",
  "error": null
}
```

**GET /api/debug/export**
```
Response 200 (application/json):
{
  "log": {
    "version": "1.2",
    "entries": [...]
  }
}
```

---

## Appendix C: Error Codes

### C.1 HTTP Proxy Errors

| Code | Description |
|------|-------------|
| 400 | Bad Request - Malformed request |
| 407 | Proxy Authentication Required |
| 502 | Bad Gateway - Backend connection failed |
| 503 | Service Unavailable - No healthy backends |
| 504 | Gateway Timeout - Backend timeout |

### C.2 SOCKS5 Reply Codes

| Code | Description |
|------|-------------|
| 0x00 | Success |
| 0x01 | General SOCKS server failure |
| 0x02 | Connection not allowed by ruleset |
| 0x03 | Network unreachable |
| 0x04 | Host unreachable |
| 0x05 | Connection refused |
| 0x06 | TTL expired |
| 0x07 | Command not supported |
| 0x08 | Address type not supported |

### C.3 API Error Responses

**Standard error format:**
```json
{
  "error": "human readable message",
  "code": "ERROR_CODE",
  "details": {}
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_REQUEST | 400 | Request validation failed |
| UNAUTHORIZED | 401 | Authentication required |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource already exists |
| INTERNAL_ERROR | 500 | Internal server error |

---

## Appendix D: Configuration Reference

### D.1 Server Config Example

```yaml
# Bifrost Server Configuration

server:
  http_port: 8080
  socks5_port: 1080
  bind_address: "0.0.0.0"
  web_ui_port: 8081

network:
  ipv6:
    enabled: true
    prefer_ipv6: false
  timeouts:
    connect: "10s"
    read: "30s"
    write: "30s"
    idle: "60s"
  keepalive:
    enabled: true
    interval: "30s"
    max_idle_conns: 100
    max_idle_time: "90s"
  limits:
    max_connections: 10000
    max_connections_per_ip: 100
    max_connections_per_backend: 50

rate_limiting:
  enabled: true
  global:
    requests_per_second: 1000
    burst: 100
  per_ip:
    requests_per_second: 100
    burst: 20
  per_user:
    requests_per_second: 200
    burst: 50

access_control:
  whitelist: []
  blacklist: []

access_log:
  enabled: true
  format: "json"
  output: "file"
  file: "/var/log/bifrost/access.log"
  mask_headers:
    - "Authorization"
    - "Cookie"

auth:
  mode: "none"  # none, native, system, ldap, oauth

health_checks:
  interval: "30s"
  timeout: "5s"
  healthy_threshold: 2
  unhealthy_threshold: 3

metrics:
  enabled: true
  endpoint: "/metrics"
  port: 9090

shutdown:
  drain_timeout: "30s"
  force_timeout: "60s"

backends:
  - name: "direct"
    type: "direct"

  - name: "germany"
    type: "wireguard"
    wireguard:
      config_file: "/etc/wireguard/germany.conf"
    health_check:
      enabled: true
      type: "tcp"
      interval: "30s"
      timeout: "5s"

rules:
  - name: "streaming"
    match:
      domains:
        - "*.crunchyroll.com"
        - "*.netflix.com"
    backend: "germany"

  - name: "default"
    match:
      domains:
        - "*"
    backend: "direct"

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

### D.2 Client Config Example

```yaml
# Bifrost Client Configuration

client:
  http_port: 3128
  socks5_port: 1081
  bind_address: "127.0.0.1"
  web_ui_port: 3129

tray:
  enabled: true
  start_minimized: false
  show_notifications: true
  autostart: false

server:
  address: "proxy.example.com:7080"
  protocol: "http"
  auth:
    enabled: false
    username: ""
    password: ""

debug:
  enabled: true
  log_requests: true
  log_responses: true
  log_headers: false
  log_body: false
  max_body_log_size: 1024
  output: "file"
  log_file: "./traffic.log"
  filter:
    domains: []
    methods: []
    status_codes: []

rules:
  - name: "streaming"
    match:
      domains:
        - "*.crunchyroll.com"
        - "*.netflix.com"
    action: "server"

  - name: "default"
    match:
      domains:
        - "*"
    action: "direct"

logging:
  level: "info"
  format: "text"
  output: "stdout"
```

---

## Dependency Graph

```
Phase 1: Foundation
    │
    ▼
Phase 2: Core Libraries
    │
    ├──────────────────────────────────────────┐
    │                                          │
    ▼                                          ▼
Phase 3: Backend System              Phase 4: Proxy Protocols
    │                                          │
    └────────────────┬─────────────────────────┘
                     │
                     ▼
              Phase 5: Traffic Management
                     │
                     ▼
              Phase 6: Authentication
                     │
                     ▼
              Phase 7: Observability
                     │
    ┌────────────────┼────────────────┐
    │                │                │
    ▼                ▼                ▼
Phase 8:       Phase 9:        Phase 10:
Server App     Client App      System Tray
    │                │                │
    └────────────────┴────────────────┘
                     │
                     ▼
              Phase 11: Web Interfaces
                     │
                     ▼
              Phase 12: DevOps
                     │
                     ▼
              Phase 13: Testing
                     │
                     ▼
              Phase 14: Documentation & Release
```

---

## Risk Management

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| WireGuard permissions | High | Medium | Userspace impl, document requirements |
| OpenVPN not installed | Medium | Medium | Clear error, Docker includes it |
| System tray unavailable | Low | Medium | CLI-only fallback |
| LDAP unreachable | Medium | Low | Timeout, connection pooling |
| OAuth provider down | Medium | Low | Token caching |
| Cross-platform issues | Medium | Medium | CI on all platforms |
| Performance at scale | High | Low | Benchmark, optimize |
| Security vulnerabilities | High | Low | Security scanning, updates |

---

*This implementation plan should be reviewed and updated as implementation progresses.*
