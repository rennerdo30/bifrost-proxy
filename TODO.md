# Bifrost - Implementation Checklist

Track implementation progress by checking off completed items.

---

## Phase 1: Project Foundation

### 1.1 Repository Setup
- [x] Initialize Git repository
- [x] Create `.gitignore` file
- [x] Add MIT LICENSE file
- [x] Create initial README.md

### 1.2 Go Module Initialization
- [x] Run `go mod init`
- [x] Set Go version to 1.22+
- [x] Add initial dependencies to go.mod

### 1.3 Project Structure
- [x] Create `cmd/server/` directory
- [x] Create `cmd/client/` directory
- [x] Create `internal/` directory
- [x] Create `pkg/` directory
- [x] Create `web/` directory
- [x] Create `configs/` directory
- [x] Create `assets/` directory
- [x] Create `docker/` directory
- [x] Create `.github/` directory
- [x] Create `docs/` directory

### 1.4 Build System
- [x] Create Makefile
- [x] Add `build` target
- [x] Add `build-server` target
- [x] Add `build-client` target
- [x] Add `test` target
- [x] Add `lint` target
- [x] Add `clean` target
- [x] Add `build-all` (cross-platform) target
- [x] Add version injection via ldflags

### 1.5 Development Tooling
- [x] Create `.golangci.yml` linter config
- [x] Create `.editorconfig`
- [x] Test that `make build` works
- [x] Test that `make lint` works

---

## Phase 2: Core Libraries

### 2.1 Version Package
- [x] Create `internal/version/version.go`
- [x] Define Version variable
- [x] Define GitCommit variable
- [x] Define BuildTime variable
- [x] Create version string function

### 2.2 Logging System
- [x] Create `internal/logging/` directory
- [x] Create `logging.go` with Setup function
- [x] Implement log level parsing (debug, info, warn, error)
- [x] Implement JSON format handler
- [x] Implement text format handler
- [x] Implement stdout output
- [x] Implement stderr output
- [x] Implement file output
- [x] Create `context.go` for context-based logging
- [x] Define standard attribute keys
- [x] Create `logging_test.go` with tests

### 2.3 Configuration System
- [x] Create `internal/config/` directory
- [x] Create `config.go` with Load function
- [x] Implement YAML parsing
- [x] Implement environment variable expansion
- [x] Implement Duration type for YAML
- [x] Create `server.go` with ServerConfig struct
- [x] Define ServerSettings struct
- [x] Define NetworkSettings struct
- [x] Define TimeoutConfig struct
- [x] Define RateLimitConfig struct
- [x] Define BandwidthConfig struct
- [x] Define AccessLogConfig struct
- [x] Define AuthConfig struct
- [x] Define NativeAuthConfig struct
- [x] Define LDAPAuthConfig struct
- [x] Define OAuthConfig struct
- [x] Define HealthCheckDefaults struct
- [x] Define MetricsConfig struct
- [x] Define BackendConfig struct
- [x] Define WireGuardConfig struct
- [x] Define OpenVPNConfig struct
- [x] Define ProxyConfig struct
- [x] Define HealthCheckConfig struct
- [x] Define RuleConfig struct
- [x] Define LoadBalancingConfig struct
- [x] Implement DefaultServerConfig function
- [x] Create `client.go` with ClientConfig struct
- [x] Define ClientSettings struct
- [x] Define TrayConfig struct
- [x] Define ServerConnection struct
- [x] Define DebugConfig struct
- [x] Define DebugFilter struct
- [x] Define ClientRule struct
- [x] Implement DefaultClientConfig function
- [x] Implement ValidateServerConfig
- [x] Implement ValidateClientConfig
- [x] Create `config_test.go` with tests

### 2.4 Domain Matching Engine
- [x] Create `internal/matcher/` directory
- [x] Create `matcher.go`
- [x] Implement Matcher struct
- [x] Implement Add method
- [x] Implement AddAll method
- [x] Implement Match method
- [x] Implement Clear method
- [x] Support exact match (example.com)
- [x] Support wildcard subdomain (*.example.com)
- [x] Support full wildcard (*)
- [x] Implement case-insensitive matching
- [x] Make thread-safe with mutex
- [x] Create `matcher_test.go` with tests

### 2.5 Common Utilities
- [x] Create `internal/util/` directory
- [x] Create context helpers
- [x] Create error wrapping utilities
- [x] Create network utilities (IP parsing, CIDR)

---

## Phase 3: Backend System

### 3.1 Backend Interface
- [x] Create `internal/backend/` directory
- [x] Create `backend.go`
- [x] Define Backend interface
- [x] Define BackendStatus struct
- [x] Create `errors.go`
- [x] Define ErrBackendNotStarted
- [x] Define ErrBackendStopped
- [x] Define ErrConnectionFailed
- [x] Define ErrTimeout
- [x] Define BackendError type

### 3.2 Direct Backend
- [x] Create `direct.go`
- [x] Implement DirectBackend struct
- [x] Implement NewDirect constructor
- [x] Implement Name method
- [x] Implement Type method
- [x] Implement Start method
- [x] Implement Stop method
- [x] Implement Dial method
- [x] Implement Status method
- [x] Implement connection tracking (active count)
- [x] Implement bytes tracking (sent/received)
- [x] Create trackedConn wrapper
- [x] Create `direct_test.go` with tests

### 3.3 WireGuard Backend
- [x] Create `internal/backend/wireguard.go`
- [x] Implement WireGuardBackend struct
- [x] Implement NewWireGuard constructor
- [x] Implement Name method
- [x] Implement Type method
- [x] Implement Start method (create tunnel)
- [x] Implement Stop method (close tunnel)
- [x] Implement Dial method (dial through tunnel)
- [x] Implement Status method
- [x] Integrate wireguard-go library
- [x] Use netstack for userspace networking
- [x] Implement connection/byte tracking

### 3.4 OpenVPN Backend
- [x] Create `internal/backend/openvpn.go`
- [x] Implement OpenVPNBackend struct
- [x] Implement NewOpenVPN constructor
- [x] Implement Name method
- [x] Implement Type method
- [x] Implement Start method
- [x] Implement Stop method
- [x] Implement Dial method
- [x] Implement Status method
- [x] Implement connection/byte tracking

### 3.5 HTTP Proxy Backend
- [x] Create `internal/backend/httpproxy.go`
- [x] Implement HTTPProxyBackend struct
- [x] Implement NewHTTPProxy constructor
- [x] Implement Name method
- [x] Implement Type method
- [x] Implement Start method
- [x] Implement Stop method
- [x] Implement Dial method
- [x] Send HTTP CONNECT request
- [x] Handle Proxy-Authorization header
- [x] Parse proxy response
- [x] Verify 200 OK status
- [x] Implement Status method
- [x] Implement connection/byte tracking

### 3.6 SOCKS5 Proxy Backend
- [x] Create `internal/backend/socks5proxy.go`
- [x] Implement SOCKS5ProxyBackend struct
- [x] Implement NewSOCKS5Proxy constructor
- [x] Implement Name method
- [x] Implement Type method
- [x] Implement Start method
- [x] Implement Stop method
- [x] Implement Dial method (use golang.org/x/net/proxy)
- [x] Support username/password auth
- [x] Implement Status method
- [x] Implement connection/byte tracking

### 3.7 Backend Factory
- [x] Create `internal/backend/factory.go`
- [x] Implement Factory struct
- [x] Implement NewFactory constructor
- [x] Implement Create method
- [x] Handle "direct" type
- [x] Handle "wireguard" type
- [x] Handle "openvpn" type
- [x] Handle "http" type
- [x] Handle "socks5" type
- [x] Return error for unknown types
- [x] Validate required config per type

### 3.8 Backend Manager
- [x] Create `internal/backend/manager.go`
- [x] Implement Manager struct
- [x] Implement NewManager constructor
- [x] Implement StartAll method
- [x] Implement StopAll method
- [x] Implement Get method (by name)
- [x] Implement List method
- [x] Implement Add method (runtime)
- [x] Implement Remove method (runtime)
- [x] Thread-safe with mutex

---

## Phase 4: Proxy Protocols

### 4.1 Router System
- [x] Create `internal/router/` directory
- [x] Create `router.go`
- [x] Define Route struct
- [x] Implement BaseRouter struct
- [x] Implement Match method
- [x] Implement AddRule method
- [x] Implement Routes method
- [x] Thread-safe with mutex
- [x] Create `server.go`
- [x] Implement ServerRouter
- [x] Implement LoadFromConfig method
- [x] Create `client.go`
- [x] Implement ClientRouter
- [x] Implement LoadFromConfig method
- [x] Implement ShouldRouteToServer method
- [x] Create `router_test.go` with tests

### 4.2 HTTP Proxy Handler
- [x] Create `internal/proxy/` directory
- [x] Create `http.go`
- [x] Implement HTTPHandler struct
- [x] Implement NewHTTPHandler constructor
- [x] Implement ServeConn method
- [x] Handle plain HTTP requests (absolute URL)
- [x] Handle HTTPS CONNECT requests
- [x] Extract target host from request
- [x] Route through backend manager
- [x] Forward request to backend
- [x] Stream response back to client
- [x] Handle hop-by-hop headers
- [x] Implement connection hijacking for CONNECT
- [x] Implement bidirectional copy
- [x] Handle timeouts
- [x] Return proper error status codes

### 4.3 SOCKS5 Proxy Handler
- [x] Create `internal/proxy/socks5.go`
- [x] Implement SOCKS5Handler struct
- [x] Implement NewSOCKS5Handler constructor
- [x] Implement ServeConn method
- [x] Handle SOCKS5 handshake
- [x] Support no auth method (0x00)
- [x] Support username/password method (0x02)
- [x] Handle CONNECT command (0x01)
- [x] Parse IPv4 address type
- [x] Parse IPv6 address type
- [x] Parse domain name address type
- [x] Route through backend manager
- [x] Send success/failure response
- [x] Implement bidirectional copy
- [x] Handle timeouts

### 4.4 Connection Copier
- [x] Create `internal/proxy/copy.go`
- [x] Implement bidirectional copy function
- [x] Track bytes transferred both directions
- [x] Handle EOF properly
- [x] Handle errors properly
- [x] Support deadline/timeout

---

## Phase 5: Traffic Management

### 5.1 Rate Limiting
- [x] Create `internal/ratelimit/` directory
- [x] Create `limiter.go` with interface
- [x] Create `token_bucket.go`
- [x] Implement TokenBucket struct
- [x] Implement Allow method
- [x] Implement AllowN method
- [x] Thread-safe implementation
- [x] Implement per-IP limiter with map
- [x] Implement cleanup for expired entries
- [x] Create `bandwidth.go`
- [x] Implement BandwidthThrottler
- [x] Wrap connections with throttled reader/writer
- [x] Create tests

### 5.2 Health Checks
- [x] Create `internal/health/` directory
- [x] Create `checker.go` with interface
- [x] Define HealthResult struct
- [x] Create `tcp.go`
- [x] Implement TCPHealthCheck
- [x] Attempt TCP connection
- [x] Return success/failure
- [x] Create `http.go`
- [x] Implement HTTPHealthCheck
- [x] Send HTTP GET request
- [x] Check expected status code
- [x] Create `ping.go`
- [x] Implement PingHealthCheck (ICMP)
- [x] Create `manager.go`
- [x] Implement HealthChecker manager
- [x] Run periodic health checks per backend
- [x] Track consecutive successes/failures
- [x] Store last check time
- [x] Store latency
- [x] Store last error
- [x] Create tests

### 5.3 Load Balancer
- [x] Create `internal/router/loadbalancer.go`
- [x] Implement RoundRobin algorithm
- [x] Implement LeastConnections algorithm
- [x] Implement IPHash algorithm (sticky sessions)
- [x] Select from healthy backends only

---

## Phase 6: Authentication System

### 6.1 Authentication Interface
- [x] Create `internal/auth/` directory
- [x] Create `auth.go`
- [x] Define Authenticator interface
- [x] Define Credentials struct
- [x] Define User struct
- [x] Create `errors.go`
- [x] Define ErrInvalidCredentials
- [x] Define ErrUserNotFound
- [x] Define ErrAuthenticationFailed

### 6.2 No Authentication
- [x] Create `internal/auth/none.go`
- [x] Implement NoneAuthenticator
- [x] Always return success
- [x] Return anonymous user

### 6.3 Native Authentication
- [x] Create `internal/auth/native.go`
- [x] Implement NativeAuthenticator
- [x] Store users from config
- [x] Validate password with bcrypt
- [x] Return user with groups

### 6.4 LDAP Authentication
- [x] Create `internal/auth/ldap.go`
- [x] Implement LDAPAuthenticator
- [x] Connect to LDAP server
- [x] Support LDAP and LDAPS
- [x] Bind with service account
- [x] Search for user by filter
- [x] Bind as user to validate password
- [x] Search for group membership
- [x] Check against allowed groups
- [x] Support TLS with custom CA
- [x] Support skip TLS verify option
- [x] Implement Close method

### 6.5 Authentication Middleware
- [x] Create `internal/auth/middleware.go`
- [x] Implement ProxyAuthMiddleware
- [x] Extract Proxy-Authorization header
- [x] Parse Basic auth (base64 user:pass)
- [x] Call authenticator
- [x] Return 407 on failure

### 6.6 Auth Tests
- [x] Create `internal/auth/auth_test.go`

---

## Phase 7: Observability

### 7.1 Access Logging
- [x] Create `internal/accesslog/` directory
- [x] Create `logger.go` with interface
- [x] Define AccessLogEntry struct
- [x] Implement JSONAccessLogger
- [x] Implement ApacheCombinedLogger
- [x] Support file output
- [x] Support stdout output

### 7.2 Prometheus Metrics
- [x] Create `internal/metrics/` directory
- [x] Create `prometheus.go`
- [x] Create custom Prometheus registry
- [x] Define proxy_connections_total counter
- [x] Define proxy_connections_active gauge
- [x] Define proxy_connection_errors_total counter
- [x] Define proxy_requests_total counter
- [x] Define proxy_request_duration_seconds histogram
- [x] Define proxy_request_bytes_total counter
- [x] Define proxy_backend_healthy gauge
- [x] Define proxy_backend_latency_seconds gauge
- [x] Define proxy_rate_limit_exceeded_total counter
- [x] Create `collector.go`
- [x] Implement MetricsCollector
- [x] Implement RecordRequest method
- [x] Implement RecordConnection method
- [x] Implement RecordBytes method
- [x] Implement Handler method for /metrics

---

## Phase 8: Server Application

### 8.1 Server Core
- [x] Create `internal/server/` directory
- [x] Create `server.go`
- [x] Define Server struct
- [x] Hold config reference
- [x] Hold backend manager
- [x] Hold router
- [x] Hold rate limiter
- [x] Hold health checker
- [x] Hold authenticator
- [x] Hold metrics collector
- [x] Hold access logger
- [x] Implement New constructor
- [x] Implement Start method
- [x] Initialize all components
- [x] Start HTTP proxy listener
- [x] Start SOCKS5 proxy listener
- [x] Implement Stop method
- [x] Graceful shutdown
- [x] Connection draining
- [x] Stop all components

### 8.2 Server REST API
- [x] Create `internal/api/server/` directory
- [x] Create `server.go`
- [x] Setup Chi router
- [x] Add logging middleware
- [x] Add recovery middleware
- [x] Add CORS middleware
- [x] Add auth middleware (for API)
- [x] Implement GET /api/v1/health
- [x] Implement GET /api/v1/version
- [x] Implement GET /api/v1/status
- [x] Implement GET /api/v1/backends
- [x] Implement GET /api/v1/backends/:name

### 8.3 Server CLI
- [x] Create `cmd/server/main.go`
- [x] Setup Cobra root command
- [x] Implement `start` (default) command
- [x] Implement `validate` command
- [x] Implement `version` command
- [x] Support --config flag

---

## Phase 9: Client Application

### 9.1 Traffic Debugger
- [x] Create `internal/debug/` directory
- [x] Create `entry.go`
- [x] Define TrafficEntry struct
- [x] Create `storage.go`
- [x] Implement ring buffer storage
- [x] Add new entries
- [x] Evict oldest when full
- [x] Query by filters
- [x] Get entry by ID
- [x] Clear all entries
- [x] Create `logger.go`
- [x] Implement DebugLogger
- [x] Log requests
- [x] Log responses
- [x] Apply domain filter

### 9.2 Client Core
- [x] Create `internal/client/` directory
- [x] Create `client.go`
- [x] Define Client struct
- [x] Hold config reference
- [x] Hold client router
- [x] Hold server connection
- [x] Hold traffic debugger
- [x] Implement New constructor
- [x] Implement Start method
- [x] Initialize all components
- [x] Start HTTP proxy listener
- [x] Start SOCKS5 proxy listener
- [x] Implement Stop method
- [x] Graceful shutdown
- [x] Create `backend.go`
- [x] Implement ClientBackend
- [x] Create `server_conn.go`
- [x] Implement server connection

### 9.3 Client REST API
- [x] Create `internal/api/client/` directory
- [x] Create `server.go`
- [x] Setup Chi router
- [x] Add middleware
- [x] Implement GET /api/v1/health
- [x] Implement GET /api/v1/version
- [x] Implement GET /api/v1/status
- [x] Implement GET /api/v1/debug/entries
- [x] Implement GET /api/v1/debug/entries/last/:count
- [x] Implement DELETE /api/v1/debug/entries
- [x] Implement GET /api/v1/debug/errors
- [x] Implement GET /api/v1/routes
- [x] Implement GET /api/v1/routes/test

### 9.4 Client CLI
- [x] Create `cmd/client/main.go`
- [x] Setup Cobra root command
- [x] Implement `start` (default) command
- [x] Implement `validate` command
- [x] Implement `version` command
- [x] Support --config flag

---

## Phase 10: System Tray

### 10.1 Tray Interface
- [x] Create `internal/tray/` directory
- [x] Create `tray.go`
- [x] Define Tray struct
- [x] Define TrayState enum (connected, disconnected, warning, error)
- [x] Implement Start method
- [x] Implement Stop method
- [x] Implement SetState method
- [x] Implement SetConnected method

### 10.2 Tray Implementation
- [x] Use fyne.io/systray library
- [x] Create menu structure
- [x] Add "Status" item
- [x] Add "Open Web UI" item
- [x] Add separator
- [x] Add "Quit" item
- [x] Handle menu item clicks
- [x] Open browser for Web UI

### 10.3 Icons
- [x] Create `icons.go`
- [x] Embed icons using Go embed package

---

## Phase 11: Web Interfaces

### 11.1 Server Web UI
- [x] Create `web/server/` directory
- [x] Setup frontend framework
- [x] Create Dashboard page
- [x] Create Backends page
- [x] Create Rules page
- [x] Create Statistics page
- [x] Create Settings page

### 11.2 Client Web UI
- [x] Create `web/client/` directory
- [x] Setup frontend framework
- [x] Create Dashboard page
- [x] Create Traffic page
- [x] Create Rules page
- [x] Create Settings page

---

## Phase 12: DevOps & Deployment

### 12.1 Docker - Server
- [x] Create `docker/Dockerfile`
- [x] Multi-stage build
- [x] Builder stage with Go
- [x] Runtime stage with Alpine
- [x] Copy binary
- [x] Expose ports 8080, 1080, 9090
- [x] Set entry point
- [x] Create `docker/docker-compose.yml`
- [x] Define server service
- [x] Add config volume mount
- [x] Add health check

### 12.2 Docker - Client
- [x] Create `docker/Dockerfile.client`
- [x] Simpler image without VPN

### 12.3 GitHub Actions - CI
- [x] Create `.github/workflows/ci.yml`
- [x] Trigger on push to main
- [x] Trigger on pull requests
- [x] Add test job
- [x] Run on ubuntu-latest
- [x] Setup Go 1.22
- [x] Download dependencies
- [x] Build
- [x] Run tests with race detector
- [x] Add lint job
- [x] Run golangci-lint

### 12.4 GitHub Actions - Release
- [x] Create `.github/workflows/release.yml`
- [x] Trigger on tag push (v*)
- [x] Use GoReleaser
- [x] Build for linux/amd64
- [x] Build for linux/arm64
- [x] Build for darwin/amd64
- [x] Build for darwin/arm64
- [x] Build for windows/amd64
- [x] Create GitHub release
- [x] Upload binaries
- [x] Generate changelog

### 12.5 GoReleaser
- [x] Create `.goreleaser.yml`
- [x] Configure server build
- [x] Configure client build
- [x] Configure archives (tar.gz, zip)
- [x] Configure checksums
- [x] Configure changelog

### 12.6 Service Files
- [x] Create systemd service for server
- [x] Create systemd service for client
- [x] Create launchd plist for macOS

---

## Phase 13: Testing & Quality

### 13.1 Unit Tests
- [x] Config parsing tests
- [x] Domain matcher tests
- [x] Backend tests with mocks
- [x] Router tests
- [x] Rate limiter tests
- [x] Auth provider tests
- [x] Health checker tests
- [x] All tests pass with `go test ./...`

### 13.2 Integration Tests
- [x] Create integration test build tag
- [x] Backend integration tests
- [x] HTTP proxy end-to-end test
- [x] SOCKS5 proxy end-to-end test
- [x] Auth provider integration tests
- [x] Config reload test

### 13.3 Benchmarks
- [x] Domain matching benchmark
- [x] Connection handling benchmark
- [x] Request forwarding benchmark
- [x] Concurrent connections benchmark

---

## Phase 14: Documentation & Release

### 14.1 README.md
- [x] Add project description
- [x] Add feature list
- [x] Add quick start guide
- [x] Add installation instructions (binary)
- [x] Add installation instructions (Docker)
- [x] Add installation instructions (from source)
- [x] Add basic usage examples
- [x] Add configuration overview
- [x] Add links to documentation

### 14.2 Documentation
- [x] Create Getting Started guide
- [x] Create Server Configuration Reference
- [x] Create Client Configuration Reference
- [x] Create Backend Types Guide
- [x] Create Authentication Guide
- [x] Create API Reference

### 14.3 Example Configs
- [x] Create `configs/server-config.example.yaml`
- [x] Add detailed comments
- [x] Create `configs/client-config.example.yaml`
- [x] Add detailed comments

### 14.4 Contributing
- [x] Create CONTRIBUTING.md
- [x] Document development setup
- [x] Document code style
- [x] Document PR process
- [x] Create issue templates
- [x] Create PR template

### 14.5 Changelog
- [x] Create CHANGELOG.md
- [x] Use Keep a Changelog format
- [x] Document initial release

### 14.6 Release
- [x] Update version in code
- [x] Update CHANGELOG.md
- [x] Create git tag
- [x] Push tag to trigger release
- [x] Verify GitHub release created
- [x] Verify Docker image published

---

## Summary

### Phase Progress
- [x] Phase 1: Project Foundation
- [x] Phase 2: Core Libraries
- [x] Phase 3: Backend System
- [x] Phase 4: Proxy Protocols
- [x] Phase 5: Traffic Management
- [x] Phase 6: Authentication System
- [x] Phase 7: Observability
- [x] Phase 8: Server Application
- [x] Phase 9: Client Application
- [x] Phase 10: System Tray
- [x] Phase 11: Web Interfaces
- [x] Phase 12: DevOps & Deployment
- [x] Phase 13: Testing & Quality
- [x] Phase 14: Documentation & Release

### Milestones
- [x] **MVP**: Server with direct/WireGuard, HTTP/SOCKS5, routing, basic CLI, client
- [x] **v1.0**: All features complete, documentation, CI/CD

---

## Known Issues & Future Improvements

### 1. System Auth on Windows Bug

**Problem**: `internal/auth/system.go` - The `validatePassword` function falls back to `validateWithSu()` on Windows, which uses the Unix `su` command that doesn't exist on Windows. Authentication will silently fail.

- [x] **Phase 1: Immediate Fix - Return explicit error** ✅ COMPLETED
  - [x] Add `case "windows":` to `validatePassword()` switch statement in `internal/auth/system.go`
  - [x] Return `ErrAuthMethodUnsupported` with descriptive message
  - [x] Add test case for Windows platform detection in `internal/auth/auth_test.go`
  - [x] Update `NewSystemAuthenticator()` to log warning on Windows

- [x] **Phase 2: Documentation** ✅ COMPLETED
  - [x] Add warning to `docs/authentication.md` about Windows limitation
  - [x] Add note to `docs/deployment.md` Windows section
  - [x] Add troubleshooting entry in `docs/troubleshooting.md`

- [ ] **Phase 3: Windows API Implementation**
  - [ ] Research `LogonUserW` Win32 API requirements
  - [ ] Create `internal/auth/system_windows.go` with build tags
  - [ ] Implement `validateWindows()` using syscall or CGO
  - [ ] Add Windows-specific tests with mocks
  - [ ] Test on actual Windows system (Windows 10/11 and Server)

---

### 2. Docker Fixes (Uncommitted Changes)

**Problem**: Recent Docker fixes need to be committed.

- [x] **Health Check Fixes** ✅ VERIFIED
  - [x] Verify `docker/Dockerfile` uses `127.0.0.1:7090` (not localhost)
  - [x] Verify `docker/Dockerfile.client` uses `127.0.0.1:7383` (not localhost)
  - [x] Verify comments explain IPv6 resolution issue

- [x] **Client Docker Config** ✅ VERIFIED
  - [x] Verify `configs/client-config.docker.yaml` exists with `0.0.0.0` bindings
  - [x] Verify `Dockerfile.client` copies `client-config.docker.yaml` (not example)
  - [x] Verify server address is `bifrost-server:7080` (Docker DNS)
  - [x] Verify tray is disabled (`enabled: false`) for headless container

- [x] **Docker Compose Updates** ✅ VERIFIED
  - [x] Verify `version: '3.8'` line is removed (deprecated)
  - [x] Verify Grafana port mapping is `3001:3000` (avoids conflicts)

- [x] **Testing** ✅ COMPLETED
  - [x] Run `docker compose build` - verify success
  - [x] Run `docker compose up -d` - verify all containers start
  - [x] Verify health checks pass (all containers show "healthy")
  - [x] Test client can connect to server via Docker network

- [x] **Commit & Push** ✅ COMPLETED
  - [x] Stage: `docker/Dockerfile`, `docker/Dockerfile.client`, `docker/docker-compose.yml`
  - [x] Stage: `configs/client-config.docker.yaml`
  - [x] Create commit with descriptive message
  - [x] Push to remote

---

### 3. Documentation Gaps

- [x] **Document Windows system auth limitation** ✅ COMPLETED
  - [x] **In `docs/authentication.md`**
    - [x] Add "System Authentication" section if missing
    - [x] Add platform support matrix table (Linux ✓, macOS ✓, Windows ✗)
    - [x] Add admonition warning (`!!! warning`) for Windows limitation
    - [x] Document PAM service configuration for Linux
    - [x] Document `dscl` usage on macOS
  - [x] **In `docs/deployment.md`**
    - [x] Add note in Windows section about auth limitations
    - [x] Recommend Native/LDAP/OAuth for Windows deployments
  - [x] **In `docs/troubleshooting.md`**
    - [x] Add "Windows Authentication Issues" section
    - [x] Document error messages and workarounds

- [x] **Update CHANGELOG.md release date** ✅ COMPLETED
  - [x] Decide on version number (0.1.0 vs 1.0.0) → 1.0.0
  - [x] Update placeholder date `2024-XX-XX` to actual release date (2026-01-16)
  - [x] Move "Unreleased" items to versioned section if releasing
  - [x] Add any missing entries for recent changes (Docker fixes, etc.)
  - [x] Update `docs/changelog.md` to match root CHANGELOG.md

---

### 4. VPN Provider Support ✅ COMPLETED

Native support for major VPN providers with full API integration.

- [x] **Core Infrastructure**
  - [x] Provider interface and common types (`internal/vpnprovider/provider.go`)
  - [x] Server caching with TTL (`internal/vpnprovider/cache.go`)
  - [x] Provider-specific errors (`internal/vpnprovider/errors.go`)

- [x] **NordVPN Provider**
  - [x] API client for server list and recommendations
  - [x] WireGuard (NordLynx) and OpenVPN support
  - [x] Backend wrapper (`internal/backend/nordvpn.go`)
  - [x] Web UI form component

- [x] **Mullvad Provider**
  - [x] API client with WireGuard key registration
  - [x] Account number authentication
  - [x] Backend wrapper (`internal/backend/mullvad.go`)
  - [x] Web UI form component

- [x] **PIA (Private Internet Access) Provider**
  - [x] API client with token authentication
  - [x] Port forwarding support
  - [x] Backend wrapper (`internal/backend/pia.go`)
  - [x] Web UI form component

- [x] **ProtonVPN Provider**
  - [x] API client with manual credentials mode
  - [x] Tier-based server filtering (free/basic/plus)
  - [x] Secure Core support
  - [x] Backend wrapper (`internal/backend/protonvpn.go`)
  - [x] Web UI form component

- [x] **Factory Registration**
  - [x] Added nordvpn, mullvad, pia, protonvpn to backend factory

---

### 5. Platform Enhancements

- [ ] **Windows system authentication support (LogonUser API)**
  - [ ] Research Windows LogonUser API requirements
  - [ ] Determine CGO vs syscall approach
  - [ ] Create build-tagged `internal/auth/system_windows.go`
  - [ ] Implement `LogonUserW` call with proper error handling
  - [ ] Handle domain vs local user authentication
  - [ ] Add comprehensive tests with mocks
  - [ ] Test on Windows 10/11 and Windows Server

- [ ] **Platform-specific tray implementations**
  - [ ] Evaluate current `fyne.io/systray` limitations
  - [ ] Research native implementations:
    - [ ] Windows: Win32 `Shell_NotifyIcon` API
    - [ ] macOS: `NSStatusItem` API
    - [ ] Linux: AppIndicator/StatusNotifierItem
  - [ ] Determine if custom implementation provides value over fyne.io/systray
  - [ ] Consider using build tags for platform separation

- [ ] **OAuth authorization code flow**
  - [ ] Research OAuth 2.0 authorization code flow requirements
  - [ ] Design callback server for code exchange
  - [ ] Implement PKCE (Proof Key for Code Exchange) for public clients
  - [ ] Add state parameter for CSRF protection
  - [ ] Store and refresh tokens securely
  - [ ] Add configuration options for redirect URI
  - [ ] Test with common providers (Google, GitHub, Azure AD, Okta)

---

## Security Review - Open Issues (2026-01-16)

Issues identified during deep code review. All CRITICAL, HIGH, and MEDIUM priority items have been fixed.

### Medium Priority - ALL COMPLETED ✅

#### 5. LDAP Context Not Propagated ✅ FIXED
**File:** `internal/auth/ldap.go`

- [x] Pass context to LDAP `DialURL` operation via context-aware dialer
- [x] Pass context to LDAP search operations (checked before dialing)
- [x] Enable proper timeout/cancellation handling

**Fixed:** Added `connectWithContext()` function using `net.Dialer` with context support.

---

#### 6. LDAP Time/Size Limits Not Set ✅ FIXED
**File:** `internal/auth/ldap.go`

- [x] Add `TimeLimit` to search requests (30 seconds)
- [x] Add `SizeLimit` to group queries (100 results)

**Fixed:** Added `ldapSearchTimeLimit`, `ldapSearchSizeLimit`, and `ldapGroupSizeLimit` constants.

---

#### 7. OAuth Tokens Cached in Plaintext ✅ FIXED
**File:** `internal/auth/oauth.go`

- [x] Hash tokens before using as cache keys
- [x] Use `sha256.Sum256()` + `hex.EncodeToString()`

**Fixed:** Added `hashToken()` function, tokens are now hashed before cache storage.

---

#### 8. No Brute Force Protection ✅ FIXED
**File:** `internal/auth/bruteforce.go` (NEW)

- [x] Track failed authentication attempts per IP/username
- [x] Implement exponential backoff or lockout after N failures
- [x] Created `BruteForceProtector` with configurable limits

**Fixed:** New `BruteForceProtector` struct with exponential backoff, window-based tracking, and automatic cleanup.

---

#### 9. WebSocket No Read Timeout ✅ FIXED
**File:** `internal/api/server/websocket.go`

- [x] Add `SetReadDeadline` in `ServeWS` read loop
- [x] Set timeout to 60 seconds (`WebSocketReadTimeout` constant)

**Fixed:** `ws.SetReadDeadline(time.Now().Add(WebSocketReadTimeout))` added before each read.

---

#### 10. WebSocket Broadcast Race Condition ✅ FIXED
**File:** `internal/api/server/websocket.go`

- [x] Collect failed clients in slice while holding RLock
- [x] Send to unregister channel after releasing lock

**Fixed:** Failed clients collected in `var failed []*websocket.Conn` slice, unregister sent after `RUnlock()`.

---

#### 11. Query Parameter Validation Missing ✅ FIXED
**File:** `internal/api/server/server.go`

- [x] Handle `strconv` errors for `limit` parameter
- [x] Handle `strconv` errors for `since` parameter
- [x] Return 400 Bad Request for invalid values

**Fixed:** Proper error handling with descriptive error messages in `handleGetRequests()`.

---

#### 12. Config Reload Error Silently Ignored ✅ FIXED
**File:** `internal/api/server/config_handlers.go`

- [x] Remove `_ = a.reloadConfig()` pattern
- [x] Always handle and return reload errors to caller

**Fixed:** Error logged with `slog.Error()` and included in response as `reloadError`.

---

#### 13. SOCKS5 No Domain Length Validation ✅ FIXED
**File:** `internal/proxy/socks5.go`

- [x] Add basic domain format validation
- [x] Validate characters and structure, not just length

**Fixed:** Added `isValidDomain()` function with RFC 1035 compliant regex validation.

---

#### 14. OpenVPN Temp File Cleanup Not Guaranteed ✅ FIXED
**File:** `internal/backend/openvpn.go`

- [x] Added `cleanupTempFiles()` helper function
- [x] Cleanup called on Start() failure
- [x] Cleanup called in Stop() method

**Fixed:** Temp files now cleaned up on both successful Stop() and Start() failure.

---

### Low Priority

#### 15. LDAP Groups Retrieval Silently Fails ✅ FIXED
**File:** `internal/auth/plugin/ldap/ldap.go`

- [x] Make group lookup failure behavior configurable (fail-open vs fail-closed)

**Fixed:** Added `group_lookup_fail_closed` config option. When true, authentication fails if group lookup fails (fail-closed behavior). Default is false (fail-open, maintains backward compatibility).

---

#### 16. No Audit Logging of Auth Failures ✅ FIXED
**File:** `internal/auth/middleware.go`

- [x] Add structured audit logging for all auth events
- [x] Log username, reason, client IP for failures
- [x] Use `slog.Warn` with consistent fields

**Fixed:** Added `logAuthFailure()` method to middleware that logs authentication failures with client_ip, username, reason, path, method, and error fields.

---

#### 17. Router Potential Nil Dereference ✅ FIXED
**Files:** `internal/router/router.go`, `internal/router/server.go`, `internal/router/client.go`

- [x] Add nil checks before accessing internal state
- [x] Check for nil routes and matchers in Match methods
- [x] Check for nil backendManager in GetBackendForDomain

**Fixed:** Added comprehensive nil checks throughout router package.

---

#### 18. Context Timeout Not Applied in Direct Backend ✅ FIXED
**File:** `internal/backend/direct.go`

- [x] Wrap dial with explicit timeout from context
- [x] Ensure underlying dialer respects context

**Fixed:** Added explicit context deadline check in Dial(). If context has a deadline shorter than configured timeout, creates a new dialer with the shorter timeout. Also checks for context cancellation before dialing.

---

#### 19. IPv6 Address Formatting in SOCKS5 ✅ FIXED
**File:** `internal/proxy/socks5.go`

- [x] Use consistent IPv6 formatting with brackets in error messages/logs

---

#### 20. No Backend Name Validation ✅ FIXED
**File:** `internal/backend/manager.go`

- [x] Validate backend names against regex pattern
- [x] Allow only alphanumeric, hyphens, underscores

**Fixed:** Added `ValidateName()` function and `backendNamePattern` regex. Names must start with alphanumeric and contain only alphanumeric, hyphens, and underscores.

---

#### 21. Hardcoded Timeout in ConnTracker ✅ FIXED
**File:** `internal/vpn/conntrack.go`

- [x] Make idle timeout configurable via ConnTrackerConfig

**Fixed:** Added `ConnTrackerConfig` struct with `IdleTimeout` and `CleanupInterval` fields. `NewConnTrackerWithConfig()` accepts custom configuration. Default values maintained for backward compatibility.

---

## Code Review Findings (2026-01-23)

Comprehensive review of the entire codebase for issues, missing tests, and improvements needed.

### CRITICAL - Go Backend

#### CR-1. File Descriptor Leak in Logging System ✅ FIXED
**File:** `internal/logging/logging.go`
**Confidence:** 90%

- [x] Track opened file descriptors - `currentLogFile` variable added
- [x] Close the previous file descriptor before opening a new one - handled in `Setup()`
- [x] Implement a proper `Close()` method for cleanup - `Close()` method added

**Fixed:** File descriptors are now properly tracked and closed.

---

#### CR-2. Unsafe Type Assertion Can Cause Panic ✅ FIXED
**File:** `internal/server/server.go:705, 795`
**Confidence:** 85%

- [x] Use safe two-value form of type assertion
- [x] Handle non-TCP connections gracefully

**Fixed:** Code already uses safe two-value form `tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)` and handles non-TCP connections by logging and closing.

---

#### CR-3. Context Cancellation Not Propagated on Shutdown ✅ FIXED
**Files:**
- `internal/service/runner_unix.go`
- `internal/service/runner_windows.go`

**Confidence:** 82%

- [x] Use timeout context for Stop(): `context.WithTimeout(context.Background(), ShutdownTimeout)`

**Fixed:** Both Unix and Windows runners use `ShutdownTimeout = 30 * time.Second` with timeout context.

---

#### CR-4. Incomplete Peer Relay Implementation
**File:** `internal/mesh/node.go:856`
**Confidence:** 75%

TODO comment indicates feature is not implemented:
```go
if n.config.Connection.RelayViaPeers {
    n.p2pManager.GetStats() // TODO: Add peer as relay
}
```

- [ ] Implement peer relay functionality, or
- [ ] Remove the config option if not planned for current version

---

#### CR-5. "Quick Hack" in Production Code
**File:** `internal/config/node.go:122`
**Confidence:** 75%

Comment suggests temporary code: "Quick hack: marshal to yaml bytes then unmarshal to node"

- [ ] Replace with proper implementation, or
- [ ] Remove "hack" comment if implementation is actually intentional

---

### CRITICAL - CI/CD Configuration

#### CR-6. Branch Name Mismatch in Workflows ✅ FIXED
**Files:**
- `.github/workflows/ci.yml`
- `.github/workflows/docs.yml`

**Confidence:** 100%

- [x] Update workflows to use `master` branch

**Fixed:** Updated `ci.yml` build-all job condition and `docs.yml` to use `master` branch.

---

#### CR-7. Module Path Inconsistency in golangci.yml ✅ FIXED
**File:** `.golangci.yml:36`
**Confidence:** 100%

- [x] Update to `github.com/rennerdo30/bifrost-proxy`

**Fixed:** Module path was already correct.

---

#### CR-8. Non-existent Go Version Specified ✅ FIXED
**File:** `.github/workflows/ci.yml`
**Confidence:** 82%

- [x] Update CI workflow to use Go 1.23

**Fixed:** CI workflow updated to use `GO_VERSION: '1.23'`.

---

### HIGH PRIORITY - Missing Tests

#### CR-9. No Tests for Service Runners
**Files:**
- `internal/service/runner_unix.go`
- `internal/service/runner_windows.go`

**Confidence:** 95%

Critical service management code (signal handling, Windows Service integration) has no test coverage.

- [ ] Create tests with mocked signal handling
- [ ] Test SIGHUP reload behavior
- [ ] Test SIGINT/SIGTERM shutdown
- [ ] Test Windows Service integration

---

#### CR-10. No Tests for OpenVPN Integration
**Files:**
- `internal/openvpn/config.go` - ParseConfigFile (lines 47-157)
- `internal/openvpn/process.go` - Start, Stop, monitorManagement, parseManagementLine

**Confidence:** 90%

Complex VPN configuration parsing and process management code without tests.

- [ ] Mock `exec.Command` for process tests
- [ ] Test config parsing with various .ovpn formats
- [ ] Test management interface state machine

---

#### CR-11. No Tests for System Proxy
**Files:** `internal/sysproxy/` - All platform-specific files

**Confidence:** 85%

System proxy configuration code has no tests.

- [ ] Mock platform-specific API calls
- [ ] Test SetProxy/ClearProxy on all platforms

---

#### CR-12. No CLI Integration Tests
**Files:** `cmd/server/main.go`, `cmd/client/main.go`

**Confidence:** 80%

- [ ] Test version command
- [ ] Test config init command
- [ ] Test invalid flag combinations

---

### HIGH PRIORITY - Web UI (Server)

#### CR-13. Missing NaN Validation in Number Inputs ✅ FIXED
**Files:**
- `web/server/src/components/Config/sections/CacheSection.tsx:165`
- `web/server/src/components/Config/sections/ServerSection.tsx:91, 185`
- `web/server/src/components/Config/sections/APISection.tsx:77, 99`
- `web/server/src/components/Config/sections/RateLimitSection.tsx:53, 62`

**Confidence:** 90%

`parseInt(e.target.value)` without NaN handling can store `NaN` in state.

- [x] Add fallback: `parseInt(e.target.value) || 0`

---

#### CR-14. Using Browser alert() Instead of Notifications ✅ FIXED
**File:** `web/server/src/pages/Config.tsx:21, 23, 27, 35, 38`
**Confidence:** 85%

- [x] Implement toast notification system (react-hot-toast, sonner, etc.)
- [x] Replace all `alert()` calls

---

#### CR-15. Console Logging in Production ✅ FIXED
**File:** `web/server/src/hooks/useWebSocket.ts:29, 39, 44, 48, 58`
**Confidence:** 90%

- [x] Remove console.log statements, or
- [x] Make conditional: `if (import.meta.env.DEV)`

---

### HIGH PRIORITY - Web UI (Client)

#### CR-16. Missing Error Feedback in Settings ✅ FIXED
**File:** `web/client/src/pages/Settings.tsx:200-201, 215-216`
**Confidence:** 85%

Error handling uses `console.error()` without user-visible feedback.

- [x] Add user-visible error notifications for export/defaults operations

---

#### CR-17. Missing Input Validation in VPN Split Tunnel ✅ FIXED
**File:** `web/client/src/pages/VPN.tsx:310, 341`
**Confidence:** 82%

No client-side validation for domain patterns and IP CIDR inputs.

- [x] Add domain format validation
- [x] Add CIDR notation validation

---

### MEDIUM PRIORITY - Documentation & Config

#### CR-18. Missing Security Workflow
**File:** Missing `.github/workflows/security.yml`
**Confidence:** 90%

CLAUDE.md documents a security workflow with CodeQL but it doesn't exist.

- [x] Create `.github/workflows/security.yml` as documented, or
- [ ] Remove documentation about it

---

#### CR-19. Missing Dependabot Configuration
**File:** Missing `.github/dependabot.yml`
**Confidence:** 85%

CLAUDE.md requires "Regular dependency updates via Dependabot" but no config exists.

- [x] Create `.github/dependabot.yml` for gomod and npm

---

#### CR-20. Outdated Repository URLs in Documentation
**Files:**
- `docs/getting-started.md:14, 18, 22, 29`
- `docs/authentication.md:45`
- `deploy/systemd/*.service:3`

**Confidence:** 100%

References old `github.com/bifrost-proxy/bifrost` instead of `github.com/rennerdo30/bifrost-proxy`.

- [ ] Update all URLs to current repository

---

#### CR-21. Missing Node.js Setup in CI Build
**File:** `.github/workflows/ci.yml:53-72`
**Confidence:** 85%

CI build job runs `make build` which needs Node.js for web UI, but Node.js isn't installed.

- [ ] Add Node.js setup step before build

---

### MEDIUM PRIORITY - Accessibility

#### CR-22. Missing aria-label on Icon Buttons
**Files:**
- `web/server/src/components/Config/Modal.tsx:57-64`
- `web/server/src/components/Config/ArrayInput.tsx:35-43`
- `web/server/src/components/Config/sections/APISection.tsx:53-68`
- `web/client/src/pages/Traffic.tsx:47-52`
- `web/client/src/pages/Logs.tsx:138-148`

**Confidence:** 85%

- [x] Add `aria-label` to all icon-only buttons

---

#### CR-23. Password Fields Missing autocomplete
**Files:**
- `web/server/src/components/Config/sections/APISection.tsx:46-52`
- `web/server/src/components/Config/backend-forms/OpenVPNBackendForm.tsx:240`

**Confidence:** 80%

- [x] Add `autoComplete="off"` or `autoComplete="new-password"`

---

### LOW PRIORITY - Test Coverage Improvements

#### CR-24. Load Balancer Edge Cases
**File:** `internal/router/loadbalancer.go`

- [ ] Test counter overflow scenarios
- [ ] Test zero weights
- [ ] Test IPv6 addresses
- [ ] Test dynamic health state changes

---

#### CR-25. Server Startup Error Injection Tests
**File:** `internal/server/server.go`

- [ ] Test backend startup failures
- [ ] Test cache manager failures
- [ ] Test health manager failures

---

#### CR-26. Platform-Specific Test Mocks
**Files:**
- `internal/vpn/routes_*.go`
- `internal/vpn/process_*.go`
- `internal/device/tun_*.go`
- `internal/device/tap_*.go`

- [ ] Add cross-platform test mocks

---

### LOW PRIORITY - Documentation Consistency

#### CR-27. Inconsistent Binary Naming
**Files:** CLAUDE.md, SPECIFICATION.md

Documentation uses both `simple-proxy-server/client` and `bifrost-server/client` inconsistently.

- [ ] Standardize on `bifrost-*` naming throughout

---

#### CR-28. CLAUDE.md Contains Placeholder Content
**File:** CLAUDE.md:59-66, 484-486, 607

- [x] Replace placeholder names like `github.com/yourorg/simple-proxy-server`

---

### LOW PRIORITY - Minor Code Improvements

#### CR-29. Potential EventSource Memory Leak
**File:** `web/client/src/pages/Logs.tsx:22-52`

- [x] Ensure EventSource cleanup happens in all cases

---

#### CR-30. Type Safety Improvements ✅ FIXED
**File:** `web/server/src/components/Config/backend-forms/WireGuardBackendForm.tsx`

- [x] Consider creating proper typed interfaces for each backend config type

---

#### CR-31. Inconsistent Form Validation Patterns ✅ FIXED

- [x] Standardize validation approach across all config sections

---

## Code Review Summary

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Go Backend | 5 | 1 | 0 | 0 |
| Tests | 0 | 4 | 0 | 3 |
| Web UI | 0 | 4 | 2 | 3 |
| CI/CD & Docs | 3 | 0 | 4 | 2 |
| **Total** | **8** | **9** | **6** | **8** |

**Total New Issues:** 31

---

### Completed Security Fixes (Reference)

The following issues from the security review have been fixed:

**CRITICAL (6/6):**
- [x] Timing attack on API token comparison → `crypto/subtle.ConstantTimeCompare()`
- [x] Ignored write errors in HTTP/SOCKS5 → Error logging with `log/slog`
- [x] Ignored I/O errors in SOCKS5Proxy backend → Proper error handling
- [x] CopyBidirectional return value race → Both results collected
- [x] WebSocket endpoint unauthenticated → Inside auth group
- [x] CORS wildcard origin → Restricted to localhost via `isLocalOrigin()`

**HIGH (6/6):**
- [x] WireGuard resource leak → Direct dial without intermediate connection
- [x] HTTP proxy response body leak → `defer resp.Body.Close()`
- [x] Copy timeout busy loop → Clean goroutine/channel with `io.Copy()`
- [x] OpenVPN monitor race → Lock captured before process check
- [x] OAuth unbounded read → `io.LimitReader` with 1MB limit

**MEDIUM (13/13) - ALL COMPLETED:**
- [x] Security headers → Full middleware with CSP, X-Frame-Options, etc.
- [x] WebSocket connection limit → `MaxWebSocketClients = 100`
- [x] Bcrypt cost → Increased to 12
- [x] LDAP context propagation → `connectWithContext()` with `net.Dialer`
- [x] LDAP time/size limits → 30s timeout, 100/1000 size limits
- [x] OAuth token hashing → `hashToken()` with SHA-256
- [x] Brute force protection → New `BruteForceProtector` with exponential backoff
- [x] WebSocket read timeout → 60 second `SetReadDeadline`
- [x] WebSocket broadcast race → Failed clients collected before unregister
- [x] Query parameter validation → Proper error handling with 400 responses
- [x] Config reload error handling → Logged and returned in response
- [x] SOCKS5 domain validation → RFC 1035 compliant regex
- [x] OpenVPN temp file cleanup → `cleanupTempFiles()` on failure and stop
