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
