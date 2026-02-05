# PRD: Bifrost Proxy - Complete Issue Resolution

## Overview
This PRD addresses all identified issues across the Bifrost Proxy codebase, including backend error handling, frontend UX improvements, mobile app fixes, desktop app enhancements, API completeness, and comprehensive documentation. The goal is to bring the entire project to production-ready quality with no incomplete features, no ignored errors, and full documentation coverage.

## Goals
- Eliminate all ignored errors in Go backend code with appropriate logging
- Complete all unfinished UI features across web, mobile, and desktop
- Achieve full accessibility compliance with screen reader testing
- Implement all missing API client methods with corresponding UIs
- Create comprehensive documentation for all features
- Ensure consistent API naming and behavior across all clients

## Quality Gates

These commands must pass for every user story:
- `make test` - All tests passing
- `make lint` - Linting passes (golangci-lint for Go, eslint for JS/TS)

For frontend stories, also include:
- `cd web/server && npm run build` - Server UI builds
- `cd web/client && npm run build` - Client UI builds
- `cd desktop/frontend && npm run build` - Desktop UI builds (when applicable)

## User Stories

### Epic 1: Go Backend Error Handling

---

### US-001: Fix ignored errors in proxy/copy.go
As a developer, I want all errors in the copy module properly handled so that connection issues are logged appropriately.

**Acceptance Criteria:**
- [ ] `CloseWrite()` errors at lines 22, 32 logged at debug level (expected during teardown)
- [ ] `SetReadDeadline/SetWriteDeadline` errors at lines 66-67 logged at debug level
- [ ] Add context to error messages indicating the operation that failed

---

### US-002: Fix ignored errors in P2P module
As a developer, I want all P2P networking errors properly handled so that connectivity issues can be diagnosed.

**Acceptance Criteria:**
- [ ] `internal/p2p/turn.go` - All `SetDeadline()` errors logged at debug level
- [ ] `internal/p2p/stun.go` - All `SetDeadline()` errors logged at debug level
- [ ] `internal/p2p/ice.go` - All `SetDeadline()` errors logged at debug level
- [ ] `internal/p2p/connection.go` - All `SetDeadline()` errors logged at debug level
- [ ] `internal/p2p/manager.go` - All `SetDeadline()` errors logged at debug level
- [ ] Unexpected errors (non-timeout) logged at warn level

---

### US-003: Fix cache recovery error handling
As a developer, I want cache recovery errors logged so that disk cache issues are visible.

**Acceptance Criteria:**
- [ ] `internal/cache/disk.go:560` - Log cache entry recovery failures at warn level
- [ ] `internal/cache/disk.go:574` - Log cache metadata read failures at warn level
- [ ] `internal/cache/disk.go:579` - Log cache data read failures at warn level
- [ ] Include file path in error context for debugging

---

### US-004: Fix VPN and OpenVPN error handling
As a developer, I want VPN-related errors properly logged so that tunnel issues can be diagnosed.

**Acceptance Criteria:**
- [ ] `internal/vpn/udp.go:248` - `SetReadDeadline` error logged at debug level
- [ ] `internal/openvpn/process.go:223` - `SetReadDeadline` error logged at debug level
- [ ] Add connection context (remote address, tunnel name) to log messages

---

### Epic 2: Web Client UI Completion

---

### US-005: Implement route management in client Settings
As a user, I want to manage proxy routes in the client settings so that I can control traffic routing.

**Acceptance Criteria:**
- [ ] Remove "coming soon" placeholder from `web/client/src/pages/Settings.tsx:583`
- [ ] Create RouteManager component with list view of all routes
- [ ] Implement add route dialog with domain pattern, backend, and priority fields
- [ ] Implement edit route functionality with inline or modal editing
- [ ] Implement delete route with confirmation dialog
- [ ] Add import routes from file (JSON/YAML format)
- [ ] Add export routes to file functionality
- [ ] Add route testing tool (test if domain matches route)
- [ ] Show route match statistics (hit count, last matched)

---

### US-006: Implement Cache management UI for client
As a user, I want to manage the response cache so that I can view cached items and clear cache when needed.

**Acceptance Criteria:**
- [ ] Add Cache page/section to client web UI
- [ ] Display cache statistics (size, item count, hit rate)
- [ ] List cached entries with URL, size, age, TTL
- [ ] Implement search/filter for cached items
- [ ] Add clear single item functionality
- [ ] Add clear all cache functionality
- [ ] Add cache settings (max size, TTL defaults)

---

### US-007: Implement Mesh networking UI for client
As a user, I want to view and manage mesh network connections so that I can see peer connectivity status.

**Acceptance Criteria:**
- [ ] Add Mesh page/section to client web UI
- [ ] Display mesh network status (enabled/disabled, peer count)
- [ ] List connected peers with status, latency, bandwidth
- [ ] Show mesh topology visualization (network graph)
- [ ] Add/remove peer connections manually
- [ ] Display mesh routing table
- [ ] Show mesh traffic statistics

---

### Epic 3: Web Server UI Completion

---

### US-008: Add missing backend API methods to server client
As a developer, I want complete API client coverage so that all backend operations are available in the UI.

**Acceptance Criteria:**
- [ ] Add `addBackend(config)` method to `web/server/src/api/client.ts`
- [ ] Add `removeBackend(name)` method to API client
- [ ] Add `testBackend(name)` method to API client
- [ ] Update TypeScript types for backend configuration
- [ ] Add proper error handling for each new method

---

### US-009: Implement backend add/edit UI
As an admin, I want to add and edit backends through the UI so that I can manage proxy backends without editing config files.

**Acceptance Criteria:**
- [ ] Add "Add Backend" button to Backends page
- [ ] Create AddBackendDialog with form for all backend types (direct, wireguard, openvpn, httpproxy, socks5)
- [ ] Dynamic form fields based on selected backend type
- [ ] Implement edit backend functionality
- [ ] Add backend test button with result feedback
- [ ] Form validation for required fields
- [ ] Show success/error toast on operations

---

### US-010: Implement Cache management UI for server
As an admin, I want to manage the server-side cache so that I can monitor and control caching behavior.

**Acceptance Criteria:**
- [ ] Add Cache page to server web UI navigation
- [ ] Implement cache API client methods (stats, list, clear, delete)
- [ ] Display cache statistics dashboard (memory/disk usage, hit rates)
- [ ] List cached responses with filtering and search
- [ ] Implement cache invalidation by pattern
- [ ] Add cache configuration UI (size limits, TTL settings)

---

### US-011: Implement Mesh management UI for server
As an admin, I want to manage mesh networking from the server UI so that I can configure and monitor P2P connectivity.

**Acceptance Criteria:**
- [ ] Add Mesh page to server web UI navigation
- [ ] Implement mesh API client methods
- [ ] Display mesh network overview (nodes, connections, health)
- [ ] Visualize mesh topology with interactive graph
- [ ] Show peer details on selection (latency, throughput, routes)
- [ ] Add mesh configuration settings
- [ ] Display mesh event log

---

### US-012: Fix Modal accessibility in server UI
As a user with accessibility needs, I want modals to be properly accessible so that screen readers work correctly.

**Acceptance Criteria:**
- [ ] Add `aria-hidden="true"` to SVG close icon in `web/server/src/components/Config/Modal.tsx:62-64`
- [ ] Verify focus trap works correctly
- [ ] Ensure escape key closes modal
- [ ] Add proper ARIA labels to all modal elements

---

### Epic 4: Mobile App Fixes

---

### US-013: Replace hardcoded values with dynamic data
As a mobile user, I want to see actual server information so that I know which server I'm connected to.

**Acceptance Criteria:**
- [ ] Replace "Primary Server" hardcoded text at `HomeScreen.tsx:172` with actual server name from API
- [ ] Replace "vpn.bifrost.io:8080" at `HomeScreen.tsx:173` with actual server address
- [ ] Make API base URL configurable in `api.ts:11` instead of hardcoded localhost
- [ ] Add server URL configuration in Settings screen
- [ ] Store configured server URL in AsyncStorage
- [ ] Handle connection errors gracefully when server URL is invalid

---

### US-014: Implement split tunneling configuration
As a mobile user, I want to configure split tunneling so that I can control which apps use the proxy.

**Acceptance Criteria:**
- [ ] Replace toast-only "Configure" button at `SettingsScreen.tsx:216-222` with actual functionality
- [ ] Create SplitTunnelingScreen with list of installed apps
- [ ] Allow toggling apps to include/exclude from proxy
- [ ] Add domain-based split tunneling rules
- [ ] Save configuration to device storage
- [ ] Apply split tunneling rules when VPN connects

---

### US-015: Complete mobile accessibility audit
As a user with accessibility needs, I want the mobile app to be fully accessible with screen readers.

**Acceptance Criteria:**
- [ ] Add `accessibilityLabel` and `accessibilityRole` to StatusCard component
- [ ] Add accessibility labels to tab bar icons in RootNavigator (replace emoji with proper icons + labels)
- [ ] Add `accessibilityRole="button"` to server list items in ServersScreen
- [ ] Add accessibility labels to all interactive elements
- [ ] Test with VoiceOver (iOS) and document findings
- [ ] Test with TalkBack (Android) and document findings
- [ ] Fix any issues found during screen reader testing

---

### US-016: Fix mobile data refresh behavior
As a mobile user, I want pull-to-refresh to reliably update data so that I see current information.

**Acceptance Criteria:**
- [ ] Replace `invalidateQueries()` with `refetchQueries()` at `HomeScreen.tsx:58-62`
- [ ] Add loading indicator during refresh
- [ ] Show error toast if refresh fails
- [ ] Implement exponential backoff for failed refreshes

---

### Epic 5: Desktop App Enhancements

---

### US-017: Implement multi-server management
As a desktop user, I want to manage multiple proxy servers so that I can switch between different configurations.

**Acceptance Criteria:**
- [ ] Update `desktop/app.go` to support multiple servers from config
- [ ] Create ServerManager component with list of configured servers
- [ ] Implement add server dialog (name, address, auth settings)
- [ ] Implement edit server functionality
- [ ] Implement delete server with confirmation
- [ ] Add quick-switch server dropdown in main UI
- [ ] Persist server list to configuration file
- [ ] Show connection status per server

---

### US-018: Implement Toast notification system
As a desktop user, I want toast notifications so that I receive feedback on actions and events.

**Acceptance Criteria:**
- [ ] Create Toast component with success, error, warning, info variants
- [ ] Create ToastProvider context for app-wide toast management
- [ ] Add toast animations (slide in/out)
- [ ] Implement auto-dismiss with configurable duration
- [ ] Add manual dismiss button
- [ ] Queue multiple toasts properly
- [ ] Respect user's notification preference setting

---

### US-019: Add loading states to desktop components
As a desktop user, I want loading indicators so that I know when data is being fetched.

**Acceptance Criteria:**
- [ ] Add skeleton loader to StatusIndicator component (like QuickSettings has)
- [ ] Add loading state to ServerSelector during server switching
- [ ] Add loading feedback to VPN toggle at `QuickSettings.tsx:155-160`
- [ ] Show spinner or progress indicator during connection changes

---

### US-020: Fix desktop accessibility issues
As a user with accessibility needs, I want the desktop app to be fully accessible.

**Acceptance Criteria:**
- [ ] Add `aria-hidden="true"` to logo SVG in `App.tsx:37-39`
- [ ] Add `aria-hidden="true"` to decorative SVGs in `StatusIndicator.tsx:55,61,67`
- [ ] Add proper ARIA labels to all interactive elements
- [ ] Ensure keyboard navigation works throughout the app
- [ ] Test with screen reader and document findings

---

### US-021: Fix ServerSelector null reference
As a developer, I want the ServerSelector to handle empty server lists so that the app doesn't crash.

**Acceptance Criteria:**
- [ ] Add null/empty check at `ServerSelector.tsx:28`
- [ ] Show "No servers configured" message when list is empty
- [ ] Add "Add Server" button when no servers exist
- [ ] Handle edge case of selected server being removed

---

### US-022: Implement Error Boundaries
As a desktop user, I want the app to handle errors gracefully so that crashes don't lose my work.

**Acceptance Criteria:**
- [ ] Create ErrorBoundary component with fallback UI
- [ ] Wrap main app sections in error boundaries
- [ ] Show user-friendly error message with retry option
- [ ] Log errors for debugging
- [ ] Add "Report Issue" link in error UI

---

### Epic 6: API Consistency

---

### US-023: Fix API type naming inconsistencies
As a developer, I want consistent API naming so that client integrations are straightforward.

**Acceptance Criteria:**
- [ ] Standardize VersionInfo field to `git_commit` across all APIs (or `commit` - pick one)
- [ ] Update server API response
- [ ] Update client API response
- [ ] Update all TypeScript types to match
- [ ] Update all Go structs to match
- [ ] Add API versioning documentation

---

### Epic 7: Comprehensive Documentation

---

### US-024: Fix broken documentation links
As a user, I want documentation links to work so that I can find information easily.

**Acceptance Criteria:**
- [ ] Fix `README.md:121-125` links to point to correct `docs/src/content/docs/*.mdx` paths
- [ ] Fix broken file:// URL in `SPECIFICATION.md:1277`
- [ ] Audit all documentation for broken links
- [ ] Add link checking to CI/CD pipeline

---

### US-025: Document P2P/Relay networking
As a developer, I want P2P networking documented so that I can understand and extend mesh functionality.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/features/mesh-networking.mdx`
- [ ] Document STUN/TURN/ICE implementation in `internal/p2p/`
- [ ] Add architecture diagram using Mermaid
- [ ] Document peer discovery and connection flow
- [ ] Add configuration examples
- [ ] Document troubleshooting common P2P issues
- [ ] Add interactive examples where applicable

---

### US-026: Document traffic debugging system
As a developer, I want traffic debugging documented so that I can use and extend the debugging features.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/features/traffic-debugging.mdx`
- [ ] Document `internal/debug/` module architecture
- [ ] Explain capture modes and filtering
- [ ] Add examples of common debugging scenarios
- [ ] Document WebSocket streaming for real-time inspection
- [ ] Add Mermaid diagrams for data flow

---

### US-027: Document frame processing system
As a developer, I want frame processing documented so that I can understand the packet handling pipeline.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/internals/frame-processing.mdx`
- [ ] Document `internal/frame/` module
- [ ] Explain frame types and structure
- [ ] Add Mermaid diagrams for frame flow
- [ ] Document extension points for custom frame handlers

---

### US-028: Document system proxy integration
As a user, I want system proxy integration documented so that I can configure OS-level proxy settings.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/features/system-proxy.mdx`
- [ ] Document `internal/sysproxy/` module
- [ ] Add platform-specific instructions (Windows, macOS, Linux)
- [ ] Document automatic proxy configuration
- [ ] Add troubleshooting section for common issues
- [ ] Include screenshots or diagrams for each platform

---

### US-029: Document auto-update system
As a user, I want auto-update documented so that I understand how updates are delivered.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/features/auto-update.mdx`
- [ ] Document `internal/updater/` module
- [ ] Explain update channels (stable, beta, nightly)
- [ ] Document update verification and rollback
- [ ] Add configuration options
- [ ] Document self-update process for each platform

---

### US-030: Document advanced authentication plugins
As an admin, I want authentication plugins documented so that I can configure enterprise auth.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/configuration/authentication.mdx`
- [ ] Document Kerberos authentication setup and configuration
- [ ] Document NTLM authentication setup and configuration
- [ ] Document mTLS (mutual TLS) configuration
- [ ] Document SPNEGO authentication setup
- [ ] Add integration examples for each auth type
- [ ] Include Mermaid diagrams for auth flows
- [ ] Add troubleshooting section for each auth method

---

### US-031: Document health check overrides
As an admin, I want health check overrides documented so that I can customize backend health monitoring.

**Acceptance Criteria:**
- [ ] Create section in `docs/src/content/docs/configuration/backends.mdx` for health overrides
- [ ] Document `internal/backend/health_override.go` functionality
- [ ] Add configuration examples
- [ ] Explain health check intervals and thresholds
- [ ] Document custom health check endpoints

---

### US-032: Document client CLI commands
As a user, I want CLI commands documented so that I can use the client effectively from terminal.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/usage/cli-reference.mdx`
- [ ] Document all client CLI commands and flags
- [ ] Add usage examples for common operations
- [ ] Document environment variables
- [ ] Add shell completion instructions
- [ ] Include man page generation if applicable

---

### US-033: Create API reference documentation
As a developer, I want complete API documentation so that I can integrate with Bifrost programmatically.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/api/` section
- [ ] Document all server REST API endpoints with request/response examples
- [ ] Document all client REST API endpoints with request/response examples
- [ ] Document WebSocket APIs (real-time events, traffic streaming)
- [ ] Add OpenAPI/Swagger spec generation
- [ ] Include authentication requirements for each endpoint
- [ ] Add rate limiting documentation

---

### US-034: Create troubleshooting guide
As a user, I want a troubleshooting guide so that I can resolve common issues myself.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/troubleshooting/` section
- [ ] Document common connection issues and solutions
- [ ] Document performance troubleshooting
- [ ] Document authentication troubleshooting
- [ ] Document VPN/tunnel troubleshooting
- [ ] Add diagnostic commands and log analysis
- [ ] Include FAQ section

---

### US-035: Add architecture documentation with diagrams
As a developer, I want architecture documentation so that I can understand the system design.

**Acceptance Criteria:**
- [ ] Create `docs/src/content/docs/internals/architecture.mdx`
- [ ] Add high-level system architecture diagram (Mermaid)
- [ ] Document component interactions
- [ ] Add data flow diagrams for key operations
- [ ] Document threading/concurrency model
- [ ] Add module dependency diagram
- [ ] Document extension points and plugin architecture

---

## Functional Requirements

- FR-1: All ignored Go errors must be logged at appropriate levels (debug for expected, warn for unexpected)
- FR-2: All web UIs must have complete CRUD operations for their respective resources
- FR-3: Mobile app must fetch and display real server information from API
- FR-4: Desktop app must support multiple server configurations
- FR-5: All interactive elements must have proper accessibility attributes
- FR-6: API naming must be consistent across server and client
- FR-7: All features must be documented with examples and diagrams
- FR-8: Documentation must use Mermaid for all diagrams
- FR-9: Route management must support import/export functionality
- FR-10: Cache and Mesh UIs must be available in both server and client web interfaces

## Non-Goals

- Mobile app native code changes (staying in React Native)
- Breaking API changes (maintain backwards compatibility)
- Redesigning existing UI layouts (only adding missing functionality)
- Adding new backend types (only documenting existing ones)
- Performance optimization (separate effort)
- Internationalization/localization (future enhancement)

## Technical Considerations

- Error logging should use structured logging with `log/slog`
- Frontend components should follow existing patterns in each codebase
- Mobile accessibility must work with both VoiceOver and TalkBack
- Desktop app uses Wails v2 for Go/JS bridge
- Documentation uses Astro/Starlight and must build successfully
- All new API endpoints must include TypeScript types

## Success Metrics

- Zero ignored errors in `golangci-lint` output
- All web UI pages fully functional (no "coming soon" placeholders)
- Mobile app shows real server data, not hardcoded values
- Desktop app supports at least 5 configured servers
- Screen reader testing completed for mobile and desktop
- 100% of features documented with examples
- All documentation links resolve correctly
- API client coverage matches backend endpoints

## Open Questions

- Should we add E2E tests for the new UI features?
- What is the preferred icon library for mobile (to replace emoji tab icons)?
- Should mesh topology visualization use a specific graph library (D3, vis.js, etc.)?
- Are there specific enterprise auth environments available for testing Kerberos/NTLM?