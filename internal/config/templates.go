package config

// DefaultClientConfigTemplate is the fully commented default configuration for the client.
const DefaultClientConfigTemplate = `# Bifrost Client Configuration
# This file contains the configuration for the Bifrost proxy client.

# Local proxy settings
# Define the local listeners for HTTP and SOCKS5 proxies.
proxy:
  http:
    listen: "127.0.0.1:7380"     # Address to listen on for HTTP proxy
    read_timeout: "30s"          # Max time to read the entire request
    write_timeout: "30s"         # Max time to write the response
    idle_timeout: "60s"          # Max time to wait for the next request
  socks5:
    listen: "127.0.0.1:7381"     # Address to listen on for SOCKS5 proxy

# Bifrost server connection
# Settings for connecting to the upstream Bifrost server.
server:
  address: "proxy.example.com:7080" # Address of the Bifrost server
  protocol: http                    # Protocol to use (http or socks5)
  # username: "user"                # Authentication username (optional)
  # password: "pass"                # Authentication password (optional)
  timeout: "30s"                    # Connection timeout
  retry_count: 3                    # Number of retries on connection failure
  retry_delay: "1s"                 # Delay between retries

# Client-side routing rules
# Determine how traffic is routed based on domains.
routes:
  # Direct connection for local addresses (bypass server)
  - domains:
      - "localhost"
      - "127.0.0.1"
      - "*.local"
    action: direct
    priority: 100

  # Direct connection for specific domains
  - domains:
      - "*.example.com"
    action: direct
    priority: 50

  # Everything else through the server
  - domains:
      - "*"
    action: server
    priority: 1

# Traffic debugging
# Capture and inspect traffic for debugging purposes.
debug:
  enabled: true             # Enable traffic capture
  max_entries: 1000         # Maximum number of entries to keep in memory
  capture_body: false       # Capture request/response bodies (warning: high memory usage)
  max_body_size: 65536      # 64KB - Max body size to capture if capture_body is true
  # filter_domains:         # Only capture traffic for these domains (optional)
  #   - "*.example.com"

# Application logging
# Configure how the application logs events.
logging:
  level: info               # Log level (debug, info, warn, error)
  format: text              # Log format (text or json)
  output: stdout            # Output destination (stdout, stderr, file)

# Web UI (local dashboard)
# Settings for the local web interface.
web_ui:
  enabled: true             # Enable the web UI
  listen: "127.0.0.1:7382"  # Address to listen on for the web UI

# REST API
# Settings for the local REST API (used by Web UI and CLI).
api:
  enabled: true             # Enable the API
  listen: "127.0.0.1:7383"  # Address to listen on for the API
  # token: "your-api-token" # API authentication token (optional)

# System tray
# Settings for the system tray icon (Desktop only).
tray:
  enabled: true             # Show system tray icon
  start_minimized: false    # Start application minimized to tray
  show_quick_gui: true      # Show quick settings on tray icon click
  auto_connect: false       # Connect to server automatically on startup
  show_notifications: true  # Show desktop notifications for events

# Auto-Update
# Settings for automatic application updates.
auto_update:
  enabled: false            # Enable automatic updates
  check_interval: "24h"     # How often to check for updates
  channel: "stable"         # Update channel (stable, beta, nightly)

# VPN Mode
# Settings for system-wide VPN (TUN device).
vpn:
  enabled: false            # Enable VPN mode
  tun:
    name: "bifrost0"        # Name of the TUN interface
    address: "10.255.0.2/24" # IP address for the TUN interface
    mtu: 1500               # MTU for the TUN interface
  split_tunnel:
    mode: "exclude"         # Split tunnel mode (exclude or include)
    # apps:                 # List of applications to exclude/include (by process name)
    #   - name: "chrome"
    # domains:              # List of domains to exclude/include
    #   - "netflix.com"
    # ips:                  # List of IP CIDRs to exclude/include
    #   - "192.168.1.0/24"

# Mesh Network (Experimental)
# Settings for P2P mesh networking.
mesh:
  enabled: false            # Enable mesh networking
  # network_id: "my-mesh"   # Unique ID for the mesh network
  # peer_name: "my-device"  # Name of this device in the mesh
`

// DefaultServerConfigTemplate is the fully commented default configuration for the server.
const DefaultServerConfigTemplate = `# Bifrost Server Configuration
# This file contains the configuration for the Bifrost proxy server.

server:
  http:
    listen: ":7080"           # Address to listen on for HTTP connections
    read_timeout: "30s"       # timeout for reading the entire request
    write_timeout: "30s"      # timeout for writing the response
    idle_timeout: "60s"       # timeout for keep-alive connections
  socks5:
    listen: ":7180"           # Address to listen on for SOCKS5 connections
  graceful_period: "30s"      # Time to wait for active connections to finish on shutdown

# Backend definitions
# Backends are upstream proxy servers or tunnels (WireGuard, Direct, etc.)
backends:
  # Direct connection (no tunnel)
  - name: direct
    type: direct
    enabled: true
    priority: 10

  # WireGuard tunnel example
  # - name: wg-tunnel
  #   type: wireguard
  #   enabled: true
  #   priority: 20
  #   config:
  #     private_key: "YOUR_PRIVATE_KEY_BASE64"
  #     address: "10.0.0.2/24"
  #     dns: ["1.1.1.1"]
  #     mtu: 1420
  #     peer:
  #       public_key: "PEER_PUBLIC_KEY_BASE64"
  #       endpoint: "vpn.example.com:51820"
  #       allowed_ips: ["0.0.0.0/0"]
  #       persistent_keepalive: 25

# Routing rules
# Determine which backend to use based on domain matching.
routes:
  # Default route - all traffic through the direct backend
  - domains: ["*"]
    backend: direct
    priority: 1

# Authentication settings
auth:
  mode: none                  # Auth mode (none, native, system, ldap, oauth)

# Rate limiting
# Control the flow of incoming requests.
rate_limit:
  enabled: false              # Enable rate limiting
  requests_per_second: 100    # Sustained rate limit
  burst_size: 200             # Maximum burst size
  per_ip: true                # Rate limit per IP address
  per_user: false             # Rate limit per authenticated user

# Access logging
# Log all connections handled by the server.
access_log:
  enabled: true               # Enable access logging
  format: json                # Log format (json, apache)
  output: stdout              # Output destination (stdout, stderr, or file path)

# Metrics
# Expose server metrics in Prometheus format.
metrics:
  enabled: true               # Enable metrics collection
  listen: ":7090"             # Address to listen on for metrics scraper
  path: "/metrics"            # URL path for metrics

# Application logging
# Configure server's own diagnostic logs.
logging:
  level: info                 # Log level (debug, info, warn, error)
  format: text                # Log format (json, text)
  output: stdout              # Output destination

# Web UI (Management interface)
web_ui:
  enabled: false              # Enable management dashboard
  listen: ":7081"             # Address to listen on for the Web UI

# REST API
# Programmatic management of the server.
api:
  enabled: true               # Enable REST API
  listen: ":7082"             # Address to listen on for the API
  # token: "your-api-token"   # Optional API authentication token
`
