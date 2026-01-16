# Deployment Guide

This guide covers deploying Bifrost in production environments using Docker, systemd (Linux), and launchd (macOS).

## Docker Deployment

### Quick Start with Docker Compose

The easiest way to deploy Bifrost is using Docker Compose:

```bash
cd docker
docker-compose up -d
```

This starts:

| Service | Port | Description |
|---------|------|-------------|
| bifrost-server | 8080 | HTTP proxy |
| bifrost-server | 1080 | SOCKS5 proxy |
| bifrost-server | 8081 | Web UI |
| bifrost-server | 8082 | REST API |
| bifrost-server | 9090 | Prometheus metrics |
| bifrost-client | 3128 | Local HTTP proxy |
| bifrost-client | 1081 | Local SOCKS5 proxy |
| prometheus | 9091 | Metrics collection |
| grafana | 3000 | Dashboards |

### Docker Compose Configuration

```yaml
version: '3.8'

services:
  bifrost-server:
    image: bifrost-server:latest
    container_name: bifrost-server
    restart: unless-stopped
    ports:
      - "8080:8080"   # HTTP proxy
      - "1080:1080"   # SOCKS5 proxy
      - "9090:9090"   # Metrics
      - "8081:8081"   # Web UI
      - "8082:8082"   # API
    volumes:
      - bifrost-data:/app/data
      - bifrost-logs:/var/log/bifrost
    environment:
      - TZ=UTC
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:9090/metrics"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  bifrost-data:
  bifrost-logs:
```

### Building Docker Images

```bash
# Build server image
docker build -t bifrost-server:latest -f docker/Dockerfile .

# Build client image
docker build -t bifrost-client:latest -f docker/Dockerfile.client .
```

### Custom Configuration

Mount your own config file:

```yaml
volumes:
  - ./my-config.yaml:/app/data/config.yaml
```

### Environment Variables

Pass configuration via environment variables:

```yaml
environment:
  - BIFROST_LOG_LEVEL=debug
  - BIFROST_API_TOKEN=your-secret-token
```

### Docker Commands

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f bifrost-server

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up -d --build

# Check status
docker-compose ps
```

---

## Linux (systemd)

### Prerequisites

1. Create the bifrost user and group:

```bash
sudo useradd -r -s /sbin/nologin bifrost
```

2. Create directories:

```bash
sudo mkdir -p /etc/bifrost
sudo mkdir -p /var/log/bifrost
sudo chown bifrost:bifrost /var/log/bifrost
```

3. Install the binary:

```bash
sudo cp bin/bifrost-server /usr/local/bin/
sudo chmod +x /usr/local/bin/bifrost-server
```

4. Copy your configuration:

```bash
sudo cp server-config.yaml /etc/bifrost/
sudo chown bifrost:bifrost /etc/bifrost/server-config.yaml
sudo chmod 600 /etc/bifrost/server-config.yaml
```

### Server Service File

Create `/etc/systemd/system/bifrost-server.service`:

```ini
[Unit]
Description=Bifrost Proxy Server
Documentation=https://github.com/rennerdo30/bifrost-proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bifrost
Group=bifrost

ExecStart=/usr/local/bin/bifrost-server -c /etc/bifrost/server-config.yaml
ExecReload=/bin/kill -HUP $MAINPID

Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/bifrost

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bifrost-server

[Install]
WantedBy=multi-user.target
```

### Client Service File

Create `/etc/systemd/system/bifrost-client.service`:

```ini
[Unit]
Description=Bifrost Proxy Client
Documentation=https://github.com/rennerdo30/bifrost-proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bifrost
Group=bifrost

ExecStart=/usr/local/bin/bifrost-client -c /etc/bifrost/client-config.yaml
ExecReload=/bin/kill -HUP $MAINPID

Restart=always
RestartSec=5

NoNewPrivileges=yes
PrivateTmp=yes

StandardOutput=journal
StandardError=journal
SyslogIdentifier=bifrost-client

[Install]
WantedBy=multi-user.target
```

### Managing the Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable bifrost-server

# Start the service
sudo systemctl start bifrost-server

# Check status
sudo systemctl status bifrost-server

# View logs
sudo journalctl -u bifrost-server -f

# Reload configuration (hot-reload)
sudo systemctl reload bifrost-server

# Restart service
sudo systemctl restart bifrost-server

# Stop service
sudo systemctl stop bifrost-server
```

### Log Rotation

Create `/etc/logrotate.d/bifrost`:

```
/var/log/bifrost/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 bifrost bifrost
    sharedscripts
    postrotate
        systemctl reload bifrost-server >/dev/null 2>&1 || true
    endscript
}
```

---

## macOS (launchd)

### Prerequisites

1. Install the binary:

```bash
sudo cp bin/bifrost-client /usr/local/bin/
sudo chmod +x /usr/local/bin/bifrost-client
```

2. Create directories:

```bash
sudo mkdir -p /etc/bifrost
sudo mkdir -p /var/log/bifrost
sudo mkdir -p /var/lib/bifrost
```

3. Copy your configuration:

```bash
sudo cp client-config.yaml /etc/bifrost/
```

### Client Launch Agent (User)

For running as the current user, create `~/Library/LaunchAgents/com.bifrost.client.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.bifrost.client</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/bifrost-client</string>
        <string>-c</string>
        <string>/etc/bifrost/client-config.yaml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/var/log/bifrost/client.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/bifrost/client.error.log</string>

    <key>WorkingDirectory</key>
    <string>/var/lib/bifrost</string>
</dict>
</plist>
```

### Managing the Launch Agent

```bash
# Load (start) the service
launchctl load ~/Library/LaunchAgents/com.bifrost.client.plist

# Unload (stop) the service
launchctl unload ~/Library/LaunchAgents/com.bifrost.client.plist

# Check if running
launchctl list | grep bifrost

# View logs
tail -f /var/log/bifrost/client.log
```

### System-Wide Daemon

For running as a system daemon, place the plist in `/Library/LaunchDaemons/` and use:

```bash
sudo launchctl load /Library/LaunchDaemons/com.bifrost.client.plist
```

---

## Windows

!!! note "Authentication Limitation"
    System authentication (`auth.mode: system`) is **not supported on Windows**.
    Use `native`, `ldap`, or `oauth` authentication instead.
    See the [Authentication Guide](authentication.md#system-authentication) for details.

### Manual Installation

1. Download the Windows binary (`bifrost-server.exe` or `bifrost-client.exe`)

2. Create a configuration directory:
   ```cmd
   mkdir C:\ProgramData\Bifrost
   ```

3. Copy your config file to `C:\ProgramData\Bifrost\config.yaml`

4. Run from command line:
   ```cmd
   bifrost-server.exe -c C:\ProgramData\Bifrost\config.yaml
   ```

### Windows Service (NSSM)

Use [NSSM](https://nssm.cc/) to run Bifrost as a Windows service:

```cmd
# Install as service
nssm install BifrostServer C:\path\to\bifrost-server.exe -c C:\ProgramData\Bifrost\config.yaml

# Start the service
nssm start BifrostServer

# Stop the service
nssm stop BifrostServer

# Remove the service
nssm remove BifrostServer
```

### Firewall Configuration

Allow Bifrost through Windows Firewall:

```powershell
# HTTP Proxy
New-NetFirewallRule -DisplayName "Bifrost HTTP Proxy" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow

# SOCKS5 Proxy
New-NetFirewallRule -DisplayName "Bifrost SOCKS5 Proxy" -Direction Inbound -LocalPort 1080 -Protocol TCP -Action Allow

# Web UI
New-NetFirewallRule -DisplayName "Bifrost Web UI" -Direction Inbound -LocalPort 8081 -Protocol TCP -Action Allow
```

---

## Health Checks

### HTTP Health Check

```bash
curl http://localhost:8082/api/v1/health
```

Expected response:
```json
{"status": "healthy", "time": "2024-01-15T10:30:00Z"}
```

### Prometheus Metrics

```bash
curl http://localhost:9090/metrics
```

### Docker Health Check

The Docker Compose configuration includes built-in health checks that verify the service is responding.

---

## Upgrading

### Docker

```bash
# Pull new images
docker-compose pull

# Restart with new images
docker-compose up -d
```

### Systemd

```bash
# Stop service
sudo systemctl stop bifrost-server

# Replace binary
sudo cp new-bifrost-server /usr/local/bin/bifrost-server

# Start service
sudo systemctl start bifrost-server
```

### Configuration Changes

Most configuration changes can be applied via hot-reload:

```bash
# Systemd
sudo systemctl reload bifrost-server

# Docker
docker exec bifrost-server kill -HUP 1
```

!!! warning "Restart Required"
    Some changes require a full restart:

    - Listener address/port changes
    - TLS certificate changes
    - Authentication mode changes
