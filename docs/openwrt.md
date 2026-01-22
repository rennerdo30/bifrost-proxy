# OpenWrt Installation Guide

This guide covers installing and running Bifrost on OpenWrt routers and other resource-constrained Linux devices.

## Supported Architectures

| Architecture | Build Target | Common Devices |
|--------------|--------------|----------------|
| MIPS (big-endian) | `bifrost-server-linux-mips` | TP-Link TL-WR841N, Archer C7 |
| MIPS (little-endian) | `bifrost-server-linux-mipsle` | GL-MT1300 (Beryl), GL-MT300N (Mango), Netgear R6220 |
| ARM v6 | `bifrost-server-linux-arm6` | Raspberry Pi 1, Pi Zero |
| ARM v7 | `bifrost-server-linux-arm7` | GL-A1300 (Slate Plus), Raspberry Pi 2, GL-AR750 |
| ARM64 | `bifrost-server-linux-arm64-openwrt` | GL-MT6000 (Flint 2), GL-MT3000 (Beryl AX), GL-AX1800 (Flint), GL-MT2500 (Brume 2) |

## Hardware Requirements

| Profile | RAM | Flash | Max Connections | Recommended For |
|---------|-----|-------|-----------------|-----------------|
| **Minimal** | 32MB | 8MB | 25-50 | Basic routing only |
| **Low** | 64MB | 16MB | 50-100 | Small networks |
| **Standard** | 128MB | 32MB | 100-500 | Home/small office |
| **High** | 256MB+ | 64MB+ | Unlimited | Full features |

### Binary Sizes (stripped)

- MIPS: ~11-13MB
- ARM7: ~10-12MB
- ARM64: ~10-12MB

Ensure your device has sufficient flash storage. If space is limited, consider mounting `/usr/bin` on external storage (USB/SD card).

## Building for OpenWrt

### Build All Architectures

```bash
make build-openwrt
```

This creates stripped binaries (30-40% smaller) in `dist/`:

```
dist/
├── bifrost-server-linux-mips
├── bifrost-server-linux-mipsle
├── bifrost-server-linux-arm6
├── bifrost-server-linux-arm7
├── bifrost-server-linux-arm64-openwrt
├── bifrost-client-linux-mips
├── bifrost-client-linux-mipsle
├── bifrost-client-linux-arm6
├── bifrost-client-linux-arm7
└── bifrost-client-linux-arm64-openwrt
```

### Build Specific Architecture

```bash
# MIPS only (big-endian and little-endian)
make build-openwrt-mips

# ARM only (v6, v7, arm64)
make build-openwrt-arm

# Stripped binaries for local testing
make build-stripped
```

## Installation

### 1. Transfer Binary

Determine your router's architecture:

```bash
ssh root@router "cat /proc/cpuinfo | grep -E '(system type|model name|Hardware)'"
```

Copy the appropriate binary:

```bash
# Example for MIPS little-endian
scp dist/bifrost-server-linux-mipsle root@router:/usr/bin/bifrost-server
ssh root@router "chmod +x /usr/bin/bifrost-server"
```

### 2. Install Configuration

```bash
# Create config directory
ssh root@router "mkdir -p /etc/bifrost"

# Copy OpenWrt-optimized config
scp configs/server-config.openwrt.yaml root@router:/etc/bifrost/config.yaml
```

### 3. Install Init Script

```bash
# Copy procd init script
scp openwrt/etc/init.d/bifrost root@router:/etc/init.d/
ssh root@router "chmod +x /etc/init.d/bifrost"

# Enable on boot
ssh root@router "/etc/init.d/bifrost enable"
```

### 4. Start Service

```bash
ssh root@router "/etc/init.d/bifrost start"
```

## Installation via LuCI GUI (OPKG)

This is the easiest method and is recommended for most users, especially those using GL.iNet routers.

### 1. Download the `.ipk` Package

1.  Identify your router's architecture from the [Supported Architectures](#supported-architectures) table.
2.  Go to the [Bifrost GitHub Releases](https://github.com/rennerdo30/bifrost-proxy/releases).
3.  Download the `.ipk` file for your architecture (e.g., `bifrost-server_1.0.0_arm64-openwrt.ipk`).

### 2. Upload and Install via LuCI

1.  Log into your router's LuCI interface.
2.  Navigate to **System** -> **Software**.
3.  Click the **Upload Package...** button.
4.  Select the `.ipk` file you downloaded.
5.  Click **Upload**, then click **Install**.
6.  The package will automatically install the binary, the init script, and a default configuration.

### 3. Start the Service

1.  Navigate to **System** -> **Startup**.
2.  Find `bifrost` in the list.
3.  Click **Enabled** (if not already enabled) and click **Start**.

## GL.iNet Specific Guide

Most GL.iNet routers (Flint, Beryl, Slate, etc.) run a customized version of OpenWrt. You can access the standard LuCI interface from within the GL.iNet Admin Panel.

1.  Log into your GL.iNet Admin Panel (usually `http://192.168.8.1`).
2.  Navigate to **Applications** -> **Plug-ins** (or **System** -> **Advanced Settings** in older versions).
3.  In some versions, you click "Advanced Settings" which opens LuCI in a new tab.
4.  Once in LuCI, follow the [OPKG Installation](#installation-via-luci-gui-opkg) steps above.

## Alternative LuCI Methods

If you don't want to use the `.ipk` package, you can still install manually via LuCI.

### 1. Identify Architecture

1.  Log into your router's LuCI interface (usually at `http://192.168.1.1`).
2.  Navigate to **Status** -> **Overview**.
3.  Look for **Architecture** or **Model** in the "System" section.
4.  Match your architecture to the [Build Targets](#supported-architectures) table above.

### 2. Download Bifrost

1.  Go to the [Bifrost GitHub Releases](https://github.com/rennerdo30/bifrost-proxy/releases) (or the Nightly builds).
2.  Download the appropriate binary for your architecture (e.g., `bifrost-server-linux-mipsle`).

### 3. Upload and Install

Since LuCI does not have a generic file upload tool for binaries by default, we recommend one of the following plugins:

#### Option A: Using `luci-app-commands` (Recommended)

1.  Navigate to **System** -> **Software**.
2.  Click **Update lists...** then search for and install `luci-app-commands`.
3.  Go to **System** -> **Custom Commands**.
4.  In the "Custom Commands" section, you can use `wget` to download the binary directly to the router:
    ```bash
    wget -O /usr/bin/bifrost-server https://github.com/rennerdo30/bifrost-proxy/releases/download/nightly/bifrost-server-linux-YOUR_ARCH
    chmod +x /usr/bin/bifrost-server
    ```
5.  Click **Run** to execute the command.

#### Option B: Using `luci-app-filebrowser`

1.  Install `luci-app-filebrowser` via **System** -> **Software**.
2.  Navigate to **Tools** -> **File Browser**.
3.  Browse to `/usr/bin/`.
4.  Upload your downloaded `bifrost-server` binary.
5.  Click on the uploaded file and set permissions to `755` (Executable).

### 4. Upload Configuration

1.  Using your chosen File Browser plugin, browse to `/etc/`.
2.  Create a new directory named `bifrost`.
3.  Upload your `config.yaml` (you can use [server-config.openwrt.yaml](https://github.com/rennerdo30/bifrost-proxy/blob/main/configs/server-config.openwrt.yaml) as a template).

### 5. Install Init Script

To ensure Bifrost starts on boot, you must upload the init script:

1.  Download the [init script](https://github.com/rennerdo30/bifrost-proxy/blob/main/openwrt/etc/init.d/bifrost).
2.  Upload it to `/etc/init.d/bifrost` on your router.
3.  Make it executable (`chmod +x /etc/init.d/bifrost`).

### 6. Start and Enable Service

1.  Navigate to **System** -> **Startup**.
2.  Find `bifrost` in the list.
3.  Click **Enabled** (it should toggle from "Disabled" to "Enabled").
4.  Click **Start** to run the service immediately.

## Configuration

### Minimal Configuration (32MB RAM)

For devices with 32MB RAM, use these conservative settings:

```yaml
server:
  http:
    listen: ":7080"
    max_connections: 25
  socks5:
    listen: ":7180"
    max_connections: 25

logging:
  level: error

api:
  enabled: true
  listen: ":7082"
  websocket_max_clients: 2

metrics:
  enabled: false

access_log:
  enabled: false

web_ui:
  enabled: false
```

### Standard Configuration (64-128MB RAM)

See `configs/server-config.openwrt.yaml` for a balanced configuration suitable for most OpenWrt devices.

### Configuration Options for Resource Tuning

| Option | Default | OpenWrt Recommended | Effect |
|--------|---------|---------------------|--------|
| `server.http.max_connections` | 0 (unlimited) | 100 | Prevents OOM |
| `server.socks5.max_connections` | 0 (unlimited) | 100 | Prevents OOM |
| `metrics.enabled` | true | false | Saves 1-2MB RAM |
| `metrics.collection_interval` | 15s | 300s | 4x less CPU |
| `api.websocket_max_clients` | 100 | 5 | Saves ~1MB |
| `access_log.enabled` | true | false | Reduces I/O |
| `logging.level` | info | warn | Reduces I/O |

## Service Management

### Using procd

```bash
# Start
/etc/init.d/bifrost start

# Stop
/etc/init.d/bifrost stop

# Restart
/etc/init.d/bifrost restart

# Reload config (hot reload)
/etc/init.d/bifrost reload

# Check status
/etc/init.d/bifrost status

# Enable on boot
/etc/init.d/bifrost enable

# Disable on boot
/etc/init.d/bifrost disable
```

### Checking Logs

```bash
# View recent logs
logread | grep bifrost

# Follow logs
logread -f | grep bifrost
```

### Monitoring Resource Usage

```bash
# Memory usage
ps aux | grep bifrost
free -m

# Check open connections
netstat -an | grep -E ':7080|:7180' | wc -l
```

## Firewall Configuration

Add firewall rules to allow proxy traffic:

```bash
# /etc/config/firewall

config rule
    option name 'Allow-Bifrost-HTTP'
    option src 'lan'
    option dest_port '8080'
    option proto 'tcp'
    option target 'ACCEPT'

config rule
    option name 'Allow-Bifrost-SOCKS5'
    option src 'lan'
    option dest_port '1080'
    option proto 'tcp'
    option target 'ACCEPT'

config rule
    option name 'Allow-Bifrost-API'
    option src 'lan'
    option dest_port '8082'
    option proto 'tcp'
    option target 'ACCEPT'
```

Apply changes:

```bash
/etc/init.d/firewall restart
```

## Troubleshooting

### Binary Won't Start

**Wrong architecture:**
```bash
# Check if binary runs
/usr/bin/bifrost-server version
# If "Exec format error", you have the wrong architecture
```

**Missing libraries:**
Bifrost is statically compiled (`CGO_ENABLED=0`), so this shouldn't happen. If it does:
```bash
ldd /usr/bin/bifrost-server
```

### Out of Memory

**Symptoms:** Router becomes unresponsive, bifrost crashes

**Solutions:**
1. Reduce `max_connections` to 25-50
2. Disable metrics: `metrics.enabled: false`
3. Reduce WebSocket clients: `websocket_max_clients: 2`
4. Disable access log: `access_log.enabled: false`

### High CPU Usage

**Symptoms:** Router becomes slow, high load average

**Solutions:**
1. Disable metrics or increase collection interval to 300s
2. Reduce logging level to `warn` or `error`
3. Disable access log

### Connection Refused

**Check service is running:**
```bash
/etc/init.d/bifrost status
ps aux | grep bifrost
```

**Check ports are listening:**
```bash
netstat -tlnp | grep bifrost
```

**Check firewall:**
```bash
iptables -L -n | grep -E '8080|1080|8082'
```

## Performance Benchmarks

Approximate performance on common devices:

| Device | RAM | Throughput | Max Connections |
|--------|-----|------------|-----------------|
| TP-Link Archer C7 | 128MB | ~50 Mbps | 200 |
| GL.iNet GL-AR750 | 128MB | ~80 Mbps | 300 |
| Raspberry Pi 3 | 1GB | ~200 Mbps | 1000+ |
| NanoPi R4S | 4GB | ~900 Mbps | 5000+ |

*Note: Throughput depends on backend type and network conditions.*

## Updating

To update Bifrost:

```bash
# Stop service
/etc/init.d/bifrost stop

# Backup config
cp /etc/bifrost/config.yaml /etc/bifrost/config.yaml.bak

# Upload new binary
scp dist/bifrost-server-linux-ARCH root@router:/usr/bin/bifrost-server

# Start service
/etc/init.d/bifrost start

# Verify version
/usr/bin/bifrost-server version
```

## Uninstallation

```bash
# Stop and disable
/etc/init.d/bifrost stop
/etc/init.d/bifrost disable

# Remove files
rm /usr/bin/bifrost-server
rm /etc/init.d/bifrost
rm -rf /etc/bifrost
rm /etc/config/bifrost  # if using UCI
```
