# Desktop Client

The Bifrost Desktop Client is a native application built with [Wails](https://wails.io/) that provides a graphical interface for managing the proxy client.

## Features

- **Quick GUI**: Compact floating window for quick access
- **System Tray**: Background operation with status indicators
- **Connection Dashboard**: Real-time statistics and monitoring
- **Server Management**: Configure and switch between servers
- **Split Tunneling**: Visual rule editor
- **Logs Viewer**: Real-time log streaming

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [Releases page](https://github.com/rennerdo30/bifrost-proxy/releases).

| Platform | File |
|----------|------|
| Windows | `bifrost-desktop-windows-amd64.exe` |
| macOS (Intel) | `bifrost-desktop-darwin-amd64` |
| macOS (Apple Silicon) | `bifrost-desktop-darwin-arm64` |
| Linux | `bifrost-desktop-linux-amd64` |

### Building from Source

#### Prerequisites

- Go 1.22+
- Node.js 18+
- Wails CLI v2

```bash
# Install Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Verify installation
wails doctor
```

#### Build Commands

```bash
# Clone repository
git clone https://github.com/rennerdo30/bifrost-proxy.git
cd bifrost-proxy/desktop

# Install frontend dependencies
cd frontend && npm install && cd ..

# Build for current platform
wails build

# Build for specific platform
wails build -platform darwin/amd64
wails build -platform darwin/arm64
wails build -platform windows/amd64
wails build -platform linux/amd64

# Development mode with hot reload
wails dev
```

## User Interface

### Main Window

The main window provides a comprehensive dashboard:

```
┌─────────────────────────────────────────┐
│  Bifrost Desktop                    ─ □ ×│
├─────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐       │
│  │   Status    │  │   Traffic   │       │
│  │  Connected  │  │  ↑ 1.2 GB   │       │
│  │             │  │  ↓ 3.4 GB   │       │
│  └─────────────┘  └─────────────┘       │
│                                         │
│  Server: us-west.example.com            │
│  Protocol: WireGuard                    │
│  Uptime: 2h 34m                         │
│                                         │
│  ┌─────────────────────────────────────┐│
│  │ Recent Connections                  ││
│  │ ─────────────────────────────────── ││
│  │ example.com:443      → direct       ││
│  │ api.service.io:443   → server       ││
│  │ cdn.assets.com:443   → server       ││
│  └─────────────────────────────────────┘│
│                                         │
│  [Connect]  [Settings]  [View Logs]     │
└─────────────────────────────────────────┘
```

### Quick GUI

The Quick GUI is a compact, always-on-top window:

```
┌─────────────────────┐
│ ● Connected   [≡]   │
├─────────────────────┤
│ ↑ 12.5 MB  ↓ 45.2 MB│
│ 2h 15m              │
└─────────────────────┘
```

Features:
- Connection status indicator
- Quick toggle (click status to connect/disconnect)
- Bandwidth usage
- Session duration
- Menu access for full dashboard

### System Tray

The application runs in the system tray with these menu options:

- **Status**: Shows current connection state
- **Connect/Disconnect**: Toggle VPN connection
- **Open Dashboard**: Show main window
- **Quick GUI**: Show/hide compact window
- **Settings**: Open settings panel
- **Quit**: Exit application

#### Tray Icon States

| Icon | State | Description |
|------|-------|-------------|
| 🟢 | Connected | VPN active and routing traffic |
| 🟡 | Connecting | Establishing connection |
| 🔴 | Disconnected | VPN not active |
| ⚠️ | Error | Connection error occurred |

## Configuration

Configuration is stored in platform-specific locations:

| Platform | Location |
|----------|----------|
| Windows | `%APPDATA%\Bifrost\config.yaml` |
| macOS | `~/Library/Application Support/Bifrost/config.yaml` |
| Linux | `~/.config/bifrost/config.yaml` |

### Example Configuration

```yaml
# Desktop client configuration
server:
  address: "proxy.example.com:7080"
  protocol: "http"

tray:
  enabled: true
  start_minimized: false
  show_quick_gui: true
  auto_connect: false
  show_notifications: true

vpn:
  enabled: true
  mode: tun

debug:
  enabled: false
  log_level: "info"
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + Q` | Quit application |
| `Ctrl/Cmd + H` | Hide to tray |
| `Ctrl/Cmd + Shift + C` | Toggle connection |
| `Ctrl/Cmd + ,` | Open settings |
| `Ctrl/Cmd + L` | View logs |
| `Escape` | Close Quick GUI |

## Auto-Start

### Windows

The application can register itself to start with Windows:

1. Open Settings
2. Enable "Start with Windows"

Or manually add to startup:
```
Win + R → shell:startup → Create shortcut to bifrost-desktop.exe
```

### macOS

Enable "Start at Login" in Settings, or use launchd:

```bash
# Create launch agent
cat > ~/Library/LaunchAgents/com.bifrost.desktop.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.bifrost.desktop</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Bifrost.app/Contents/MacOS/Bifrost</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.bifrost.desktop.plist
```

### Linux

Enable "Start at Login" in Settings, or create autostart entry:

```bash
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/bifrost.desktop << EOF
[Desktop Entry]
Type=Application
Name=Bifrost
Exec=/usr/local/bin/bifrost-desktop
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF
```

## Troubleshooting

### Application Won't Start

1. Check system requirements (Go 1.22+, WebView2 on Windows)
2. Verify no other instance is running
3. Check logs in config directory

### System Tray Not Showing

- **Linux**: Ensure you have an app indicator extension (GNOME: AppIndicator, KDE: built-in)
- **macOS**: Check System Preferences → Dock & Menu Bar
- **Windows**: Check hidden icons in system tray

### Connection Issues

1. Verify server address in settings
2. Check network connectivity
3. Review logs for error messages
4. Ensure firewall allows application

### High CPU/Memory Usage

1. Disable debug logging
2. Reduce log retention
3. Check for excessive connections
