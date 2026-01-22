# Bifrost Proxy - Issues Tracking

## Recent Fixes

### VPN Manager Nil Pointer Panic
- **Description**: Calling `Status()` or other methods on a nil `VPNManager` caused a panic.
- **Fix**: Added nil checks in `internal/vpn/vpn.go` and ensured `internal/api/client/server.go` handles nil managers gracefully.
- **Status**: Fixed

### Auto-Updater Version Comparison
- **Description**: Auto-updater could report "up to date" even when a newer version was available, or fail to compare non-SemVer versions correctly.
- **Fix**: 
  - Increased release fetch limit from 10 to 30.
  - Implemented proper SemVer sorting for releases.
  - Added fallback to timestamp comparison for dev builds/nightlies.
- **Status**: Fixed

## Known Issues

### System Proxy Support Limited to Windows
- **Description**: Currently, the `system_proxy` feature only works on Windows.
- **Plan**: Implement `sysproxy` support for macOS (using `networksetup`) and Linux (supporting GNOME/KDE settings).
- **Status**: Open

### Service Management Platform Coverage
- **Description**: Service installation is implemented for systemd (Linux), launchd (macOS), and SCM (Windows).
- **Plan**: Verify compatibility with older Linux distributions using SysVinit or Upstart if requested.
- **Status**: Open
