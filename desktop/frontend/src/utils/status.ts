/**
 * Shared utility functions for status display
 */

/**
 * The vocabulary the Go side actually emits (desktop/app.go GetServers):
 * 'connected'    — the selected server answered a reachability probe
 * 'disconnected' — the selected server did not answer
 * 'available'    — configured but not selected (never probed)
 * The previous set here (online/offline/busy) matched nothing the backend
 * ever sent, so every server rendered the fallback style.
 */
export type ServerStatus = 'connected' | 'disconnected' | 'available' | 'unknown'

/**
 * Get the CSS color class for a server status
 */
export function getStatusColor(status: ServerStatus | string): string {
  switch (status) {
    case 'connected':
      return 'bg-bifrost-success'
    case 'disconnected':
      return 'bg-bifrost-error'
    case 'available':
      return 'bg-bifrost-accent'
    default:
      return 'bg-bifrost-muted'
  }
}

/**
 * Get the text label for a server status (for accessibility)
 */
export function getStatusLabel(status: ServerStatus | string): string {
  switch (status) {
    case 'connected':
      return 'Connected'
    case 'disconnected':
      return 'Unreachable'
    case 'available':
      return 'Available'
    default:
      return 'Unknown'
  }
}

/**
 * Validate server address format (host:port)
 */
export function validateServerAddress(address: string): string | null {
  if (!address.trim()) {
    return 'Server address is required'
  }

  // Check for host:port format
  const parts = address.split(':')
  if (parts.length !== 2) {
    return 'Address must be in host:port format (e.g., example.com:8080)'
  }

  const [host, port] = parts

  if (!host.trim()) {
    return 'Host cannot be empty'
  }

  const portNum = parseInt(port, 10)
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return 'Port must be between 1 and 65535'
  }

  return null
}

/**
 * Get the hex color for a server status (for use in inline styles)
 */
export function getStatusHexColor(status: ServerStatus | string): string {
  switch (status) {
    case 'online':
      return '#22c55e'
    case 'offline':
      return '#ef4444'
    case 'busy':
      return '#f59e0b'
    default:
      return '#6b7280'
  }
}
