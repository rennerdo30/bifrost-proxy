/**
 * Shared utility functions for status display
 */

export type ServerStatus = 'online' | 'offline' | 'busy' | 'unknown'

/**
 * Get the CSS color class for a server status
 */
export function getStatusColor(status: ServerStatus | string): string {
  switch (status) {
    case 'online':
      return 'bg-bifrost-success'
    case 'offline':
      return 'bg-bifrost-error'
    case 'busy':
      return 'bg-bifrost-warning'
    default:
      return 'bg-bifrost-muted'
  }
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
