/**
 * Shared utility functions for status display
 */

type ServerStatus = 'online' | 'offline' | 'busy' | 'unknown'

/**
 * Get the hex color for a server status
 */
export function getStatusColor(status: ServerStatus | string): string {
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

type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error'

/**
 * Get the color for a connection status
 */
export function getConnectionStatusColor(status: ConnectionStatus): string {
  switch (status) {
    case 'connected':
      return '#22c55e'
    case 'connecting':
      return '#f59e0b'
    case 'error':
      return '#ef4444'
    default:
      return '#6b7280'
  }
}
