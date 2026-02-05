// API service for communicating with Bifrost client

const DEFAULT_TIMEOUT = 10000

interface APIConfig {
  baseUrl: string
  token?: string
}

let config: APIConfig = {
  baseUrl: 'http://localhost:7383/api/v1',
}

export function setAPIConfig(newConfig: Partial<APIConfig>) {
  config = { ...config, ...newConfig }
}

export function getAPIConfig(): APIConfig {
  return { ...config }
}

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (config.token) {
      headers['Authorization'] = `Bearer ${config.token}`
    }

    const res = await fetch(`${config.baseUrl}${path}`, {
      ...options,
      headers: { ...headers, ...options?.headers },
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new Error(text || `Request failed with status ${res.status}`)
    }

    return res.json()
  } catch (err) {
    clearTimeout(timeoutId)
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('Request timed out. Check your connection and try again.')
    }
    throw err
  }
}

// Types
export interface StatusResponse {
  status: string
  server_status: string
  version: string
  debug_entries: number
}

export interface VPNStatus {
  status: string
  enabled: boolean
  tunnel_type?: string
  interface_name?: string
  local_ip?: string
  gateway?: string
  dns_servers?: string[]
  mtu?: number
  port?: number
  encryption?: string
  bytes_sent: number
  bytes_received: number
  connected_since?: string
  last_error?: string
}

export interface ServerInfo {
  id: string
  name: string
  address: string
  protocol: string
  is_default: boolean
  latency_ms?: number
  status: 'online' | 'offline' | 'busy' | 'unknown'
}

export interface ConnectionStats {
  bytes_sent: number
  bytes_received: number
  active_connections: number
  uptime_seconds: number
}

export interface AppRule {
  name: string
  path?: string
}

export interface SplitTunnelConfig {
  mode: string
  apps: AppRule[]
  domains: string[]
  ips: string[]
}

export interface ClientConfig {
  proxy?: {
    http?: { listen: string }
    socks5?: { listen: string }
  }
  server?: {
    address: string
    protocol: string
    username?: string
  }
  tray?: {
    enabled: boolean
    start_minimized: boolean
    show_quick_gui: boolean
    auto_connect: boolean
    show_notifications: boolean
  }
  vpn?: {
    enabled: boolean
    mode: string
    interface_name?: string
  }
  debug?: {
    enabled: boolean
    max_entries: number
    capture_body: boolean
  }
}

// API methods
export const api = {
  // Health & Status
  getHealth: () => fetchJSON<{ status: string }>('/health'),
  getStatus: () => fetchJSON<StatusResponse>('/status'),

  // VPN
  getVPNStatus: () => fetchJSON<VPNStatus>('/vpn/status'),
  enableVPN: () => fetchJSON<{ status: string }>('/vpn/enable', { method: 'POST' }),
  disableVPN: () => fetchJSON<{ status: string }>('/vpn/disable', { method: 'POST' }),
  getSplitTunnelRules: () => fetchJSON<SplitTunnelConfig>('/vpn/split/rules'),
  addSplitTunnelApp: (app: AppRule) =>
    fetchJSON<{ status: string }>('/vpn/split/apps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(app),
    }),
  removeSplitTunnelApp: (name: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/apps/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  // Config
  getConfig: () => fetchJSON<ClientConfig>('/config'),
  updateConfig: (updates: Partial<ClientConfig>) =>
    fetchJSON<{ status: string }>('/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    }),
  reloadConfig: () => fetchJSON<{ status: string }>('/config/reload', { method: 'POST' }),

  // Servers
  getServers: () => fetchJSON<ServerInfo[]>('/servers'),
  selectServer: (id: string) =>
    fetchJSON<{ status: string }>(`/servers/${encodeURIComponent(id)}/select`, { method: 'POST' }),

  // Connection management
  connect: () => fetchJSON<{ status: string }>('/connect', { method: 'POST' }),
  disconnect: () => fetchJSON<{ status: string }>('/disconnect', { method: 'POST' }),

  // Data management
  clearCache: () => fetchJSON<{ status: string }>('/debug/entries', { method: 'DELETE' }),
}

// Utility functions
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60

  if (hours > 0) {
    return `${hours}h ${minutes}m`
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`
  }
  return `${secs}s`
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
