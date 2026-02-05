import type { VersionInfo, StatusResponse, DebugEntry, Route, RouteTestResult, CacheStats, CacheEntriesResponse } from './types'

const API_BASE = '/api/v1'

// Helper function to convert routes to YAML format
function routesToYaml(routes: Route[]): string {
  let yaml = 'routes:\n'
  for (const route of routes) {
    yaml += `  - name: "${route.name}"\n`
    yaml += `    patterns:\n`
    for (const pattern of route.patterns) {
      yaml += `      - "${pattern}"\n`
    }
    yaml += `    action: "${route.action}"\n`
    yaml += `    priority: ${route.priority}\n`
  }
  return yaml
}
const DEFAULT_TIMEOUT = 30000 // 30 seconds

class APIError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message)
    this.name = 'APIError'
  }
}

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

  // Add CSRF protection and content type headers
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest', // CSRF protection
    ...options?.headers,
  }

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new APIError(res.status, text || `Request failed with status ${res.status}`)
    }
    return res.json()
  } catch (err) {
    clearTimeout(timeoutId)
    if (err instanceof APIError) throw err
    if (err instanceof Error && err.name === 'AbortError') {
      throw new APIError(0, 'Request timed out - server may be unavailable')
    }
    throw new APIError(0, err instanceof Error ? err.message : 'Network error - check your connection')
  }
}

export { APIError }

// VPN Types
export interface VPNStatus {
  status: string
  enabled: boolean
  tunnel_type?: string
  interface_name?: string
  local_ip?: string
  gateway?: string
  dns_servers?: string[]
  bytes_sent: number
  bytes_received: number
  connected_since?: string
  last_error?: string
}

export interface VPNConnection {
  id: string
  remote_addr: string
  local_addr: string
  protocol: string
  started_at: string
  bytes_sent: number
  bytes_received: number
}

export interface SplitTunnelConfig {
  mode: string
  apps: AppRule[]
  domains: string[]
  ips: string[]
}

export interface AppRule {
  name: string
  path?: string
}

// Config Types
export interface ClientConfig {
  proxy: ProxySettings
  server: ServerConnection
  routes: RouteConfig[]
  debug: DebugSettings
  logging: LoggingSettings
  web_ui: WebUISettings
  api: APISettings
  tray: TraySettings
  auto_update: AutoUpdateSettings
  vpn: VPNSettings
  mesh: MeshSettings
}

export interface ProxySettings {
  http: ListenerConfig
  socks5: ListenerConfig
}

export interface ListenerConfig {
  listen: string
  tls?: TLSConfig
  read_timeout?: string
  write_timeout?: string
  idle_timeout?: string
  max_connections?: number
}

export interface TLSConfig {
  enabled: boolean
  cert_file?: string
  key_file?: string
}

export interface ServerConnection {
  address: string
  protocol: string
  tls?: TLSConfig
  username?: string
  password?: string
  timeout?: string
  retry_count?: number
  retry_delay?: string
  health_check?: HealthCheckConfig
}

export interface HealthCheckConfig {
  type: string
  interval?: string
  timeout?: string
  target?: string
}

export interface RouteConfig {
  name?: string
  domains: string[]
  action: string
  priority: number
}

export interface DebugSettings {
  enabled: boolean
  max_entries: number
  capture_body: boolean
  max_body_size?: number
  filter_domains?: string[]
}

export interface LoggingSettings {
  level: string
  format: string
  output: string
  time_format?: string
}

export interface WebUISettings {
  enabled: boolean
  listen: string
  base_path?: string
}

export interface APISettings {
  enabled: boolean
  listen: string
  token?: string
  enable_request_log?: boolean
  request_log_size?: number
  websocket_max_clients?: number
}

export interface TraySettings {
  enabled: boolean
  start_minimized: boolean
  show_quick_gui: boolean
  auto_connect: boolean
  show_notifications: boolean
  window_x?: number
  window_y?: number
}

export interface AutoUpdateSettings {
  enabled: boolean
  check_interval?: string
  channel?: string
}

export interface VPNSettings {
  enabled: boolean
  tun?: TunConfig
  split_tunnel?: SplitTunnelSettings
  dns?: DNSSettings
}

export interface TunConfig {
  name?: string
  address?: string
  mtu?: number
}

export interface SplitTunnelSettings {
  mode: string
  apps?: AppRule[]
  domains?: string[]
  ips?: string[]
  always_bypass?: string[]
}

export interface DNSSettings {
  enabled: boolean
  listen?: string
  upstream?: string[]
  cache_ttl?: string
  intercept_mode?: string
}

export interface MeshSettings {
  enabled: boolean
  network_id?: string
  network_cidr?: string
  peer_name?: string
  device?: MeshDeviceConfig
  discovery?: MeshDiscoveryConfig
  stun?: STUNConfig
  turn?: TURNConfig
  connection?: MeshConnectionConfig
  security?: MeshSecurityConfig
}

export interface MeshDeviceConfig {
  type: string
  name?: string
  mtu?: number
  mac_address?: string
}

export interface MeshDiscoveryConfig {
  server?: string
  heartbeat_interval?: string
  peer_timeout?: string
  token?: string
}

export interface STUNConfig {
  servers?: string[]
  timeout?: string
}

export interface TURNConfig {
  enabled: boolean
  servers?: TURNServerConfig[]
}

export interface TURNServerConfig {
  url: string
  username?: string
  password?: string
}

export interface MeshConnectionConfig {
  direct_connect?: boolean
  relay_enabled?: boolean
  relay_via_peers?: boolean
  connect_timeout?: string
  keepalive_interval?: string
}

export interface MeshSecurityConfig {
  private_key?: string
  allowed_peers?: string[]
  require_encryption?: boolean
}

// Config update response
export interface ConfigUpdateResponse {
  status: string
  restart_required: boolean
  restart_fields?: string[]
  warnings?: string[]
}

// Config validation result
export interface ConfigValidationResult {
  valid: boolean
  errors?: string[]
  warnings?: string[]
}

// Log Types
export interface LogEntry {
  timestamp: string
  level: string
  message: string
  fields?: Record<string, unknown>
}

export interface LogsResponse {
  entries: LogEntry[]
  total: number
  limit: number
  offset: number
}

export const api = {
  getHealth: () => fetchJSON<{ status: string }>('/health'),
  getVersion: () => fetchJSON<VersionInfo>('/version'),
  getStatus: () => fetchJSON<StatusResponse>('/status'),

  // Debug/Traffic
  getEntries: (count = 50) => fetchJSON<DebugEntry[]>(`/debug/entries/last/${count}`),
  getAllEntries: () => fetchJSON<DebugEntry[]>('/debug/entries'),
  getErrors: () => fetchJSON<DebugEntry[]>('/debug/errors'),
  clearEntries: () => fetchJSON<{ message: string }>('/debug/entries', { method: 'DELETE' }),

  // Routes
  getRoutes: () => fetchJSON<Route[]>('/routes'),
  testRoute: (domain: string) => fetchJSON<RouteTestResult>(`/routes/test?domain=${encodeURIComponent(domain)}`),
  addRoute: (route: { name: string; domains: string[]; action: string; priority: number }) =>
    fetchJSON<{ status: string; route: string }>('/routes', {
      method: 'POST',
      body: JSON.stringify(route),
    }),
  removeRoute: (name: string) =>
    fetchJSON<{ status: string; route: string }>(`/routes/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),
  exportRoutes: async (format: 'json' | 'yaml' = 'json') => {
    const routes = await fetchJSON<Route[]>('/routes')
    const content = format === 'json' ? JSON.stringify(routes, null, 2) : routesToYaml(routes)
    return new Blob([content], { type: format === 'json' ? 'application/json' : 'application/x-yaml' })
  },
  importRoutes: async (routes: Route[]) => {
    const results = []
    for (const route of routes) {
      try {
        await fetchJSON<{ status: string }>('/routes', {
          method: 'POST',
          body: JSON.stringify({
            name: route.name,
            domains: route.patterns,
            action: route.action,
            priority: route.priority,
          }),
        })
        results.push({ name: route.name, success: true })
      } catch (err) {
        results.push({ name: route.name, success: false, error: err instanceof Error ? err.message : 'Unknown error' })
      }
    }
    return results
  },

  // Config
  getConfig: () => fetchJSON<ClientConfig>('/config'),
  updateConfig: (updates: Partial<ClientConfig>) =>
    fetchJSON<ConfigUpdateResponse>('/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    }),
  reloadConfig: () => fetchJSON<{ status: string }>('/config/reload', { method: 'POST' }),
  validateConfig: (updates: Partial<ClientConfig>) =>
    fetchJSON<ConfigValidationResult>('/config/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    }),
  getConfigDefaults: () => fetchJSON<ClientConfig>('/config/defaults'),
  exportConfig: async (format: 'json' | 'yaml' = 'yaml') => {
    const res = await fetch(`${API_BASE}/config/export?format=${format}`, { method: 'POST' })
    if (!res.ok) throw new APIError(res.status, 'Failed to export config')
    return res.blob()
  },
  importConfig: (config: string, format: 'json' | 'yaml' = 'yaml') =>
    fetchJSON<ConfigUpdateResponse>(`/config/import?format=${format}`, {
      method: 'POST',
      headers: { 'Content-Type': format === 'yaml' ? 'application/x-yaml' : 'application/json' },
      body: config,
    }),

  // Logs
  getLogs: (limit = 100, offset = 0, level?: string) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (level) params.set('level', level)
    return fetchJSON<LogsResponse>(`/logs?${params}`)
  },

  // VPN
  getVPNStatus: () => fetchJSON<VPNStatus>('/vpn/status'),
  enableVPN: () => fetchJSON<{ status: string }>('/vpn/enable', { method: 'POST' }),
  disableVPN: () => fetchJSON<{ status: string }>('/vpn/disable', { method: 'POST' }),
  getVPNConnections: () => fetchJSON<VPNConnection[]>('/vpn/connections'),
  getSplitTunnelRules: () => fetchJSON<SplitTunnelConfig>('/vpn/split/rules'),
  setSplitTunnelMode: (mode: 'exclude' | 'include') =>
    fetchJSON<{ status: string; mode: string }>('/vpn/split/mode', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    }),
  addSplitTunnelApp: (app: AppRule) =>
    fetchJSON<{ status: string }>('/vpn/split/apps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(app),
    }),
  removeSplitTunnelApp: (name: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/apps/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  addSplitTunnelDomain: (pattern: string) =>
    fetchJSON<{ status: string }>('/vpn/split/domains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern }),
    }),
  removeSplitTunnelDomain: (pattern: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/domains/${encodeURIComponent(pattern)}`, { method: 'DELETE' }),
  addSplitTunnelIP: (cidr: string) =>
    fetchJSON<{ status: string }>('/vpn/split/ips', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cidr }),
    }),
  removeSplitTunnelIP: (cidr: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/ips/${encodeURIComponent(cidr)}`, { method: 'DELETE' }),

  // Cache
  getCacheStats: () => fetchJSON<CacheStats>('/cache/stats'),
  getCacheEntries: (limit = 100, offset = 0, domain?: string) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (domain) params.set('domain', domain)
    return fetchJSON<CacheEntriesResponse>(`/cache/entries?${params}`)
  },
  deleteCacheEntry: (key: string) =>
    fetchJSON<{ status: string; key: string }>(`/cache/entries/${encodeURIComponent(key)}`, { method: 'DELETE' }),
  clearCache: () =>
    fetchJSON<{ status: string }>('/cache/clear', { method: 'POST' }),
}
