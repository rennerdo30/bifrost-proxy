export interface VersionInfo {
  version: string
  git_commit: string
  build_time: string
  go_version: string
  platform: string
}

export interface StatusResponse {
  status: string
  version: string
  server_connected: boolean
  server_address?: string
  http_proxy?: string
  socks5_proxy?: string
  vpn_enabled: boolean
  vpn_status: string
  debug_entries: number
  uptime: string
  bytes_sent: number
  bytes_received: number
  active_connections: number
  timestamp: string
}

export interface DebugEntry {
  id: string
  timestamp: string
  type: string
  host: string
  method?: string
  path?: string
  protocol: string
  status_code?: number
  duration_ms: number
  bytes_sent: number
  bytes_received: number
  action: 'server' | 'direct'
  client_addr: string
  error?: string
  request_headers?: Record<string, string>
  response_headers?: Record<string, string>
}

export interface Route {
  name: string
  patterns: string[]
  action: 'server' | 'direct'
  priority: number
}

export interface RouteTestResult {
  domain: string
  action: 'server' | 'direct'
  matched_route?: string
}
