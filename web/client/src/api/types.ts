export interface VersionInfo {
  version: string
  git_commit: string
  build_time: string
  go_version: string
  platform: string
}

export interface StatusResponse {
  status: string
  server_status: 'connected' | 'disconnected'
  time: string
  version: string
  debug_entries: number
}

export interface DebugEntry {
  id: number
  timestamp: string
  method: string
  host: string
  path: string
  status_code: number
  duration_ms: number
  route: 'server' | 'direct'
  error?: string
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
