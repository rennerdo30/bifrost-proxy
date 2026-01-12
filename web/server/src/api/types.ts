// Backend types
export interface BackendStats {
  total_connections: number
  active_connections: number
  bytes_sent: number
  bytes_received: number
  errors: number
  last_error: string
  last_error_time: string
}

export interface Backend {
  name: string
  type: string
  healthy: boolean
  stats: BackendStats
}

// Server stats
export interface ServerStats {
  total_connections: number
  active_connections: number
  bytes_sent: number
  bytes_received: number
  backends: {
    total: number
    healthy: number
  }
  time: string
}

// Health & Status
export interface HealthResponse {
  status: 'healthy' | 'degraded'
  time: string
}

export interface StatusResponse {
  status: string
  time: string
  version: string
  backends: number
}

export interface VersionInfo {
  version: string
  commit: string
  build_time: string
  go_version: string
}

// Request Log
export interface RequestLogEntry {
  id: number
  timestamp: string
  method: string
  host: string
  path: string
  url: string
  user_agent: string
  client_ip: string
  username: string
  backend: string
  status_code: number
  bytes_sent: number
  bytes_recv: number
  duration_ms: number
  error: string
  protocol: string
}

export interface RequestLogResponse {
  enabled: boolean
  requests: RequestLogEntry[]
  message?: string
}

export interface RequestLogStats {
  enabled: boolean
  total_requests: number
  total_bytes_sent: number
  total_bytes_recv: number
  requests_by_method: Record<string, number>
  requests_by_status: Record<string, number>
  top_hosts: Array<{ host: string; count: number }>
}

// Configuration types
export interface ServerSettings {
  http_listen?: string
  socks5_listen?: string
  connect_timeout?: string
  idle_timeout?: string
}

export interface BackendConfig {
  name: string
  type: string
  address?: string
  username?: string
  password?: string
  priority?: number
  weight?: number
  config_path?: string
  interface_name?: string
}

export interface RouteConfig {
  pattern: string
  backend: string
  priority?: number
}

export interface AuthConfig {
  mode: 'none' | 'basic' | 'file'
  users?: Record<string, string>
  file?: string
}

export interface RateLimitConfig {
  enabled: boolean
  requests_per_second?: number
  burst?: number
  per_ip?: boolean
}

export interface AccessLogConfig {
  enabled: boolean
  format?: string
  output?: string
  file?: string
}

export interface MetricsConfig {
  enabled: boolean
  listen?: string
}

export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error'
  format?: 'text' | 'json'
}

export interface APIConfig {
  enabled: boolean
  listen?: string
  token?: string
  enable_request_log?: boolean
  request_log_size?: number
}

export interface ServerConfig {
  server?: ServerSettings
  backends?: BackendConfig[]
  routes?: RouteConfig[]
  auth?: AuthConfig
  rate_limit?: RateLimitConfig
  access_log?: AccessLogConfig
  metrics?: MetricsConfig
  logging?: LoggingConfig
  api?: APIConfig
}

// Config metadata
export interface ConfigMeta {
  sections: Array<{
    name: string
    hot_reloadable: boolean
    description: string
  }>
}

// Config save
export interface ConfigSaveRequest {
  config: ServerConfig
  create_backup?: boolean
}

export interface ConfigSaveResponse {
  success: boolean
  message: string
  backup_path?: string
  requires_restart: boolean
  changed_sections?: string[]
}

// WebSocket events
export interface WSEvent {
  type: 'stats' | 'backend_status' | 'config_reload' | 'request'
  data: unknown
}
