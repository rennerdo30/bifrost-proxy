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

// ============================================
// Configuration Types (Full Structure)
// ============================================

// TLS Configuration
export interface TLSConfig {
  enabled: boolean
  cert_file: string
  key_file: string
}

// Listener Configuration
export interface ListenerConfig {
  listen: string
  tls?: TLSConfig
  read_timeout?: string
  write_timeout?: string
  idle_timeout?: string
  max_connections?: number
}

// Server Settings
export interface ServerSettings {
  http: ListenerConfig
  socks5: ListenerConfig
  graceful_period?: string
}

// Health Check Configuration
export interface HealthCheckConfig {
  type: 'tcp' | 'http' | 'ping'
  interval: string
  timeout: string
  target?: string
  path?: string
}

// Backend Configuration
export interface BackendConfig {
  name: string
  type: 'direct' | 'wireguard' | 'openvpn' | 'http_proxy' | 'socks5_proxy'
  enabled: boolean
  priority: number
  weight: number
  config?: Record<string, unknown>
  health_check?: HealthCheckConfig
}

// Backend type-specific configs
export interface WireGuardPeerConfig {
  public_key: string
  endpoint: string
  preshared_key?: string
  allowed_ips: string[]
  persistent_keepalive?: number
}

export interface WireGuardBackendConfig {
  private_key: string
  address: string
  dns?: string[]
  mtu?: number
  peer: WireGuardPeerConfig
}

export interface OpenVPNBackendConfig {
  config_file: string
  auth_file?: string
  binary?: string
  management_addr?: string
  management_port?: number
  connect_timeout?: string
  extra_args?: string[]
}

export interface ProxyBackendConfig {
  address: string
  username?: string
  password?: string
  connect_timeout?: string
}

export interface DirectBackendConfig {
  connect_timeout?: string
  keep_alive?: string
  local_addr?: string
}

// Route Configuration
export interface RouteConfig {
  name?: string
  domains: string[]
  backend?: string
  backends?: string[]
  priority: number
  load_balance?: 'round_robin' | 'least_conn' | 'ip_hash' | 'weighted'
}

// Native User
export interface NativeUser {
  username: string
  password_hash: string
}

// Native Authentication
export interface NativeAuth {
  users: NativeUser[]
}

// System Authentication (PAM)
export interface SystemAuth {
  service?: string
  allowed_users?: string[]
  allowed_groups?: string[]
}

// LDAP Authentication
export interface LDAPAuth {
  url: string
  base_dn: string
  bind_dn: string
  bind_password: string
  user_filter: string
  group_filter?: string
  require_group?: string
  tls: boolean
  insecure_skip_verify: boolean
}

// OAuth Authentication
export interface OAuthAuth {
  provider: string
  client_id: string
  client_secret: string
  issuer_url: string
  redirect_url: string
  scopes: string[]
}

// Auth Provider (for multiple auth backends)
export interface AuthProvider {
  name: string
  type: 'none' | 'native' | 'system' | 'ldap' | 'oauth'
  enabled: boolean
  priority: number
  native?: NativeAuth
  system?: SystemAuth
  ldap?: LDAPAuth
  oauth?: OAuthAuth
}

// Auth Configuration
export interface AuthConfig {
  // Legacy single-mode (backwards compatible)
  mode?: 'none' | 'native' | 'system' | 'ldap' | 'oauth'
  native?: NativeAuth
  system?: SystemAuth
  ldap?: LDAPAuth
  oauth?: OAuthAuth
  // New multi-provider configuration
  providers?: AuthProvider[]
}

// Bandwidth Configuration
export interface BandwidthConfig {
  enabled: boolean
  upload: string
  download: string
}

// Rate Limit Configuration
export interface RateLimitConfig {
  enabled: boolean
  requests_per_second: number
  burst_size: number
  per_ip: boolean
  per_user: boolean
  bandwidth?: BandwidthConfig
}

// Auto Update Configuration
export interface AutoUpdateConfig {
  enabled: boolean
  check_interval: string
  channel: 'stable' | 'prerelease'
}

// Cache Configuration
export interface MemoryStorageConfig {
  max_size: string
  max_entries: number
  evict_policy: 'lru' | 'lfu' | 'fifo'
}

export interface DiskStorageConfig {
  path: string
  max_size: string
  cleanup_interval: string
  shard_count?: number
}

export interface TieredStorageConfig {
  memory_threshold: string
}

export interface CacheStorageConfig {
  type: 'memory' | 'disk' | 'tiered'
  tiered?: TieredStorageConfig
  memory?: MemoryStorageConfig
  disk?: DiskStorageConfig
}

export interface CacheRuleConfig {
  name: string
  domains: string[]
  enabled: boolean
  ttl: string
  max_size?: string
  priority: number
  methods?: string[]
  content_types?: string[]
  ignore_query?: boolean
  respect_cache_control?: boolean
  strip_headers?: string[]
}

export interface CacheConfig {
  enabled: boolean
  default_ttl: string
  max_file_size: string
  storage: CacheStorageConfig
  presets?: string[]
  rules?: CacheRuleConfig[]
}

// Access Log Configuration
export interface AccessLogConfig {
  enabled: boolean
  format: 'json' | 'apache'
  output: string
}

// Metrics Configuration
export interface MetricsConfig {
  enabled: boolean
  listen: string
  path: string
  collection_interval?: string
}

// Logging Configuration
export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error'
  format: 'text' | 'json'
  output?: string
  time_format?: string
}

// Web UI Configuration
export interface WebUIConfig {
  enabled: boolean
  listen: string
  base_path?: string
}

// API Configuration
export interface APIConfig {
  enabled: boolean
  listen: string
  token?: string
  enable_request_log?: boolean
  request_log_size?: number
  websocket_max_clients?: number
}

// Full Server Configuration
export interface ServerConfig {
  server: ServerSettings
  backends: BackendConfig[]
  routes: RouteConfig[]
  auth: AuthConfig
  rate_limit: RateLimitConfig
  access_log: AccessLogConfig
  metrics: MetricsConfig
  logging: LoggingConfig
  web_ui: WebUIConfig
  api: APIConfig
  health_check?: HealthCheckConfig
  auto_update: AutoUpdateConfig
  cache: CacheConfig
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

// Connection tracking
export interface Connection {
  id: string
  client_ip: string
  client_port: string
  host: string
  backend: string
  protocol: string
  start_time: string
  bytes_sent: number
  bytes_recv: number
}

export interface ConnectionsResponse {
  connections: Connection[]
  count: number
  time: string
}

export interface ClientSummary {
  client_ip: string
  connections: number
  bytes_sent: number
  bytes_recv: number
  first_seen: string
}

export interface ClientsResponse {
  clients: ClientSummary[]
  count: number
  time: string
}

// WebSocket events
export interface WSEvent {
  type: 'stats' | 'backend_status' | 'config_reload' | 'request'
  data: unknown
}
