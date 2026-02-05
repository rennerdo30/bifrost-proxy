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

// Cache Types
export interface CacheStats {
  enabled: boolean
  storage_type: string
  entries: number
  total_size_bytes: number
  max_size_bytes: number
  used_percent: number
  hit_count: number
  miss_count: number
  hit_rate: number
  eviction_count: number
  rules_count: number
  presets_count: number
  custom_rules_count: number
}

export interface CacheEntry {
  key: string
  url: string
  host: string
  content_length: number
  content_type: string
  created_at: string
  expires_at: string
  accessed_at: string
  access_count: number
  size_bytes: number
  tier: string
  ttl_seconds: number
}

export interface CacheEntriesResponse {
  entries: CacheEntry[]
  total: number
  limit: number
  offset: number
}

// Mesh Types
export interface MeshStatus {
  status: string
  enabled: boolean
  peer_id?: string
  virtual_ip?: string
  network_id?: string
  network_cidr?: string
  peer_name?: string
  peer_count: number
  connected_peers: number
  direct_connections: number
  relayed_connections: number
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  uptime?: string
}

export interface MeshStats {
  status: string
  peer_count: number
  connected_peers: number
  direct_connections: number
  relayed_connections: number
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  uptime: number
}

export interface MeshPeer {
  id: string
  name: string
  virtual_ip?: string
  virtual_mac?: string
  public_key?: string
  status: string
  connection_type?: string
  latency_ms: number
  last_seen: string
  joined_at: string
  bytes_sent: number
  bytes_received: number
  endpoints?: MeshEndpoint[]
  metadata?: Record<string, string>
}

export interface MeshEndpoint {
  address: string
  port: number
  type: string
  priority: number
}

export interface MeshRoute {
  dest_peer_id: string
  dest_ip?: string
  next_hop?: string
  type: string
  metric: number
  latency_ms: number
  hop_count: number
  last_updated: string
  active: boolean
}

export interface MeshNetwork {
  network_id: string
  network_cidr: string
  peer_name: string
  local_peer_id: string
  virtual_ip: string
}
