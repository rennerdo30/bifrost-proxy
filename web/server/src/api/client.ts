import type {
  Backend,
  BackendConfig,
  ServerStats,
  HealthResponse,
  StatusResponse,
  VersionInfo,
  RequestLogResponse,
  RequestLogStats,
  ServerConfig,
  ConfigMeta,
  ConfigSaveRequest,
  ConfigSaveResponse,
  ConnectionsResponse,
  ClientsResponse,
  AddBackendResponse,
  RemoveBackendResponse,
  TestBackendRequest,
  TestBackendResponse,
  CacheStatsResponse,
  CacheEntriesResponse,
  CacheEntryMetadata,
  CacheRulesResponse,
  CachePresetsResponse,
  CacheMessageResponse,
  AddCacheRuleRequest,
  MeshNetworksResponse,
  MeshNetwork,
  CreateMeshNetworkRequest,
  MeshPeersResponse,
  MeshPeerInfo,
  RegisterMeshPeerRequest,
  RegisterMeshPeerResponse,
  UpdateMeshPeerRequest,
} from './types'

const API_BASE = '/api/v1'
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
  const token = localStorage.getItem('bifrost_api_token')
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest', // CSRF protection
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options?.headers,
  }

  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

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

export const api = {
  // Health & Status
  getHealth: () => fetchJSON<HealthResponse>('/health'),
  getStatus: () => fetchJSON<StatusResponse>('/status'),
  getVersion: () => fetchJSON<VersionInfo>('/version'),
  getStats: () => fetchJSON<ServerStats>('/stats'),

  // Backends
  listBackends: () => fetchJSON<Backend[]>('/backends/'),
  getBackend: (name: string) => fetchJSON<Backend>(`/backends/${encodeURIComponent(name)}`),
  getBackendStats: (name: string) => fetchJSON<Backend['stats']>(`/backends/${encodeURIComponent(name)}/stats`),
  addBackend: (config: BackendConfig) =>
    fetchJSON<AddBackendResponse>('/backends/', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
  removeBackend: (name: string) =>
    fetchJSON<RemoveBackendResponse>(`/backends/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),
  testBackend: (name: string, options?: TestBackendRequest) =>
    fetchJSON<TestBackendResponse>(`/backends/${encodeURIComponent(name)}/test`, {
      method: 'POST',
      body: options ? JSON.stringify(options) : undefined,
    }),

  // Request Log
  getRequests: (limit = 100, since?: number) => {
    const params = new URLSearchParams()
    if (limit) params.set('limit', String(limit))
    if (since) params.set('since', String(since))
    return fetchJSON<RequestLogResponse>(`/requests/?${params}`)
  },
  getRequestStats: () => fetchJSON<RequestLogStats>('/requests/stats'),
  clearRequests: () => fetchJSON<{ message: string }>('/requests/', { method: 'DELETE' }),

  // Config
  getConfig: () => fetchJSON<ServerConfig>('/config/'),
  getFullConfig: () => fetchJSON<ServerConfig>('/config/full'),
  getConfigMeta: () => fetchJSON<ConfigMeta>('/config/meta'),
  saveConfig: (request: ConfigSaveRequest) =>
    fetchJSON<ConfigSaveResponse>('/config/', {
      method: 'PUT',
      body: JSON.stringify(request),
    }),
  validateConfig: (config: ServerConfig) =>
    fetchJSON<{ valid: boolean; errors?: string[] }>('/config/validate', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
  reloadConfig: () =>
    fetchJSON<{ message: string; time: string }>('/config/reload', {
      method: 'POST',
    }),

  // Connections
  getConnections: () => fetchJSON<ConnectionsResponse>('/connections/'),
  getClients: () => fetchJSON<ClientsResponse>('/connections/clients'),

  // Cache
  getCacheStats: () => fetchJSON<CacheStatsResponse>('/cache/stats'),
  getCacheEntries: (options?: { domain?: string; offset?: number; limit?: number }) => {
    const params = new URLSearchParams()
    if (options?.domain) params.set('domain', options.domain)
    if (options?.offset !== undefined) params.set('offset', String(options.offset))
    if (options?.limit !== undefined) params.set('limit', String(options.limit))
    const query = params.toString()
    return fetchJSON<CacheEntriesResponse>(`/cache/entries${query ? `?${query}` : ''}`)
  },
  getCacheEntry: (key: string) =>
    fetchJSON<CacheEntryMetadata>(`/cache/entries/${encodeURIComponent(key)}`),
  deleteCacheEntry: (key: string) =>
    fetchJSON<CacheMessageResponse>(`/cache/entries/${encodeURIComponent(key)}`, {
      method: 'DELETE',
    }),
  clearCache: () =>
    fetchJSON<CacheMessageResponse>('/cache/entries?confirm=true', {
      method: 'DELETE',
    }),
  purgeDomain: (domain: string) =>
    fetchJSON<CacheMessageResponse>(`/cache/domain/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    }),
  getCacheRules: () => fetchJSON<CacheRulesResponse>('/cache/rules'),
  addCacheRule: (rule: AddCacheRuleRequest) =>
    fetchJSON<CacheMessageResponse>('/cache/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),
  updateCacheRule: (name: string, update: { enabled?: boolean }) =>
    fetchJSON<CacheMessageResponse>(`/cache/rules/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify(update),
    }),
  deleteCacheRule: (name: string) =>
    fetchJSON<CacheMessageResponse>(`/cache/rules/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),
  getCachePresets: () => fetchJSON<CachePresetsResponse>('/cache/presets'),
  enableCachePreset: (name: string) =>
    fetchJSON<CacheMessageResponse>(`/cache/presets/${encodeURIComponent(name)}/enable`, {
      method: 'POST',
    }),
  disableCachePreset: (name: string) =>
    fetchJSON<CacheMessageResponse>(`/cache/presets/${encodeURIComponent(name)}/disable`, {
      method: 'POST',
    }),

  // Mesh Networks
  listMeshNetworks: () => fetchJSON<MeshNetworksResponse>('/mesh/networks'),
  getMeshNetwork: (networkId: string) =>
    fetchJSON<MeshNetwork>(`/mesh/networks/${encodeURIComponent(networkId)}`),
  createMeshNetwork: (request: CreateMeshNetworkRequest) =>
    fetchJSON<MeshNetwork>('/mesh/networks', {
      method: 'POST',
      body: JSON.stringify(request),
    }),
  deleteMeshNetwork: (networkId: string) =>
    fetchJSON<void>(`/mesh/networks/${encodeURIComponent(networkId)}`, {
      method: 'DELETE',
    }),

  // Mesh Peers
  listMeshPeers: (networkId: string) =>
    fetchJSON<MeshPeersResponse>(`/mesh/networks/${encodeURIComponent(networkId)}/peers`),
  getMeshPeer: (networkId: string, peerId: string) =>
    fetchJSON<MeshPeerInfo>(
      `/mesh/networks/${encodeURIComponent(networkId)}/peers/${encodeURIComponent(peerId)}`
    ),
  registerMeshPeer: (networkId: string, request: RegisterMeshPeerRequest) =>
    fetchJSON<RegisterMeshPeerResponse>(
      `/mesh/networks/${encodeURIComponent(networkId)}/peers`,
      {
        method: 'POST',
        body: JSON.stringify(request),
      }
    ),
  updateMeshPeer: (networkId: string, peerId: string, request: UpdateMeshPeerRequest) =>
    fetchJSON<void>(
      `/mesh/networks/${encodeURIComponent(networkId)}/peers/${encodeURIComponent(peerId)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(request),
      }
    ),
  deregisterMeshPeer: (networkId: string, peerId: string) =>
    fetchJSON<void>(
      `/mesh/networks/${encodeURIComponent(networkId)}/peers/${encodeURIComponent(peerId)}`,
      {
        method: 'DELETE',
      }
    ),
  sendMeshHeartbeat: (networkId: string, peerId: string) =>
    fetchJSON<void>(
      `/mesh/networks/${encodeURIComponent(networkId)}/peers/${encodeURIComponent(peerId)}/heartbeat`,
      {
        method: 'POST',
      }
    ),
}

// Token management
export function setApiToken(token: string) {
  localStorage.setItem('bifrost_api_token', token)
}

export function getApiToken(): string | null {
  return localStorage.getItem('bifrost_api_token')
}

export function clearApiToken() {
  localStorage.removeItem('bifrost_api_token')
}

export { APIError }
