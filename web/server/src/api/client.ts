import type {
  Backend,
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
