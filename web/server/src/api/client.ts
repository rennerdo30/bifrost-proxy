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
  ConfigMetaResponse,
  ConfigSaveRequest,
  ConfigSaveResponse,
  ConfigValidateResponse,
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
  AuthPluginsResponse,
  MeshPeersResponse,
  MeshPeerInfo,
  RegisterMeshPeerRequest,
  RegisterMeshPeerResponse,
  UpdateMeshPeerRequest,
} from './types'

// Base path of the SPA — everything in window.location.pathname stripped
// of trailing slashes. With HashRouter, pathname only ever contains the
// reverse-proxy mount point (the SPA's own route lives in the URL hash),
// so this is the right prefix to put in front of API calls. Works behind
// Home Assistant Ingress (/api/hassio_ingress/<token>), Traefik sub-paths,
// nginx subpaths, Cloudflare Tunnel sub-domains — and a no-op (empty
// string) when served at the host root.
export const BASE_PATH = window.location.pathname.replace(/\/+$/, '')
const API_BASE = `${BASE_PATH}/api/v1`
const DEFAULT_TIMEOUT = 30000 // 30 seconds

/** HTTP status chi returns for a path that has no handler registered. */
const HTTP_NOT_FOUND = 404
const HTTP_STATUS_UNAUTHORIZED = 401
/** The login endpoint answers this when no session store is configured. */
const HTTP_STATUS_SERVICE_UNAVAILABLE = 503

class APIError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message)
    this.name = 'APIError'
  }
}

/**
 * True when a request failed because the endpoint is not mounted at all.
 *
 * Whole API groups are registered conditionally by the server: /cache/* only
 * when a `cache:` section is configured, /mesh/* only when `mesh.enabled` is
 * true (internal/api/server/server.go). On such a server every call in the
 * group 404s forever, so a 404 there means "this feature is not configured",
 * not "this item does not exist" — and the UI must say so instead of rendering
 * an empty list.
 */
export function isFeatureUnavailable(error: unknown): boolean {
  return error instanceof APIError && error.status === HTTP_NOT_FOUND
}

/** Attempts a failing query makes before giving up (react-query's default). */
const MAX_QUERY_RETRIES = 3

/**
 * react-query retry policy that gives up immediately on an unmounted
 * endpoint. Retrying cannot make a conditionally mounted route appear, and the
 * default backoff would delay the "not configured" banner by several seconds
 * while the page shows loading skeletons.
 */
export function retryUnlessUnavailable(failureCount: number, error: unknown): boolean {
  return !isFeatureUnavailable(error) && failureCount < MAX_QUERY_RETRIES
}

/** Fired when the server rejects our credential, so the shell can prompt. */
export const UNAUTHORIZED_EVENT = 'bifrost:unauthorized'

function onUnauthorized() {
  if (localStorage.getItem(SESSION_STORAGE_KEY) === '1') {
    localStorage.removeItem(SESSION_STORAGE_KEY)
  }
  window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
}

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  // Once the token has been exchanged for an HttpOnly session cookie the token
  // is no longer stored, and the cookie the browser sends is the credential.
  const token = getApiToken()
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
      // Send the session cookie. Same-origin by default, but explicit so the
      // credential is not dropped if the dashboard is ever served cross-origin.
      credentials: 'same-origin',
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    if (!res.ok) {
      if (res.status === HTTP_STATUS_UNAUTHORIZED) {
        // A session cookie expires. Drop the stale "signed in" marker and let
        // the shell prompt for the token again, rather than leaving every page
        // showing a bare error the operator cannot act on.
        onUnauthorized()
      }
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
  getConfigMeta: () => fetchJSON<ConfigMetaResponse>('/config/meta'),
  saveConfig: (request: ConfigSaveRequest) =>
    fetchJSON<ConfigSaveResponse>('/config/', {
      method: 'PUT',
      body: JSON.stringify(request),
    }),
  validateConfig: (config: ServerConfig) =>
    fetchJSON<ConfigValidateResponse>('/config/validate', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
  reloadConfig: () =>
    fetchJSON<{ message: string; time: string }>('/config/reload', {
      method: 'POST',
    }),

  // Auth plugins — which providers this server build can actually
  // authenticate with (see AuthPluginInfo).
  getAuthPlugins: () => fetchJSON<AuthPluginsResponse>('/auth/plugins'),

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

// ---------------------------------------------------------------------------
// Credentials
//
// Two mechanisms, in order of preference:
//
//   1. A session cookie, obtained by POSTing the API token to /login. The
//      cookie is HttpOnly, so script cannot read it and an XSS cannot exfiltrate
//      it. The token itself is then NOT persisted.
//   2. The raw API token in localStorage, sent as `Authorization: Bearer`. This
//      is the fallback for servers with no `session:` block configured, where
//      /login answers 503.
//
// Mechanism 1 is what the server's login endpoint was built for; the dashboard
// previously only ever did 2, keeping a long-lived credential where any injected
// script could read it.
// ---------------------------------------------------------------------------

const TOKEN_STORAGE_KEY = 'bifrost_api_token'
const SESSION_STORAGE_KEY = 'bifrost_session_active'

/** True when a session cookie was successfully established. */
export function hasSession(): boolean {
  return localStorage.getItem(SESSION_STORAGE_KEY) === '1'
}

export function setApiToken(token: string) {
  localStorage.setItem(TOKEN_STORAGE_KEY, token)
}

export function getApiToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY)
}

export function clearApiToken() {
  localStorage.removeItem(TOKEN_STORAGE_KEY)
  localStorage.removeItem(SESSION_STORAGE_KEY)
}

export interface LoginOutcome {
  /** 'session': cookie established, token discarded. 'token': falling back to bearer. */
  mode: 'session' | 'token'
  expiresAt?: string
}

/**
 * Exchange an API token for a session cookie.
 *
 * On success the token is deliberately *not* written to localStorage — the
 * cookie is the credential from then on. When the server has no session store
 * configured it answers 503, and we fall back to persisting the bearer token so
 * the dashboard keeps working; that is a weaker posture, and `mode` reports it
 * so the UI can say so.
 *
 * A wrong token throws, and nothing is persisted.
 */
export async function login(token: string): Promise<LoginOutcome> {
  const res = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    credentials: 'same-origin',
    body: JSON.stringify({ token }),
  })

  // 503 means "endpoint exists, feature disabled". 404 is tolerated too, for a
  // server built before /login was mounted unconditionally — there the route
  // simply did not exist when no session store was configured.
  if (res.status === HTTP_STATUS_SERVICE_UNAVAILABLE || res.status === HTTP_NOT_FOUND) {
    // No session store on this server: fall back to the bearer token.
    setApiToken(token)
    localStorage.removeItem(SESSION_STORAGE_KEY)
    return { mode: 'token' }
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new APIError(res.status, text || `Login failed with status ${res.status}`)
  }

  const body = (await res.json().catch(() => ({}))) as { expires_at?: string }

  // The cookie is now the credential; do not keep the token around.
  localStorage.removeItem(TOKEN_STORAGE_KEY)
  localStorage.setItem(SESSION_STORAGE_KEY, '1')
  return { mode: 'session', expiresAt: body.expires_at }
}

/** Destroy the server-side session and forget every local credential. */
export async function logout(): Promise<void> {
  try {
    await fetch(`${API_BASE}/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      credentials: 'same-origin',
    })
  } finally {
    clearApiToken()
  }
}

export { APIError }
