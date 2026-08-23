// API service for communicating with Bifrost client

import {
  getStoredAPIToken,
  getStoredServerUrl,
  setStoredAPIToken,
  setStoredServerUrl,
} from './storage'

const DEFAULT_TIMEOUT = 10000

/** Path prefix of the Bifrost client REST API. */
const API_PATH = '/api/v1'

/** Supported URL schemes for reaching a Bifrost client. */
export const HTTP_SCHEME = 'http'
export const HTTPS_SCHEME = 'https'

/** Scheme assumed when the operator types a bare `host:port`. */
const DEFAULT_SCHEME = HTTP_SCHEME

/** Default listen address of a local Bifrost client. */
const DEFAULT_HOST = 'localhost'
const DEFAULT_PORT = 7383

/** Well-known ports that are implied by their scheme and therefore omitted. */
const IMPLICIT_PORTS: Record<string, number> = {
  [HTTP_SCHEME]: 80,
  [HTTPS_SCHEME]: 443,
}

const MIN_PORT = 1
const MAX_PORT = 65535

const DEFAULT_BASE_URL = `${DEFAULT_SCHEME}://${DEFAULT_HOST}:${DEFAULT_PORT}${API_PATH}`

/**
 * CSRF protection. `internal/api/client/server.go` rejects every
 * POST/PUT/DELETE/PATCH that does not carry this header with 403, so it must be
 * sent on every request - exactly as both web dashboards do.
 */
const CSRF_HEADER = 'X-Requested-With'
const CSRF_HEADER_VALUE = 'XMLHttpRequest'

const CONTENT_TYPE_HEADER = 'Content-Type'
const CONTENT_TYPE_JSON = 'application/json'
const AUTHORIZATION_HEADER = 'Authorization'

/** HTTP status codes the app reacts to specifically. */
export const HTTP_STATUS_UNAUTHORIZED = 401
export const HTTP_STATUS_FORBIDDEN = 403

/** Status used for failures that never reached the server (timeouts, DNS, ...). */
export const HTTP_STATUS_NETWORK_ERROR = 0

/** `vpn.VPNStats.Uptime` is a Go `time.Duration`, which marshals to nanoseconds. */
const NANOSECONDS_PER_SECOND = 1_000_000_000

const BYTES_PER_UNIT = 1024
const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600

interface APIConfig {
  baseUrl: string
  token?: string
}

let config: APIConfig = {
  baseUrl: DEFAULT_BASE_URL,
}

let isInitialized = false

/**
 * Error carrying the HTTP status of a failed request so callers can tell an
 * authentication problem apart from an unreachable client.
 */
export class APIError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'APIError'
    this.status = status
  }

  /** True when the client rejected the request because the token is missing or wrong. */
  get isUnauthorized(): boolean {
    return this.status === HTTP_STATUS_UNAUTHORIZED
  }

  /** True when the request never reached the client. */
  get isNetworkError(): boolean {
    return this.status === HTTP_STATUS_NETWORK_ERROR
  }
}

/**
 * Initialize the API config from stored settings.
 * Should be called once when the app starts.
 */
export async function initializeAPIConfig(): Promise<void> {
  if (isInitialized) return

  try {
    const storedUrl = await getStoredServerUrl()
    if (storedUrl) {
      config.baseUrl = storedUrl
    }
    const storedToken = await getStoredAPIToken()
    if (storedToken) {
      config.token = storedToken
    }
    isInitialized = true
  } catch (error) {
    console.error('Failed to initialize API config:', error)
    isInitialized = true
  }
}

/**
 * Check if the API has been initialized
 */
export function isAPIInitialized(): boolean {
  return isInitialized
}

/** Test hook: reset module state so each test starts from the defaults. */
export function resetAPIConfigForTesting(): void {
  config = { baseUrl: DEFAULT_BASE_URL }
  isInitialized = false
}

export function setAPIConfig(newConfig: Partial<APIConfig>) {
  config = { ...config, ...newConfig }
}

export function getAPIConfig(): APIConfig {
  return { ...config }
}

/** True when an API token is configured. Never returns the token itself. */
export function hasAPIToken(): boolean {
  return !!config.token
}

/**
 * Update and persist the API bearer token. An empty value clears it.
 * The token is a credential and is never logged.
 */
export async function setAPIToken(token: string): Promise<void> {
  const trimmed = token.trim()
  setAPIConfig({ token: trimmed || undefined })
  await setStoredAPIToken(trimmed)
}

export interface ParsedServerAddress {
  scheme: typeof HTTP_SCHEME | typeof HTTPS_SCHEME
  host: string
  port: number
}

/**
 * Parse an operator-supplied client address.
 *
 * Accepts `host:port`, `host` (default port), and either form prefixed with
 * `http://` or `https://`. Returns the parsed parts or a human-readable error.
 */
export function parseServerAddress(
  input: string
): { address: ParsedServerAddress } | { error: string } {
  const raw = input.trim()
  if (!raw) {
    return { error: 'Server address is required' }
  }

  let scheme: ParsedServerAddress['scheme'] = DEFAULT_SCHEME
  let remainder = raw

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/.exec(raw)
  if (schemeMatch) {
    const candidate = schemeMatch[1].toLowerCase()
    if (candidate !== HTTP_SCHEME && candidate !== HTTPS_SCHEME) {
      return { error: `Unsupported scheme "${candidate}". Use ${HTTP_SCHEME}:// or ${HTTPS_SCHEME}://` }
    }
    scheme = candidate
    remainder = schemeMatch[2]
  }

  // Drop any path/query the operator pasted along with the host.
  remainder = remainder.split('/')[0].split('?')[0]
  if (!remainder) {
    return { error: 'Host cannot be empty' }
  }

  let host = remainder
  let port = scheme === HTTPS_SCHEME ? IMPLICIT_PORTS[HTTPS_SCHEME] : DEFAULT_PORT

  if (remainder.startsWith('[')) {
    // Bracketed IPv6 literal, optionally followed by :port
    const closing = remainder.indexOf(']')
    if (closing < 0) {
      return { error: 'Unterminated IPv6 address - expected a closing "]"' }
    }
    host = remainder.slice(0, closing + 1)
    const rest = remainder.slice(closing + 1)
    if (rest) {
      if (!rest.startsWith(':')) {
        return { error: 'Address must be in host:port format (e.g., example.com:7383)' }
      }
      const parsed = parsePort(rest.slice(1))
      if ('error' in parsed) return parsed
      port = parsed.port
    }
  } else {
    const colonCount = (remainder.match(/:/g) || []).length
    if (colonCount > 1) {
      return { error: 'Wrap IPv6 addresses in brackets (e.g., [::1]:7383)' }
    }
    if (colonCount === 1) {
      const [hostPart, portPart] = remainder.split(':')
      if (!hostPart) {
        return { error: 'Host cannot be empty' }
      }
      host = hostPart
      const parsed = parsePort(portPart)
      if ('error' in parsed) return parsed
      port = parsed.port
    }
  }

  if (!host.trim()) {
    return { error: 'Host cannot be empty' }
  }

  return { address: { scheme, host, port } }
}

function parsePort(value: string): { port: number } | { error: string } {
  if (!/^\d+$/.test(value)) {
    return { error: `Port must be between ${MIN_PORT} and ${MAX_PORT}` }
  }
  const port = parseInt(value, 10)
  if (port < MIN_PORT || port > MAX_PORT) {
    return { error: `Port must be between ${MIN_PORT} and ${MAX_PORT}` }
  }
  return { port }
}

/** Build the API base URL for a parsed address. */
export function buildBaseUrl(address: ParsedServerAddress): string {
  const implicitPort = IMPLICIT_PORTS[address.scheme]
  const authority = address.port === implicitPort ? address.host : `${address.host}:${address.port}`
  return `${address.scheme}://${authority}${API_PATH}`
}

/**
 * Update and persist the server URL.
 *
 * Accepts `host:port` (plain HTTP) as well as an explicit `https://host:port`,
 * so the app can also manage a TLS-terminated client.
 */
export async function setServerUrl(serverAddress: string): Promise<void> {
  const parsed = parseServerAddress(serverAddress)
  if ('error' in parsed) {
    throw new Error(parsed.error)
  }
  const baseUrl = buildBaseUrl(parsed.address)
  setAPIConfig({ baseUrl })
  await setStoredServerUrl(baseUrl)
}

/**
 * Get the default base URL
 */
export function getDefaultBaseUrl(): string {
  return DEFAULT_BASE_URL
}

/**
 * Render a base URL back into the form the Settings field accepts:
 * `host:port` for plain HTTP, `https://host:port` when TLS is in use.
 */
export function extractServerAddress(baseUrl: string): string {
  let scheme = DEFAULT_SCHEME
  let authority: string

  try {
    const url = new URL(baseUrl)
    scheme = url.protocol.replace(':', '') === HTTPS_SCHEME ? HTTPS_SCHEME : HTTP_SCHEME
    authority = url.port ? `${url.hostname}:${url.port}` : url.hostname
  } catch {
    // Fallback: try to parse manually
    const match = baseUrl.match(/^(?:([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)?([^/]+)/)
    if (!match) {
      return `${DEFAULT_HOST}:${DEFAULT_PORT}`
    }
    if (match[1]?.toLowerCase() === HTTPS_SCHEME) {
      scheme = HTTPS_SCHEME
    }
    authority = match[2]
  }

  return scheme === HTTPS_SCHEME ? `${HTTPS_SCHEME}://${authority}` : authority
}

/**
 * Get the current connected server info from config
 */
export function getCurrentServerAddress(): string {
  return extractServerAddress(config.baseUrl)
}

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

  try {
    const headers: Record<string, string> = {
      [CONTENT_TYPE_HEADER]: CONTENT_TYPE_JSON,
      // Required by the client API's CSRF middleware on every mutating request.
      [CSRF_HEADER]: CSRF_HEADER_VALUE,
    }

    if (config.token) {
      headers[AUTHORIZATION_HEADER] = `Bearer ${config.token}`
    }

    const res = await fetch(`${config.baseUrl}${path}`, {
      ...options,
      headers: { ...headers, ...options?.headers },
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
    if (err instanceof APIError) {
      throw err
    }
    if (err instanceof Error && err.name === 'AbortError') {
      throw new APIError(
        HTTP_STATUS_NETWORK_ERROR,
        'Request timed out. Check your connection and try again.'
      )
    }
    throw new APIError(
      HTTP_STATUS_NETWORK_ERROR,
      err instanceof Error ? err.message : 'Network error - check your connection'
    )
  }
}

// Types

/**
 * Response of `GET /api/v1/status`, mirroring the map built by
 * `(*API).handleStatus` in `internal/api/client/server.go`.
 */
export interface StatusResponse {
  status: string
  version: string
  server_connected: boolean
  server_address: string
  http_proxy: string
  socks5_proxy: string
  vpn_enabled: boolean
  vpn_status: VPNStatusValue
  debug_entries: number
  /** Human-readable Go duration string, e.g. "1h2m3s". */
  uptime: string
  bytes_sent: number
  bytes_received: number
  active_connections: number
  timestamp: string
}

/** Mirrors `vpn.Status` in `internal/vpn/vpn.go`. */
export type VPNStatusValue = 'disabled' | 'connecting' | 'connected' | 'disconnected' | 'error'

/**
 * Response of `GET /api/v1/vpn/status`, mirroring `vpn.VPNStats`.
 * Every field here exists on the wire - do not add speculative ones.
 */
export interface VPNStatus {
  status: VPNStatusValue
  /** Go `time.Duration`: nanoseconds. Use {@link formatUptime}. */
  uptime: number
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  active_connections: number
  tunneled_connections: number
  bypassed_connections: number
  dns_queries: number
  dns_cache_hits: number
  last_error?: string
  last_error_time?: string
}

/** Mirrors `client.ServerInfo`. Note: the server emits no `id`. */
export interface ServerInfo {
  name: string
  address: string
  protocol: string
  is_default: boolean
  latency_ms?: number
  status: 'online' | 'offline' | 'busy' | 'unknown'
}

export interface AppRule {
  name: string
  path?: string
}

/**
 * Response of `GET /api/v1/vpn/split/rules`, per the documented snake_case
 * contract in `docs/src/content/docs/api/client.mdx`.
 */
export interface SplitTunnelConfig {
  mode: string
  apps: AppRule[]
  domains: string[]
  ips: string[]
  always_bypass?: string[]
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
      body: JSON.stringify(app),
    }),
  removeSplitTunnelApp: (name: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/apps/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  setSplitTunnelMode: (mode: 'exclude' | 'include') =>
    fetchJSON<{ status: string }>('/vpn/split/mode', {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    }),
  addSplitTunnelDomain: (domain: string) =>
    fetchJSON<{ status: string }>('/vpn/split/domains', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),
  removeSplitTunnelDomain: (domain: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/domains/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
  addSplitTunnelIP: (cidr: string) =>
    fetchJSON<{ status: string }>('/vpn/split/ips', {
      method: 'POST',
      body: JSON.stringify({ cidr }),
    }),
  removeSplitTunnelIP: (cidr: string) =>
    fetchJSON<{ status: string }>(`/vpn/split/ips/${encodeURIComponent(cidr)}`, { method: 'DELETE' }),

  // Config
  getConfig: () => fetchJSON<ClientConfig>('/config'),
  updateConfig: (updates: Partial<ClientConfig>) =>
    fetchJSON<{ status: string }>('/config', {
      method: 'PUT',
      body: JSON.stringify(updates),
    }),
  reloadConfig: () => fetchJSON<{ status: string }>('/config/reload', { method: 'POST' }),

  // Servers
  getServers: () => fetchJSON<ServerInfo[]>('/servers'),
  getActiveServer: async (): Promise<ServerInfo | null> => {
    const servers = await fetchJSON<ServerInfo[]>('/servers')
    return servers.find((s) => s.is_default) || servers[0] || null
  },
  /**
   * Select a configured server by name.
   * Route: `POST /api/v1/server/select` with `{"server": "<name>"}`.
   */
  selectServer: (name: string) =>
    fetchJSON<{ status: string; server: string }>('/server/select', {
      method: 'POST',
      body: JSON.stringify({ server: name }),
    }),

  // Connection management
  connect: () => fetchJSON<{ status: string }>('/connect', { method: 'POST' }),
  disconnect: () => fetchJSON<{ status: string }>('/disconnect', { method: 'POST' }),

  // Data management
  clearCache: () => fetchJSON<{ status: string }>('/debug/entries', { method: 'DELETE' }),

  // Connection testing
  testConnection: async (): Promise<{ success: boolean; error?: string }> => {
    try {
      await fetchJSON<{ status: string }>('/health')
      return { success: true }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Connection failed',
      }
    }
  },
}

// Utility functions
export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B'
  const exponent = Math.min(
    Math.floor(Math.log(bytes) / Math.log(BYTES_PER_UNIT)),
    BYTE_UNITS.length - 1
  )
  const value = bytes / Math.pow(BYTES_PER_UNIT, exponent)
  return `${parseFloat(value.toFixed(1))} ${BYTE_UNITS[exponent]}`
}

export function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / SECONDS_PER_HOUR)
  const minutes = Math.floor((seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE)
  const secs = Math.floor(seconds % SECONDS_PER_MINUTE)

  if (hours > 0) {
    return `${hours}h ${minutes}m`
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`
  }
  return `${secs}s`
}

/**
 * Format `vpn.VPNStats.uptime`, which arrives as a Go `time.Duration`
 * (nanoseconds), as a human-readable session length.
 */
export function formatUptime(nanoseconds: number | undefined): string | null {
  if (nanoseconds == null || !Number.isFinite(nanoseconds) || nanoseconds <= 0) {
    return null
  }
  return formatDuration(nanoseconds / NANOSECONDS_PER_SECOND)
}

/**
 * Validate a server address. Returns an error message, or null when valid.
 */
export function validateServerAddress(address: string): string | null {
  const parsed = parseServerAddress(address)
  return 'error' in parsed ? parsed.error : null
}
