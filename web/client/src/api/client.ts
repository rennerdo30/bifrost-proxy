import type { VersionInfo, StatusResponse, DebugEntry, Route, RouteTestResult } from './types'

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
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
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
}
