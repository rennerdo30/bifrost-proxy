import type { VersionInfo, StatusResponse, DebugEntry, Route, RouteTestResult } from './types'

const API_BASE = '/api/v1'

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, options)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

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
