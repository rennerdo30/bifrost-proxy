// Shared test helpers.
//
// The services under test import React Native modules that cannot be loaded in
// plain Node, so `@react-native-async-storage/async-storage` is replaced with an
// in-memory stand-in before the modules are imported.

import { mock } from 'node:test'

export interface FakeAsyncStorage {
  store: Map<string, string>
  getItem(key: string): Promise<string | null>
  setItem(key: string, value: string): Promise<void>
  removeItem(key: string): Promise<void>
  multiRemove(keys: string[]): Promise<void>
  clear(): Promise<void>
}

export function createFakeAsyncStorage(): FakeAsyncStorage {
  const store = new Map<string, string>()
  return {
    store,
    async getItem(key) {
      return store.has(key) ? (store.get(key) as string) : null
    },
    async setItem(key, value) {
      store.set(key, value)
    },
    async removeItem(key) {
      store.delete(key)
    },
    async multiRemove(keys) {
      for (const key of keys) store.delete(key)
    },
    async clear() {
      store.clear()
    },
  }
}

/** Install the in-memory AsyncStorage. Must run before importing the services. */
export function mockAsyncStorage(): FakeAsyncStorage {
  const fake = createFakeAsyncStorage()
  mock.module('@react-native-async-storage/async-storage', {
    defaultExport: fake,
  })
  return fake
}

export interface RecordedRequest {
  url: string
  method: string
  headers: Record<string, string>
  body?: string
}

export interface FetchStub {
  requests: RecordedRequest[]
  restore(): void
}

interface FetchStubOptions {
  status?: number
  body?: unknown
  statusText?: string
}

/**
 * Replace the global fetch with a recorder that answers every call with the
 * given JSON payload. Returns the recorded requests.
 */
export function stubFetch(options: FetchStubOptions = {}): FetchStub {
  const status = options.status ?? 200
  const payload = JSON.stringify(options.body ?? { status: 'ok' })
  const original = globalThis.fetch
  const requests: RecordedRequest[] = []

  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const headers: Record<string, string> = {}
    const rawHeaders = (init?.headers ?? {}) as Record<string, string>
    for (const [key, value] of Object.entries(rawHeaders)) {
      headers[key] = value
    }
    requests.push({
      url: String(input),
      method: init?.method ?? 'GET',
      headers,
      body: typeof init?.body === 'string' ? init.body : undefined,
    })
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: options.statusText ?? '',
      async json() {
        return JSON.parse(payload)
      },
      async text() {
        return payload
      },
    }
  }) as typeof globalThis.fetch

  return {
    requests,
    restore() {
      globalThis.fetch = original
    },
  }
}
