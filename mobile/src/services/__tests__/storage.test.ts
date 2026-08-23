import { before, beforeEach, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { mockAsyncStorage, type FakeAsyncStorage } from './helpers.ts'

const storageMock: FakeAsyncStorage = mockAsyncStorage()

const API_TOKEN_KEY = '@bifrost/api_token'

type StorageModule = typeof import('../storage.ts')
let storage: StorageModule

before(async () => {
  storage = await import('../storage.ts')
})

beforeEach(() => {
  storageMock.store.clear()
})

describe('API token persistence', () => {
  it('returns null when nothing is stored', async () => {
    assert.equal(await storage.getStoredAPIToken(), null)
  })

  it('round-trips a token', async () => {
    await storage.setStoredAPIToken('abc123')
    assert.equal(storageMock.store.get(API_TOKEN_KEY), 'abc123')
    assert.equal(await storage.getStoredAPIToken(), 'abc123')
  })

  it('removes the key when given an empty value', async () => {
    await storage.setStoredAPIToken('abc123')
    await storage.setStoredAPIToken('')
    assert.equal(storageMock.store.has(API_TOKEN_KEY), false)
    assert.equal(await storage.getStoredAPIToken(), null)
  })

  it('clears the token explicitly', async () => {
    await storage.setStoredAPIToken('abc123')
    await storage.clearStoredAPIToken()
    assert.equal(await storage.getStoredAPIToken(), null)
  })

  it('keeps the token out of the server config keys', async () => {
    await storage.setStoredServerUrl('http://localhost:7383/api/v1')
    await storage.setStoredAPIToken('abc123')
    await storage.clearStoredServerConfig()

    // Clearing the server address must not silently drop the credential.
    assert.equal(await storage.getStoredAPIToken(), 'abc123')
    assert.equal(await storage.getStoredServerUrl(), null)
  })
})

describe('server URL persistence', () => {
  it('round-trips a URL', async () => {
    await storage.setStoredServerUrl('https://client.example.com/api/v1')
    assert.equal(await storage.getStoredServerUrl(), 'https://client.example.com/api/v1')
  })
})

describe('split tunnel persistence', () => {
  it('returns defaults when nothing is stored', async () => {
    const config = await storage.getStoredSplitTunnelConfig()
    assert.deepEqual(config, { mode: 'exclude', apps: [], domains: [], ips: [] })
  })

  it('round-trips a config', async () => {
    const config = {
      mode: 'include' as const,
      apps: [{ name: 'Slack', packageId: 'com.slack', enabled: true }],
      domains: [{ domain: 'example.com', enabled: false }],
      ips: [{ cidr: '10.0.0.0/8', enabled: true }],
    }
    await storage.setStoredSplitTunnelConfig(config)
    assert.deepEqual(await storage.getStoredSplitTunnelConfig(), config)
  })

  it('falls back to defaults on corrupt JSON', async () => {
    storageMock.store.set('@bifrost/split_tunnel_config', '{not json')
    const config = await storage.getStoredSplitTunnelConfig()
    assert.equal(config.mode, 'exclude')
  })
})
