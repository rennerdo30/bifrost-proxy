import { after, before, beforeEach, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { mockAsyncStorage, stubFetch, type FakeAsyncStorage } from './helpers.ts'

const storageMock: FakeAsyncStorage = mockAsyncStorage()

type ApiModule = typeof import('../api.ts')
let apiModule: ApiModule

before(async () => {
  apiModule = await import('../api.ts')
})

beforeEach(() => {
  storageMock.store.clear()
  apiModule.resetAPIConfigForTesting()
})

describe('CSRF header', () => {
  // internal/api/client/server.go rejects every POST/PUT/DELETE/PATCH that does
  // not carry X-Requested-With: XMLHttpRequest with 403.
  const mutations: [string, () => Promise<unknown>][] = [
    ['enableVPN', () => apiModule.api.enableVPN()],
    ['disableVPN', () => apiModule.api.disableVPN()],
    ['selectServer', () => apiModule.api.selectServer('eu-west')],
    ['updateConfig', () => apiModule.api.updateConfig({ vpn: { enabled: true, mode: 'tun' } })],
    ['clearCache', () => apiModule.api.clearCache()],
    ['setSplitTunnelMode', () => apiModule.api.setSplitTunnelMode('exclude')],
    ['addSplitTunnelApp', () => apiModule.api.addSplitTunnelApp({ name: 'slack' })],
    ['removeSplitTunnelApp', () => apiModule.api.removeSplitTunnelApp('slack')],
    ['addSplitTunnelDomain', () => apiModule.api.addSplitTunnelDomain('example.com')],
    ['removeSplitTunnelDomain', () => apiModule.api.removeSplitTunnelDomain('example.com')],
    ['addSplitTunnelIP', () => apiModule.api.addSplitTunnelIP('10.0.0.0/8')],
    ['removeSplitTunnelIP', () => apiModule.api.removeSplitTunnelIP('10.0.0.0/8')],
  ]

  for (const [name, call] of mutations) {
    it(`${name} sends X-Requested-With: XMLHttpRequest`, async () => {
      const fetchStub = stubFetch()
      try {
        await call()
      } finally {
        fetchStub.restore()
      }
      assert.equal(fetchStub.requests.length, 1)
      assert.equal(fetchStub.requests[0].headers['X-Requested-With'], 'XMLHttpRequest')
    })
  }

  it('sends the header on reads too, matching both web dashboards', async () => {
    const fetchStub = stubFetch({ body: { status: 'running' } })
    try {
      await apiModule.api.getStatus()
    } finally {
      fetchStub.restore()
    }
    assert.equal(fetchStub.requests[0].headers['X-Requested-With'], 'XMLHttpRequest')
  })
})

describe('server selection', () => {
  it('posts the server name to /server/select', async () => {
    const fetchStub = stubFetch({ body: { status: 'selected', server: 'eu-west' } })
    try {
      await apiModule.api.selectServer('eu-west')
    } finally {
      fetchStub.restore()
    }

    const request = fetchStub.requests[0]
    assert.equal(request.url, 'http://localhost:7383/api/v1/server/select')
    assert.equal(request.method, 'POST')
    assert.deepEqual(JSON.parse(request.body as string), { server: 'eu-west' })
  })

  it('does not use the non-existent /servers/{id}/select route', async () => {
    const fetchStub = stubFetch()
    try {
      await apiModule.api.selectServer('eu-west')
    } finally {
      fetchStub.restore()
    }
    assert.ok(!/\/servers\/[^/]+\/select$/.test(fetchStub.requests[0].url))
  })
})

describe('split tunneling request bodies', () => {
  // internal/api/client/server.go decodes exact JSON keys and 400s on a miss;
  // header-only assertions let a wrong body ("domain" instead of "pattern")
  // stay green while every rule add failed against a real client.
  it('adds a domain rule with the "pattern" key the handler decodes', async () => {
    const fetchStub = stubFetch({ body: { status: 'added' } })
    try {
      await apiModule.api.addSplitTunnelDomain('*.example.com')
    } finally {
      fetchStub.restore()
    }
    const request = fetchStub.requests[0]
    assert.equal(request.url, 'http://localhost:7383/api/v1/vpn/split/domains')
    assert.equal(request.method, 'POST')
    assert.deepEqual(JSON.parse(request.body as string), { pattern: '*.example.com' })
  })

  it('adds an IP rule with the "cidr" key', async () => {
    const fetchStub = stubFetch({ body: { status: 'added' } })
    try {
      await apiModule.api.addSplitTunnelIP('10.0.0.0/8')
    } finally {
      fetchStub.restore()
    }
    assert.deepEqual(JSON.parse(fetchStub.requests[0].body as string), { cidr: '10.0.0.0/8' })
  })

  it('adds an app rule with the "name"/"path" keys', async () => {
    const fetchStub = stubFetch({ body: { status: 'added' } })
    try {
      await apiModule.api.addSplitTunnelApp({ name: 'slack' })
    } finally {
      fetchStub.restore()
    }
    assert.deepEqual(JSON.parse(fetchStub.requests[0].body as string), { name: 'slack' })
  })
})

describe('authentication', () => {
  it('omits Authorization when no token is configured', async () => {
    const fetchStub = stubFetch()
    try {
      await apiModule.api.getStatus()
    } finally {
      fetchStub.restore()
    }
    assert.equal(fetchStub.requests[0].headers['Authorization'], undefined)
    assert.equal(apiModule.hasAPIToken(), false)
  })

  it('persists a token and sends it as a bearer credential', async () => {
    await apiModule.setAPIToken('  s3cret-token  ')
    assert.equal(apiModule.hasAPIToken(), true)

    const fetchStub = stubFetch()
    try {
      await apiModule.api.getStatus()
    } finally {
      fetchStub.restore()
    }
    assert.equal(fetchStub.requests[0].headers['Authorization'], 'Bearer s3cret-token')
  })

  it('loads the persisted token on startup', async () => {
    await apiModule.setAPIToken('stored-token')
    apiModule.resetAPIConfigForTesting()
    assert.equal(apiModule.hasAPIToken(), false)

    await apiModule.initializeAPIConfig()
    assert.equal(apiModule.hasAPIToken(), true)

    const fetchStub = stubFetch()
    try {
      await apiModule.api.getStatus()
    } finally {
      fetchStub.restore()
    }
    assert.equal(fetchStub.requests[0].headers['Authorization'], 'Bearer stored-token')
  })

  it('clears the token when set to an empty value', async () => {
    await apiModule.setAPIToken('stored-token')
    await apiModule.setAPIToken('')
    assert.equal(apiModule.hasAPIToken(), false)

    apiModule.resetAPIConfigForTesting()
    await apiModule.initializeAPIConfig()
    assert.equal(apiModule.hasAPIToken(), false)
  })

  it('surfaces a 401 as an unauthorized APIError', async () => {
    const fetchStub = stubFetch({ status: 401, body: 'Unauthorized' })
    try {
      await assert.rejects(
        () => apiModule.api.getStatus(),
        (err: unknown) => {
          assert.ok(err instanceof apiModule.APIError)
          assert.equal(err.status, apiModule.HTTP_STATUS_UNAUTHORIZED)
          assert.equal(err.isUnauthorized, true)
          return true
        }
      )
    } finally {
      fetchStub.restore()
    }
  })

  it('reports an unreachable client as a network APIError', async () => {
    const original = globalThis.fetch
    globalThis.fetch = (async () => {
      throw new TypeError('Network request failed')
    }) as typeof globalThis.fetch
    try {
      await assert.rejects(
        () => apiModule.api.getStatus(),
        (err: unknown) => {
          assert.ok(err instanceof apiModule.APIError)
          assert.equal(err.isNetworkError, true)
          return true
        }
      )
    } finally {
      globalThis.fetch = original
    }
  })
})

describe('server address handling', () => {
  it('defaults a bare host:port to http', async () => {
    await apiModule.setServerUrl('192.168.1.20:7383')
    assert.equal(apiModule.getAPIConfig().baseUrl, 'http://192.168.1.20:7383/api/v1')
  })

  it('honors an explicit https scheme', async () => {
    await apiModule.setServerUrl('https://client.example.com:7383')
    assert.equal(apiModule.getAPIConfig().baseUrl, 'https://client.example.com:7383/api/v1')
  })

  it('omits the implicit port for https', async () => {
    await apiModule.setServerUrl('https://client.example.com')
    assert.equal(apiModule.getAPIConfig().baseUrl, 'https://client.example.com/api/v1')
  })

  it('persists the resolved base URL', async () => {
    await apiModule.setServerUrl('https://client.example.com:8443')
    assert.equal(
      storageMock.store.get('@bifrost/server_url'),
      'https://client.example.com:8443/api/v1'
    )
  })

  it('accepts bracketed IPv6 literals', () => {
    const parsed = apiModule.parseServerAddress('[fd00::1]:7383')
    assert.ok('address' in parsed)
    assert.equal(apiModule.buildBaseUrl(parsed.address), 'http://[fd00::1]:7383/api/v1')
  })

  it('rejects an unsupported scheme', () => {
    assert.match(apiModule.validateServerAddress('ftp://host:21') ?? '', /Unsupported scheme/)
  })

  it('rejects an out-of-range port', () => {
    assert.match(apiModule.validateServerAddress('host:70000') ?? '', /Port must be between/)
  })

  it('rejects a non-numeric port', () => {
    assert.match(apiModule.validateServerAddress('host:abc') ?? '', /Port must be between/)
  })

  it('rejects an empty address', () => {
    assert.match(apiModule.validateServerAddress('   ') ?? '', /required/)
  })

  it('round-trips an https base URL back into the input form', () => {
    assert.equal(
      apiModule.extractServerAddress('https://client.example.com:8443/api/v1'),
      'https://client.example.com:8443'
    )
  })

  it('round-trips an http base URL as bare host:port', () => {
    assert.equal(
      apiModule.extractServerAddress('http://192.168.1.20:7383/api/v1'),
      '192.168.1.20:7383'
    )
  })
})

describe('formatUptime', () => {
  // vpn.VPNStats.Uptime is a Go time.Duration and marshals to nanoseconds.
  it('converts nanoseconds to a human-readable duration', () => {
    assert.equal(apiModule.formatUptime(45 * 1_000_000_000), '45s')
    assert.equal(apiModule.formatUptime(90 * 1_000_000_000), '1m 30s')
    assert.equal(apiModule.formatUptime(3 * 3600 * 1_000_000_000 + 25 * 60 * 1_000_000_000), '3h 25m')
  })

  it('returns null when there is no session', () => {
    assert.equal(apiModule.formatUptime(0), null)
    assert.equal(apiModule.formatUptime(undefined), null)
  })
})

describe('formatBytes', () => {
  it('formats byte counts', () => {
    assert.equal(apiModule.formatBytes(0), '0 B')
    assert.equal(apiModule.formatBytes(1536), '1.5 KB')
  })

  it('clamps beyond the largest known unit', () => {
    assert.equal(apiModule.formatBytes(Math.pow(1024, 6)), '1,048,576 TB')
  })
})

after(() => {
  apiModule.resetAPIConfigForTesting()
})
