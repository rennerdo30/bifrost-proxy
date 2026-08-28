import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  reconcileSplitTunnelConfig,
  replaceRemoteSplitTunnelConfig,
  type SplitTunnelRemoteAPI,
} from '../splitTunnelSync.ts'
import type { SplitTunnelConfig } from '../api.ts'
import type { StoredSplitTunnelConfig } from '../storage.ts'

const localConfig: StoredSplitTunnelConfig = {
  mode: 'exclude',
  apps: [
    { name: 'Browser', packageId: '/apps/browser', enabled: true },
    { name: 'Parked', packageId: '/apps/parked', enabled: false },
  ],
  domains: [
    { domain: 'local.example', enabled: true },
    { domain: 'parked.example', enabled: false },
  ],
  ips: [
    { cidr: '10.0.0.0/8', enabled: true },
    { cidr: '192.168.0.0/16', enabled: false },
  ],
}

describe('reconcileSplitTunnelConfig', () => {
  it('imports remote truth and preserves absent local rules as disabled', () => {
    const remote: SplitTunnelConfig = {
      mode: 'include',
      apps: [
        { name: 'Browser', path: '/remote/browser' },
        { name: 'RemoteOnly', path: '/remote/only' },
      ],
      domains: ['local.example', 'remote.example'],
      ips: ['10.0.0.0/8', '203.0.113.7/32'],
    }

    const reconciled = reconcileSplitTunnelConfig(localConfig, remote)

    assert.equal(reconciled.mode, 'include')
    assert.deepEqual(reconciled.apps, [
      { name: 'Browser', packageId: '/remote/browser', enabled: true },
      { name: 'RemoteOnly', packageId: '/remote/only', enabled: true },
      { name: 'Parked', packageId: '/apps/parked', enabled: false },
    ])
    assert.deepEqual(reconciled.domains, [
      { domain: 'local.example', enabled: true },
      { domain: 'remote.example', enabled: true },
      { domain: 'parked.example', enabled: false },
    ])
    assert.deepEqual(reconciled.ips, [
      { cidr: '10.0.0.0/8', enabled: true },
      { cidr: '203.0.113.7/32', enabled: true },
      { cidr: '192.168.0.0/16', enabled: false },
    ])
  })
})

function recordingAPI(remote: SplitTunnelConfig) {
  const calls: string[] = []
  const api: SplitTunnelRemoteAPI = {
    async getSplitTunnelRules() {
      calls.push('get')
      return remote
    },
    async setSplitTunnelMode(mode) {
      calls.push(`mode:${mode}`)
    },
    async addSplitTunnelApp(app) {
      calls.push(`add-app:${app.name}:${app.path || ''}`)
    },
    async removeSplitTunnelApp(name) {
      calls.push(`remove-app:${name}`)
    },
    async addSplitTunnelDomain(domain) {
      calls.push(`add-domain:${domain}`)
    },
    async removeSplitTunnelDomain(domain) {
      calls.push(`remove-domain:${domain}`)
    },
    async addSplitTunnelIP(cidr) {
      calls.push(`add-ip:${cidr}`)
    },
    async removeSplitTunnelIP(cidr) {
      calls.push(`remove-ip:${cidr}`)
    },
  }
  return { api, calls }
}

describe('replaceRemoteSplitTunnelConfig', () => {
  it('removes stale rules, replaces changed app paths, and adds missing rules', async () => {
    const remote: SplitTunnelConfig = {
      mode: 'include',
      apps: [
        { name: 'Browser', path: '/old/browser' },
        { name: 'Stale', path: '/apps/stale' },
      ],
      domains: ['stale.example'],
      ips: ['198.51.100.0/24'],
    }
    const { api, calls } = recordingAPI(remote)

    await replaceRemoteSplitTunnelConfig(api, localConfig)

    assert.deepEqual(calls, [
      'get',
      'remove-app:Browser',
      'remove-app:Stale',
      'add-app:Browser:/apps/browser',
      'remove-domain:stale.example',
      'add-domain:local.example',
      'remove-ip:198.51.100.0/24',
      'add-ip:10.0.0.0/8',
      'mode:exclude',
    ])
  })

  it('aborts at the first failed operation and reports which policy step failed', async () => {
    const remote: SplitTunnelConfig = {
      mode: 'exclude',
      apps: [{ name: 'Stale' }],
      domains: [],
      ips: [],
    }
    const { api, calls } = recordingAPI(remote)
    api.removeSplitTunnelApp = async (name) => {
      calls.push(`remove-app:${name}`)
      throw new Error('client rejected removal')
    }

    await assert.rejects(
      replaceRemoteSplitTunnelConfig(api, localConfig),
      /Failed to remove remote app rule "Stale": client rejected removal/
    )
    assert.deepEqual(calls, ['get', 'remove-app:Stale'])
  })
})
