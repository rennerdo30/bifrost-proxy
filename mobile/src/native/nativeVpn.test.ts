// Tests for the native VPN capability gate.
//
// The point of this file is the invariant in `refuses to route traffic over the
// placeholder data path`: linking the native module must NOT be sufficient to
// carry user traffic, because the native forwarders are raw-UDP placeholders.
// The gate is a code path, not a comment, so it is testable -- and these
// assertions fail the moment NATIVE_DATA_PATH_IS_SECURE is flipped, which is
// the deliberate acknowledgement that a real tunnel has landed.

import { describe, it, mock, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

/** Mutable stand-in for react-native's NativeModules registry. */
const nativeModules: Record<string, unknown> = {}

/** Records what the "native" side was actually asked to do. */
interface NativeCalls {
  start: unknown[]
  stop: number
  requestPermission: number
}

const calls: NativeCalls = { start: [], stop: 0, requestPermission: 0 }

const platform = { OS: 'ios' as string }

class FakeNativeEventEmitter {
  addListener(): { remove(): void } {
    return { remove() {} }
  }
}

// `namedExports` is deprecated in favour of `exports` at runtime, but the
// pinned @types/node does not declare `exports` on MockModuleOptions yet, and
// `npm run typecheck` is a gate. Switch when the types catch up.
mock.module('react-native', {
  namedExports: {
    NativeModules: nativeModules,
    NativeEventEmitter: FakeNativeEventEmitter,
    Platform: platform,
  },
})

const { BifrostVpn, isNativeVpnAvailable, isNativeVpnUsable, NATIVE_DATA_PATH_IS_SECURE } =
  await import('./BifrostVpn.ts')
const { selectVpnMode } = await import('./index.ts')

/** Install a fake linked native module, as a config plugin would. */
function linkNativeModule(): void {
  nativeModules.BifrostVpn = {
    async requestPermission() {
      calls.requestPermission += 1
      return true
    },
    async start(config: unknown) {
      calls.start.push(config)
    },
    async stop() {
      calls.stop += 1
    },
    async getStatus() {
      return {
        connected: true,
        serverAddress: 'vpn.example',
        tunnelAddress: '10.0.0.2',
        bytesIn: 1,
        bytesOut: 2,
      }
    },
  }
}

function unlinkNativeModule(): void {
  delete nativeModules.BifrostVpn
}

beforeEach(() => {
  unlinkNativeModule()
  platform.OS = 'ios'
  calls.start = []
  calls.stop = 0
  calls.requestPermission = 0
})

describe('native VPN capability gate', () => {
  it('declares the placeholder data path insecure', () => {
    assert.equal(
      NATIVE_DATA_PATH_IS_SECURE,
      false,
      'NATIVE_DATA_PATH_IS_SECURE must stay false while the native forwarders ' +
        'are raw-UDP placeholders. If a real, on-device-validated ' +
        'WireGuard/OpenVPN data path has landed, update this file together ' +
        'with the flag -- do not flip the flag alone.'
    )
  })

  it('refuses to route traffic over the placeholder data path', async () => {
    linkNativeModule()

    // The module is linked, so "is it available?" is now true...
    assert.equal(isNativeVpnAvailable(), true)

    // ...but that must not be enough to use it.
    assert.equal(isNativeVpnUsable(), false)
    assert.equal(selectVpnMode(), 'server')

    await assert.rejects(
      () => BifrostVpn.start({ serverAddress: 'vpn.example' }),
      /raw-UDP placeholder/
    )
    assert.deepEqual(calls.start, [], 'the native side must never be asked to start')
  })

  it('does not prompt for OS tunnel permission it cannot honour', async () => {
    linkNativeModule()

    assert.equal(await BifrostVpn.requestPermission(), false)
    assert.equal(
      calls.requestPermission,
      0,
      'no OS permission prompt for a tunnel that will refuse to start'
    )
  })

  it('reports the module unavailable when it is not linked', async () => {
    assert.equal(isNativeVpnAvailable(), false)
    assert.equal(isNativeVpnUsable(), false)
    assert.equal(selectVpnMode(), 'server')

    await assert.rejects(
      () => BifrostVpn.start({ serverAddress: 'vpn.example' }),
      /not linked/
    )
  })

  it('reports the module unavailable on web even when linked', () => {
    linkNativeModule()
    platform.OS = 'web'

    assert.equal(isNativeVpnAvailable(), false)
    assert.equal(selectVpnMode(), 'server')
  })

  it('keeps stop and getStatus safe no-ops when unavailable', async () => {
    await BifrostVpn.stop()
    assert.equal(calls.stop, 0)

    const status = await BifrostVpn.getStatus()
    assert.equal(status.connected, false)
    assert.equal(status.bytesIn, 0)
  })

  it('still forwards stop to a linked module so a tunnel can always be torn down', async () => {
    linkNativeModule()

    await BifrostVpn.stop()
    assert.equal(calls.stop, 1, 'stop must reach the native side regardless of the gate')
  })

  it('resolves the native module lazily, not at import time', () => {
    // The module was absent when this file first imported the bridge; linking it
    // afterwards must still be observed.
    assert.equal(isNativeVpnAvailable(), false)
    linkNativeModule()
    assert.equal(isNativeVpnAvailable(), true)
  })
})
