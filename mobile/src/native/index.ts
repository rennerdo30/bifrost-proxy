// Native bridge barrel.
//
// Re-exports the on-device native VPN bridge. See ./BifrostVpn.ts and
// mobile/README.md for the build/integration status (currently a documented
// scaffold; the native module is not yet linked).

export {
  BifrostVpn,
  isNativeVpnAvailable,
  isNativeVpnUsable,
  NATIVE_DATA_PATH_IS_SECURE,
} from './BifrostVpn'
export type {
  NativeVpnConfig,
  NativeVpnStatus,
  NativeVpnState,
  NativeVpnStateEvent,
} from './BifrostVpn'

import { BifrostVpn } from './BifrostVpn'
import type { NativeVpnConfig } from './BifrostVpn'

/**
 * Decide which VPN path to use.
 *
 * Returns 'native' only when the on-device native VPN module is linked into the
 * running build *and* its data path is a real secure tunnel; otherwise 'server'
 * so the app falls back to the client/server REST VPN flow (api.enableVPN /
 * api.disableVPN).
 *
 * The second condition is what keeps this honest. The native forwarders are
 * currently raw-UDP placeholders, and merely applying the config plugin would
 * make the module linked -- so gating on "linked" alone would silently route
 * user traffic over an insecure link labelled VPN. See
 * NATIVE_DATA_PATH_IS_SECURE in ./BifrostVpn.
 */
export function selectVpnMode(): 'native' | 'server' {
  return BifrostVpn.isUsable() ? 'native' : 'server'
}

/**
 * Build the native tunnel config from a "host:port" server address string,
 * matching the format validated by services/api.validateServerAddress.
 *
 * Returns null if the address cannot be parsed into host[:port].
 */
export function buildNativeVpnConfig(
  serverAddress: string,
  overrides?: Partial<NativeVpnConfig>
): NativeVpnConfig | null {
  const trimmed = serverAddress.trim()
  if (!trimmed) return null

  const parts = trimmed.split(':')
  const host = parts[0]?.trim()
  if (!host) return null

  let port: number | undefined
  if (parts.length > 1) {
    const parsed = parseInt(parts[1], 10)
    if (Number.isNaN(parsed) || parsed < 1 || parsed > 65535) return null
    port = parsed
  }

  return {
    serverAddress: host,
    serverPort: port,
    ...overrides,
  }
}
