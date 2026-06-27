// Native bridge barrel.
//
// Re-exports the on-device native VPN bridge. See ./BifrostVpn.ts and
// mobile/README.md for the build/integration status (currently a documented
// scaffold; the native module is not yet linked).

export {
  BifrostVpn,
  isNativeVpnAvailable,
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
 * Returns 'native' only when the on-device native VPN module is actually linked
 * into the running build; otherwise 'server' so the app falls back to the
 * existing client/server REST VPN flow (api.enableVPN / api.disableVPN).
 *
 * NOTE: even when 'native' is returned, the current native data path is a
 * raw-UDP placeholder, not a secure tunnel (see README). Callers should treat
 * the native path as experimental and keep it opt-in until the real
 * WireGuard/OpenVPN integration lands.
 */
export function selectVpnMode(): 'native' | 'server' {
  return BifrostVpn.isAvailable() ? 'native' : 'server'
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
