// BifrostVpn.ts
//
// JavaScript bridge to the on-device native VPN implementations:
//   - iOS:     ios/BifrostVPN/PacketTunnelProvider.swift (NEPacketTunnelProvider)
//   - Android: android/app/src/main/java/com/bifrost/vpn/BifrostVpnService.kt (VpnService)
//
// IMPORTANT (security / status):
//   The native modules referenced here are NOT yet built or linked. They require
//   platform-specific toolchains and a config plugin to register the iOS Network
//   Extension target and the Android <service>/permissions (see mobile/README.md).
//   Until then, `isNativeVpnAvailable()` returns false and the public methods
//   resolve to inert no-ops so the JS/TS app keeps building and running.
//
//   The current native packet forwarders are RAW-UDP PLACEHOLDERS, not a secure
//   tunnel. They must be replaced with a real WireGuard/OpenVPN data path
//   (e.g. wireguard-go via gomobile, or the WireGuardKit / wireguard-android
//   libraries) before being shipped or enabled by default. Do not present the
//   native path as "secure" until that work lands and is validated on-device.

import { NativeModules, NativeEventEmitter, Platform } from 'react-native'

/**
 * Configuration handed to the native tunnel providers.
 *
 * Mirrors the keys consumed by:
 *   - PacketTunnelProvider.swift  (providerConfiguration)
 *   - BifrostVpnService.kt        (intent extras)
 */
export interface NativeVpnConfig {
  /** Server host (without port), e.g. "vpn.example.com". */
  serverAddress: string
  /** Server UDP port. Defaults to 51820 (WireGuard) on the native side. */
  serverPort?: number
  /** Local tunnel address assigned to the device, e.g. "10.0.0.2". */
  tunnelAddress?: string
  /** DNS servers to push into the tunnel. */
  dnsServers?: string[]
  /** Tunnel MTU. Defaults to 1420 on the native side. */
  mtu?: number
}

/** Snapshot of the native tunnel state. */
export interface NativeVpnStatus {
  connected: boolean
  serverAddress: string
  tunnelAddress: string
  bytesIn: number
  bytesOut: number
}

/** Lifecycle states emitted by the native modules (when available). */
export type NativeVpnState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'disconnecting'
  | 'error'

export interface NativeVpnStateEvent {
  state: NativeVpnState
  error?: string
}

/**
 * Shape of the TurboModule / NativeModule that the platform code must expose.
 * Android: a ReactContextBaseJavaModule named "BifrostVpn".
 * iOS:     an RCTBridgeModule named "BifrostVpn".
 *
 * This interface documents the contract the native side must satisfy; it is the
 * spec for the not-yet-built native module.
 */
interface BifrostVpnNativeModule {
  /**
   * Request VPN permission from the OS (Android: VpnService.prepare();
   * iOS: NETunnelProviderManager save/load). Resolves true if granted.
   */
  requestPermission(): Promise<boolean>
  /** Start the on-device tunnel with the given config. */
  start(config: NativeVpnConfig): Promise<void>
  /** Stop the on-device tunnel. */
  stop(): Promise<void>
  /** Fetch the current native tunnel status. */
  getStatus(): Promise<NativeVpnStatus>
}

const LINK_HINT =
  'Native VPN module is not linked. See mobile/README.md for the iOS Network ' +
  'Extension / Android VpnService build steps.'

const nativeModule: BifrostVpnNativeModule | undefined =
  (NativeModules as Record<string, BifrostVpnNativeModule | undefined>).BifrostVpn

/**
 * Whether the on-device native VPN module is actually linked into this build.
 *
 * Returns false in Expo Go, in the current scaffold (no config plugin applied),
 * and on web. Callers MUST gate any native VPN usage behind this check and fall
 * back to the server-side/client REST VPN flow otherwise.
 */
export function isNativeVpnAvailable(): boolean {
  return Platform.OS !== 'web' && nativeModule != null
}

let eventEmitter: NativeEventEmitter | null = null

function getEmitter(): NativeEventEmitter | null {
  if (!isNativeVpnAvailable()) return null
  if (eventEmitter == null) {
    // nativeModule is non-null here per isNativeVpnAvailable().
    eventEmitter = new NativeEventEmitter(
      nativeModule as unknown as ConstructorParameters<typeof NativeEventEmitter>[0]
    )
  }
  return eventEmitter
}

const DISCONNECTED_STATUS: NativeVpnStatus = {
  connected: false,
  serverAddress: '',
  tunnelAddress: '',
  bytesIn: 0,
  bytesOut: 0,
}

/**
 * Public bridge surface. When the native module is unavailable, methods are
 * safe no-ops (or rejected promises with a clear hint) so the rest of the app
 * keeps functioning against the existing server-side VPN REST API.
 */
export const BifrostVpn = {
  isAvailable: isNativeVpnAvailable,

  async requestPermission(): Promise<boolean> {
    if (!isNativeVpnAvailable()) return false
    return nativeModule!.requestPermission()
  },

  async start(config: NativeVpnConfig): Promise<void> {
    if (!isNativeVpnAvailable()) {
      throw new Error(LINK_HINT)
    }
    if (!config.serverAddress) {
      throw new Error('serverAddress is required to start the native VPN')
    }
    return nativeModule!.start(config)
  },

  async stop(): Promise<void> {
    if (!isNativeVpnAvailable()) return
    return nativeModule!.stop()
  },

  async getStatus(): Promise<NativeVpnStatus> {
    if (!isNativeVpnAvailable()) return { ...DISCONNECTED_STATUS }
    return nativeModule!.getStatus()
  },

  /**
   * Subscribe to native tunnel state changes. Returns an unsubscribe function.
   * No-op (returns a no-op unsubscribe) when the native module is unavailable.
   */
  addStateListener(listener: (event: NativeVpnStateEvent) => void): () => void {
    const emitter = getEmitter()
    if (emitter == null) {
      return () => {}
    }
    const subscription = emitter.addListener('BifrostVpnStateChanged', listener)
    return () => subscription.remove()
  },
}

export default BifrostVpn
