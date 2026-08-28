// Storage service for persisting app configuration

import AsyncStorage from '@react-native-async-storage/async-storage'

const STORAGE_KEYS = {
  SERVER_URL: '@bifrost/server_url',
  SERVER_NAME: '@bifrost/server_name',
  API_TOKEN: '@bifrost/api_token',
  SPLIT_TUNNEL_CONFIG: '@bifrost/split_tunnel_config',
} as const

export interface StoredServerConfig {
  url: string
  name?: string
}

/**
 * Get the stored server URL from AsyncStorage
 */
export async function getStoredServerUrl(): Promise<string | null> {
  try {
    return await AsyncStorage.getItem(STORAGE_KEYS.SERVER_URL)
  } catch (error) {
    console.error('Failed to get stored server URL:', error)
    return null
  }
}

/**
 * Store the server URL in AsyncStorage
 */
export async function setStoredServerUrl(url: string): Promise<void> {
  try {
    await AsyncStorage.setItem(STORAGE_KEYS.SERVER_URL, url)
  } catch (error) {
    console.error('Failed to store server URL:', error)
    throw error
  }
}

/**
 * Get the stored server name from AsyncStorage
 */
export async function getStoredServerName(): Promise<string | null> {
  try {
    return await AsyncStorage.getItem(STORAGE_KEYS.SERVER_NAME)
  } catch (error) {
    console.error('Failed to get stored server name:', error)
    return null
  }
}

/**
 * Store the server name in AsyncStorage
 */
export async function setStoredServerName(name: string): Promise<void> {
  try {
    await AsyncStorage.setItem(STORAGE_KEYS.SERVER_NAME, name)
  } catch (error) {
    console.error('Failed to store server name:', error)
    throw error
  }
}

/**
 * Get complete stored server configuration
 */
export async function getStoredServerConfig(): Promise<StoredServerConfig | null> {
  try {
    const url = await getStoredServerUrl()
    if (!url) return null

    const name = await getStoredServerName()
    return { url, name: name || undefined }
  } catch (error) {
    console.error('Failed to get stored server config:', error)
    return null
  }
}

/**
 * Clear stored server configuration
 */
export async function clearStoredServerConfig(): Promise<void> {
  try {
    await AsyncStorage.multiRemove([STORAGE_KEYS.SERVER_URL, STORAGE_KEYS.SERVER_NAME])
  } catch (error) {
    console.error('Failed to clear stored server config:', error)
    throw error
  }
}

// API token
//
// The Bifrost client API is guarded by a bearer token whenever `api.token` is
// configured on the client. The token is a credential: it is never written to a
// log, and error messages below deliberately carry no value.

/**
 * Get the stored API bearer token, or null when none is configured.
 */
export async function getStoredAPIToken(): Promise<string | null> {
  try {
    return await AsyncStorage.getItem(STORAGE_KEYS.API_TOKEN)
  } catch (error) {
    console.error('Failed to read stored API token:', error)
    return null
  }
}

/**
 * Store the API bearer token. An empty value clears it.
 */
export async function setStoredAPIToken(token: string): Promise<void> {
  try {
    if (token) {
      await AsyncStorage.setItem(STORAGE_KEYS.API_TOKEN, token)
    } else {
      await AsyncStorage.removeItem(STORAGE_KEYS.API_TOKEN)
    }
  } catch (error) {
    console.error('Failed to store API token:', error)
    throw error
  }
}

/**
 * Clear the stored API bearer token.
 */
export async function clearStoredAPIToken(): Promise<void> {
  try {
    await AsyncStorage.removeItem(STORAGE_KEYS.API_TOKEN)
  } catch (error) {
    console.error('Failed to clear stored API token:', error)
    throw error
  }
}

// Split Tunneling Configuration

export interface SplitTunnelApp {
  name: string
  packageId: string
  enabled: boolean
}

export interface SplitTunnelDomain {
  domain: string
  enabled: boolean
}

export interface SplitTunnelIP {
  cidr: string
  enabled: boolean
}

export interface StoredSplitTunnelConfig {
  mode: 'exclude' | 'include'
  apps: SplitTunnelApp[]
  domains: SplitTunnelDomain[]
  ips: SplitTunnelIP[]
}

const DEFAULT_SPLIT_TUNNEL_CONFIG: StoredSplitTunnelConfig = {
  mode: 'exclude',
  apps: [],
  domains: [],
  ips: [],
}

/**
 * Get stored split tunnel configuration
 */
export async function getStoredSplitTunnelConfig(): Promise<StoredSplitTunnelConfig> {
  try {
    const stored = await AsyncStorage.getItem(STORAGE_KEYS.SPLIT_TUNNEL_CONFIG)
    if (stored) {
      return JSON.parse(stored) as StoredSplitTunnelConfig
    }
    return DEFAULT_SPLIT_TUNNEL_CONFIG
  } catch (error) {
    console.error('Failed to get stored split tunnel config:', error)
    return DEFAULT_SPLIT_TUNNEL_CONFIG
  }
}

/**
 * Store split tunnel configuration
 */
export async function setStoredSplitTunnelConfig(config: StoredSplitTunnelConfig): Promise<void> {
  try {
    await AsyncStorage.setItem(STORAGE_KEYS.SPLIT_TUNNEL_CONFIG, JSON.stringify(config))
  } catch (error) {
    console.error('Failed to store split tunnel config:', error)
    throw error
  }
}

/**
 * Clear split tunnel configuration
 */
export async function clearStoredSplitTunnelConfig(): Promise<void> {
  try {
    await AsyncStorage.removeItem(STORAGE_KEYS.SPLIT_TUNNEL_CONFIG)
  } catch (error) {
    console.error('Failed to clear split tunnel config:', error)
    throw error
  }
}
