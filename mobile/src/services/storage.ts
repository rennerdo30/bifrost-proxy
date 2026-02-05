// Storage service for persisting app configuration

import AsyncStorage from '@react-native-async-storage/async-storage'

const STORAGE_KEYS = {
  SERVER_URL: '@bifrost/server_url',
  SERVER_NAME: '@bifrost/server_name',
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
