import { createContext, useContext, useCallback, ReactNode } from 'react'
import type { ClientConfig } from '../../api/client'

interface SettingsContextType {
  config: ClientConfig | undefined
  pendingChanges: Partial<ClientConfig>
  getValue: <K extends keyof ClientConfig>(section: K, field: string, defaultValue?: unknown) => unknown
  getNestedValue: (section: keyof ClientConfig, path: string[], defaultValue?: unknown) => unknown
  updateField: <K extends keyof ClientConfig>(section: K, field: string, value: unknown) => void
  updateNestedField: (section: keyof ClientConfig, path: string[], value: unknown) => void
  setPendingChanges: React.Dispatch<React.SetStateAction<Partial<ClientConfig>>>
  setHasChanges: (hasChanges: boolean) => void
}

const SettingsContext = createContext<SettingsContextType | null>(null)

export function useSettings() {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider')
  return ctx
}

interface SettingsProviderProps {
  config: ClientConfig | undefined
  pendingChanges: Partial<ClientConfig>
  setPendingChanges: React.Dispatch<React.SetStateAction<Partial<ClientConfig>>>
  setHasChanges: (hasChanges: boolean) => void
  children: ReactNode
}

export function SettingsProvider({
  config,
  pendingChanges,
  setPendingChanges,
  setHasChanges,
  children,
}: SettingsProviderProps) {
  // Get current value (pending or config), for top-level section fields
  const getValue = useCallback(<K extends keyof ClientConfig>(
    section: K,
    field: string,
    defaultValue: unknown = ''
  ): unknown => {
    const pending = pendingChanges[section] as Record<string, unknown> | undefined
    if (pending && field in pending) {
      return pending[field]
    }
    const configSection = config?.[section] as Record<string, unknown> | undefined
    return configSection?.[field] ?? defaultValue
  }, [config, pendingChanges])

  // Get nested value that checks pendingChanges first, then config
  // e.g., getNestedValue('vpn', ['split_tunnel', 'mode'], 'exclude')
  const getNestedValue = useCallback((
    section: keyof ClientConfig,
    path: string[],
    defaultValue: unknown = ''
  ): unknown => {
    // Check pending changes first
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let pendingVal: any = pendingChanges[section]
    if (pendingVal !== undefined) {
      let found = true
      for (const key of path) {
        if (pendingVal && typeof pendingVal === 'object' && key in pendingVal) {
          pendingVal = pendingVal[key]
        } else {
          found = false
          break
        }
      }
      if (found && pendingVal !== undefined) return pendingVal
    }

    // Fall back to config
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let configVal: any = config?.[section]
    if (configVal !== undefined) {
      for (const key of path) {
        if (configVal && typeof configVal === 'object' && key in configVal) {
          configVal = configVal[key]
        } else {
          return defaultValue
        }
      }
      return configVal ?? defaultValue
    }

    return defaultValue
  }, [config, pendingChanges])

  // Update a top-level section field
  const updateField = useCallback(<K extends keyof ClientConfig>(
    section: K,
    field: string,
    value: unknown
  ) => {
    setPendingChanges(prev => {
      const newChanges = { ...prev }
      if (!newChanges[section]) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        newChanges[section] = {} as any
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (newChanges[section] as any)[field] = value
      return newChanges
    })
    setHasChanges(true)
  }, [setPendingChanges, setHasChanges])

  // Update a nested field within a section
  // e.g., updateNestedField('vpn', ['split_tunnel', 'mode'], 'include')
  const updateNestedField = useCallback((
    section: keyof ClientConfig,
    path: string[],
    value: unknown
  ) => {
    setPendingChanges(prev => {
      const newChanges = { ...prev }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (!newChanges[section]) newChanges[section] = {} as any

      if (path.length === 1) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (newChanges[section] as any)[path[0]] = value
      } else if (path.length === 2) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const sectionObj = newChanges[section] as any
        if (!sectionObj[path[0]]) {
          // Merge with existing config values
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const existing = (config as any)?.[section]?.[path[0]] || {}
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const prevSection = prev[section] as any
          sectionObj[path[0]] = { ...existing, ...(prevSection?.[path[0]] || {}) }
        }
        sectionObj[path[0]][path[1]] = value
      }

      return newChanges
    })
    setHasChanges(true)
  }, [config, setPendingChanges, setHasChanges])

  return (
    <SettingsContext.Provider value={{
      config,
      pendingChanges,
      getValue,
      getNestedValue,
      updateField,
      updateNestedField,
      setPendingChanges,
      setHasChanges,
    }}>
      {children}
    </SettingsContext.Provider>
  )
}
