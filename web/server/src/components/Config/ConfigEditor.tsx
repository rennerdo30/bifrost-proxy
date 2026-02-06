import { useState, useEffect, useCallback, useMemo } from 'react'
import yaml from 'js-yaml'
import type { ServerConfig } from '../../api/types'
import { deepEqual } from '../../utils/deepEqual'
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts'
import { ServerSection } from './sections/ServerSection'
import { BackendsSection } from './sections/BackendsSection'
import { RoutesSection } from './sections/RoutesSection'
import { AuthSection } from './sections/AuthSection'
import { RateLimitSection } from './sections/RateLimitSection'
import { AccessControlSection } from './sections/AccessControlSection'
import { AccessLogSection } from './sections/AccessLogSection'
import { MetricsSection } from './sections/MetricsSection'
import { LoggingSection } from './sections/LoggingSection'
import { WebUISection } from './sections/WebUISection'
import { APISection } from './sections/APISection'
import { HealthCheckSection } from './sections/HealthCheckSection'
import { AutoUpdateSection } from './sections/AutoUpdateSection'
import { CacheSection } from './sections/CacheSection'

interface ConfigEditorProps {
  config: ServerConfig | undefined
  isLoading: boolean
  onSave: (config: ServerConfig, backup: boolean) => Promise<void>
  onReload: () => Promise<void>
  onValidate?: (config: ServerConfig) => Promise<{ valid: boolean; errors?: string[] }>
}

// Default config values for initialization
const defaultServer = {
  http: { listen: ':8080' },
  socks5: { listen: ':1080' },
}

const defaultAuth = { mode: 'none' as const }

const defaultRateLimit = {
  enabled: false,
  requests_per_second: 100,
  burst_size: 200,
  per_ip: true,
  per_user: false,
}

const defaultAccessControl = {
  whitelist: [] as string[],
  blacklist: [] as string[],
}

const defaultAccessLog = {
  enabled: true,
  format: 'json' as const,
  output: 'stdout',
}

const defaultMetrics = {
  enabled: true,
  listen: ':9090',
  path: '/metrics',
}

const defaultLogging = {
  level: 'info' as const,
  format: 'text' as const,
}

const defaultWebUI = {
  enabled: false,
  listen: ':8081',
}

const defaultAPI = {
  enabled: true,
  listen: ':8082',
}

const defaultAutoUpdate = {
  enabled: false,
  check_interval: '24h',
  channel: 'stable' as const,
}

const defaultCache = {
  enabled: false,
  default_ttl: '30d',
  max_file_size: '50GB',
  storage: {
    type: 'tiered' as const,
    tiered: {
      memory_threshold: '10MB',
    },
    memory: {
      max_size: '2GB',
      max_entries: 50000,
      evict_policy: 'lru' as const,
    },
    disk: {
      path: '/var/cache/bifrost',
      max_size: '500GB',
      cleanup_interval: '1h',
      shard_count: 256,
    },
  },
}

const defaultConfig: ServerConfig = {
  server: defaultServer,
  backends: [],
  routes: [],
  auth: defaultAuth,
  rate_limit: defaultRateLimit,
  access_control: defaultAccessControl,
  access_log: defaultAccessLog,
  metrics: defaultMetrics,
  logging: defaultLogging,
  web_ui: defaultWebUI,
  api: defaultAPI,
  auto_update: defaultAutoUpdate,
  cache: defaultCache,
}

export function ConfigEditor({ config, isLoading, onSave, onReload, onValidate }: ConfigEditorProps) {
  const [isSaving, setIsSaving] = useState(false)
  const [isValidating, setIsValidating] = useState(false)
  const [isReloading, setIsReloading] = useState(false)
  const [createBackup, setCreateBackup] = useState(true)
  const [editedConfig, setEditedConfig] = useState<ServerConfig | null>(null)
  const [editorMode, setEditorMode] = useState<'visual' | 'raw'>('visual')
  const [rawYaml, setRawYaml] = useState('')
  const [rawError, setRawError] = useState<string | null>(null)

  // Initialize editedConfig when config loads
  useEffect(() => {
    if (config && !editedConfig) {
      setEditedConfig({ ...defaultConfig, ...config })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config])

  const currentConfig = editedConfig || config || defaultConfig

  // Fix: proper structural comparison instead of just !!editedConfig
  const hasChanges = useMemo(() => {
    if (!editedConfig || !config) return false
    return !deepEqual(editedConfig, config)
  }, [editedConfig, config])

  const handleSave = useCallback(async () => {
    if (!currentConfig) return

    // Validate before saving if validator is available
    if (onValidate) {
      setIsValidating(true)
      try {
        const result = await onValidate(currentConfig)
        if (!result.valid && result.errors) {
          setIsValidating(false)
          return result.errors
        }
      } catch {
        // Continue with save if validation endpoint fails
      } finally {
        setIsValidating(false)
      }
    }

    setIsSaving(true)
    try {
      await onSave(currentConfig, createBackup)
      setEditedConfig(null) // Reset edited state after successful save
    } finally {
      setIsSaving(false)
    }
    return undefined
  }, [currentConfig, createBackup, onSave, onValidate])

  const handleReload = async () => {
    setIsReloading(true)
    try {
      await onReload()
      setEditedConfig(null)
    } finally {
      setIsReloading(false)
    }
  }

  const updateConfig = (partial: Partial<ServerConfig>) => {
    setEditedConfig((prev) => ({
      ...(prev || config || defaultConfig),
      ...partial,
    }))
  }

  // Keyboard shortcuts
  const shortcuts = useMemo(() => ({
    'mod+s': () => { if (hasChanges) handleSave() },
  }), [hasChanges, handleSave])
  useKeyboardShortcuts(shortcuts)

  // Toggle to raw YAML mode
  const switchToRawMode = () => {
    try {
      setRawYaml(yaml.dump(currentConfig, { indent: 2, lineWidth: 120, noRefs: true }))
      setRawError(null)
      setEditorMode('raw')
    } catch {
      setRawError('Failed to serialize config to YAML')
    }
  }

  // Toggle back to visual mode
  const switchToVisualMode = () => {
    if (rawError) {
      setEditorMode('visual')
      return
    }
    try {
      const parsed = yaml.load(rawYaml) as ServerConfig
      if (parsed && typeof parsed === 'object') {
        setEditedConfig({ ...defaultConfig, ...parsed })
      }
      setRawError(null)
      setEditorMode('visual')
    } catch (e) {
      setRawError(e instanceof Error ? e.message : 'Invalid YAML')
    }
  }

  // Handle raw YAML editing
  const handleRawYamlChange = (value: string) => {
    setRawYaml(value)
    try {
      const parsed = yaml.load(value) as ServerConfig
      if (parsed && typeof parsed === 'object') {
        setEditedConfig({ ...defaultConfig, ...parsed })
        setRawError(null)
      }
    } catch (e) {
      setRawError(e instanceof Error ? e.message : 'Invalid YAML')
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="card animate-pulse">
            <div className="h-6 bg-bifrost-border rounded w-32 mb-2" />
            <div className="h-4 bg-bifrost-border rounded w-48" />
          </div>
        ))}
      </div>
    )
  }

  if (!config) {
    return (
      <div className="card text-center py-12">
        <p className="text-gray-400">Unable to load configuration</p>
      </div>
    )
  }

  const availableBackends = currentConfig.backends?.map((b) => b.name) || []

  return (
    <div className="space-y-4">
      {/* Editor Mode Toggle */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 bg-bifrost-bg rounded-lg p-1">
          <button
            onClick={() => editorMode === 'raw' ? switchToVisualMode() : undefined}
            className={`px-3 py-1.5 text-sm rounded-md transition-all ${
              editorMode === 'visual'
                ? 'bg-bifrost-accent text-white'
                : 'text-bifrost-muted hover:text-white'
            }`}
          >
            Visual Editor
          </button>
          <button
            onClick={() => editorMode === 'visual' ? switchToRawMode() : undefined}
            className={`px-3 py-1.5 text-sm rounded-md transition-all ${
              editorMode === 'raw'
                ? 'bg-bifrost-accent text-white'
                : 'text-bifrost-muted hover:text-white'
            }`}
          >
            Raw YAML
          </button>
        </div>
        <div className="text-xs text-bifrost-muted">
          <span className="badge badge-success text-xs mr-2">Hot Reload</span>
          applied without restart
          <span className="badge badge-warning text-xs mx-2">Restart Required</span>
          needs server restart
        </div>
      </div>

      {/* Raw YAML Editor */}
      {editorMode === 'raw' ? (
        <div className="space-y-2">
          {rawError && (
            <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-sm text-bifrost-error">
              YAML Error: {rawError}
            </div>
          )}
          <textarea
            value={rawYaml}
            onChange={(e) => handleRawYamlChange(e.target.value)}
            className="w-full h-[600px] font-mono text-sm bg-bifrost-bg border border-bifrost-border rounded-lg p-4 text-gray-100 placeholder-bifrost-muted focus:outline-none focus:ring-2 focus:ring-bifrost-accent/50 focus:border-bifrost-accent resize-y"
            spellCheck={false}
          />
        </div>
      ) : (
        <>
          {/* Server Settings */}
          <ServerSection
            config={currentConfig.server || defaultServer}
            onChange={(server) => updateConfig({ server })}
          />

          {/* Backends */}
          <BackendsSection
            backends={currentConfig.backends || []}
            onChange={(backends) => updateConfig({ backends })}
          />

          {/* Routes */}
          <RoutesSection
            routes={currentConfig.routes || []}
            availableBackends={availableBackends}
            onChange={(routes) => updateConfig({ routes })}
          />

          {/* Authentication */}
          <AuthSection
            config={currentConfig.auth || defaultAuth}
            onChange={(auth) => updateConfig({ auth })}
          />

          {/* Rate Limiting */}
          <RateLimitSection
            config={currentConfig.rate_limit || defaultRateLimit}
            onChange={(rate_limit) => updateConfig({ rate_limit })}
          />

          {/* Access Control */}
          <AccessControlSection
            config={currentConfig.access_control || defaultAccessControl}
            onChange={(access_control) => updateConfig({ access_control })}
          />

          {/* Access Logging */}
          <AccessLogSection
            config={currentConfig.access_log || defaultAccessLog}
            onChange={(access_log) => updateConfig({ access_log })}
          />

          {/* Prometheus Metrics */}
          <MetricsSection
            config={currentConfig.metrics || defaultMetrics}
            onChange={(metrics) => updateConfig({ metrics })}
          />

          {/* Application Logging */}
          <LoggingSection
            config={currentConfig.logging || defaultLogging}
            onChange={(logging) => updateConfig({ logging })}
          />

          {/* Web UI */}
          <WebUISection
            config={currentConfig.web_ui || defaultWebUI}
            onChange={(web_ui) => updateConfig({ web_ui })}
          />

          {/* REST API */}
          <APISection
            config={currentConfig.api || defaultAPI}
            onChange={(api) => updateConfig({ api })}
          />

          {/* Global Health Checks */}
          <HealthCheckSection
            config={currentConfig.health_check}
            onChange={(health_check) => updateConfig({ health_check })}
          />

          {/* Auto Update */}
          <AutoUpdateSection
            config={currentConfig.auto_update || defaultAutoUpdate}
            onChange={(auto_update) => updateConfig({ auto_update })}
          />

          {/* Cache */}
          <CacheSection
            config={currentConfig.cache || defaultCache}
            onChange={(cache) => updateConfig({ cache })}
          />
        </>
      )}

      {/* Sticky Save Bar */}
      {hasChanges && (
        <div className="sticky-bar">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={createBackup}
                  onChange={(e) => setCreateBackup(e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm text-gray-400">Create backup</span>
              </label>
              <span className="text-xs text-bifrost-muted hidden sm:inline">
                Press <kbd className="px-1.5 py-0.5 bg-bifrost-bg rounded text-xs border border-bifrost-border">
                  {navigator.platform.includes('Mac') ? '\u2318' : 'Ctrl'}+S
                </kbd> to save
              </span>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleReload}
                disabled={isReloading || isSaving}
                className="btn btn-secondary text-sm"
              >
                {isReloading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Reloading...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Reload
                  </>
                )}
              </button>
              <button
                onClick={handleSave}
                disabled={isSaving || isReloading || isValidating}
                className="btn btn-primary text-sm"
              >
                {isValidating ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Validating...
                  </>
                ) : isSaving ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                    </svg>
                    Save Changes
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
