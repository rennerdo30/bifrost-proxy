import { useState, useEffect } from 'react'
import type { ServerConfig } from '../../api/types'
import { ServerSection } from './sections/ServerSection'
import { BackendsSection } from './sections/BackendsSection'
import { RoutesSection } from './sections/RoutesSection'
import { AuthSection } from './sections/AuthSection'
import { RateLimitSection } from './sections/RateLimitSection'
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
  access_log: defaultAccessLog,
  metrics: defaultMetrics,
  logging: defaultLogging,
  web_ui: defaultWebUI,
  api: defaultAPI,
  auto_update: defaultAutoUpdate,
  cache: defaultCache,
}

export function ConfigEditor({ config, isLoading, onSave, onReload }: ConfigEditorProps) {
  const [isSaving, setIsSaving] = useState(false)
  const [isReloading, setIsReloading] = useState(false)
  const [createBackup, setCreateBackup] = useState(true)
  const [editedConfig, setEditedConfig] = useState<ServerConfig | null>(null)

  // Initialize editedConfig when config loads
  useEffect(() => {
    if (config && !editedConfig) {
      setEditedConfig({ ...defaultConfig, ...config })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config])

  const currentConfig = editedConfig || config || defaultConfig
  const hasChanges = !!editedConfig

  const handleSave = async () => {
    if (!currentConfig) return
    setIsSaving(true)
    try {
      await onSave(currentConfig, createBackup)
      setEditedConfig(null) // Reset edited state after successful save
    } finally {
      setIsSaving(false)
    }
  }

  const handleReload = async () => {
    setIsReloading(true)
    try {
      await onReload()
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
      {/* Info Banner */}
      <div className="p-4 bg-bifrost-accent/10 border border-bifrost-accent/30 rounded-lg">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-bifrost-accent mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <p className="text-sm text-gray-300">
              <span className="badge badge-success text-xs mr-2">Hot Reload</span>
              sections can be applied without restart.
              <span className="badge badge-warning text-xs mx-2">Restart Required</span>
              sections need a server restart.
            </p>
          </div>
        </div>
      </div>

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

      {/* Actions */}
      <div className="card">
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={createBackup}
              onChange={(e) => setCreateBackup(e.target.checked)}
              className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
            />
            <span className="text-sm text-gray-400">Create backup before saving</span>
          </label>
          <div className="flex items-center gap-3">
            <button
              onClick={handleReload}
              disabled={isReloading || isSaving}
              className="btn btn-secondary"
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
                  Reload Config
                </>
              )}
            </button>
            <button
              onClick={handleSave}
              disabled={isSaving || isReloading || !hasChanges}
              className="btn btn-primary"
            >
              {isSaving ? (
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
    </div>
  )
}
