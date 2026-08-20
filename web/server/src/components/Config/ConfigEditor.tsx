import { useState, useEffect, useCallback, useMemo } from 'react'
import * as yaml from 'js-yaml'
import type { ServerConfig, ConfigValidateResponse } from '../../api/types'
import { deepEqual } from '../../utils/deepEqual'
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts'
import { ConfigSectionProvider } from './ConfigSectionContext'
import {
  CONFIG_SECTIONS,
  sectionLabel,
  type ConfigSectionKey,
} from './sectionMeta'
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
import { NetworkSection } from './sections/NetworkSection'
import { SessionSection } from './sections/SessionSection'
import { MITMSection } from './sections/MITMSection'

interface ConfigEditorProps {
  config: ServerConfig | undefined
  isLoading: boolean
  onSave: (config: ServerConfig, backup: boolean) => Promise<void>
  onReload: () => Promise<void>
  onValidate?: (config: ServerConfig) => Promise<ConfigValidateResponse>
  /**
   * Server-reported hot-reloadability per section (GET /config/meta). When a
   * section is absent the local fallback in sectionMeta is used.
   */
  hotReloadableSections?: Record<string, boolean>
  /** Notifies the page of unsaved edits so it can guard navigation. */
  onDirtyChange?: (dirty: boolean) => void
  /** Section the sidebar asked to reveal; expanded and scrolled into view. */
  revealSection?: ConfigSectionKey | null
  onSectionRevealed?: () => void
  /**
   * Changing this discards in-progress edits and re-adopts the incoming config.
   * Used when the config is replaced wholesale (import), where keeping the old
   * edits would mean a subsequent save reverts the replacement.
   */
  resetKey?: number
}

// Default config values for initialization
const defaultServer = {
  http: { listen: ':8080' },
  socks5: { listen: ':1080' },
}

// The server only accepts the multi-provider format; an empty providers
// list means "no authentication" and never emits the rejected `mode` field.
const defaultAuth = { providers: [] }

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

/** Sections opened by default so the editor is not a wall of collapsed rows. */
const INITIALLY_OPEN_SECTIONS: ConfigSectionKey[] = ['server', 'backends', 'routes']

const YAML_DUMP_OPTIONS = { indent: 2, lineWidth: 120, noRefs: true } as const

/** Height of the raw-YAML textarea. */
const RAW_EDITOR_CLASS = 'w-full h-[600px]'

export function ConfigEditor({
  config,
  isLoading,
  onSave,
  onReload,
  onValidate,
  hotReloadableSections,
  onDirtyChange,
  revealSection,
  onSectionRevealed,
  resetKey = 0,
}: ConfigEditorProps) {
  const [isSaving, setIsSaving] = useState(false)
  const [isValidating, setIsValidating] = useState(false)
  const [isReloading, setIsReloading] = useState(false)
  const [createBackup, setCreateBackup] = useState(true)
  const [editedConfig, setEditedConfig] = useState<ServerConfig | null>(null)
  const [editorMode, setEditorMode] = useState<'visual' | 'raw'>('visual')
  const [rawYaml, setRawYaml] = useState('')
  const [rawError, setRawError] = useState<string | null>(null)
  const [openSections, setOpenSections] = useState<Set<ConfigSectionKey>>(
    () => new Set(INITIALLY_OPEN_SECTIONS)
  )

  // Initialize editedConfig when config loads
  useEffect(() => {
    if (config && !editedConfig) {
      setEditedConfig({ ...defaultConfig, ...config })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config])

  // Discard in-progress edits when the caller replaces the config wholesale.
  // The initialiser above then re-adopts the incoming config.
  useEffect(() => {
    if (resetKey > 0) setEditedConfig(null)
  }, [resetKey])

  const currentConfig = editedConfig || config || defaultConfig

  /**
   * The unedited config, normalised the same way `editedConfig` is initialised.
   * Comparing against the raw server response instead would report a change for
   * any section the server omits but `defaultConfig` supplies, marking the
   * editor dirty before the operator has touched anything.
   */
  const baselineConfig = useMemo(
    () => (config ? { ...defaultConfig, ...config } : null),
    [config]
  )

  // Proper structural comparison instead of just !!editedConfig
  const hasChanges = useMemo(() => {
    if (!editedConfig || !baselineConfig) return false
    return !deepEqual(editedConfig, baselineConfig)
  }, [editedConfig, baselineConfig])

  // Report unsaved edits upward so the page can warn before navigation. This
  // used to be tracked only while a save was in flight, which meant the guard
  // never fired for the case it exists for.
  useEffect(() => {
    onDirtyChange?.(hasChanges)
  }, [hasChanges, onDirtyChange])

  /**
   * Which sections the operator has actually edited. Mirrors the server's
   * per-section comparison so the pre-save summary matches what the save
   * response will report.
   */
  const dirtySections = useMemo(() => {
    const dirty = new Set<ConfigSectionKey>()
    if (!editedConfig || !baselineConfig) return dirty
    for (const section of CONFIG_SECTIONS) {
      const before: unknown = baselineConfig[section.key]
      const after: unknown = editedConfig[section.key]
      // Treat "absent" and "absent" as equal so an optional section neither
      // side sets is never reported as an edit.
      if (before === undefined && after === undefined) continue
      if (!deepEqual(before ?? null, after ?? null)) dirty.add(section.key)
    }
    return dirty
  }, [editedConfig, baselineConfig])

  const isHotReloadable = useCallback(
    (key: ConfigSectionKey) => {
      const fromServer = hotReloadableSections?.[key]
      if (typeof fromServer === 'boolean') return fromServer
      return CONFIG_SECTIONS.find((s) => s.key === key)?.hotReloadable ?? false
    },
    [hotReloadableSections]
  )

  const { pendingHotReload, pendingRestart } = useMemo(() => {
    const hot: ConfigSectionKey[] = []
    const restart: ConfigSectionKey[] = []
    for (const section of CONFIG_SECTIONS) {
      if (!dirtySections.has(section.key)) continue
      if (isHotReloadable(section.key)) hot.push(section.key)
      else restart.push(section.key)
    }
    return { pendingHotReload: hot, pendingRestart: restart }
  }, [dirtySections, isHotReloadable])

  const toggleSection = useCallback((key: ConfigSectionKey) => {
    setOpenSections((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }, [])

  const openSection = useCallback((key: ConfigSectionKey) => {
    setOpenSections((prev) => (prev.has(key) ? prev : new Set(prev).add(key)))
  }, [])

  // Reveal a section requested from the sidebar: leave raw mode, expand the
  // panel, then scroll. Expanding first means the anchor is where the operator
  // expects rather than a collapsed one-line header.
  useEffect(() => {
    if (!revealSection) return
    setEditorMode('visual')
    openSection(revealSection)
    const meta = CONFIG_SECTIONS.find((s) => s.key === revealSection)
    const frame = requestAnimationFrame(() => {
      if (meta) document.getElementById(meta.domId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      onSectionRevealed?.()
    })
    return () => cancelAnimationFrame(frame)
  }, [revealSection, openSection, onSectionRevealed])

  const sectionState = useMemo(
    () => ({
      hotReloadable: isHotReloadable,
      dirtySections,
      openSections,
      toggleSection,
    }),
    [isHotReloadable, dirtySections, openSections, toggleSection]
  )

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

  const handleDiscard = () => {
    setEditedConfig(baselineConfig)
    setRawError(null)
    if (editorMode === 'raw' && baselineConfig) {
      setRawYaml(yaml.dump(baselineConfig, YAML_DUMP_OPTIONS))
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
      setRawYaml(yaml.dump(currentConfig, YAML_DUMP_OPTIONS))
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

  const expandAll = () => setOpenSections(new Set(CONFIG_SECTIONS.map((s) => s.key)))
  const collapseAll = () => setOpenSections(new Set())

  if (isLoading) {
    return (
      <div className="space-y-4" aria-busy="true" aria-live="polite">
        <span className="sr-only">Loading configuration…</span>
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
      <div className="card text-center py-12 space-y-3" role="alert">
        <p className="text-bifrost-heading font-medium">Unable to load configuration</p>
        <p className="text-sm text-bifrost-subtle max-w-md mx-auto">
          The server did not return its configuration. This usually means the API is
          unreachable, or the server was started without a config file path.
        </p>
        <button onClick={() => window.location.reload()} className="btn btn-secondary text-sm">
          Retry
        </button>
      </div>
    )
  }

  const availableBackends = currentConfig.backends?.map((b) => b.name) || []

  return (
    <div className="space-y-4">
      {/* Editor mode + bulk expand/collapse */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-1 bg-bifrost-bg rounded-lg p-1" role="tablist" aria-label="Editor mode">
          <button
            role="tab"
            aria-selected={editorMode === 'visual'}
            onClick={() => editorMode === 'raw' ? switchToVisualMode() : undefined}
            className={`px-3 py-1.5 text-sm rounded-md transition-all ${
              editorMode === 'visual'
                ? 'bg-bifrost-accent text-bifrost-on-accent'
                : 'text-bifrost-muted hover:text-bifrost-heading'
            }`}
          >
            Visual Editor
          </button>
          <button
            role="tab"
            aria-selected={editorMode === 'raw'}
            onClick={() => editorMode === 'visual' ? switchToRawMode() : undefined}
            className={`px-3 py-1.5 text-sm rounded-md transition-all ${
              editorMode === 'raw'
                ? 'bg-bifrost-accent text-bifrost-on-accent'
                : 'text-bifrost-muted hover:text-bifrost-heading'
            }`}
          >
            Raw YAML
          </button>
        </div>

        {editorMode === 'visual' && (
          <div className="flex items-center gap-2">
            <button onClick={expandAll} className="btn btn-ghost btn-sm text-xs">Expand all</button>
            <button onClick={collapseAll} className="btn btn-ghost btn-sm text-xs">Collapse all</button>
          </div>
        )}
      </div>

      {/* Legend: what the per-section badges mean */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-bifrost-muted">
        <span className="flex items-center gap-1.5">
          <span className="badge badge-success text-xs">Hot Reload</span>
          applied on save, no restart
        </span>
        <span className="flex items-center gap-1.5">
          <span className="badge badge-warning text-xs">Restart Required</span>
          saved to disk, applies after restart
        </span>
        <span className="flex items-center gap-1.5">
          <span className="badge badge-info text-xs">Modified</span>
          unsaved edit in this section
        </span>
      </div>

      {/* Raw YAML Editor */}
      {editorMode === 'raw' ? (
        <div className="space-y-2">
          {rawError && (
            <div
              className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-sm text-bifrost-error"
              role="alert"
            >
              YAML Error: {rawError}
            </div>
          )}
          <label className="sr-only" htmlFor="raw-yaml-editor">Raw YAML configuration</label>
          <textarea
            id="raw-yaml-editor"
            value={rawYaml}
            onChange={(e) => handleRawYamlChange(e.target.value)}
            aria-invalid={!!rawError}
            className={`${RAW_EDITOR_CLASS} font-mono text-sm bg-bifrost-bg border border-bifrost-border rounded-lg p-4 text-bifrost-heading placeholder-bifrost-muted focus:outline-none focus:ring-2 focus:ring-bifrost-accent/50 focus:border-bifrost-accent resize-y`}
            spellCheck={false}
          />
        </div>
      ) : (
        <ConfigSectionProvider value={sectionState}>
          <ServerSection
            config={currentConfig.server || defaultServer}
            onChange={(server) => updateConfig({ server })}
          />

          <BackendsSection
            backends={currentConfig.backends || []}
            onChange={(backends) => updateConfig({ backends })}
          />

          <RoutesSection
            routes={currentConfig.routes || []}
            availableBackends={availableBackends}
            onChange={(routes) => updateConfig({ routes })}
          />

          <AuthSection
            config={currentConfig.auth || defaultAuth}
            onChange={(auth) => updateConfig({ auth })}
          />

          <AccessControlSection
            config={currentConfig.access_control || defaultAccessControl}
            onChange={(access_control) => updateConfig({ access_control })}
          />

          <MITMSection
            config={currentConfig.mitm}
            onChange={(mitm) => updateConfig({ mitm })}
          />

          <RateLimitSection
            config={currentConfig.rate_limit || defaultRateLimit}
            onChange={(rate_limit) => updateConfig({ rate_limit })}
          />

          <CacheSection
            config={currentConfig.cache || defaultCache}
            onChange={(cache) => updateConfig({ cache })}
          />

          <HealthCheckSection
            config={currentConfig.health_check}
            onChange={(health_check) => updateConfig({ health_check })}
          />

          <NetworkSection
            config={currentConfig.network}
            onChange={(network) => updateConfig({ network })}
          />

          <AccessLogSection
            config={currentConfig.access_log || defaultAccessLog}
            onChange={(access_log) => updateConfig({ access_log })}
          />

          <MetricsSection
            config={currentConfig.metrics || defaultMetrics}
            onChange={(metrics) => updateConfig({ metrics })}
          />

          <LoggingSection
            config={currentConfig.logging || defaultLogging}
            onChange={(logging) => updateConfig({ logging })}
          />

          <WebUISection
            config={currentConfig.web_ui || defaultWebUI}
            onChange={(web_ui) => updateConfig({ web_ui })}
          />

          <APISection
            config={currentConfig.api || defaultAPI}
            onChange={(api) => updateConfig({ api })}
          />

          <SessionSection
            config={currentConfig.session}
            onChange={(session) => updateConfig({ session })}
          />

          <AutoUpdateSection
            config={currentConfig.auto_update || defaultAutoUpdate}
            onChange={(auto_update) => updateConfig({ auto_update })}
          />
        </ConfigSectionProvider>
      )}

      {/* Sticky Save Bar */}
      {hasChanges && (
        <div className="sticky-bar" role="region" aria-label="Unsaved configuration changes">
          <div className="space-y-3">
            {/* What is about to happen, before the operator commits to it */}
            <div className="flex flex-wrap items-start gap-x-6 gap-y-2 text-xs">
              {pendingHotReload.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="badge badge-success text-xs">Applies immediately</span>
                  {pendingHotReload.map((key) => (
                    <span key={key} className="text-bifrost-subtle">{sectionLabel(key)}</span>
                  ))}
                </div>
              )}
              {pendingRestart.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="badge badge-warning text-xs">Needs restart</span>
                  {pendingRestart.map((key) => (
                    <span key={key} className="text-bifrost-subtle">{sectionLabel(key)}</span>
                  ))}
                </div>
              )}
              {pendingHotReload.length === 0 && pendingRestart.length === 0 && (
                <span className="text-bifrost-muted">Unsaved changes</span>
              )}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={createBackup}
                    onChange={(e) => setCreateBackup(e.target.checked)}
                    className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                  />
                  <span className="text-sm text-bifrost-subtle">Create backup</span>
                </label>
                <span className="text-xs text-bifrost-muted hidden sm:inline">
                  Press <kbd className="px-1.5 py-0.5 bg-bifrost-bg rounded text-xs border border-bifrost-border">
                    {navigator.platform.includes('Mac') ? '⌘' : 'Ctrl'}+S
                  </kbd> to save
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDiscard}
                  disabled={isSaving || isReloading || isValidating}
                  className="btn btn-ghost text-sm"
                >
                  Discard
                </button>
                <button
                  onClick={handleReload}
                  disabled={isReloading || isSaving}
                  className="btn btn-secondary text-sm"
                  title="Discard edits and re-apply the config file currently on disk"
                >
                  {isReloading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Reloading...
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
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
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
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
      )}
    </div>
  )
}
